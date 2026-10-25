import json
import os
import re
import time
import csv
import io
import boto3
import urllib.request
import urllib.parse
import hashlib
import hmac
import uuid
import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Key
from google import genai

# ============================================================
# 1. CONFIGURAÇÕES E CREDENCIAIS
# ============================================================
client = genai.Client(api_key=os.environ.get('GEMINI_API_KEY'))
MODEL_ID = 'gemini-2.5-flash'

TELEGRAM_TOKEN        = os.environ.get('TELEGRAM_TOKEN')
# SEC10: Segredo configurado no BotFather para validar webhooks do bot
TELEGRAM_SECRET_TOKEN = os.environ.get('TELEGRAM_SECRET_TOKEN', '')
ZENTRIX_USER_ID       = os.environ.get('ZENTRIX_USER_ID', '')

# SEC09: Manter * apenas nas rotas públicas. Rotas autenticadas não precisam de CORS
# pois são chamadas diretamente pelo React Native (não pelo browser).
CORS_PUBLICO = {'Access-Control-Allow-Origin': '*'}

# DynamoDB — inicializado uma vez no cold start da Lambda (connection reuse)
_dynamodb          = boto3.resource('dynamodb')
table_users        = _dynamodb.Table('ZentrixUsers')
table_sessions     = _dynamodb.Table('ZentrixSessions')
table_transactions = _dynamodb.Table('ZentrixTransactions')

MINHAS_CATEGORIAS = [
    "Essencial", "Role e Lazer", "Rangos", "Transporte",
    "Assinaturas", "Compras e Mimos", "A receber", "Outros"
]

# ============================================================
# 2. UTILITÁRIOS
# ============================================================

def _to_decimal(value):
    """Converte float/int para Decimal (exigido pelo boto3 no put_item/update_item)."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, int):
        return Decimal(value)
    return value


def _decimal_default(obj):
    """Serializador JSON para converter Decimal → float nas respostas HTTP."""
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def enviar_mensagem_telegram(chat_id, texto):
    """Envia mensagem de confirmação via Telegram Bot."""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": texto, "parse_mode": "Markdown"}
    data = json.dumps(payload).encode('utf-8')
    req  = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read()
    except Exception as e:
        print(f"ERRO AO ENVIAR MENSAGEM TELEGRAM: {str(e)}")


def sanitizar_frase(texto, max_chars=500):
    """
    SEC06 – Sanitiza input de texto livre antes de enviar à IA:
    - Remove tags HTML
    - Remove caracteres de controle
    - Trunca em max_chars
    """
    if not texto or not isinstance(texto, str):
        return ''
    texto = re.sub(r'<[^>]+>', '', texto)           # remove tags HTML
    texto = re.sub(r'[\x00-\x1f\x7f]', '', texto)  # remove chars de controle
    return texto[:max_chars].strip()


def validar_sessao(event, user_id):
    """
    SEC01 – Verifica se o token Bearer no header Authorization
    pertence ao user_id e ainda está dentro do prazo de expiração.
    Substituição: SELECT sessions WHERE token → get_item na ZentrixSessions.
    """
    headers = event.get('headers', {}) or {}
    auth_header = headers.get('Authorization') or headers.get('authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    token = auth_header.split(' ', 1)[1]

    try:
        resp    = table_sessions.get_item(Key={'token': token})
        session = resp.get('Item')
        if not session:
            return False
        # SEC01: token deve pertencer a uma sessão consumida (auth_code já removido)
        if session.get('auth_code'):
            return False
        if str(session.get('user_id', '')) != str(user_id):
            return False
        expires_at_str = session.get('expires_at')
        if expires_at_str:
            if datetime.datetime.fromisoformat(expires_at_str) < datetime.datetime.now():
                return False
        return True
    except Exception as e:
        print(f"Erro ao validar sessão: {e}")
        return False


def _resposta_nao_autorizado():
    return {
        'statusCode': 401,
        'body': json.dumps({'erro': 'Nao autorizado.'})
    }


def _resposta_erro_json():
    return {
        'statusCode': 400,
        'body': json.dumps({'erro': 'Corpo da requisicao invalido.'})
    }


# ============================================================
# 3. RESUMO / INSIGHT IA
# ============================================================

def _upsert_usuario_telegram(user_telegram_id, first_name):
    """
    Busca ou cria usuário pelo ID do Telegram. Retorna o id final (string).
    Substituição: SELECT + INSERT INTO usuarios → get_item + put_item na ZentrixUsers.
    """
    user_id_str = str(user_telegram_id)
    resp        = table_users.get_item(Key={'id': user_id_str})
    if resp.get('Item'):
        return user_id_str
    table_users.put_item(Item={
        'id':            user_id_str,
        'nome':          first_name,
        'email':         f"{user_id_str}@telegram.zentrix",
        'password_hash': 'TELEGRAM_AUTH',
        'created_at':    datetime.datetime.now().isoformat()
    })
    return user_id_str


def obter_resumo_usuario(user_id):
    """
    Consolida dados do mês e aciona o Gemini para gerar insights financeiros.

    Substituição das queries SQL com SUM/GROUP BY/PERIOD_DIFF:
    → query() busca TODAS as transações do user_id.
    → Filtragem de mês, rateio de parcelas e somatória são feitos em Python (in-memory).

    Lógica de rateio:
    - Transações à vista (installments_total <= 1): incluídas apenas se criadas no mês/ano atual.
    - Transações parceladas (Crédito Parcelado / Emprestado, installments_total > 1):
        diff_meses = (ano_atual*12 + mes_atual) - (ano_criação*12 + mes_criação)
        Incluída se 0 <= diff_meses < installments_total.
        Valor efetivo = amount / installments_total.
    """
    resp_user = table_users.get_item(Key={'id': str(user_id)})
    user_info = resp_user.get('Item')
    if not user_info:
        return None

    resp_tx          = table_transactions.query(
        KeyConditionExpression=Key('user_id').eq(str(user_id))
    )
    todas_transacoes = resp_tx.get('Items', [])

    agora     = datetime.datetime.now()
    ano_atual = agora.year
    mes_atual = agora.month

    total_geral             = 0.0
    distribuicao_categorias = {}

    for tx in todas_transacoes:
        if tx.get('status') == 'deleted':
            continue
        try:
            created_at = datetime.datetime.fromisoformat(tx.get('created_at', ''))
        except (ValueError, TypeError):
            continue

        tipo               = tx.get('type', '')
        installments_total = int(tx.get('installments_total') or 1)
        amount             = float(tx.get('amount') or 0)
        categoria          = tx.get('category', 'Outros')

        eh_parcelado = tipo in ('Crédito Parcelado', 'Emprestado') and installments_total > 1

        if eh_parcelado:
            # Equivalente ao PERIOD_DIFF do MySQL, calculado em Python
            diff_meses = (ano_atual * 12 + mes_atual) - (created_at.year * 12 + created_at.month)
            if not (0 <= diff_meses < installments_total):
                continue
            valor_efetivo = amount / installments_total
        else:
            if created_at.year != ano_atual or created_at.month != mes_atual:
                continue
            valor_efetivo = amount

        total_geral += valor_efetivo
        distribuicao_categorias[categoria] = (
            distribuicao_categorias.get(categoria, 0.0) + valor_efetivo
        )

    limite    = float(user_info.get('limite_mensal') or 0)
    cat_texto = ", ".join([f"{c}: R$ {v:.2f}" for c, v in distribuicao_categorias.items()])

    insight_ia = "Sem transações registradas no mês para analisar."
    if total_geral > 0:
        prompt_insight = f"""
        Aja como um consultor financeiro de alto nível. Analise os gastos do mês atual do usuário {user_info['nome']}:
        - Limite de Gastos Mensal: R$ {limite}
        - Total já gasto: R$ {total_geral:.2f}
        - Distribuição por categorias: [{cat_texto}]

        Dê um feedback direto, curto e motivador. Se passou do limite ou está perto, avise.
        Aponte o maior vilão e dê uma dica prática. Max 3 linhas.
        """
        try:
            response   = client.models.generate_content(model=MODEL_ID, contents=prompt_insight)
            insight_ia = response.text.strip()
        except Exception as e:
            print("Erro IA Resumo:", e)
            insight_ia = "A cota gratuita da Inteligência Artificial atingiu o limite de requisições por hoje. Volte amanhã para novos insights!"

    return {
        'nome':                   user_info['nome'],
        'total_gasto':            total_geral,
        'limite_definido':        limite,
        'saldo_disponivel':       limite - total_geral,
        'distribuicao_categorias': distribuicao_categorias,
        'insight_ia':             insight_ia
    }


# ============================================================
# 4. ROTEADOR PRINCIPAL
# ============================================================

def lambda_handler(event, context):
    metodo = event.get('httpMethod') or event.get('requestContext', {}).get('http', {}).get('method')

    try:
        if metodo == 'POST':
            return tratar_post(event)
        elif metodo == 'GET':
            return tratar_get(event)
        elif metodo == 'DELETE':
            return tratar_delete(event)
        elif metodo == 'PUT':
            return tratar_put(event)
        else:
            return tratar_post(event)
    except Exception as e:
        # SEC02: Loga internamente; nunca expõe detalhes ao cliente.
        print(f"ERRO CRÍTICO NÃO TRATADO: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'erro': 'Erro interno do servidor. Tente novamente mais tarde.'})
        }


# ============================================================
# 5. POST
# ============================================================


def processar_csv_c6(user_id, csv_text):
    """
    Processa CSV do C6 Bank e salva transações no DynamoDB.
    Substituição: INSERT INTO transacoes → put_item na ZentrixTransactions.
    ID gerado via uuid.uuid4().hex (substitui o AUTO_INCREMENT do MySQL).
    """
    f      = io.StringIO(csv_text.strip())
    reader = list(csv.DictReader(f, delimiter=';'))
    descricoes_brutas = list(set([row.get('Descrição', '') for row in reader if row.get('Descrição')]))

    prompt_lote = f'''
    Você é um categorizador financeiro.
    Categorias permitidas: {MINHAS_CATEGORIAS}.
    Analise os itens a seguir e retorne APENAS um array de objetos JSON (sem blocos de código ou aspas extras), neste formato estrito:
    [
      {{"orig": "NOME ORIGINAL", "limpa": "Nome Bonito", "cat": "Categoria Correta"}}
    ]
    Itens para analisar: {descricoes_brutas}
    '''
    try:
        response = client.models.generate_content(model=MODEL_ID, contents=prompt_lote)
        texto_ia = response.text.strip()
    except Exception as e:
        print("Erro IA Lote:", e)
        texto_ia = "[]"
    if texto_ia.startswith('```'):
        texto_ia = texto_ia.split('\n', 1)[-1]
        if texto_ia.endswith('```'):
            texto_ia = texto_ia.rsplit('\n', 1)[0]

    mapa_categorias = {}
    try:
        lista_ia = json.loads(texto_ia.strip())
        for item in lista_ia:
            mapa_categorias[item['orig']] = {"desc_limpa": item['limpa'], "cat": item['cat']}
    except Exception as e:
        print("Erro ao decodificar JSON da IA:", e)
        print("Resposta bruta:", texto_ia)

    contagem = 0
    for row in reader:
        desc_orig   = row.get('Descrição', '')
        valor_bruto = row.get('Valor (em R$)', '0')
        if ',' in valor_bruto and '.' in valor_bruto:
            valor_bruto = valor_bruto.replace('.', '').replace(',', '.')
        elif ',' in valor_bruto:
            valor_bruto = valor_bruto.replace(',', '.')
        try:
            valor = float(valor_bruto)
        except ValueError:
            continue
        if valor <= 0:
            continue

        info_ia     = mapa_categorias.get(desc_orig, {"desc_limpa": desc_orig[:100], "cat": "Outros"})
        parcela_raw = row.get('Parcela', 'Única')
        total_p = paga_p = 1
        if "/" in parcela_raw:
            partes  = parcela_raw.split("/")
            paga_p  = int(partes[0])
            total_p = int(partes[1])

        tipo_movimentacao = "Crédito Parcelado" if "/" in parcela_raw else "Crédito à Vista"
        if info_ia['cat'] == "A receber":
            tipo_movimentacao = "Emprestado"

        table_transactions.put_item(Item={
            'user_id':            str(user_id),
            'id':                 uuid.uuid4().hex,          # substitui AUTO_INCREMENT
            'description':        info_ia['desc_limpa'],
            'amount':             Decimal(str(valor)),        # Decimal obrigatório no boto3
            'category':           info_ia['cat'],
            'type':               tipo_movimentacao,
            'source':             'C6_BANK',
            'installments_total': total_p,
            'installments_paid':  paga_p,
            'status':             'active',
            'created_at':         datetime.datetime.now().isoformat()
        })
        contagem += 1
    return contagem

def tratar_post(event):

    # Bug fix: captura JSON inválido antes de qualquer processamento
    try:
        body = json.loads(event.get('body', '{}') or '{}')
    except json.JSONDecodeError:
        return _resposta_erro_json()

    # --- CASO 1: BOT DO TELEGRAM ---
    if 'message' in body:
        # SEC10: Valida o secret token do webhook do Telegram Bot
        if TELEGRAM_SECRET_TOKEN:
            headers = event.get('headers', {}) or {}
            incoming_secret = headers.get('X-Telegram-Bot-Api-Secret-Token') or \
                              headers.get('x-telegram-bot-api-secret-token', '')
            if not hmac.compare_digest(incoming_secret, TELEGRAM_SECRET_TOKEN):
                print("SEC10: Webhook do bot recebido sem secret token válido.")
                return {'statusCode': 200, 'body': json.dumps('Ignorado')}

        telegram_msg      = body.get('message', {})
        chat_id           = telegram_msg.get('chat', {}).get('id')
        user_telegram_id  = telegram_msg.get('from', {}).get('id')
        first_name        = telegram_msg.get('from', {}).get('first_name', 'Usuário Telegram')
        texto_recebido    = telegram_msg.get('text', '')

        # ---- Processamento de Arquivos CSV via Telegram ----
        if 'document' in telegram_msg:
            document  = telegram_msg['document']
            file_name = document.get('file_name', '').lower()

            if not file_name.endswith('.csv'):
                enviar_mensagem_telegram(chat_id, "⚠️ Por favor, envie apenas arquivos CSV da fatura do C6 Bank.")
                return {'statusCode': 200, 'body': json.dumps('Not CSV')}

            enviar_mensagem_telegram(chat_id, "⏳ Recebi seu arquivo CSV! Analisando com a IA Zentrix... aguarde um instante.")
            try:
                # Pegar o path do arquivo
                req_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getFile?file_id={document['file_id']}"
                with urllib.request.urlopen(req_url) as resp:
                    file_info = json.loads(resp.read())
                    file_path = file_info['result']['file_path']

                # Baixar o arquivo
                dl_url = f"https://api.telegram.org/file/bot{TELEGRAM_TOKEN}/{file_path}"
                with urllib.request.urlopen(dl_url) as resp:
                    csv_bytes = resp.read()

                if len(csv_bytes) > 1_048_576:
                    enviar_mensagem_telegram(chat_id, "❌ Arquivo muito grande. O limite é 1MB.")
                    return {'statusCode': 200, 'body': json.dumps('Too large')}

                csv_text_tg = csv_bytes.decode('utf-8')
                id_final_u  = _upsert_usuario_telegram(user_telegram_id, first_name)
                contagem    = processar_csv_c6(id_final_u, csv_text_tg)

                enviar_mensagem_telegram(chat_id, f"✅ Sucesso! O arquivo foi analisado e **{contagem} transações** foram salvas no seu histórico do Zentrix de forma inteligente.")
                return {'statusCode': 200, 'body': json.dumps('CSV processado pelo Telegram')}
            except Exception as e:
                enviar_mensagem_telegram(chat_id, f"❌ Ocorreu um erro ao processar o CSV: {str(e)}")
                return {'statusCode': 200, 'body': json.dumps('Error CSV TG')}

        if not texto_recebido:
            enviar_mensagem_telegram(chat_id, "⚠️ Por enquanto só consigo processar mensagens de texto.")
            return {'statusCode': 200, 'body': json.dumps('Mensagem sem texto')}


        id_final_usuario = _upsert_usuario_telegram(user_telegram_id, first_name)

        texto_limpo = texto_recebido.strip().lower()
        if texto_limpo.startswith('/resumo') or 'resumo' in texto_limpo:
            resumo = obter_resumo_usuario(id_final_usuario)
            if not resumo:
                enviar_mensagem_telegram(chat_id, "❌ Configure suas métricas no painel antes de pedir um resumo.")
                return {'statusCode': 200, 'body': json.dumps('Sem dados')}

            msg_resumo = (
                f"📊 *Resumo Financeiro - {resumo['nome']}*\n\n"
                f"💰 *Total Gasto:* R$ {resumo['total_gasto']:.2f}\n"
                f"🎯 *Limite Mensal:* R$ {resumo['limite_definido']:.2f}\n"
                f"💵 *Saldo Disponível:* R$ {resumo['saldo_disponivel']:.2f}\n\n"
                f"🗂️ *Divisão por Categorias:*\n"
            )
            for cat, valor in resumo['distribuicao_categorias'].items():
                msg_resumo += f"  ▪️ _{cat}_: R$ {valor:.2f}\n"
            msg_resumo += f"\n💡 *Insight da IA Zentrix:*\n_{resumo['insight_ia']}_"
            enviar_mensagem_telegram(chat_id, msg_resumo)
            return {'statusCode': 200, 'body': json.dumps('Telegram resumo enviado')}

        else:
            # SEC06: Sanitiza a frase antes de enviar ao Gemini
            frase_segura = sanitizar_frase(texto_recebido)
            prompt_ia    = f"""
            Extraia os dados da frase: '{frase_segura}'
            Categorias: {MINHAS_CATEGORIAS}
            Tipos permitidos: [Débito, Crédito à Vista, Crédito Parcelado, Emprestado]

            Regras de Tipo:
            - 'no débito' ou 'no pix' -> Débito
            - Com parcelas -> Crédito Parcelado
            - 'A receber' -> Emprestado
            - Padrão -> Crédito à Vista

            Retorne APENAS um JSON: {{"description": "nome", "amount": float, "category": "categoria", "type": "tipo", "installments": int, "debtor_name": "nome ou null"}}
            """
            try:
                response = client.models.generate_content(model=MODEL_ID, contents=prompt_ia)
                dados    = json.loads(response.text.replace('```json', '').replace('```', '').strip())
            except Exception as e:
                print("Erro IA Telegram:", e)
                enviar_mensagem_telegram(chat_id, "⚠️ A IA está sobrecarregada no momento e não conseguiu processar sua requisição. Tente usar uma categoria ou tente amanhã.")
                return {'statusCode': 200, 'body': json.dumps('Rate limit IA')}

            # Validação SEC: amount deve ser positivo
            if not isinstance(dados.get('amount'), (int, float)) or dados['amount'] <= 0:
                enviar_mensagem_telegram(chat_id, "⚠️ Não consegui identificar um valor válido. Tente novamente.")
                return {'statusCode': 200, 'body': json.dumps('Valor inválido')}

            # SEC08: raw_input_phrase removido — não armazenamos PII desnecessário
            table_transactions.put_item(Item={
                'user_id':            str(id_final_usuario),
                'id':                 uuid.uuid4().hex,
                'description':        dados['description'],
                'amount':             Decimal(str(dados['amount'])),
                'category':           dados['category'],
                'type':               dados['type'],
                'source':             'TELEGRAM_BOT',
                'installments_total': dados.get('installments', 1),
                'debtor_name':        dados.get('debtor_name'),
                'status':             'active',
                'created_at':         datetime.datetime.now().isoformat()
            })

            msg_confirmacao = (
                f"✅ *Transação Salva no Zentrix!*\n\n"
                f"📝 *Item:* {dados['description']}\n"
                f"💰 *Valor:* R$ {dados['amount']:.2f}\n"
                f"🏷️ *Categoria:* {dados['category']}\n"
                f"💳 *Tipo:* {dados['type']}"
            )
            if dados.get('installments', 1) > 1:
                msg_confirmacao += f"\n🔢 *Parcelas:* {dados['installments']}"
            if dados.get('debtor_name'):
                msg_confirmacao += f"\n👤 *Devedor:* {dados['debtor_name']}"

            enviar_mensagem_telegram(chat_id, msg_confirmacao)
            return {'statusCode': 200, 'body': json.dumps('Telegram processado')}

    # --- CASO 2: AUTENTICAÇÃO WEB (via POST com hash do Telegram) ---
    elif 'hash' in body and 'id' in body:
        tg_hash     = body.get('hash')
        auth_date   = body.get('auth_date')
        telegram_id = body.get('id')
        first_name  = body.get('first_name', '')

        data_check_list = [f"{k}={v}" for k, v in sorted(body.items()) if k != 'hash']
        data_check_string = "\n".join(data_check_list)

        secret_key = hashlib.sha256(TELEGRAM_TOKEN.encode('utf-8')).digest()
        local_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(local_hash, tg_hash):
            return {
                'statusCode': 401,
                'headers': CORS_PUBLICO,
                'body': json.dumps({'erro': 'Assinatura inválida.'})
            }

        if time.time() - int(auth_date) > 86400:
            return {
                'statusCode': 401,
                'headers': CORS_PUBLICO,
                'body': json.dumps({'erro': 'Assinatura do Telegram expirada.'})
            }

        id_final_usuario = _upsert_usuario_telegram(telegram_id, first_name)

        session_token = str(uuid.uuid4())
        expires_at    = (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat()
        # Sessão sem auth_code: já é válida para uso direto pelo frontend web
        table_sessions.put_item(Item={
            'token':      session_token,
            'user_id':    str(telegram_id),
            'expires_at': expires_at
        })

        return {
            'statusCode': 200,
            'headers': CORS_PUBLICO,
            'body': json.dumps({
                'login':           True,
                'token_sessao':    session_token,
                'user_id_interno': id_final_usuario,
                'nome':            first_name
            })
        }

    # --- CASO 3: IMPORTAÇÃO DE CSV (C6 BANK) ---
    elif 'csv_text' in body:
        user_id  = body.get('user_id', ZENTRIX_USER_ID)
        csv_text = body.get('csv_text', '')

        if not validar_sessao(event, user_id):
            return _resposta_nao_autorizado()

        # SEC07: Limite de tamanho de 1MB para evitar DoS no Lambda
        if len(csv_text) > 1_048_576:
            return {
                'statusCode': 413,
                'body': json.dumps({'erro': 'Arquivo CSV muito grande. Limite de 1MB.'})
            }


        contagem = processar_csv_c6(user_id, csv_text)
        return {'statusCode': 201, 'body': json.dumps(f'{contagem} itens processados!')}

    # --- CASO 4: FRASE POR VOZ / DIRECT API ---
    elif 'frase' in body:
        user_id = body.get('user_id', ZENTRIX_USER_ID)
        if not validar_sessao(event, user_id):
            return _resposta_nao_autorizado()

        # SEC06: Sanitiza antes de enviar ao Gemini
        frase_segura = sanitizar_frase(body['frase'])
        if not frase_segura:
            return {'statusCode': 400, 'body': json.dumps({'erro': 'Frase inválida ou vazia.'})}

        prompt_ia = f"""
        Extraia os dados da frase: '{frase_segura}'
        Categorias: {MINHAS_CATEGORIAS}
        Tipos permitidos: [Débito, Crédito à Vista, Crédito Parcelado, Emprestado]

        Retorne APENAS um JSON: {{"description": "nome", "amount": float, "category": "categoria", "type": "tipo", "installments": int, "debtor_name": "nome ou null"}}
        """
        try:
            response = client.models.generate_content(model=MODEL_ID, contents=prompt_ia)
            dados    = json.loads(response.text.replace('```json', '').replace('```', '').strip())
        except Exception as e:
            print("Erro IA Direct:", e)
            return {'statusCode': 429, 'body': json.dumps({'erro': 'Limite de uso da IA excedido. Tente novamente mais tarde.'})}

        if not isinstance(dados.get('amount'), (int, float)) or dados['amount'] <= 0:
            return {'statusCode': 422, 'body': json.dumps({'erro': 'Não foi possível identificar um valor válido na frase.'})}

        # SEC08: raw_input_phrase removido
        table_transactions.put_item(Item={
            'user_id':            str(user_id),
            'id':                 uuid.uuid4().hex,
            'description':        dados['description'],
            'amount':             Decimal(str(dados['amount'])),
            'category':           dados['category'],
            'type':               dados['type'],
            'source':             'IA_CHAT',
            'installments_total': dados.get('installments', 1),
            'debtor_name':        dados.get('debtor_name'),
            'status':             'active',
            'created_at':         datetime.datetime.now().isoformat()
        })
        return {'statusCode': 201, 'body': json.dumps({'message': 'Salvo!', 'dados': dados})}

    return {'statusCode': 400, 'body': json.dumps({'erro': 'Requisição POST não reconhecida.'})}


# ============================================================
# 6. GET
# ============================================================

def tratar_get(event):
    params = event.get('queryStringParameters', {}) or {}
    action = params.get('action')

    # --- Rota pública: Página HTML de Login ---
    if action == 'telegram-login':
        app_redirect_uri = params.get('app_redirect_uri', 'zentrix://auth/callback')
        return servir_pagina_telegram_login(app_redirect_uri)

    # --- Rota pública: Callback server-side do Telegram ---
    if action == 'telegram-callback':
        return tratar_telegram_callback(params)

    # --- SEC03: Rota de troca de auth_code por token real ---
    if action == 'trocar-codigo':
        return tratar_troca_codigo(params)

    # --- Rotas autenticadas ---
    user_id = params.get('user_id', ZENTRIX_USER_ID)
    if not user_id:
        return {'statusCode': 400, 'body': json.dumps('user_id é obrigatório')}

    if not validar_sessao(event, user_id):
        return _resposta_nao_autorizado()

    if action == 'summary':
        resumo = obter_resumo_usuario(user_id)
        if not resumo:
            return {'statusCode': 404, 'body': json.dumps('Usuário não encontrado')}
        return {
            'statusCode': 200,
            'body': json.dumps({
                'metricas': {
                    'total_gasto':             resumo['total_gasto'],
                    'limite_definido':         resumo['limite_definido'],
                    'saldo_disponivel':        resumo['saldo_disponivel'],
                    'distribuicao_categorias': resumo['distribuicao_categorias']
                },
                'insight_ia': resumo['insight_ia']
            }, default=_decimal_default)
        }
    else:
        # Busca todas as transações e ordena por created_at DESC em Python
        # Substituição: SELECT * FROM transacoes ORDER BY created_at DESC
        resp_tx = table_transactions.query(
            KeyConditionExpression=Key('user_id').eq(str(user_id))
        )
        items = resp_tx.get('Items', [])
        items.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        # Busca dados do usuário e remove password_hash (SEC)
        resp_user = table_users.get_item(Key={'id': str(user_id)})
        user_info = resp_user.get('Item')
        if user_info:
            user_info.pop('password_hash', None)

        return {
            'statusCode': 200,
            'body': json.dumps(
                {'transacoes': items, 'usuario': user_info},
                default=_decimal_default
            )
        }


# ============================================================
# 7. DELETE
# ============================================================

def tratar_delete(event):
    try:
        body = json.loads(event.get('body', '{}') or '{}')
    except json.JSONDecodeError:
        return _resposta_erro_json()

    user_id      = body.get('user_id', ZENTRIX_USER_ID)
    transacao_id = body.get('id')

    if not user_id or not transacao_id:
        return {'statusCode': 400, 'body': json.dumps('Faltam chaves para deletar')}

    if not validar_sessao(event, user_id):
        return _resposta_nao_autorizado()

    # Substituição: DELETE FROM transacoes WHERE id = %s AND user_id = %s
    # A chave composta (PK=user_id + SK=id) já garante o isolamento por usuário
    table_transactions.delete_item(
        Key={
            'user_id': str(user_id),
            'id':      str(transacao_id)
        }
    )
    return {'statusCode': 200, 'body': json.dumps('Item removido.')}


# ============================================================
# 8. PUT
# ============================================================

def tratar_put(event):
    try:
        body = json.loads(event.get('body', '{}') or '{}')
    except json.JSONDecodeError:
        return _resposta_erro_json()

    user_id = body.get('user_id', ZENTRIX_USER_ID)
    action  = body.get('action')

    if not validar_sessao(event, user_id):
        return _resposta_nao_autorizado()

    if action == 'update_transaction':
        transacao_id = body.get('id')
        if not transacao_id:
            return {'statusCode': 400, 'body': json.dumps('ID da transação não fornecido')}

        update_parts = []
        expr_values  = {}
        expr_names   = {}

        # Whitelist de campos permitidos para atualização.
        # Todos passam por ExpressionAttributeNames para evitar conflito
        # com palavras reservadas do DynamoDB (ex: 'status', 'description').
        CAMPOS_PERMITIDOS = {'amount', 'description', 'category', 'status'}
        for campo in CAMPOS_PERMITIDOS:
            if campo not in body:
                continue
            if campo == 'amount':
                try:
                    val = float(body[campo])
                    if val <= 0:
                        return {'statusCode': 400, 'body': json.dumps('Valor deve ser positivo')}
                    update_parts.append(f"#f_{campo} = :v_{campo}")
                    expr_names[f'#f_{campo}']  = campo
                    expr_values[f':v_{campo}'] = Decimal(str(val))
                except (ValueError, TypeError):
                    return {'statusCode': 400, 'body': json.dumps('Valor inválido')}
            else:
                update_parts.append(f"#f_{campo} = :v_{campo}")
                expr_names[f'#f_{campo}']  = campo
                expr_values[f':v_{campo}'] = body[campo]

        if not update_parts:
            return {'statusCode': 400, 'body': json.dumps('Nenhum campo válido para atualizar')}

        # Substituição: UPDATE transacoes SET ... WHERE id = %s AND user_id = %s
        table_transactions.update_item(
            Key={
                'user_id': str(user_id),
                'id':      str(transacao_id)
            },
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values
        )
        return {'statusCode': 200, 'body': json.dumps({'message': 'Transação atualizada'})}

    elif action == 'update_user':
        update_parts = []
        expr_values  = {}
        expr_names   = {}

        # Substituição: UPDATE usuarios SET ... WHERE id = %s
        # Valores monetários usam Decimal (boto3 não aceita float nativo)
        if 'salario_mensal' in body:
            update_parts.append("#f_salario = :v_salario")
            expr_names['#f_salario']  = 'salario_mensal'
            expr_values[':v_salario'] = Decimal(str(body['salario_mensal']))
        if 'limite_mensal' in body:
            update_parts.append("#f_limite = :v_limite")
            expr_names['#f_limite']  = 'limite_mensal'
            expr_values[':v_limite'] = Decimal(str(body['limite_mensal']))
        if 'dia_vencimento_fatura' in body:
            update_parts.append("#f_dia_venc = :v_dia_venc")
            expr_names['#f_dia_venc']  = 'dia_vencimento_fatura'
            expr_values[':v_dia_venc'] = body['dia_vencimento_fatura']

        if not update_parts:
            return {'statusCode': 400, 'body': json.dumps('Nenhum campo para atualizar no usuário')}

        table_users.update_item(
            Key={'id': str(user_id)},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values
        )
        return {'statusCode': 200, 'body': json.dumps({'message': 'Perfil atualizado'})}

    else:
        return {'statusCode': 400, 'body': json.dumps('Ação PUT desconhecida')}


# ============================================================
# 9. PÁGINA HTML DE LOGIN (Pública)
# ============================================================

def servir_pagina_telegram_login(app_redirect_uri):
    callback_base = "https://agog0k90kc.execute-api.sa-east-1.amazonaws.com/default/api-financas-ia?action=telegram-callback"
    callback_url  = callback_base + "&app_redirect_uri=" + urllib.parse.quote(app_redirect_uri)

    html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zentrix — Login com Telegram</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh; display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            background: linear-gradient(135deg, #274C77 0%, #4471A0 100%);
            color: #fff; padding: 20px;
        }
        .container { text-align: center; max-width: 400px; width: 100%; }
        .logo {
            width: 72px; height: 72px; border-radius: 50%; background: #fff;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .logo svg { width: 36px; height: 36px; }
        h1 { font-size: 2.2rem; font-weight: 300; letter-spacing: 3px; margin-bottom: 8px; }
        .subtitle { font-size: 0.95rem; color: #A3CEF1; margin-bottom: 40px; }
        .glass-card {
            background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.25);
            border-radius: 20px; padding: 36px 28px;
            backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
        }
        .card-title { font-size: 1.15rem; font-weight: 500; margin-bottom: 8px; }
        .card-description { font-size: 0.85rem; color: rgba(255,255,255,0.75); line-height: 1.6; margin-bottom: 28px; }
        #telegram-widget-container { display: flex; justify-content: center; min-height: 50px; }
        .security-note { display: flex; align-items: center; justify-content: center; gap: 6px; margin-top: 24px; font-size: 0.72rem; color: rgba(255,255,255,0.4); }
        .security-note svg { width: 14px; height: 14px; flex-shrink: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="#274C77" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline>
                <polyline points="16 7 22 7 22 13"></polyline>
            </svg>
        </div>
        <h1>Zentrix</h1>
        <p class="subtitle">Controle Financeiro Inteligente</p>
        <div class="glass-card">
            <p class="card-title">Conecte sua conta</p>
            <p class="card-description">
                Clique no botão abaixo para entrar com sua conta do Telegram.
                Cada conta é única e seus dados ficam isolados e seguros.
            </p>
            <div id="telegram-widget-container">
                <script async src="https://telegram.org/js/telegram-widget.js?22"
                    data-telegram-login="ZentrixOFCBot"
                    data-size="large"
                    data-radius="14"
                    data-auth-url="__CALLBACK_URL__"
                    data-request-access="write">
                </script>
            </div>
            <div class="security-note">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span>Autenticação verificada via assinatura criptográfica do Telegram</span>
            </div>
        </div>
    </div>
</body>
</html>""".replace("__CALLBACK_URL__", callback_url)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html',
            'Access-Control-Allow-Origin': '*'  # Pública: retorna HTML para o browser
        },
        'body': html
    }


# ============================================================
# 10. CALLBACK DO TELEGRAM (SEC03: Gera auth_code temporário)
# ============================================================

def tratar_telegram_callback(params):
    """
    SEC03: Em vez de colocar o token real na URL do deep link,
    gera um auth_code temporário (válido 10 min) e o app
    faz um GET ?action=trocar-codigo para pegar o token real.
    """
    app_redirect_uri = params.get('app_redirect_uri', 'zentrix://auth/callback')
    tg_hash    = params.get('hash', '')
    auth_date  = params.get('auth_date', '0')
    telegram_id = params.get('id', '')
    first_name  = params.get('first_name', 'Usuario')

    def redirect_error(error_code):
        sep = '&' if '?' in app_redirect_uri else '?'
        return {
            'statusCode': 302,
            'headers': {'Location': f'{app_redirect_uri}{sep}error={error_code}'},
            'body': ''
        }

    if not tg_hash or not telegram_id:
        return redirect_error('dados_incompletos')

    # Validar hash HMAC-SHA256
    data_check_list   = [f"{k}={params[k]}" for k in sorted(params.keys()) if k not in ['hash', 'action', 'app_redirect_uri']]
    data_check_string = "\n".join(data_check_list)
    secret_key = hashlib.sha256(TELEGRAM_TOKEN.encode('utf-8')).digest()
    local_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(local_hash, tg_hash):
        return redirect_error('hash_invalido')

    if time.time() - int(auth_date) > 86400:
        return redirect_error('expirado')

    # Garante que o usuário existe no DynamoDB
    _upsert_usuario_telegram(telegram_id, first_name)

    # SEC03: Gerar token real + auth_code temporário (10 min)
    session_token        = str(uuid.uuid4())
    auth_code            = str(uuid.uuid4())
    expires_at           = (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat()
    auth_code_expires_at = (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat()

    table_sessions.put_item(Item={
        'token':                session_token,
        'user_id':              str(telegram_id),
        'expires_at':           expires_at,
        'auth_code':            auth_code,
        'auth_code_expires_at': auth_code_expires_at
    })

    # Apenas auth_code e user_id_interno na URL — token real NUNCA exposto
    callback_params = urllib.parse.urlencode({
        'auth_code':       auth_code,
        'user_id_interno': str(telegram_id),
        'nome':            first_name
    })
    sep = '&' if '?' in app_redirect_uri else '?'
    redirect_url = app_redirect_uri + sep + callback_params

    return {
        'statusCode': 302,
        'headers': {
            'Location': redirect_url,
            'Access-Control-Allow-Origin': '*'
        },
        'body': ''
    }


# ============================================================
# 11. TROCA DE CÓDIGO (SEC03)
# ============================================================

def tratar_troca_codigo(params):
    """
    SEC03: O app envia o auth_code (que veio na URL) e recebe o
    token_sessao real em JSON. O auth_code é invalidado após o uso.
    Substituição: Query no GSI auth_code-index da tabela ZentrixSessions.
    """
    auth_code = params.get('code', '')
    if not auth_code:
        return {'statusCode': 400, 'body': json.dumps({'erro': 'Código inválido.'})}

    # Query no GSI auth_code-index
    resp = table_sessions.query(
        IndexName='auth_code-index',
        KeyConditionExpression=Key('auth_code').eq(auth_code)
    )
    items = resp.get('Items', [])
    if not items:
        return {'statusCode': 401, 'body': json.dumps({'erro': 'Código inválido ou já utilizado.'})}

    # Como o GSI foi configurado como Keys only (ou All), pegamos o token
    session_gsi = items[0]
    token = session_gsi.get('token')
    if not token:
        return {'statusCode': 401, 'body': json.dumps({'erro': 'Sessão inválida.'})}

    # Busca a sessão completa pela chave primária (token)
    resp_sess = table_sessions.get_item(Key={'token': token})
    session = resp_sess.get('Item')
    if not session:
        return {'statusCode': 401, 'body': json.dumps({'erro': 'Sessão não encontrada.'})}

    # Valida se o auth_code ainda está presente e dentro do prazo
    auth_code_expires_at = session.get('auth_code_expires_at')
    if not auth_code_expires_at:
        return {'statusCode': 401, 'body': json.dumps({'erro': 'Código inválido ou já utilizado.'})}

    try:
        if datetime.datetime.fromisoformat(auth_code_expires_at) < datetime.datetime.now():
            return {'statusCode': 401, 'body': json.dumps({'erro': 'Código expirado. Faça login novamente.'})}
    except Exception:
        pass

    # Invalida o auth_code removendo-o da sessão.
    # Como o DynamoDB suporta Sparse Index, ao remover auth_code o item sai automaticamente do GSI auth_code-index!
    table_sessions.update_item(
        Key={'token': token},
        UpdateExpression="REMOVE auth_code, auth_code_expires_at"
    )

    return {
        'statusCode': 200,
        'body': json.dumps({
            'token_sessao': session['token'],
            'user_id_interno': str(session['user_id'])
        })
    }