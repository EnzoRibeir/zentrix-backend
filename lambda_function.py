import csv
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from google import genai

# ============================================================
# 1. CONFIGURAÇÕES E CREDENCIAIS
# ============================================================
_GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
client = genai.Client(api_key=_GEMINI_API_KEY) if _GEMINI_API_KEY else None
MODEL_ID = 'gemini-2.5-flash'

TELEGRAM_TOKEN        = os.environ.get('TELEGRAM_TOKEN', '')
# SEC10: Segredo configurado no BotFather para validar webhooks do bot
TELEGRAM_SECRET_TOKEN = os.environ.get('TELEGRAM_SECRET_TOKEN', '')
ZENTRIX_USER_ID       = os.environ.get('ZENTRIX_USER_ID', '')

DEFAULT_API_BASE_URL = (
    'https://agog0k90kc.execute-api.sa-east-1.amazonaws.com/default/api-financas-ia'
)
DEFAULT_APP_REDIRECT_URI = 'zentrix://auth/callback'

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Telegram-Bot-Api-Secret-Token',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
}

# DynamoDB — inicializado uma vez no cold start da Lambda (connection reuse)
_AWS_REGION        = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'sa-east-1'
_dynamodb          = boto3.resource('dynamodb', region_name=_AWS_REGION)
table_users        = _dynamodb.Table('ZentrixUsers')
table_sessions     = _dynamodb.Table('ZentrixSessions')
table_transactions = _dynamodb.Table('ZentrixTransactions')

MINHAS_CATEGORIAS = [
    "Essencial", "Role e Lazer", "Rangos", "Transporte",
    "Assinaturas", "Compras e Mimos", "A receber", "Outros"
]

TIPOS_PERMITIDOS = [
    "Débito", "Crédito à Vista", "Crédito Parcelado", "Emprestado"
]


# ============================================================
# 2. UTILITÁRIOS E SEGURANÇA
# ============================================================

def _obter_cliente_ia():
    """Retorna o cliente Gemini inicializado (suporta injeção de mock em `client`)."""
    global client
    if client is None:
        client = genai.Client(api_key=os.environ.get('GEMINI_API_KEY'))
    return client


def _to_decimal(value):
    """Converte float/int para Decimal (exigido pelo boto3 no put_item/update_item)."""
    if isinstance(value, bool):
        raise ValueError("Booleano não é um número válido.")
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, int):
        return Decimal(value)
    return value


def _decimal_default(obj):
    """Serializador JSON para converter Decimal -> float nas respostas HTTP."""
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _resposta(status_code, payload, extra_headers=None):
    """Monta resposta HTTP padronizada em JSON com headers de CORS."""
    headers = {
        **CORS_HEADERS,
        'Content-Type': 'application/json',
    }
    if extra_headers:
        headers.update(extra_headers)
    body = '' if status_code == 204 and payload == '' else json.dumps(payload, default=_decimal_default)
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': body,
    }


def _resposta_nao_autorizado():
    return _resposta(401, {'erro': 'Nao autorizado.'})


def _resposta_erro_json():
    return _resposta(400, {'erro': 'Corpo da requisicao invalido.'})


def _validar_redirect_uri(uri):
    """
    SEC – Previne Open Redirect / XSS em deep links e callbacks de login.
    Permite apenas:
      - zentrix://, exp://, exps://
      - http://localhost, http://127.0.0.1
      - https://
    Qualquer valor fora da whitelist faz fallback seguro para 'zentrix://auth/callback'.
    """
    if not uri or not isinstance(uri, str):
        return DEFAULT_APP_REDIRECT_URI

    uri_limpa = uri.strip()
    if not uri_limpa or re.search(r'[\x00-\x20\\]', uri_limpa):
        return DEFAULT_APP_REDIRECT_URI

    try:
        parsed = urllib.parse.urlparse(uri_limpa)
    except ValueError:
        return DEFAULT_APP_REDIRECT_URI

    scheme = (parsed.scheme or '').lower()

    if scheme in ('zentrix', 'exp', 'exps'):
        if uri_limpa.lower().startswith(f'{scheme}://') and (parsed.netloc or parsed.path):
            return uri_limpa
        return DEFAULT_APP_REDIRECT_URI

    if scheme == 'http':
        if parsed.hostname in ('localhost', '127.0.0.1'):
            return uri_limpa
        return DEFAULT_APP_REDIRECT_URI

    if scheme == 'https':
        if parsed.hostname:
            return uri_limpa
        return DEFAULT_APP_REDIRECT_URI

    return DEFAULT_APP_REDIRECT_URI


def _extrair_json_ia(texto):
    """
    Remove cercas markdown (```json ... ```) e extrai o primeiro objeto `{...}`
    ou array `[...]` JSON válido caso o modelo adicione texto extra.
    """
    if not texto or not isinstance(texto, str):
        raise ValueError("Resposta vazia da IA.")

    limpo = texto.strip()
    limpo = re.sub(r'^```(?:json)?\s*', '', limpo, flags=re.IGNORECASE)
    limpo = re.sub(r'\s*```$', '', limpo).strip()

    try:
        return json.loads(limpo)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(limpo):
        if ch in ('{', '['):
            try:
                obj, _ = decoder.raw_decode(limpo[idx:])
                return obj
            except json.JSONDecodeError:
                continue

    raise ValueError("Nenhum JSON válido encontrado na resposta da IA.")


def _normalizar_dados_transacao_ia(dados):
    """Normaliza e valida categoria, tipo, parcelas e descrição vindos da IA."""
    if not isinstance(dados, dict):
        raise ValueError("Formato de transação inválido retornado pela IA.")

    raw_type = dados.get('type')
    raw_cat = dados.get('category')

    if raw_type in TIPOS_PERMITIDOS:
        tipo = raw_type
    elif raw_cat == 'A receber':
        tipo = 'Emprestado'
    else:
        tipo = 'Crédito à Vista'

    if raw_cat in MINHAS_CATEGORIAS:
        categoria = raw_cat
    else:
        categoria = 'A receber' if tipo == 'Emprestado' else 'Outros'

    try:
        installments_total = max(1, int(dados.get('installments') or 1))
    except (ValueError, TypeError):
        installments_total = 1

    descricao = sanitizar_frase(str(dados.get('description') or ''), max_chars=200) or 'Transação'

    raw_amount = dados.get('amount')
    if isinstance(raw_amount, bool):
        valor = -1.0
    else:
        try:
            valor = float(raw_amount)
        except (ValueError, TypeError):
            valor = -1.0

    debtor_name = dados.get('debtor_name')
    if isinstance(debtor_name, str):
        debtor_name = sanitizar_frase(debtor_name, max_chars=120) or None
    else:
        debtor_name = None

    return {
        'description': descricao,
        'amount': valor,
        'category': categoria,
        'type': tipo,
        'installments': installments_total,
        'debtor_name': debtor_name,
    }


def _listar_transacoes_usuario(user_id):
    """
    Lista todas as transações ativas do usuário no DynamoDB iterando
    por todas as páginas (`LastEvaluatedKey`) e filtrando `status == 'deleted'`.
    """
    itens = []
    kwargs = {
        'KeyConditionExpression': Key('user_id').eq(str(user_id))
    }
    while True:
        resp = table_transactions.query(**kwargs)
        for tx in resp.get('Items', []):
            if tx.get('status') != 'deleted':
                itens.append(tx)
        last_key = resp.get('LastEvaluatedKey')
        if not last_key:
            break
        kwargs['ExclusiveStartKey'] = last_key
    return itens


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
    """
    if not user_id:
        return False
    headers = event.get('headers', {}) or {}
    auth_header = headers.get('Authorization') or headers.get('authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    token = auth_header.split(' ', 1)[1].strip()
    if not token:
        return False

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


# ============================================================
# 3. RESUMO / INSIGHT IA
# ============================================================

def _upsert_usuario_telegram(user_telegram_id, first_name):
    """Busca ou cria usuário pelo ID do Telegram. Retorna o id final (string)."""
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
    Consolida dados do mês atual separando despesas (`total_gasto`) de valores
    emprestados (`total_receber`), alinhado com as regras do frontend.
    """
    resp_user = table_users.get_item(Key={'id': str(user_id)})
    user_info = resp_user.get('Item')
    if not user_info:
        return None

    todas_transacoes = _listar_transacoes_usuario(user_id)

    agora     = datetime.datetime.now()
    ano_atual = agora.year
    mes_atual = agora.month

    total_gasto             = 0.0
    total_receber           = 0.0
    distribuicao_categorias = {}

    for tx in todas_transacoes:
        try:
            created_at = datetime.datetime.fromisoformat(tx.get('created_at', ''))
        except (ValueError, TypeError):
            continue

        tipo               = tx.get('type', '')
        installments_total = max(1, int(tx.get('installments_total') or 1))
        amount             = float(tx.get('amount') or 0)
        categoria          = tx.get('category', 'Outros')

        eh_parcelado = tipo in ('Crédito Parcelado', 'Emprestado') and installments_total > 1

        if eh_parcelado:
            diff_meses = (ano_atual * 12 + mes_atual) - (created_at.year * 12 + created_at.month)
            if not (0 <= diff_meses < installments_total):
                continue
            valor_efetivo = amount / installments_total
        else:
            if created_at.year != ano_atual or created_at.month != mes_atual:
                continue
            valor_efetivo = amount

        if tipo == 'Emprestado':
            total_receber += valor_efetivo
        else:
            total_gasto += valor_efetivo
            distribuicao_categorias[categoria] = (
                distribuicao_categorias.get(categoria, 0.0) + valor_efetivo
            )

    limite           = float(user_info.get('limite_mensal') or 0)
    saldo_disponivel = limite - total_gasto
    cat_texto        = ", ".join([f"{c}: R$ {v:.2f}" for c, v in distribuicao_categorias.items()])

    insight_ia = "Sem transações registradas no mês para analisar."
    if total_gasto > 0:
        prompt_insight = f"""
        Aja como um consultor financeiro de alto nível. Analise os gastos do mês atual do usuário {user_info['nome']}:
        - Limite de Gastos Mensal: R$ {limite}
        - Total já gasto: R$ {total_gasto:.2f}
        - Total a receber (emprestado): R$ {total_receber:.2f}
        - Distribuição por categorias: [{cat_texto}]

        Dê um feedback direto, curto e motivador. Se passou do limite ou está perto, avise.
        Aponte o maior vilão e dê uma dica prática. Max 3 linhas.
        """
        try:
            ia_client  = _obter_cliente_ia()
            response   = ia_client.models.generate_content(model=MODEL_ID, contents=prompt_insight)
            insight_ia = response.text.strip()
        except Exception as e:
            print("Erro IA Resumo:", e)
            insight_ia = (
                "A cota gratuita da Inteligência Artificial atingiu o limite de requisições "
                "por hoje. Volte amanhã para novos insights!"
            )

    return {
        'nome':                    user_info['nome'],
        'total_gasto':             total_gasto,
        'total_receber':           total_receber,
        'limite_definido':         limite,
        'saldo_disponivel':        saldo_disponivel,
        'distribuicao_categorias': distribuicao_categorias,
        'insight_ia':              insight_ia,
    }


# ============================================================
# 4. ROTEADOR PRINCIPAL
# ============================================================

def lambda_handler(event, context):
    event = event or {}
    metodo = (
        event.get('httpMethod')
        or event.get('requestContext', {}).get('http', {}).get('method')
    )
    if isinstance(metodo, str):
        metodo = metodo.upper()

    try:
        if metodo == 'OPTIONS':
            return {
                'statusCode': 204,
                'headers': dict(CORS_HEADERS),
                'body': '',
            }
        elif metodo is None or metodo == 'POST':
            return tratar_post(event)
        elif metodo == 'GET':
            return tratar_get(event)
        elif metodo == 'PUT':
            return tratar_put(event)
        elif metodo == 'DELETE':
            return tratar_delete(event)
        else:
            return _resposta(405, {'erro': 'Metodo nao permitido.'})
    except Exception as e:
        # SEC02: Loga internamente; nunca expõe detalhes ao cliente.
        print(f"ERRO CRÍTICO NÃO TRATADO: {str(e)}")
        return _resposta(500, {'erro': 'Erro interno do servidor. Tente novamente mais tarde.'})


# ============================================================
# 5. POST E PROCESSAMENTO DE CSV
# ============================================================

def _parse_data_csv(data_raw):
    """Converte datas DD/MM/YYYY ou YYYY-MM-DD para ISO 8601, ou retorna agora."""
    if data_raw and isinstance(data_raw, str):
        texto = data_raw.strip()
        for fmt in ('%d/%m/%Y', '%Y-%m-%d'):
            try:
                dt = datetime.datetime.strptime(texto[:10], fmt)
                return dt.isoformat()
            except ValueError:
                continue
    return datetime.datetime.now().isoformat()


def processar_csv_c6(user_id, csv_text):
    """
    Processa CSV do C6 Bank (com suporte a BOM UTF-8, delimitador `;` ou `,`,
    colunas com/sem acento e datas de compra) e salva transações no DynamoDB.
    """
    csv_limpo = (csv_text or '').lstrip('\ufeff').strip()
    if not csv_limpo:
        return 0

    primeira_linha = csv_limpo.splitlines()[0]
    delimitador = ';' if ';' in primeira_linha else ','

    f = io.StringIO(csv_limpo)
    reader = list(csv.DictReader(f, delimiter=delimitador))
    if not reader:
        return 0

    descricoes_brutas = list({
        (row.get('Descrição') or row.get('Descricao') or '').strip()
        for row in reader
        if (row.get('Descrição') or row.get('Descricao') or '').strip()
    })

    mapa_categorias = {}
    if descricoes_brutas:
        prompt_lote = f'''
        Você é um categorizador financeiro.
        Categorias permitidas: {MINHAS_CATEGORIAS}.
        Analise os itens a seguir e retorne APENAS um array de objetos JSON (sem blocos de código ou aspas extras), neste formato estrito:
        [
          {{"orig": "NOME ORIGINAL", "limpa": "Nome Bonito", "cat": "Categoria Correta"}}
        ]
        Itens para analisar: {descricoes_brutas}
        '''
        texto_ia = "[]"
        try:
            ia_client = _obter_cliente_ia()
            response = ia_client.models.generate_content(model=MODEL_ID, contents=prompt_lote)
            texto_ia = response.text.strip()
            lista_ia = _extrair_json_ia(texto_ia)
            if isinstance(lista_ia, list):
                for item in lista_ia:
                    if isinstance(item, dict) and 'orig' in item:
                        cat_ia = item.get('cat')
                        if cat_ia not in MINHAS_CATEGORIAS:
                            cat_ia = 'Outros'
                        desc_ia = sanitizar_frase(str(item.get('limpa') or ''), max_chars=100)
                        mapa_categorias[item['orig']] = {
                            'desc_limpa': desc_ia or str(item['orig'])[:100],
                            'cat': cat_ia,
                        }
        except Exception as e:
            print("Erro IA Lote / JSON CSV:", e)
            print("Resposta bruta:", texto_ia)

    contagem = 0
    for row in reader:
        desc_orig   = (row.get('Descrição') or row.get('Descricao') or '').strip()
        valor_bruto = str(row.get('Valor (em R$)') or row.get('Valor') or '0').replace('R$', '').strip()

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

        fallback_desc = sanitizar_frase(desc_orig, max_chars=100) or 'Compra C6'
        info_ia = mapa_categorias.get(desc_orig, {'desc_limpa': fallback_desc, 'cat': 'Outros'})
        cat_final = info_ia.get('cat') if info_ia.get('cat') in MINHAS_CATEGORIAS else 'Outros'
        desc_final = info_ia.get('desc_limpa') or fallback_desc

        parcela_raw = str(row.get('Parcela') or 'Única').strip()
        total_p = 1
        paga_p = 1
        eh_parcela_valida = False
        if '/' in parcela_raw:
            try:
                partes = parcela_raw.split('/')
                paga_p = max(1, int(partes[0].strip()))
                total_p = max(1, int(partes[1].strip()))
                eh_parcela_valida = total_p > 1
            except (ValueError, IndexError):
                paga_p = 1
                total_p = 1
                eh_parcela_valida = False

        tipo_movimentacao = 'Crédito Parcelado' if eh_parcela_valida else 'Crédito à Vista'
        if cat_final == 'A receber':
            tipo_movimentacao = 'Emprestado'

        data_raw = row.get('Data de Compra') or row.get('Data') or ''
        created_at = _parse_data_csv(data_raw)

        table_transactions.put_item(Item={
            'user_id':            str(user_id),
            'id':                 uuid.uuid4().hex,
            'description':        desc_final,
            'amount':             Decimal(str(valor)),
            'category':           cat_final,
            'type':               tipo_movimentacao,
            'source':             'C6_BANK',
            'installments_total': total_p,
            'installments_paid':  paga_p,
            'status':             'active',
            'created_at':         created_at,
        })
        contagem += 1

    return contagem


def tratar_post(event):
    try:
        body = json.loads(event.get('body', '{}') or '{}')
        if not isinstance(body, dict):
            return _resposta_erro_json()
    except json.JSONDecodeError:
        return _resposta_erro_json()

    # --- CASO 1: BOT DO TELEGRAM ---
    if 'message' in body:
        # SEC10: Valida o secret token do webhook do Telegram Bot
        if TELEGRAM_SECRET_TOKEN:
            headers = event.get('headers', {}) or {}
            incoming_secret = (
                headers.get('X-Telegram-Bot-Api-Secret-Token')
                or headers.get('x-telegram-bot-api-secret-token', '')
            )
            if not hmac.compare_digest(incoming_secret, TELEGRAM_SECRET_TOKEN):
                print("SEC10: Webhook do bot recebido sem secret token válido.")
                return _resposta(200, 'Ignorado')

        telegram_msg     = body.get('message', {}) or {}
        chat_id          = telegram_msg.get('chat', {}).get('id')
        user_telegram_id = telegram_msg.get('from', {}).get('id')
        first_name       = telegram_msg.get('from', {}).get('first_name', 'Usuário Telegram')
        texto_recebido   = telegram_msg.get('text', '')

        # ---- Processamento de Arquivos CSV via Telegram ----
        if 'document' in telegram_msg:
            document  = telegram_msg['document'] or {}
            file_name = document.get('file_name', '').lower()

            if not file_name.endswith('.csv'):
                enviar_mensagem_telegram(chat_id, "⚠️ Por favor, envie apenas arquivos CSV da fatura do C6 Bank.")
                return _resposta(200, 'Not CSV')

            enviar_mensagem_telegram(chat_id, "⏳ Recebi seu arquivo CSV! Analisando com a IA Zentrix... aguarde um instante.")
            try:
                req_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getFile?file_id={document['file_id']}"
                with urllib.request.urlopen(req_url) as resp:
                    file_info = json.loads(resp.read())
                    file_path = file_info['result']['file_path']

                dl_url = f"https://api.telegram.org/file/bot{TELEGRAM_TOKEN}/{file_path}"
                with urllib.request.urlopen(dl_url) as resp:
                    csv_bytes = resp.read()

                if len(csv_bytes) > 1_048_576:
                    enviar_mensagem_telegram(chat_id, "❌ Arquivo muito grande. O limite é 1MB.")
                    return _resposta(200, 'Too large')

                try:
                    csv_text_tg = csv_bytes.decode('utf-8-sig')
                except UnicodeDecodeError:
                    csv_text_tg = csv_bytes.decode('latin-1')

                id_final_u = _upsert_usuario_telegram(user_telegram_id, first_name)
                contagem   = processar_csv_c6(id_final_u, csv_text_tg)

                enviar_mensagem_telegram(
                    chat_id,
                    f"✅ Sucesso! O arquivo foi analisado e **{contagem} transações** foram salvas no seu histórico do Zentrix de forma inteligente."
                )
                return _resposta(200, 'CSV processado pelo Telegram')
            except Exception as e:
                # SEC02: Loga erro interno sem vazar detalhes técnicos (str(e)) ao usuário
                print(f"Erro CSV Telegram: {e}")
                enviar_mensagem_telegram(
                    chat_id,
                    "❌ Ocorreu um erro ao processar o arquivo CSV. Verifique o formato da fatura e tente novamente mais tarde."
                )
                return _resposta(200, 'Error CSV TG')

        if not texto_recebido:
            enviar_mensagem_telegram(chat_id, "⚠️ Por enquanto só consigo processar mensagens de texto.")
            return _resposta(200, 'Mensagem sem texto')

        id_final_usuario = _upsert_usuario_telegram(user_telegram_id, first_name)

        texto_limpo = texto_recebido.strip().lower()
        if texto_limpo.startswith('/resumo') or 'resumo' in texto_limpo:
            resumo = obter_resumo_usuario(id_final_usuario)
            if not resumo:
                enviar_mensagem_telegram(chat_id, "❌ Configure suas métricas no painel antes de pedir um resumo.")
                return _resposta(200, 'Sem dados')

            msg_resumo = (
                f"📊 *Resumo Financeiro - {resumo['nome']}*\n\n"
                f"💰 *Total Gasto:* R$ {resumo['total_gasto']:.2f}\n"
                f"🤝 *Total a Receber:* R$ {resumo['total_receber']:.2f}\n"
                f"🎯 *Limite Mensal:* R$ {resumo['limite_definido']:.2f}\n"
                f"💵 *Saldo Disponível:* R$ {resumo['saldo_disponivel']:.2f}\n\n"
                f"🗂️ *Divisão por Categorias:*\n"
            )
            for cat, valor in resumo['distribuicao_categorias'].items():
                msg_resumo += f"  ▪️ _{cat}_: R$ {valor:.2f}\n"
            msg_resumo += f"\n💡 *Insight da IA Zentrix:*\n_{resumo['insight_ia']}_"
            enviar_mensagem_telegram(chat_id, msg_resumo)
            return _resposta(200, 'Telegram resumo enviado')

        else:
            # SEC06: Sanitiza a frase antes de enviar ao Gemini
            frase_segura = sanitizar_frase(texto_recebido)
            if not frase_segura:
                enviar_mensagem_telegram(chat_id, "⚠️ Frase inválida ou vazia.")
                return _resposta(200, 'Frase vazia')

            prompt_ia = f"""
            Extraia os dados da frase: '{frase_segura}'
            Categorias: {MINHAS_CATEGORIAS}
            Tipos permitidos: {TIPOS_PERMITIDOS}

            Regras de Tipo:
            - 'no débito' ou 'no pix' -> Débito
            - Com parcelas -> Crédito Parcelado
            - 'A receber' -> Emprestado
            - Padrão -> Crédito à Vista

            Retorne APENAS um JSON: {{"description": "nome", "amount": float, "category": "categoria", "type": "tipo", "installments": int, "debtor_name": "nome ou null"}}
            """
            try:
                ia_client  = _obter_cliente_ia()
                response   = ia_client.models.generate_content(model=MODEL_ID, contents=prompt_ia)
                dados_brut = _extrair_json_ia(response.text)
                dados      = _normalizar_dados_transacao_ia(dados_brut)
            except Exception as e:
                print("Erro IA Telegram:", e)
                enviar_mensagem_telegram(
                    chat_id,
                    "⚠️ A IA está sobrecarregada no momento e não conseguiu processar sua requisição. Tente usar uma categoria ou tente amanhã."
                )
                return _resposta(200, 'Rate limit IA')

            if dados['amount'] <= 0:
                enviar_mensagem_telegram(chat_id, "⚠️ Não consegui identificar um valor válido. Tente novamente.")
                return _resposta(200, 'Valor inválido')

            # SEC08: raw_input_phrase removido — não armazenamos PII desnecessário
            table_transactions.put_item(Item={
                'user_id':            str(id_final_usuario),
                'id':                 uuid.uuid4().hex,
                'description':        dados['description'],
                'amount':             Decimal(str(dados['amount'])),
                'category':           dados['category'],
                'type':               dados['type'],
                'source':             'TELEGRAM_BOT',
                'installments_total': dados['installments'],
                'debtor_name':        dados['debtor_name'],
                'status':             'active',
                'created_at':         datetime.datetime.now().isoformat(),
            })

            msg_confirmacao = (
                f"✅ *Transação Salva no Zentrix!*\n\n"
                f"📝 *Item:* {dados['description']}\n"
                f"💰 *Valor:* R$ {dados['amount']:.2f}\n"
                f"🏷️ *Categoria:* {dados['category']}\n"
                f"💳 *Tipo:* {dados['type']}"
            )
            if dados['installments'] > 1:
                msg_confirmacao += f"\n🔢 *Parcelas:* {dados['installments']}"
            if dados['debtor_name']:
                msg_confirmacao += f"\n👤 *Devedor:* {dados['debtor_name']}"

            enviar_mensagem_telegram(chat_id, msg_confirmacao)
            return _resposta(200, 'Telegram processado')

    # --- CASO 2: AUTENTICAÇÃO WEB (via POST com hash do Telegram) ---
    elif 'hash' in body and 'id' in body:
        tg_hash     = str(body.get('hash') or '')
        auth_date   = body.get('auth_date')
        telegram_id = body.get('id')
        first_name  = body.get('first_name', '')

        data_check_list   = [f"{k}={v}" for k, v in sorted(body.items()) if k != 'hash']
        data_check_string = "\n".join(data_check_list)

        secret_key = hashlib.sha256((TELEGRAM_TOKEN or '').encode('utf-8')).digest()
        local_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(local_hash, tg_hash):
            return _resposta(401, {'erro': 'Assinatura inválida.'})

        try:
            auth_date_int = int(auth_date)
        except (ValueError, TypeError):
            return _resposta(401, {'erro': 'Data de autenticação inválida.'})

        if time.time() - auth_date_int > 86400:
            return _resposta(401, {'erro': 'Assinatura do Telegram expirada.'})

        id_final_usuario = _upsert_usuario_telegram(telegram_id, first_name)

        session_token = str(uuid.uuid4())
        expires_at    = (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat()
        table_sessions.put_item(Item={
            'token':      session_token,
            'user_id':    str(telegram_id),
            'expires_at': expires_at,
        })

        return _resposta(200, {
            'login':           True,
            'token_sessao':    session_token,
            'user_id_interno': id_final_usuario,
            'nome':            first_name,
        })

    # --- CASO 3: IMPORTAÇÃO DE CSV (C6 BANK) ---
    elif 'csv_text' in body:
        user_id  = body.get('user_id', ZENTRIX_USER_ID)
        csv_text = body.get('csv_text', '')

        if not validar_sessao(event, user_id):
            return _resposta_nao_autorizado()

        if not isinstance(csv_text, str):
            return _resposta(400, {'erro': 'Formato de CSV inválido.'})

        # SEC07: Limite de tamanho de 1MB para evitar DoS no Lambda
        if len(csv_text.encode('utf-8')) > 1_048_576:
            return _resposta(413, {'erro': 'Arquivo CSV muito grande. Limite de 1MB.'})

        contagem = processar_csv_c6(user_id, csv_text)
        return _resposta(201, {
            'count':      contagem,
            'importadas': contagem,
            'message':    f'{contagem} itens processados!',
        })

    # --- CASO 4: FRASE POR VOZ / DIRECT API ---
    elif 'frase' in body:
        user_id = body.get('user_id', ZENTRIX_USER_ID)
        if not validar_sessao(event, user_id):
            return _resposta_nao_autorizado()

        # SEC06: Sanitiza antes de enviar ao Gemini
        frase_segura = sanitizar_frase(body['frase'])
        if not frase_segura:
            return _resposta(400, {'erro': 'Frase inválida ou vazia.'})

        prompt_ia = f"""
        Extraia os dados da frase: '{frase_segura}'
        Categorias: {MINHAS_CATEGORIAS}
        Tipos permitidos: {TIPOS_PERMITIDOS}

        Retorne APENAS um JSON: {{"description": "nome", "amount": float, "category": "categoria", "type": "tipo", "installments": int, "debtor_name": "nome ou null"}}
        """
        try:
            ia_client  = _obter_cliente_ia()
            response   = ia_client.models.generate_content(model=MODEL_ID, contents=prompt_ia)
            dados_brut = _extrair_json_ia(response.text)
            dados      = _normalizar_dados_transacao_ia(dados_brut)
        except Exception as e:
            print("Erro IA Direct:", e)
            return _resposta(429, {'erro': 'Limite de uso da IA excedido. Tente novamente mais tarde.'})

        if dados['amount'] <= 0:
            return _resposta(422, {'erro': 'Não foi possível identificar um valor válido na frase.'})

        # SEC08: raw_input_phrase removido
        table_transactions.put_item(Item={
            'user_id':            str(user_id),
            'id':                 uuid.uuid4().hex,
            'description':        dados['description'],
            'amount':             Decimal(str(dados['amount'])),
            'category':           dados['category'],
            'type':               dados['type'],
            'source':             'IA_CHAT',
            'installments_total': dados['installments'],
            'debtor_name':        dados['debtor_name'],
            'status':             'active',
            'created_at':         datetime.datetime.now().isoformat(),
        })
        return _resposta(201, {'message': 'Salvo!', 'dados': dados})

    return _resposta(400, {'erro': 'Requisição POST não reconhecida.'})


# ============================================================
# 6. GET
# ============================================================

def tratar_get(event):
    params = event.get('queryStringParameters', {}) or {}
    action = params.get('action')

    # --- Rota pública: Página HTML de Login ---
    if action == 'telegram-login':
        app_redirect_uri = _validar_redirect_uri(params.get('app_redirect_uri', DEFAULT_APP_REDIRECT_URI))
        return servir_pagina_telegram_login(app_redirect_uri, event=event)

    # --- Rota pública: Callback server-side do Telegram ---
    if action == 'telegram-callback':
        return tratar_telegram_callback(params)

    # --- SEC03: Rota de troca de auth_code por token real ---
    if action == 'trocar-codigo':
        return tratar_troca_codigo(params)

    # --- Rotas autenticadas ---
    user_id = params.get('user_id', ZENTRIX_USER_ID)
    if not user_id:
        return _resposta(400, {'erro': 'user_id é obrigatório'})

    if not validar_sessao(event, user_id):
        return _resposta_nao_autorizado()

    if action == 'summary':
        resumo = obter_resumo_usuario(user_id)
        if not resumo:
            return _resposta(404, {'erro': 'Usuário não encontrado'})
        return _resposta(200, {
            'metricas': {
                'total_gasto':             resumo['total_gasto'],
                'total_receber':           resumo['total_receber'],
                'limite_definido':         resumo['limite_definido'],
                'saldo_disponivel':        resumo['saldo_disponivel'],
                'distribuicao_categorias': resumo['distribuicao_categorias'],
            },
            'insight_ia': resumo['insight_ia'],
        })
    else:
        items = _listar_transacoes_usuario(user_id)
        items.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        # Busca dados do usuário e remove password_hash (SEC)
        resp_user = table_users.get_item(Key={'id': str(user_id)})
        user_info = resp_user.get('Item')
        if user_info:
            user_info = dict(user_info)
            user_info.pop('password_hash', None)

        return _resposta(200, {'transacoes': items, 'usuario': user_info})


# ============================================================
# 7. DELETE
# ============================================================

def tratar_delete(event):
    try:
        body = json.loads(event.get('body', '{}') or '{}')
        if not isinstance(body, dict):
            return _resposta_erro_json()
    except json.JSONDecodeError:
        return _resposta_erro_json()

    user_id      = body.get('user_id', ZENTRIX_USER_ID)
    transacao_id = body.get('id')

    if not user_id or not transacao_id:
        return _resposta(400, {'erro': 'Faltam chaves para deletar'})

    if not validar_sessao(event, user_id):
        return _resposta_nao_autorizado()

    # Chave composta (PK=user_id + SK=id) garante o isolamento por usuário (anti-IDOR)
    table_transactions.delete_item(
        Key={
            'user_id': str(user_id),
            'id':      str(transacao_id),
        }
    )
    return _resposta(200, {'message': 'Item removido.'})


# ============================================================
# 8. PUT
# ============================================================

def tratar_put(event):
    try:
        body = json.loads(event.get('body', '{}') or '{}')
        if not isinstance(body, dict):
            return _resposta_erro_json()
    except json.JSONDecodeError:
        return _resposta_erro_json()

    user_id = body.get('user_id', ZENTRIX_USER_ID)
    action  = body.get('action')

    if not validar_sessao(event, user_id):
        return _resposta_nao_autorizado()

    if action == 'update_transaction':
        transacao_id = body.get('id')
        if not transacao_id:
            return _resposta(400, {'erro': 'ID da transação não fornecido'})

        update_parts = []
        expr_values  = {}
        expr_names   = {}

        CAMPOS_PERMITIDOS = ('amount', 'description', 'category', 'type', 'status')
        for campo in CAMPOS_PERMITIDOS:
            if campo not in body:
                continue

            if campo == 'amount':
                if isinstance(body[campo], bool):
                    return _resposta(400, {'erro': 'Valor inválido'})
                try:
                    val = float(body[campo])
                except (ValueError, TypeError):
                    return _resposta(400, {'erro': 'Valor inválido'})
                if val <= 0:
                    return _resposta(400, {'erro': 'Valor deve ser positivo'})
                update_parts.append(f"#f_{campo} = :v_{campo}")
                expr_names[f'#f_{campo}']  = campo
                expr_values[f':v_{campo}'] = Decimal(str(val))

            elif campo == 'category':
                if body[campo] not in MINHAS_CATEGORIAS:
                    return _resposta(400, {'erro': 'Categoria inválida'})
                update_parts.append(f"#f_{campo} = :v_{campo}")
                expr_names[f'#f_{campo}']  = campo
                expr_values[f':v_{campo}'] = body[campo]

            elif campo == 'type':
                if body[campo] not in TIPOS_PERMITIDOS:
                    return _resposta(400, {'erro': 'Tipo de transação inválido'})
                update_parts.append(f"#f_{campo} = :v_{campo}")
                expr_names[f'#f_{campo}']  = campo
                expr_values[f':v_{campo}'] = body[campo]

            elif campo == 'description':
                desc_limpa = sanitizar_frase(body[campo], max_chars=200)
                if not desc_limpa:
                    return _resposta(400, {'erro': 'Descrição inválida ou vazia'})
                update_parts.append(f"#f_{campo} = :v_{campo}")
                expr_names[f'#f_{campo}']  = campo
                expr_values[f':v_{campo}'] = desc_limpa

            elif campo == 'status':
                status_val = body[campo]
                if not isinstance(status_val, str) or not status_val.strip():
                    return _resposta(400, {'erro': 'Status inválido'})
                update_parts.append(f"#f_{campo} = :v_{campo}")
                expr_names[f'#f_{campo}']  = campo
                expr_values[f':v_{campo}'] = status_val.strip()

        if not update_parts:
            return _resposta(400, {'erro': 'Nenhum campo válido para atualizar'})

        try:
            table_transactions.update_item(
                Key={
                    'user_id': str(user_id),
                    'id':      str(transacao_id),
                },
                UpdateExpression="SET " + ", ".join(update_parts),
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
                ConditionExpression='attribute_exists(user_id) AND attribute_exists(id)',
            )
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'ConditionalCheckFailedException':
                return _resposta(404, {'erro': 'Transação não encontrada.'})
            raise

        return _resposta(200, {'message': 'Transação atualizada'})

    elif action == 'update_user':
        update_parts = []
        expr_values  = {}
        expr_names   = {}

        if 'salario_mensal' in body:
            if isinstance(body['salario_mensal'], bool):
                return _resposta(400, {'erro': 'Salário mensal inválido'})
            try:
                val_sal = float(body['salario_mensal'])
            except (ValueError, TypeError):
                return _resposta(400, {'erro': 'Salário mensal inválido'})
            if val_sal < 0:
                return _resposta(400, {'erro': 'Salário mensal não pode ser negativo'})
            update_parts.append("#f_salario = :v_salario")
            expr_names['#f_salario']  = 'salario_mensal'
            expr_values[':v_salario'] = Decimal(str(val_sal))

        if 'limite_mensal' in body:
            if isinstance(body['limite_mensal'], bool):
                return _resposta(400, {'erro': 'Limite mensal inválido'})
            try:
                val_lim = float(body['limite_mensal'])
            except (ValueError, TypeError):
                return _resposta(400, {'erro': 'Limite mensal inválido'})
            if val_lim <= 0:
                return _resposta(400, {'erro': 'Limite mensal deve ser maior que zero'})
            update_parts.append("#f_limite = :v_limite")
            expr_names['#f_limite']  = 'limite_mensal'
            expr_values[':v_limite'] = Decimal(str(val_lim))

        if 'dia_vencimento_fatura' in body:
            if isinstance(body['dia_vencimento_fatura'], bool):
                return _resposta(400, {'erro': 'Dia de vencimento inválido'})
            try:
                dia_venc = int(body['dia_vencimento_fatura'])
            except (ValueError, TypeError):
                return _resposta(400, {'erro': 'Dia de vencimento inválido'})
            if not (1 <= dia_venc <= 31):
                return _resposta(400, {'erro': 'Dia de vencimento deve estar entre 1 e 31'})
            update_parts.append("#f_dia_venc = :v_dia_venc")
            expr_names['#f_dia_venc']  = 'dia_vencimento_fatura'
            expr_values[':v_dia_venc'] = dia_venc

        if not update_parts:
            return _resposta(400, {'erro': 'Nenhum campo para atualizar no usuário'})

        table_users.update_item(
            Key={'id': str(user_id)},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
        return _resposta(200, {'message': 'Perfil atualizado'})

    else:
        return _resposta(400, {'erro': 'Ação PUT desconhecida'})


# ============================================================
# 9. PÁGINA HTML DE LOGIN (Pública)
# ============================================================

def _derivar_base_url(event):
    """Deriva a URL base dinamicamente a partir do evento HTTP ou usa o fallback de produção."""
    if not event or not isinstance(event, dict):
        return DEFAULT_API_BASE_URL

    headers = event.get('headers') or {}
    req_ctx = event.get('requestContext') or {}
    host = headers.get('Host') or headers.get('host') or req_ctx.get('domainName')
    path = req_ctx.get('path') or event.get('rawPath') or event.get('path')
    proto = headers.get('X-Forwarded-Proto') or headers.get('x-forwarded-proto') or 'https'

    if host and path:
        return f"{proto}://{host}{path}"
    return DEFAULT_API_BASE_URL


def servir_pagina_telegram_login(app_redirect_uri, event=None):
    redirect_seguro = _validar_redirect_uri(app_redirect_uri)
    base_url        = _derivar_base_url(event)
    callback_url    = (
        f"{base_url}?action=telegram-callback"
        f"&app_redirect_uri={urllib.parse.quote(redirect_seguro, safe='')}"
    )

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
            **CORS_HEADERS,
            'Content-Type': 'text/html',
        },
        'body': html,
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
    app_redirect_uri = _validar_redirect_uri(params.get('app_redirect_uri', DEFAULT_APP_REDIRECT_URI))
    tg_hash          = params.get('hash', '')
    auth_date        = params.get('auth_date', '0')
    telegram_id      = params.get('id', '')
    first_name       = params.get('first_name', 'Usuario')

    def redirect_error(error_code):
        sep = '&' if '?' in app_redirect_uri else '?'
        return {
            'statusCode': 302,
            'headers': {
                **CORS_HEADERS,
                'Location': f'{app_redirect_uri}{sep}error={error_code}',
            },
            'body': '',
        }

    if not tg_hash or not telegram_id:
        return redirect_error('dados_incompletos')

    # Validar hash HMAC-SHA256
    data_check_list = [
        f"{k}={params[k]}"
        for k in sorted(params.keys())
        if k not in ('hash', 'action', 'app_redirect_uri')
    ]
    data_check_string = "\n".join(data_check_list)
    secret_key = hashlib.sha256((TELEGRAM_TOKEN or '').encode('utf-8')).digest()
    local_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(local_hash, tg_hash):
        return redirect_error('hash_invalido')

    try:
        auth_date_int = int(auth_date)
    except (ValueError, TypeError):
        return redirect_error('dados_incompletos')

    if time.time() - auth_date_int > 86400:
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
        'auth_code_expires_at': auth_code_expires_at,
    })

    # Apenas auth_code e user_id_interno na URL — token real NUNCA exposto
    callback_params = urllib.parse.urlencode({
        'auth_code':       auth_code,
        'user_id_interno': str(telegram_id),
        'nome':            first_name,
    })
    sep = '&' if '?' in app_redirect_uri else '?'
    redirect_url = app_redirect_uri + sep + callback_params

    return {
        'statusCode': 302,
        'headers': {
            **CORS_HEADERS,
            'Location': redirect_url,
        },
        'body': '',
    }


# ============================================================
# 11. TROCA DE CÓDIGO (SEC03)
# ============================================================

def tratar_troca_codigo(params):
    """
    SEC03: O app envia o auth_code (que veio na URL) e recebe o
    token_sessao real em JSON. O auth_code é invalidado após o uso.
    """
    auth_code = params.get('code', '')
    if not auth_code:
        return _resposta(400, {'erro': 'Código inválido.'})

    resp = table_sessions.query(
        IndexName='auth_code-index',
        KeyConditionExpression=Key('auth_code').eq(auth_code),
    )
    items = resp.get('Items', [])
    if not items:
        return _resposta(401, {'erro': 'Código inválido ou já utilizado.'})

    session_gsi = items[0]
    token = session_gsi.get('token')
    if not token:
        return _resposta(401, {'erro': 'Sessão inválida.'})

    resp_sess = table_sessions.get_item(Key={'token': token})
    session = resp_sess.get('Item')
    if not session:
        return _resposta(401, {'erro': 'Sessão não encontrada.'})

    auth_code_expires_at = session.get('auth_code_expires_at')
    if not auth_code_expires_at:
        return _resposta(401, {'erro': 'Código inválido ou já utilizado.'})

    try:
        if datetime.datetime.fromisoformat(auth_code_expires_at) < datetime.datetime.now():
            return _resposta(401, {'erro': 'Código expirado. Faça login novamente.'})
    except Exception:
        return _resposta(401, {'erro': 'Código inválido.'})

    # Invalida o auth_code removendo-o da sessão (sai automaticamente do GSI Sparse auth_code-index)
    table_sessions.update_item(
        Key={'token': token},
        UpdateExpression="REMOVE auth_code, auth_code_expires_at",
    )

    return _resposta(200, {
        'token_sessao':    session['token'],
        'user_id_interno': str(session['user_id']),
    })
