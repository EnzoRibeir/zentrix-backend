import json
import os
import re
import time
import csv
import io
import pymysql
import urllib.request
import urllib.parse
import hashlib
import hmac
import uuid
import datetime
from google import genai

# ============================================================
# 1. CONFIGURAÇÕES E CREDENCIAIS
# ============================================================
client = genai.Client(api_key=os.environ.get('GEMINI_API_KEY'))
MODEL_ID = 'gemini-2.5-flash'

DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = 'db-zentrix'
SSL_CA  = 'global-bundle.pem'

TELEGRAM_TOKEN        = os.environ.get('TELEGRAM_TOKEN')
# SEC10: Segredo configurado no BotFather para validar webhooks do bot
TELEGRAM_SECRET_TOKEN = os.environ.get('TELEGRAM_SECRET_TOKEN', '')
ZENTRIX_USER_ID       = os.environ.get('ZENTRIX_USER_ID', '')

# SEC09: Manter * apenas nas rotas públicas. Rotas autenticadas não precisam de CORS
# pois são chamadas diretamente pelo React Native (não pelo browser).
CORS_PUBLICO = {'Access-Control-Allow-Origin': '*'}

MINHAS_CATEGORIAS = [
    "Essencial", "Role e Lazer", "Rangos", "Transporte",
    "Assinaturas", "Compras e Mimos", "A receber", "Outros"
]

# ============================================================
# 2. UTILITÁRIOS
# ============================================================

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        ssl={'ca': SSL_CA},
        cursorclass=pymysql.cursors.DictCursor
    )


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
    headers = event.get('headers', {}) or {}
    auth_header = headers.get('Authorization') or headers.get('authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    token = auth_header.split(' ', 1)[1]

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, expires_at FROM sessions WHERE token = %s AND auth_code IS NULL",
                (token,)
            )
            session = cursor.fetchone()
            if not session:
                return False
            if str(session['user_id']) != str(user_id):
                return False
            if session['expires_at'] and session['expires_at'] < datetime.datetime.now():
                return False
            return True
    except Exception:
        return False
    finally:
        conn.close()


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

def obter_resumo_usuario(cursor, user_id):
    """Consolida dados do mês e aciona o Gemini para gerar insights financeiros."""
    cursor.execute("SELECT nome, limite_mensal FROM usuarios WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()
    if not user_info:
        return None

    # Consulta ajustada para rateio de parcelas (SEC05/Feature)
    # Considera transações à vista do mês atual OU transações parceladas passadas que ainda estão ativas
    query_base_filtro = """
        FROM transacoes
        WHERE user_id = %s
          AND (
              (
                  (type NOT IN ('Crédito Parcelado', 'Emprestado') OR installments_total <= 1)
                  AND MONTH(created_at) = MONTH(CURRENT_DATE())
                  AND YEAR(created_at) = YEAR(CURRENT_DATE())
              ) OR (
                  type IN ('Crédito Parcelado', 'Emprestado') AND installments_total > 1
                  AND PERIOD_DIFF(
                      EXTRACT(YEAR_MONTH FROM CURRENT_DATE()), 
                      EXTRACT(YEAR_MONTH FROM created_at)
                  ) >= 0
                  AND PERIOD_DIFF(
                      EXTRACT(YEAR_MONTH FROM CURRENT_DATE()), 
                      EXTRACT(YEAR_MONTH FROM created_at)
                  ) < installments_total
              )
          )
    """

    # Gasto por categoria (dividindo as parcelas)
    cursor.execute(f"""
        SELECT category, 
               SUM(
                   CASE 
                       WHEN type IN ('Crédito Parcelado', 'Emprestado') AND installments_total > 1 
                       THEN amount / installments_total
                       ELSE amount
                   END
               ) as total
        {query_base_filtro}
        GROUP BY category
    """, (user_id,))
    gastos_por_categoria = cursor.fetchall()

    # Total geral do mês
    cursor.execute(f"""
        SELECT SUM(
                   CASE 
                       WHEN type IN ('Crédito Parcelado', 'Emprestado') AND installments_total > 1 
                       THEN amount / installments_total
                       ELSE amount
                   END
               ) as total_geral
        {query_base_filtro}
    """, (user_id,))
    total_resultado = cursor.fetchone()

    total_geral = float(total_resultado['total_geral']) if total_resultado['total_geral'] else 0.0
    limite      = float(user_info['limite_mensal'])      if user_info['limite_mensal']      else 0.0
    cat_texto   = ", ".join([f"{c['category']}: R$ {float(c['total'])}" for c in gastos_por_categoria])

    insight_ia = "Sem transações registradas no mês para analisar."
    if total_geral > 0:
        prompt_insight = f"""
        Aja como um consultor financeiro de alto nível. Analise os gastos do mês atual do usuário {user_info['nome']}:
        - Limite de Gastos Mensal: R$ {limite}
        - Total já gasto: R$ {total_geral}
        - Distribuição por categorias: [{cat_texto}]

        Dê um feedback direto, curto e motivador. Se passou do limite ou está perto, avise.
        Aponte o maior vilão e dê uma dica prática. Max 3 linhas.
        """
        try:
            response  = client.models.generate_content(model=MODEL_ID, contents=prompt_insight)
            insight_ia = response.text.strip()
        except Exception as e:
            print("Erro IA Resumo:", e)
            insight_ia = "A cota gratuita da Inteligência Artificial atingiu o limite de requisições por hoje. Volte amanhã para novos insights!"

    return {
        'nome': user_info['nome'],
        'total_gasto': total_geral,
        'limite_definido': limite,
        'saldo_disponivel': limite - total_geral,
        'distribuicao_categorias': {c['category']: float(c['total']) for c in gastos_por_categoria},
        'insight_ia': insight_ia
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


def processar_csv_c6(cursor, user_id, csv_text):
    f = io.StringIO(csv_text.strip())
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

        info_ia   = mapa_categorias.get(desc_orig, {"desc_limpa": desc_orig[:100], "cat": "Outros"})
        parcela_raw = row.get('Parcela', 'Única')
        total_p = paga_p = 1
        if "/" in parcela_raw:
            partes  = parcela_raw.split("/")
            paga_p  = int(partes[0])
            total_p = int(partes[1])

        tipo_movimentacao = "Crédito Parcelado" if "/" in parcela_raw else "Crédito à Vista"
        if info_ia['cat'] == "A receber":
            tipo_movimentacao = "Emprestado"

        cursor.execute('''
            INSERT INTO transacoes
            (user_id, description, amount, category, type, source, installments_total, installments_paid)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (user_id, info_ia['desc_limpa'], valor, info_ia['cat'], tipo_movimentacao, 'C6_BANK', total_p, paga_p))
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
            document = telegram_msg['document']
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
                
                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        # Busca o usuario
                        cursor.execute("SELECT id FROM usuarios WHERE id = %s", (str(user_telegram_id),))
                        u = cursor.fetchone()
                        if u:
                            id_final_u = u['id']
                        else:
                            cursor.execute(
                                "INSERT INTO usuarios (id, nome, email, password_hash) VALUES (%s, %s, %s, %s)",
                                (str(user_telegram_id), first_name, f"{user_telegram_id}@telegram.zentrix", 'TELEGRAM_AUTH')
                            )
                            conn.commit()
                            id_final_u = str(user_telegram_id)
                        
                        contagem = processar_csv_c6(cursor, id_final_u, csv_text_tg)
                        conn.commit()
                        
                        enviar_mensagem_telegram(chat_id, f"✅ Sucesso! O arquivo foi analisado e **{contagem} transações** foram salvas no seu histórico do Zentrix de forma inteligente.")
                        return {'statusCode': 200, 'body': json.dumps('CSV processado pelo Telegram')}
                finally:
                    conn.close()
            except Exception as e:
                enviar_mensagem_telegram(chat_id, f"❌ Ocorreu um erro ao processar o CSV: {str(e)}")
                return {'statusCode': 200, 'body': json.dumps('Error CSV TG')}

        if not texto_recebido:

            enviar_mensagem_telegram(chat_id, "⚠️ Por enquanto só consigo processar mensagens de texto.")
            return {'statusCode': 200, 'body': json.dumps('Mensagem sem texto')}

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM usuarios WHERE id = %s", (str(user_telegram_id),))
                usuario_existente = cursor.fetchone()
                if usuario_existente:
                    id_final_usuario = usuario_existente['id']
                else:
                    email_placeholder = f"{user_telegram_id}@telegram.zentrix"
                    cursor.execute(
                        "INSERT INTO usuarios (id, nome, email, password_hash) VALUES (%s, %s, %s, %s)",
                        (str(user_telegram_id), first_name, email_placeholder, 'TELEGRAM_AUTH')
                    )
                    conn.commit()
                    id_final_usuario = str(user_telegram_id)

                texto_limpo = texto_recebido.strip().lower()
                if texto_limpo.startswith('/resumo') or 'resumo' in texto_limpo:
                    resumo = obter_resumo_usuario(cursor, id_final_usuario)
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
                    prompt_ia = f"""
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
                    cursor.execute("""
                        INSERT INTO transacoes
                        (user_id, description, amount, category, type, source, installments_total, debtor_name)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        id_final_usuario,
                        dados['description'],
                        dados['amount'],
                        dados['category'],
                        dados['type'],
                        'TELEGRAM_BOT',
                        dados.get('installments', 1),
                        dados.get('debtor_name'),
                    ))
                    conn.commit()

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
        finally:
            conn.close()

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

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM usuarios WHERE id = %s", (str(telegram_id),))
                usuario = cursor.fetchone()
                if usuario:
                    id_final_usuario = usuario['id']
                else:
                    email_placeholder = f"{telegram_id}@telegram.zentrix"
                    cursor.execute(
                        "INSERT INTO usuarios (id, nome, email, password_hash) VALUES (%s, %s, %s, %s)",
                        (str(telegram_id), first_name, email_placeholder, 'TELEGRAM_AUTH')
                    )
                    conn.commit()
                    id_final_usuario = str(telegram_id)

                session_token = str(uuid.uuid4())
                expires_at    = datetime.datetime.now() + datetime.timedelta(days=7)
                cursor.execute(
                    "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
                    (session_token, str(telegram_id), expires_at)
                )
                conn.commit()

            return {
                'statusCode': 200,
                'headers': CORS_PUBLICO,
                'body': json.dumps({
                    'login': True,
                    'token_sessao': session_token,
                    'user_id_interno': id_final_usuario,
                    'nome': first_name
                })
            }
        finally:
            conn.close()

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


        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                contagem = processar_csv_c6(cursor, user_id, csv_text)
                conn.commit()
                return {'statusCode': 201, 'body': json.dumps(f'{contagem} itens processados!')}
        finally:
            conn.close()

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

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # SEC08: raw_input_phrase removido
                cursor.execute("""
                    INSERT INTO transacoes
                    (user_id, description, amount, category, type, source, installments_total, debtor_name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user_id,
                    dados['description'],
                    dados['amount'],
                    dados['category'],
                    dados['type'],
                    'IA_CHAT',
                    dados.get('installments', 1),
                    dados.get('debtor_name'),
                ))
                conn.commit()
            return {'statusCode': 201, 'body': json.dumps({'message': 'Salvo!', 'dados': dados})}
        finally:
            conn.close()

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

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if action == 'summary':
                resumo = obter_resumo_usuario(cursor, user_id)
                if not resumo:
                    return {'statusCode': 404, 'body': json.dumps('Usuário não encontrado')}
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'metricas': {
                            'total_gasto': resumo['total_gasto'],
                            'limite_definido': resumo['limite_definido'],
                            'saldo_disponivel': resumo['saldo_disponivel'],
                            'distribuicao_categorias': resumo['distribuicao_categorias']
                        },
                        'insight_ia': resumo['insight_ia']
                    }, default=str)
                }
            else:
                cursor.execute(
                    "SELECT * FROM transacoes WHERE user_id = %s ORDER BY created_at DESC",
                    (user_id,)
                )
                items = cursor.fetchall()

                # Bug fix SEC: Removemos password_hash manualmente para evitar expor
                cursor.execute(
                    "SELECT * FROM usuarios WHERE id = %s",
                    (user_id,)
                )
                user_info = cursor.fetchone()
                if user_info and 'password_hash' in user_info:
                    del user_info['password_hash']

                return {
                    'statusCode': 200,
                    'body': json.dumps({'transacoes': items, 'usuario': user_info}, default=str)
                }
    finally:
        conn.close()


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

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM transacoes WHERE id = %s AND user_id = %s",
                (transacao_id, user_id)
            )
            conn.commit()
        return {'statusCode': 200, 'body': json.dumps('Item removido.')}
    finally:
        conn.close()


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

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if action == 'update_transaction':
                transacao_id = body.get('id')
                if not transacao_id:
                    return {'statusCode': 400, 'body': json.dumps('ID da transação não fornecido')}

                campos  = []
                valores = []

                # Whitelist de campos permitidos para atualização
                CAMPOS_PERMITIDOS = {'amount', 'description', 'category', 'status'}
                for campo in CAMPOS_PERMITIDOS:
                    if campo in body:
                        # Validação extra: amount deve ser positivo
                        if campo == 'amount':
                            try:
                                val = float(body[campo])
                                if val <= 0:
                                    return {'statusCode': 400, 'body': json.dumps('Valor deve ser positivo')}
                                campos.append("amount = %s")
                                valores.append(val)
                            except (ValueError, TypeError):
                                return {'statusCode': 400, 'body': json.dumps('Valor inválido')}
                        else:
                            campos.append(f"{campo} = %s")
                            valores.append(body[campo])

                if not campos:
                    return {'statusCode': 400, 'body': json.dumps('Nenhum campo válido para atualizar')}

                valores.extend([transacao_id, user_id])
                cursor.execute(
                    f"UPDATE transacoes SET {', '.join(campos)} WHERE id = %s AND user_id = %s",
                    tuple(valores)
                )
                conn.commit()
                return {'statusCode': 200, 'body': json.dumps({'message': 'Transação atualizada'})}

            elif action == 'update_user':
                campos  = []
                valores = []
                if 'salario_mensal' in body:
                    campos.append("salario_mensal = %s")
                    valores.append(body['salario_mensal'])
                if 'limite_mensal' in body:
                    campos.append("limite_mensal = %s")
                    valores.append(body['limite_mensal'])
                if 'dia_vencimento_fatura' in body:
                    campos.append("dia_vencimento_fatura = %s")
                    valores.append(body['dia_vencimento_fatura'])

                if not campos:
                    return {'statusCode': 400, 'body': json.dumps('Nenhum campo para atualizar no usuário')}

                valores.append(user_id)
                cursor.execute(
                    f"UPDATE usuarios SET {', '.join(campos)} WHERE id = %s",
                    tuple(valores)
                )
                conn.commit()
                return {'statusCode': 200, 'body': json.dumps({'message': 'Perfil atualizado'})}

            else:
                return {'statusCode': 400, 'body': json.dumps('Ação PUT desconhecida')}
    finally:
        conn.close()


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

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE id = %s", (str(telegram_id),))
            usuario = cursor.fetchone()
            if not usuario:
                email_placeholder = str(telegram_id) + "@telegram.zentrix"
                cursor.execute(
                    "INSERT INTO usuarios (id, nome, email, password_hash) VALUES (%s, %s, %s, %s)",
                    (str(telegram_id), first_name, email_placeholder, 'TELEGRAM_AUTH')
                )
                conn.commit()

            # SEC03: Gerar token real + auth_code temporário (10 min)
            session_token        = str(uuid.uuid4())
            auth_code            = str(uuid.uuid4())
            expires_at           = datetime.datetime.now() + datetime.timedelta(days=7)
            auth_code_expires_at = datetime.datetime.now() + datetime.timedelta(minutes=10)

            cursor.execute("""
                INSERT INTO sessions (token, user_id, expires_at, auth_code, auth_code_expires_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (session_token, str(telegram_id), expires_at, auth_code, auth_code_expires_at))
            conn.commit()

            # Apenas auth_code e user_id_interno na URL — token real NUNCA exposto
            callback_params = urllib.parse.urlencode({
                'auth_code': auth_code,
                'user_id_interno': str(telegram_id),
                'nome': first_name
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
    finally:
        conn.close()


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
        return {'statusCode': 400, 'body': json.dumps({'erro': 'Código inválido.'})}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT token, user_id, auth_code_expires_at
                FROM sessions
                WHERE auth_code = %s
            """, (auth_code,))
            session = cursor.fetchone()

            if not session:
                return {'statusCode': 401, 'body': json.dumps({'erro': 'Código inválido ou já utilizado.'})}

            if session['auth_code_expires_at'] < datetime.datetime.now():
                return {'statusCode': 401, 'body': json.dumps({'erro': 'Código expirado. Faça login novamente.'})}

            # Invalida o auth_code após uso único
            cursor.execute(
                "UPDATE sessions SET auth_code = NULL, auth_code_expires_at = NULL WHERE auth_code = %s",
                (auth_code,)
            )
            conn.commit()

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'token_sessao': session['token'],
                    'user_id_interno': str(session['user_id'])
                })
            }
    finally:
        conn.close()
