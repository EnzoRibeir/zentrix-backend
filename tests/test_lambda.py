import datetime
import hashlib
import hmac
import io
import json
import os
import sys
import time
import types
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

# Garante que a raiz do projeto esteja no sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Fallback caso google-genai não esteja instalado no ambiente local (.venv mínimo)
try:
    from google import genai as _genai  # noqa: F401
except ImportError:
    google_pkg = sys.modules.setdefault('google', types.ModuleType('google'))
    genai_stub = types.ModuleType('google.genai')
    genai_stub.Client = MagicMock()
    google_pkg.genai = genai_stub
    sys.modules['google.genai'] = genai_stub

os.environ.setdefault('AWS_DEFAULT_REGION', 'sa-east-1')

import lambda_function as lf  # noqa: E402
from utils.db_scripts import dynamodb as db_setup  # noqa: E402


BOT_TOKEN_TESTE = '123456789:ABCDEF_segredo_teste_telegram'
WEBHOOK_SECRET_TESTE = 'segredo-webhook-zentrix-123'


def _assinar_telegram(dados: dict, bot_token: str = BOT_TOKEN_TESTE) -> str:
    """Calcula o HMAC-SHA256 oficial do Telegram Login Widget para testes."""
    check_list = [
        f"{k}={dados[k]}"
        for k in sorted(dados.keys())
        if k not in ('hash', 'action', 'app_redirect_uri')
    ]
    data_check_string = "\n".join(check_list)
    secret_key = hashlib.sha256(bot_token.encode('utf-8')).digest()
    return hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()


def _headers_auth(token: str = 'tok-valido-123') -> dict:
    return {'Authorization': f'Bearer {token}'}


def _sessao_valida(user_id: str = '999', token: str = 'tok-valido-123') -> dict:
    futuro = (datetime.datetime.now() + datetime.timedelta(days=5)).isoformat()
    return {
        'token': token,
        'user_id': str(user_id),
        'expires_at': futuro,
    }


class TestZentrixLambda(unittest.TestCase):

    def setUp(self):
        self.mock_users = MagicMock()
        self.mock_sessions = MagicMock()
        self.mock_transactions = MagicMock()
        self.mock_ia_client = MagicMock()

        self.patchers = [
            patch.object(lf, 'table_users', self.mock_users),
            patch.object(lf, 'table_sessions', self.mock_sessions),
            patch.object(lf, 'table_transactions', self.mock_transactions),
            patch.object(lf, 'client', self.mock_ia_client),
            patch.object(lf, 'TELEGRAM_TOKEN', BOT_TOKEN_TESTE),
            patch.object(lf, 'TELEGRAM_SECRET_TOKEN', WEBHOOK_SECRET_TESTE),
            patch.object(lf, 'ZENTRIX_USER_ID', ''),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in reversed(self.patchers):
            p.stop()

    def _assert_cors(self, resp):
        headers = resp.get('headers', {})
        for k, v in lf.CORS_HEADERS.items():
            self.assertEqual(headers.get(k), v)

    # ============================================================
    # 1. ROTEAMENTO HTTP, CORS PREFLIGHT, 405 E ERRO 500
    # ============================================================

    def test_options_preflight_retorna_204_com_cors(self):
        resp = lf.lambda_handler({'httpMethod': 'OPTIONS'}, None)
        self.assertEqual(resp['statusCode'], 204)
        self.assertEqual(resp['body'], '')
        self._assert_cors(resp)

    def test_options_http_api_v2_retorna_204_com_cors(self):
        event = {'requestContext': {'http': {'method': 'OPTIONS'}}}
        resp = lf.lambda_handler(event, None)
        self.assertEqual(resp['statusCode'], 204)
        self._assert_cors(resp)

    def test_metodo_invalido_patch_retorna_405(self):
        resp = lf.lambda_handler({'httpMethod': 'PATCH'}, None)
        self.assertEqual(resp['statusCode'], 405)
        self._assert_cors(resp)
        body = json.loads(resp['body'])
        self.assertIn('erro', body)

    def test_metodo_none_faz_fallback_para_post(self):
        resp = lf.lambda_handler({'body': '{}'}, None)
        self.assertEqual(resp['statusCode'], 400)
        self._assert_cors(resp)

    def test_excecao_nao_tratada_retorna_500_com_cors_sem_vazar_detalhes(self):
        with patch.object(lf, 'tratar_get', side_effect=RuntimeError('segredo_banco_interno')):
            resp = lf.lambda_handler({'httpMethod': 'GET'}, None)
        self.assertEqual(resp['statusCode'], 500)
        self._assert_cors(resp)
        self.assertNotIn('segredo_banco_interno', resp['body'])

    # ============================================================
    # 2. UTILITÁRIOS DE SEGURANÇA E PARSER IA
    # ============================================================

    def test_validar_redirect_uri_bloqueia_open_redirect_e_xss(self):
        self.assertEqual(lf._validar_redirect_uri('javascript:alert(1)'), 'zentrix://auth/callback')
        self.assertEqual(lf._validar_redirect_uri('data:text/html,<script>alert(1)</script>'), 'zentrix://auth/callback')
        self.assertEqual(lf._validar_redirect_uri('http://evil.com/steal'), 'zentrix://auth/callback')
        self.assertEqual(lf._validar_redirect_uri('http://localhost.evil.com/cb'), 'zentrix://auth/callback')
        self.assertEqual(lf._validar_redirect_uri('zentrix://auth/callback\r\nEvil: 1'), 'zentrix://auth/callback')

        # Esquemas permitidos
        self.assertEqual(lf._validar_redirect_uri('zentrix://auth/callback'), 'zentrix://auth/callback')
        self.assertEqual(lf._validar_redirect_uri('exp://192.168.0.10:8081/--/auth'), 'exp://192.168.0.10:8081/--/auth')
        self.assertEqual(lf._validar_redirect_uri('exps://expo.dev/auth'), 'exps://expo.dev/auth')
        self.assertEqual(lf._validar_redirect_uri('http://localhost:8081/auth'), 'http://localhost:8081/auth')
        self.assertEqual(lf._validar_redirect_uri('http://127.0.0.1:19006/cb'), 'http://127.0.0.1:19006/cb')
        self.assertEqual(lf._validar_redirect_uri('https://zentrix.app/callback'), 'https://zentrix.app/callback')

    def test_extrair_json_ia_resiliente_a_markdown_e_texto_extra(self):
        bruto_md = '```json\n{"description": "Uber", "amount": 25.5}\n```'
        self.assertEqual(lf._extrair_json_ia(bruto_md)['amount'], 25.5)

        bruto_extra = 'Claro! Aqui está o JSON solicitado:\n{"description": "iFood", "amount": 49.9} Espero ter ajudado!'
        self.assertEqual(lf._extrair_json_ia(bruto_extra)['description'], 'iFood')

        bruto_lista = 'Resultado:\n[{"orig": "UBER", "limpa": "Uber", "cat": "Transporte"}]\nFim.'
        self.assertEqual(lf._extrair_json_ia(bruto_lista)[0]['cat'], 'Transporte')

    # ============================================================
    # 3. LOGIN TELEGRAM HTML, CALLBACK E TROCA DE CÓDIGO
    # ============================================================

    def test_get_telegram_login_retorna_html_com_cors_e_bloqueia_javascript_uri(self):
        event = {
            'httpMethod': 'GET',
            'headers': {'Host': 'api.zentrix.local', 'X-Forwarded-Proto': 'https'},
            'requestContext': {'path': '/prod/api'},
            'queryStringParameters': {
                'action': 'telegram-login',
                'app_redirect_uri': 'javascript:alert(document.cookie)',
            },
        }
        resp = lf.lambda_handler(event, None)
        self.assertEqual(resp['statusCode'], 200)
        self.assertEqual(resp['headers']['Content-Type'], 'text/html')
        self._assert_cors(resp)
        self.assertNotIn('javascript:', resp['body'])
        self.assertIn('https://api.zentrix.local/prod/api?action=telegram-callback', resp['body'])
        self.assertIn('zentrix%3A%2F%2Fauth%2Fcallback', resp['body'])

    def test_telegram_callback_hmac_valido_gera_auth_code_sem_expor_token(self):
        agora_ts = str(int(time.time()))
        params = {
            'action': 'telegram-callback',
            'app_redirect_uri': 'exp://127.0.0.1:8081/--/callback',
            'id': '777888',
            'first_name': 'Enzo',
            'auth_date': agora_ts,
        }
        params['hash'] = _assinar_telegram(params)
        self.mock_users.get_item.return_value = {}

        resp = lf.lambda_handler({'httpMethod': 'GET', 'queryStringParameters': params}, None)
        self.assertEqual(resp['statusCode'], 302)
        self._assert_cors(resp)

        location = resp['headers']['Location']
        self.assertTrue(location.startswith('exp://127.0.0.1:8081/--/callback?'))
        self.assertIn('auth_code=', location)
        self.assertNotIn('token_sessao', location)

        saved_session = self.mock_sessions.put_item.call_args.kwargs['Item']
        self.assertIn('token', saved_session)
        self.assertIn('auth_code', saved_session)
        self.assertNotIn(saved_session['token'], location)

    def test_telegram_callback_hmac_invalido_expirado_e_open_redirect(self):
        agora_ts = str(int(time.time()))
        # 1) HMAC inválido + tentativa de open redirect javascript:
        params_inv = {
            'action': 'telegram-callback',
            'app_redirect_uri': 'javascript:evil()',
            'id': '777888',
            'first_name': 'Enzo',
            'auth_date': agora_ts,
            'hash': '0' * 64,
        }
        resp_inv = lf.lambda_handler({'httpMethod': 'GET', 'queryStringParameters': params_inv}, None)
        self.assertEqual(resp_inv['statusCode'], 302)
        self.assertEqual(resp_inv['headers']['Location'], 'zentrix://auth/callback?error=hash_invalido')

        # 2) Assinatura expirada (> 86400s)
        antigo_ts = str(int(time.time()) - 90000)
        params_exp = {
            'action': 'telegram-callback',
            'app_redirect_uri': 'zentrix://auth/callback',
            'id': '777888',
            'first_name': 'Enzo',
            'auth_date': antigo_ts,
        }
        params_exp['hash'] = _assinar_telegram(params_exp)
        resp_exp = lf.lambda_handler({'httpMethod': 'GET', 'queryStringParameters': params_exp}, None)
        self.assertEqual(resp_exp['statusCode'], 302)
        self.assertIn('error=expirado', resp_exp['headers']['Location'])

    def test_trocar_codigo_sucesso_inexistente_e_expirado(self):
        futuro = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
        self.mock_sessions.query.return_value = {'Items': [{'token': 'tok-real-999', 'auth_code': 'code-1'}]}
        self.mock_sessions.get_item.return_value = {
            'Item': {
                'token': 'tok-real-999',
                'user_id': '777888',
                'auth_code': 'code-1',
                'auth_code_expires_at': futuro,
            }
        }

        resp_ok = lf.lambda_handler(
            {'httpMethod': 'GET', 'queryStringParameters': {'action': 'trocar-codigo', 'code': 'code-1'}},
            None,
        )
        self.assertEqual(resp_ok['statusCode'], 200)
        dados_ok = json.loads(resp_ok['body'])
        self.assertEqual(dados_ok['token_sessao'], 'tok-real-999')
        self.assertEqual(dados_ok['user_id_interno'], '777888')
        self.mock_sessions.update_item.assert_called_once_with(
            Key={'token': 'tok-real-999'},
            UpdateExpression='REMOVE auth_code, auth_code_expires_at',
        )

        # Código inexistente / já usado
        self.mock_sessions.query.return_value = {'Items': []}
        resp_usado = lf.lambda_handler(
            {'httpMethod': 'GET', 'queryStringParameters': {'action': 'trocar-codigo', 'code': 'code-usado'}},
            None,
        )
        self.assertEqual(resp_usado['statusCode'], 401)

        # Código expirado
        passado = (datetime.datetime.now() - datetime.timedelta(minutes=1)).isoformat()
        self.mock_sessions.query.return_value = {'Items': [{'token': 'tok-exp'}]}
        self.mock_sessions.get_item.return_value = {
            'Item': {
                'token': 'tok-exp',
                'user_id': '777888',
                'auth_code': 'code-exp',
                'auth_code_expires_at': passado,
            }
        }
        resp_exp = lf.lambda_handler(
            {'httpMethod': 'GET', 'queryStringParameters': {'action': 'trocar-codigo', 'code': 'code-exp'}},
            None,
        )
        self.assertEqual(resp_exp['statusCode'], 401)

    # ============================================================
    # 4. POST AUTENTICAÇÃO WEB TELEGRAM
    # ============================================================

    def test_post_autenticacao_web_telegram_hmac_valido_e_invalido(self):
        payload = {
            'id': 424242,
            'first_name': 'Maria',
            'auth_date': int(time.time()),
        }
        payload['hash'] = _assinar_telegram(payload)
        self.mock_users.get_item.return_value = {'Item': {'id': '424242', 'nome': 'Maria'}}

        resp_ok = lf.lambda_handler({'httpMethod': 'POST', 'body': json.dumps(payload)}, None)
        self.assertEqual(resp_ok['statusCode'], 200)
        self._assert_cors(resp_ok)
        body_ok = json.loads(resp_ok['body'])
        self.assertTrue(body_ok['login'])
        self.assertIn('token_sessao', body_ok)

        # HMAC inválido
        payload_ruim = dict(payload, hash='f' * 64)
        resp_inv = lf.lambda_handler({'httpMethod': 'POST', 'body': json.dumps(payload_ruim)}, None)
        self.assertEqual(resp_inv['statusCode'], 401)

    # ============================================================
    # 5. VALIDAÇÃO DE SESSÃO (SEC01)
    # ============================================================

    def test_validar_sessao_todos_os_cenarios(self):
        # 1) Sem header Authorization
        self.assertFalse(lf.validar_sessao({'headers': {}}, '999'))

        # 2) Sessão ainda com auth_code não trocado -> bloqueado
        sess_nao_trocada = _sessao_valida('999')
        sess_nao_trocada['auth_code'] = 'codigo-pendente'
        self.mock_sessions.get_item.return_value = {'Item': sess_nao_trocada}
        self.assertFalse(lf.validar_sessao({'headers': _headers_auth()}, '999'))

        # 3) Sessão pertence a outro user_id (anti-IDOR)
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('111')}
        self.assertFalse(lf.validar_sessao({'headers': _headers_auth()}, '999'))

        # 4) Sessão expirada
        sess_expirada = {
            'token': 'tok-valido-123',
            'user_id': '999',
            'expires_at': (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(),
        }
        self.mock_sessions.get_item.return_value = {'Item': sess_expirada}
        self.assertFalse(lf.validar_sessao({'headers': _headers_auth()}, '999'))

        # 5) Sessão válida
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}
        self.assertTrue(lf.validar_sessao({'headers': _headers_auth()}, '999'))

    # ============================================================
    # 6. GET LISTAGEM (PAGINAÇÃO, FILTRO DELETED, ORDENAÇÃO, PASSWORD_HASH)
    # ============================================================

    def test_get_listagem_paginada_ordena_desc_filtra_deleted_e_remove_password_hash(self):
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}
        self.mock_transactions.query.side_effect = [
            {
                'Items': [
                    {'user_id': '999', 'id': 'tx1', 'amount': Decimal('20.00'), 'status': 'active', 'created_at': '2026-11-01T10:00:00'},
                    {'user_id': '999', 'id': 'tx_del', 'amount': Decimal('99.00'), 'status': 'deleted', 'created_at': '2026-11-05T10:00:00'},
                ],
                'LastEvaluatedKey': {'user_id': '999', 'id': 'tx_del'},
            },
            {
                'Items': [
                    {'user_id': '999', 'id': 'tx2', 'amount': Decimal('50.50'), 'status': 'active', 'created_at': '2026-11-10T12:00:00'},
                ],
            },
        ]
        self.mock_users.get_item.return_value = {
            'Item': {'id': '999', 'nome': 'Enzo', 'password_hash': 'TELEGRAM_AUTH', 'limite_mensal': Decimal('2000')}
        }

        event = {
            'httpMethod': 'GET',
            'headers': _headers_auth(),
            'queryStringParameters': {'user_id': '999'},
        }
        resp = lf.lambda_handler(event, None)
        self.assertEqual(resp['statusCode'], 200)
        self._assert_cors(resp)
        self.assertEqual(self.mock_transactions.query.call_count, 2)

        payload = json.loads(resp['body'])
        ids_retornados = [t['id'] for t in payload['transacoes']]
        self.assertEqual(ids_retornados, ['tx2', 'tx1'])  # DESC e sem tx_del
        self.assertNotIn('password_hash', payload['usuario'])

    # ============================================================
    # 7. GET SUMMARY (SEPARAÇÃO EMPRESTADO VS GASTOS E RATEIO DE PARCELAS)
    # ============================================================

    def test_get_summary_separa_emprestado_de_gastos_e_rateia_parcelas(self):
        agora = datetime.datetime.now()
        mes_atual_iso = agora.replace(day=1, hour=12, minute=0, second=0, microsecond=0).isoformat()
        # 1 mês atrás para validar parcela ativa no mês atual
        ano_ant = agora.year if agora.month > 1 else agora.year - 1
        mes_ant = agora.month - 1 if agora.month > 1 else 12
        mes_anterior_iso = datetime.datetime(ano_ant, mes_ant, 15, 10, 0, 0).isoformat()

        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}
        self.mock_users.get_item.return_value = {
            'Item': {'id': '999', 'nome': 'Enzo', 'limite_mensal': Decimal('1000.00')}
        }
        self.mock_transactions.query.return_value = {
            'Items': [
                # Despesa à vista no mês atual: R$ 100
                {
                    'user_id': '999', 'id': '1', 'amount': Decimal('100.00'),
                    'category': 'Rangos', 'type': 'Débito', 'installments_total': 1,
                    'status': 'active', 'created_at': mes_atual_iso,
                },
                # Despesa parcelada no mês anterior (3x de 100 = 300): R$ 100 no mês atual
                {
                    'user_id': '999', 'id': '2', 'amount': Decimal('300.00'),
                    'category': 'Compras e Mimos', 'type': 'Crédito Parcelado', 'installments_total': 3,
                    'status': 'active', 'created_at': mes_anterior_iso,
                },
                # Emprestado parcelado no mês atual (2x de 75 = 150): R$ 75 em total_receber (NÃO entra em total_gasto)
                {
                    'user_id': '999', 'id': '3', 'amount': Decimal('150.00'),
                    'category': 'A receber', 'type': 'Emprestado', 'installments_total': 2,
                    'status': 'active', 'created_at': mes_atual_iso,
                },
                # Despesa à vista do mês anterior: NÃO deve entrar no mês atual
                {
                    'user_id': '999', 'id': '4', 'amount': Decimal('500.00'),
                    'category': 'Essencial', 'type': 'Débito', 'installments_total': 1,
                    'status': 'active', 'created_at': mes_anterior_iso,
                },
            ]
        }
        self.mock_ia_client.models.generate_content.return_value = MagicMock(text='Bom controle!')

        event = {
            'httpMethod': 'GET',
            'headers': _headers_auth(),
            'queryStringParameters': {'user_id': '999', 'action': 'summary'},
        }
        resp = lf.lambda_handler(event, None)
        self.assertEqual(resp['statusCode'], 200)
        dados = json.loads(resp['body'])
        metricas = dados['metricas']

        self.assertAlmostEqual(metricas['total_gasto'], 200.0)
        self.assertAlmostEqual(metricas['total_receber'], 75.0)
        self.assertAlmostEqual(metricas['limite_definido'], 1000.0)
        self.assertAlmostEqual(metricas['saldo_disponivel'], 800.0)
        self.assertNotIn('A receber', metricas['distribuicao_categorias'])
        self.assertAlmostEqual(metricas['distribuicao_categorias']['Rangos'], 100.0)
        self.assertAlmostEqual(metricas['distribuicao_categorias']['Compras e Mimos'], 100.0)

    # ============================================================
    # 8. POST FRASE (SANITIZAÇÃO, NORMALIZAÇÃO, 422, 429)
    # ============================================================

    def test_post_frase_sucesso_sanitizacao_valor_invalido_e_erro_ia(self):
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}

        # 1) Sucesso com sanitização de HTML/controle e normalização de categoria/tipo inválidos
        self.mock_ia_client.models.generate_content.return_value = MagicMock(
            text='Aqui está:\n```json\n{"description": "Almoço", "amount": 45.90, "category": "Inexistente", "type": "TipoInvalido", "installments": 0, "debtor_name": null}\n```'
        )
        event_ok = {
            'httpMethod': 'POST',
            'headers': _headers_auth(),
            'body': json.dumps({
                'user_id': '999',
                'frase': '<b>Gastei 45,90</b> no almoço\x00\x07',
            }),
        }
        resp_ok = lf.lambda_handler(event_ok, None)
        self.assertEqual(resp_ok['statusCode'], 201)
        prompt_enviado = self.mock_ia_client.models.generate_content.call_args.kwargs['contents']
        self.assertNotIn('<b>', prompt_enviado)
        self.assertNotIn('\x00', prompt_enviado)

        item_salvo = self.mock_transactions.put_item.call_args.kwargs['Item']
        self.assertEqual(item_salvo['category'], 'Outros')
        self.assertEqual(item_salvo['type'], 'Crédito à Vista')
        self.assertEqual(item_salvo['installments_total'], 1)

        # 2) Valor <= 0 -> 422
        self.mock_ia_client.models.generate_content.return_value = MagicMock(
            text='{"description": "Nada", "amount": 0, "category": "Outros", "type": "Débito", "installments": 1}'
        )
        resp_422 = lf.lambda_handler(event_ok, None)
        self.assertEqual(resp_422['statusCode'], 422)

        # 3) Erro na IA -> 429
        self.mock_ia_client.models.generate_content.side_effect = RuntimeError('Quota exceeded')
        resp_429 = lf.lambda_handler(event_ok, None)
        self.assertEqual(resp_429['statusCode'], 429)

    # ============================================================
    # 9. POST CSV C6 BANK (BOM, MOEDA BR, PARCELAS, DATA, LIMITE 1MB)
    # ============================================================

    def test_post_csv_bom_utf8_valores_br_parcelas_datas_e_limite_1mb(self):
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}
        self.mock_ia_client.models.generate_content.return_value = MagicMock(
            text='[{"orig": "NETFLIX.COM", "limpa": "Netflix", "cat": "Assinaturas"}, {"orig": "LOJA X", "limpa": "Loja X", "cat": "CategoriaMaluca"}]'
        )

        csv_conteudo = (
            "\ufeffData de Compra;Descrição;Parcela;Valor (em R$)\n"
            "15/11/2026;NETFLIX.COM;Única;55,90\n"
            "2026-11-16;LOJA X;2/6;1.234,56\n"
            "17/11/2026;ESTORNO;x/y;-10,00\n"
        )
        event_csv = {
            'httpMethod': 'POST',
            'headers': _headers_auth(),
            'body': json.dumps({'user_id': '999', 'csv_text': csv_conteudo}),
        }
        resp = lf.lambda_handler(event_csv, None)
        self.assertEqual(resp['statusCode'], 201)
        body = json.loads(resp['body'])
        self.assertEqual(body['count'], 2)
        self.assertEqual(body['importadas'], 2)

        chamadas = [c.kwargs['Item'] for c in self.mock_transactions.put_item.call_args_list]
        self.assertEqual(len(chamadas), 2)
        self.assertEqual(chamadas[0]['amount'], Decimal('55.9'))
        self.assertEqual(chamadas[0]['category'], 'Assinaturas')
        self.assertEqual(chamadas[0]['type'], 'Crédito à Vista')
        self.assertTrue(chamadas[0]['created_at'].startswith('2026-11-15'))

        self.assertEqual(chamadas[1]['amount'], Decimal('1234.56'))
        self.assertEqual(chamadas[1]['category'], 'Outros')  # Categoria inválida cai em Outros
        self.assertEqual(chamadas[1]['type'], 'Crédito Parcelado')
        self.assertEqual(chamadas[1]['installments_paid'], 2)
        self.assertEqual(chamadas[1]['installments_total'], 6)
        self.assertTrue(chamadas[1]['created_at'].startswith('2026-11-16'))

        # Limite > 1MB -> 413
        csv_gigante = 'a' * (1_048_577)
        resp_413 = lf.lambda_handler(
            {
                'httpMethod': 'POST',
                'headers': _headers_auth(),
                'body': json.dumps({'user_id': '999', 'csv_text': csv_gigante}),
            },
            None,
        )
        self.assertEqual(resp_413['statusCode'], 413)

    # ============================================================
    # 10. WEBHOOK DO BOT TELEGRAM (SECRET TOKEN, /RESUMO, FRASE, CSV SEM VAZAR ERRO)
    # ============================================================

    @patch.object(lf, 'enviar_mensagem_telegram')
    def test_webhook_telegram_secret_resumo_frase_e_csv_sem_vazar_excecao(self, mock_enviar_tg):
        # 1) Secret token inválido -> ignorado sem processar
        evento_sem_secret = {
            'httpMethod': 'POST',
            'headers': {'X-Telegram-Bot-Api-Secret-Token': 'token-errado'},
            'body': json.dumps({'message': {'chat': {'id': 10}, 'from': {'id': 999}, 'text': 'Oi'}}),
        }
        resp_ign = lf.lambda_handler(evento_sem_secret, None)
        self.assertEqual(resp_ign['statusCode'], 200)
        self.assertEqual(json.loads(resp_ign['body']), 'Ignorado')
        mock_enviar_tg.assert_not_called()

        headers_tg = {'X-Telegram-Bot-Api-Secret-Token': WEBHOOK_SECRET_TESTE}
        self.mock_users.get_item.return_value = {'Item': {'id': '999', 'nome': 'Enzo', 'limite_mensal': Decimal('1500')}}

        # 2) Comando /resumo
        self.mock_transactions.query.return_value = {'Items': []}
        evento_resumo = {
            'httpMethod': 'POST',
            'headers': headers_tg,
            'body': json.dumps({'message': {'chat': {'id': 10}, 'from': {'id': 999, 'first_name': 'Enzo'}, 'text': '/resumo'}}),
        }
        resp_resumo = lf.lambda_handler(evento_resumo, None)
        self.assertEqual(resp_resumo['statusCode'], 200)
        self.assertIn('Resumo Financeiro', mock_enviar_tg.call_args.args[1])

        # 3) Frase de gasto via Telegram
        self.mock_ia_client.models.generate_content.return_value = MagicMock(
            text='{"description": "Uber", "amount": 32.0, "category": "Transporte", "type": "Débito", "installments": 1, "debtor_name": null}'
        )
        evento_frase = {
            'httpMethod': 'POST',
            'headers': headers_tg,
            'body': json.dumps({'message': {'chat': {'id': 10}, 'from': {'id': 999, 'first_name': 'Enzo'}, 'text': 'Uber 32 no pix'}}),
        }
        resp_frase = lf.lambda_handler(evento_frase, None)
        self.assertEqual(resp_frase['statusCode'], 200)
        self.mock_transactions.put_item.assert_called_once()

        # 4) Falha ao baixar CSV no Telegram -> NÃO pode vazar str(e) ao usuário (SEC02)
        mock_enviar_tg.reset_mock()
        with patch('urllib.request.urlopen', side_effect=RuntimeError('InternalTokenSecretLeak_XYZ')):
            evento_doc = {
                'httpMethod': 'POST',
                'headers': headers_tg,
                'body': json.dumps({
                    'message': {
                        'chat': {'id': 10},
                        'from': {'id': 999, 'first_name': 'Enzo'},
                        'document': {'file_id': 'f123', 'file_name': 'fatura.csv'},
                    }
                }),
            }
            resp_doc_err = lf.lambda_handler(evento_doc, None)
            self.assertEqual(resp_doc_err['statusCode'], 200)
            mensagens_enviadas = " ".join(call.args[1] for call in mock_enviar_tg.call_args_list)
            self.assertNotIn('InternalTokenSecretLeak_XYZ', mensagens_enviadas)

        # 5) CSV em latin-1 no Telegram decodificado com sucesso via fallback
        csv_latin1 = "Data;Descrição;Parcela;Valor (em R$)\n10/11/2026;Padaria São José;Única;25,00\n".encode('latin-1')
        self.mock_ia_client.models.generate_content.return_value = MagicMock(text='[]')

        def fake_urlopen(url_or_req):
            resp_cm = MagicMock()
            if 'getFile' in str(url_or_req):
                resp_cm.__enter__.return_value.read.return_value = json.dumps(
                    {'result': {'file_path': 'docs/fatura.csv'}}
                ).encode('utf-8')
            else:
                resp_cm.__enter__.return_value.read.return_value = csv_latin1
            return resp_cm

        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            resp_doc_ok = lf.lambda_handler(evento_doc, None)
            self.assertEqual(resp_doc_ok['statusCode'], 200)
            self.assertEqual(json.loads(resp_doc_ok['body']), 'CSV processado pelo Telegram')

    # ============================================================
    # 11. PUT UPDATE_TRANSACTION E UPDATE_USER
    # ============================================================

    def test_put_update_transaction_sucesso_404_e_validacoes_400(self):
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}

        # 1) Sucesso com todos os campos válidos (incluindo type e sanitização de description)
        evento_ok = {
            'httpMethod': 'PUT',
            'headers': _headers_auth(),
            'body': json.dumps({
                'user_id': '999',
                'action': 'update_transaction',
                'id': 'tx-100',
                'amount': 89.9,
                'description': '<b>Jantar</b> Especial',
                'category': 'Rangos',
                'type': 'Débito',
                'status': 'active',
            }),
        }
        resp_ok = lf.lambda_handler(evento_ok, None)
        self.assertEqual(resp_ok['statusCode'], 200)
        kwargs_upd = self.mock_transactions.update_item.call_args.kwargs
        self.assertEqual(
            kwargs_upd['ConditionExpression'],
            'attribute_exists(user_id) AND attribute_exists(id)',
        )
        self.assertEqual(kwargs_upd['ExpressionAttributeValues'][':v_description'], 'Jantar Especial')

        # 2) ConditionalCheckFailedException -> 404
        erro_cond = ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'Not found'}},
            'UpdateItem',
        )
        self.mock_transactions.update_item.side_effect = erro_cond
        resp_404 = lf.lambda_handler(evento_ok, None)
        self.assertEqual(resp_404['statusCode'], 404)
        self.mock_transactions.update_item.side_effect = None

        # 3) Categoria inválida -> 400
        resp_cat = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({
                    'user_id': '999', 'action': 'update_transaction',
                    'id': 'tx-100', 'category': 'Cripto',
                }),
            },
            None,
        )
        self.assertEqual(resp_cat['statusCode'], 400)

        # 4) Tipo inválido -> 400
        resp_tipo = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({
                    'user_id': '999', 'action': 'update_transaction',
                    'id': 'tx-100', 'type': 'Boleto',
                }),
            },
            None,
        )
        self.assertEqual(resp_tipo['statusCode'], 400)

        # 5) Valor negativo -> 400
        resp_val = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({
                    'user_id': '999', 'action': 'update_transaction',
                    'id': 'tx-100', 'amount': -15,
                }),
            },
            None,
        )
        self.assertEqual(resp_val['statusCode'], 400)

    def test_put_update_user_sucesso_e_validacoes_400(self):
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}

        # Sucesso
        resp_ok = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({
                    'user_id': '999',
                    'action': 'update_user',
                    'salario_mensal': 3500,
                    'limite_mensal': 2000,
                    'dia_vencimento_fatura': 10,
                }),
            },
            None,
        )
        self.assertEqual(resp_ok['statusCode'], 200)

        # Salário negativo -> 400
        resp_sal = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({'user_id': '999', 'action': 'update_user', 'salario_mensal': -1}),
            },
            None,
        )
        self.assertEqual(resp_sal['statusCode'], 400)

        # Limite <= 0 -> 400
        resp_lim = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({'user_id': '999', 'action': 'update_user', 'limite_mensal': 0}),
            },
            None,
        )
        self.assertEqual(resp_lim['statusCode'], 400)

        # Dia de vencimento fora de 1..31 -> 400
        resp_dia = lf.lambda_handler(
            {
                'httpMethod': 'PUT',
                'headers': _headers_auth(),
                'body': json.dumps({'user_id': '999', 'action': 'update_user', 'dia_vencimento_fatura': 32}),
            },
            None,
        )
        self.assertEqual(resp_dia['statusCode'], 400)

    # ============================================================
    # 12. DELETE TRANSAÇÃO E SCRIPT DYNAMODB GSI
    # ============================================================

    def test_delete_transacao_sucesso_400_e_401(self):
        # Falta de chaves -> 400
        resp_400 = lf.lambda_handler(
            {'httpMethod': 'DELETE', 'headers': _headers_auth(), 'body': json.dumps({'user_id': '999'})},
            None,
        )
        self.assertEqual(resp_400['statusCode'], 400)

        # Não autorizado -> 401
        self.mock_sessions.get_item.return_value = {}
        resp_401 = lf.lambda_handler(
            {'httpMethod': 'DELETE', 'headers': _headers_auth(), 'body': json.dumps({'user_id': '999', 'id': 'tx-1'})},
            None,
        )
        self.assertEqual(resp_401['statusCode'], 401)

        # Sucesso -> 200
        self.mock_sessions.get_item.return_value = {'Item': _sessao_valida('999')}
        resp_200 = lf.lambda_handler(
            {'httpMethod': 'DELETE', 'headers': _headers_auth(), 'body': json.dumps({'user_id': '999', 'id': 'tx-1'})},
            None,
        )
        self.assertEqual(resp_200['statusCode'], 200)
        self.mock_transactions.delete_item.assert_called_once_with(
            Key={'user_id': '999', 'id': 'tx-1'}
        )

    def test_script_dynamodb_configura_gsi_auth_code_index(self):
        mock_dynamo = MagicMock()
        with patch.object(db_setup, 'dynamodb', mock_dynamo):
            db_setup.criar_todas_tabelas()

        chamadas = {c.kwargs['TableName']: c.kwargs for c in mock_dynamo.create_table.call_args_list}
        self.assertIn('ZentrixSessions', chamadas)
        sess_cfg = chamadas['ZentrixSessions']
        self.assertEqual(sess_cfg['GlobalSecondaryIndexes'][0]['IndexName'], 'auth_code-index')
        self.assertEqual(sess_cfg['GlobalSecondaryIndexes'][0]['Projection']['ProjectionType'], 'ALL')


if __name__ == '__main__':
    unittest.main()
