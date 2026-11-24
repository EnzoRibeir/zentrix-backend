# Zentrix — Backend Serverless 📱💸

**Zentrix** é um ecossistema inteligente de controle financeiro multiplataforma desenvolvido como projeto interdisciplinar universitário. Ele combina um aplicativo moderno multiplataforma com um backend serverless potencializado por Inteligência Artificial (**Google Gemini 2.5 Flash**), persistência NoSQL de baixa latência (**Amazon DynamoDB**) e autenticação criptográfica via **Telegram**.

O projeto foi arquitetado com foco em **Segurança da Informação** (modelagem de ameaças **STRIDE**), alta escalabilidade sob demanda e excelente Experiência de Usuário (UX).

---

## 🗂️ Organização dos Repositórios

O ecossistema Zentrix é dividido em dois repositórios independentes:

* **`zentrix-app` (este repositório — Backend Serverless):** Contém a função AWS Lambda (`lambda_function.py`), scripts de provisionamento do Amazon DynamoDB (`utils/db_scripts/dynamodb.py`), pipeline CI/CD de deploy automatizado (`.github/workflows/deploy.yml`) e a suíte de testes automatizados (`tests/test_lambda.py`).
* **`zentrix-frontend` (Aplicativo Mobile & Web):** Aplicação cliente desenvolvida em **React Native + Expo**, responsável pelo Dashboard interativo, gráficos de categorias, gestão de limites, importação de faturas CSV e fluxo de login com Deep Link.

---

## 🏗️ Arquitetura do Sistema

1. **Frontend (`zentrix-frontend` — Mobile & Web):** Desenvolvido em React Native via Expo, consumindo a API REST via HTTPS com suporte completo a preflight CORS (`OPTIONS`) e autenticação Bearer.
2. **Backend (`zentrix-app` — AWS Lambda / Python):** Arquitetura 100% orientada a eventos via Amazon API Gateway + AWS Lambda, eliminando servidores ociosos e reduzindo custos e superfície de ataque.
3. **Banco de Dados NoSQL (Amazon DynamoDB):** Armazenamento gerenciado em modo `PAY_PER_REQUEST` (On-Demand), estruturado em três tabelas isoladas:
   - `ZentrixUsers` (`PK`: `id` — ID do usuário no Telegram, perfil e limites financeiros).
   - `ZentrixSessions` (`PK`: `token` — sessões opacas UUIDv4 com expiração + **GSI Sparse `auth_code-index`** sobre `auth_code` para troca segura de código temporário de uso único).
   - `ZentrixTransactions` (`PK`: `user_id`, `SK`: `id` — chave primária composta que isola nativamente as transações por usuário e viabiliza consultas paginadas de alta performance).
4. **Inteligência Artificial (Google Gemini 2.5 Flash):** Processa frases em linguagem natural (via API ou Bot do Telegram), categoriza faturas CSV do C6 Bank em lote e gera *insights* financeiros personalizados sobre o orçamento mensal.
5. **Autenticação (Telegram Login Widget + Fluxo `auth_code`):** Delegação de credenciais ao Telegram validada por assinatura `HMAC-SHA256` e troca de código temporário (`auth_code` válido por 10 minutos) por `token_sessao`, evitando exposição de tokens sensíveis em URLs ou logs de navegação.

---

## 🛡️ Segurança e o Modelo STRIDE

Toda a arquitetura do Zentrix aplica *Security by Design*, mapeando e mitigando ameaças segundo o modelo **STRIDE**:

### S — Spoofing (Falsificação de Identidade)
* **Mitigação:** Autenticação via **Telegram Login Widget** verificada com `HMAC-SHA256` em tempo constante (`hmac.compare_digest`) e janela máxima de 24h (`auth_date`). No fluxo mobile/deep link, um `auth_code` efêmero (10 min) é trocado uma única vez na rota `trocar-codigo` (removendo o atributo `auth_code` do item e retirando-o automaticamente do GSI Sparse `auth_code-index`). Webhooks do Bot validam o cabeçalho `X-Telegram-Bot-Api-Secret-Token`, e URIs de redirecionamento passam por whitelist estrita (`_validar_redirect_uri`) contra *Open Redirect*.

### T — Tampering (Adulteração de Dados)
* **Mitigação:** Prevenção contra *NoSQL Injection* e colisão de palavras reservadas através do SDK `boto3` fortemente tipado (`KeyConditionExpression`, `ExpressionAttributeNames`, `ExpressionAttributeValues`, `ConditionExpression` e conversão rigorosa para `Decimal`). Entradas passam por validação estrita de domínio (`MINHAS_CATEGORIAS`, `TIPOS_PERMITIDOS`, valores positivos e limites de perfil).

### R — Repudiation (Repúdio)
* **Mitigação:** Logs operacionais estruturados no AWS CloudWatch sem exposição de segredos ou tokens, e vínculo imutável de cada transação à chave de partição `user_id` e timestamp ISO 8601 (`created_at`).

### I — Information Disclosure (Vazamento de Informações)
* **Mitigação:**
  1. Tráfego exclusivamente sobre TLS 1.2+ (HTTPS).
  2. Tratamento global de exceções (HTTP 500) e erros no processamento do Bot do Telegram que registram falhas apenas internamente, **nunca** expondo `str(e)` ou *stack traces* ao usuário final.
  3. Remoção explícita de atributos internos (`password_hash`) nas respostas de perfil e não armazenamento da frase bruta original (`raw_input_phrase`).
  4. Sanitização de HTML e caracteres de controle (`sanitizar_frase`) antes de qualquer envio ao modelo Gemini.

### D — Denial of Service (Negação de Serviço)
* **Mitigação:** Escalonamento automático via AWS Lambda e DynamoDB `PAY_PER_REQUEST`, limite rígido de **1 MB** para importação de arquivos CSV (HTTP `413`) e paginação completa via `LastEvaluatedKey`.

### E — Elevation of Privilege (Elevação de Privilégio)
* **Mitigação:** Proteção nativa contra **IDOR** (*Insecure Direct Object Reference*): todas as rotas autenticadas validam se o Bearer `token` pertence exatamente ao `user_id` requisitado, e todas as operações em `ZentrixTransactions` utilizam a chave composta `{user_id, id}` aliada a `ConditionExpression='attribute_exists(user_id) AND attribute_exists(id)'`.

---

## 🧪 Como Executar os Testes Localmente (`zentrix-app`)

1. Crie e ative um ambiente virtual Python (3.11+):
```bash
python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate
```

2. Instale as dependências de desenvolvimento:
```bash
pip install -r requirements-dev.txt
```
*(Nota: `requirements.txt` permanece vazio pois na AWS Lambda o `boto3` já faz parte do runtime oficial e `google-genai` é provido via Lambda Layer.)*

3. Execute a suíte completa de testes automatizados:
```bash
pytest -v
# ou usando unittest nativo:
python -m unittest discover -s tests -v
```

---

## 📱 Frontend (`zentrix-frontend`)

Para executar o aplicativo mobile/web em React Native + Expo, consulte o repositório dedicado **`zentrix-frontend`**.

---
*Projeto Interdisciplinar — Engenharia de Software Segura, Arquitetura Serverless e Inovação Financeira.*
