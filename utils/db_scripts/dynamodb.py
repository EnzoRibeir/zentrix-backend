import boto3

# Conecta ao DynamoDB (certifique-se de que a região está correta)
dynamodb = boto3.resource('dynamodb', region_name='sa-east-1')

def criar_tabela(nome_tabela, schema_chaves, definicao_atributos):
    try:
        table = dynamodb.create_table(
            TableName=nome_tabela,
            KeySchema=schema_chaves,
            AttributeDefinitions=definicao_atributos,
            BillingMode='PAY_PER_REQUEST' # Isso garante que fique no modelo Gratuito/Sob Demanda
        )
        print(f"Criando tabela {nome_tabela}... Aguarde.")
        table.meta.client.get_waiter('table_exists').wait(TableName=nome_tabela)
        print(f"Tabela {nome_tabela} criada com sucesso!")
    except Exception as e:
        print(f"Erro ao criar {nome_tabela}: {e}")

# 1. Tabela de Usuários (Apenas o ID do Telegram como chave principal)
criar_tabela(
    nome_tabela='ZentrixUsers',
    schema_chaves=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
    definicao_atributos=[{'AttributeName': 'id', 'AttributeType': 'S'}]
)

# 2. Tabela de Sessões (O token de autenticação é a chave)
criar_tabela(
    nome_tabela='ZentrixSessions',
    schema_chaves=[{'AttributeName': 'token', 'KeyType': 'HASH'}],
    definicao_atributos=[{'AttributeName': 'token', 'AttributeType': 'S'}]
)

# 3. Tabela de Transações (O user_id é a chave de partição e o id da transação é a chave de ordenação)
criar_tabela(
    nome_tabela='ZentrixTransactions',
    schema_chaves=[
        {'AttributeName': 'user_id', 'KeyType': 'HASH'}, 
        {'AttributeName': 'id', 'KeyType': 'RANGE'}
    ],
    definicao_atributos=[
        {'AttributeName': 'user_id', 'AttributeType': 'S'},
        {'AttributeName': 'id', 'AttributeType': 'S'}
    ]
)