import boto3

# Conecta ao DynamoDB (certifique-se de que a região está correta)
dynamodb = boto3.resource('dynamodb', region_name='sa-east-1')


def criar_tabela(nome_tabela, schema_chaves, definicao_atributos, gsi=None):
    try:
        kwargs = {
            'TableName': nome_tabela,
            'KeySchema': schema_chaves,
            'AttributeDefinitions': definicao_atributos,
            'BillingMode': 'PAY_PER_REQUEST',  # Modelo Sob Demanda / Free Tier friendly
        }
        if gsi:
            kwargs['GlobalSecondaryIndexes'] = gsi

        table = dynamodb.create_table(**kwargs)
        print(f"Criando tabela {nome_tabela}... Aguarde.")
        table.meta.client.get_waiter('table_exists').wait(TableName=nome_tabela)
        print(f"Tabela {nome_tabela} criada com sucesso!")
    except Exception as e:
        print(f"Erro ao criar {nome_tabela}: {e}")


def criar_todas_tabelas():
    # 1. Tabela de Usuários (ID do Telegram como Partition Key)
    criar_tabela(
        nome_tabela='ZentrixUsers',
        schema_chaves=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        definicao_atributos=[{'AttributeName': 'id', 'AttributeType': 'S'}],
    )

    # 2. Tabela de Sessões (token como PK + GSI Sparse auth_code-index para troca OAuth-like)
    criar_tabela(
        nome_tabela='ZentrixSessions',
        schema_chaves=[{'AttributeName': 'token', 'KeyType': 'HASH'}],
        definicao_atributos=[
            {'AttributeName': 'token', 'AttributeType': 'S'},
            {'AttributeName': 'auth_code', 'AttributeType': 'S'},
        ],
        gsi=[
            {
                'IndexName': 'auth_code-index',
                'KeySchema': [{'AttributeName': 'auth_code', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
            }
        ],
    )

    # 3. Tabela de Transações (PK = user_id, SK = id da transação)
    criar_tabela(
        nome_tabela='ZentrixTransactions',
        schema_chaves=[
            {'AttributeName': 'user_id', 'KeyType': 'HASH'},
            {'AttributeName': 'id', 'KeyType': 'RANGE'},
        ],
        definicao_atributos=[
            {'AttributeName': 'user_id', 'AttributeType': 'S'},
            {'AttributeName': 'id', 'AttributeType': 'S'},
        ],
    )


if __name__ == '__main__':
    criar_todas_tabelas()
