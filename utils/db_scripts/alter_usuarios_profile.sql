-- ============================================================
-- SCRIPT DE ATUALIZAÇÃO DO BANCO DE DADOS (ZENTRIX)
-- ============================================================
-- Propósito: Adicionar colunas de perfil do usuário (salário, limite, dia de vencimento)
-- na tabela 'usuarios'. Isso resolve o erro 500 ao tentar editar o perfil no app.
-- 
-- Para rodar no DBeaver / MySQL Workbench:
-- Selecione todo o texto e execute.

ALTER TABLE usuarios
  ADD COLUMN salario_mensal DECIMAL(10, 2) NULL DEFAULT NULL COMMENT 'Renda principal mensal do usuário',
  ADD COLUMN limite_mensal DECIMAL(10, 2) NULL DEFAULT 1000.00 COMMENT 'Teto de gastos estabelecido para o mês',
  ADD COLUMN dia_vencimento_fatura INT NULL DEFAULT NULL COMMENT 'Dia de vencimento da fatura do cartão (1 a 31)';
