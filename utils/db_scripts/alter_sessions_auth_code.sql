-- ============================================================
-- SCRIPT: Adicionar suporte a troca de código de autenticação
-- Executar no banco db-zentrix ANTES de implantar v12.py
-- ============================================================

-- Adiciona colunas de auth_code temporário na tabela sessions
ALTER TABLE sessions
  ADD COLUMN auth_code VARCHAR(36) NULL DEFAULT NULL COMMENT 'Código de uso único para troca segura do token (SEC03)',
  ADD COLUMN auth_code_expires_at DATETIME NULL DEFAULT NULL COMMENT 'Expiração do auth_code (10 minutos)',
  ADD INDEX idx_sessions_auth_code (auth_code);
