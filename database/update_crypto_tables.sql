-- Atualizações para suporte multi-cripto
USE zee_market;

-- Adicionar colunas de criptomoedas na tabela users
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS eth_balance DECIMAL(18,8) DEFAULT 0.00000000,
ADD COLUMN IF NOT EXISTS xmr_balance DECIMAL(18,8) DEFAULT 0.00000000,
ADD COLUMN IF NOT EXISTS eth_deposit_address VARCHAR(100) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS xmr_deposit_address VARCHAR(100) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS eth_private_key TEXT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS xmr_private_key TEXT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS btc_private_key TEXT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS btc_public_key TEXT DEFAULT NULL,
ADD COLUMN IF NOT EXISTS username VARCHAR(100) DEFAULT NULL;

-- Atualizar username com base no name existente
UPDATE users SET username = name WHERE username IS NULL;

-- Adicionar colunas na tabela btc_transactions para multi-cripto
ALTER TABLE btc_transactions 
ADD COLUMN IF NOT EXISTS crypto_type VARCHAR(10) DEFAULT 'BTC',
ADD COLUMN IF NOT EXISTS fee DECIMAL(18,8) DEFAULT 0.00000000,
ADD COLUMN IF NOT EXISTS platform_fee DECIMAL(18,8) DEFAULT 0.00000000,
ADD COLUMN IF NOT EXISTS to_address VARCHAR(100) DEFAULT NULL,
ADD COLUMN IF NOT EXISTS block_height INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT NULL;

-- Criar tabela de histórico de saldos
CREATE TABLE IF NOT EXISTS btc_balance_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('credit', 'debit') NOT NULL,
    amount DECIMAL(18,8) NOT NULL,
    balance_before DECIMAL(18,8) DEFAULT 0,
    balance_after DECIMAL(18,8) DEFAULT 0,
    description TEXT,
    tx_hash VARCHAR(100) DEFAULT NULL,
    crypto_type VARCHAR(10) DEFAULT 'BTC',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_crypto (user_id, crypto_type),
    INDEX idx_created_at (created_at)
);

-- Criar tabela de logs de admin
CREATE TABLE IF NOT EXISTS admin_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    details JSON DEFAULT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_action (user_id, action),
    INDEX idx_created_at (created_at)
);

-- Criar tabela de configurações do sistema
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Inserir configurações padrão
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('btc_min_deposit', '0.0001', 'Depósito mínimo de Bitcoin'),
('eth_min_deposit', '0.001', 'Depósito mínimo de Ethereum'),
('xmr_min_deposit', '0.01', 'Depósito mínimo de Monero'),
('btc_withdrawal_fee', '0.0001', 'Taxa de saque Bitcoin'),
('eth_withdrawal_fee', '0.001', 'Taxa de saque Ethereum'),
('xmr_withdrawal_fee', '0.01', 'Taxa de saque Monero'),
('platform_fee_percent', '0.5', 'Taxa da plataforma em porcentagem'),
('daily_withdrawal_limit_btc', '1.0', 'Limite diário de saque BTC'),
('daily_withdrawal_limit_eth', '10.0', 'Limite diário de saque ETH'),
('daily_withdrawal_limit_xmr', '100.0', 'Limite diário de saque XMR');

-- Criar índices para performance
CREATE INDEX IF NOT EXISTS idx_btc_deposit_address ON users(btc_deposit_address);
CREATE INDEX IF NOT EXISTS idx_eth_deposit_address ON users(eth_deposit_address);
CREATE INDEX IF NOT EXISTS idx_xmr_deposit_address ON users(xmr_deposit_address);
CREATE INDEX IF NOT EXISTS idx_last_deposit_check ON users(last_deposit_check);
CREATE INDEX IF NOT EXISTS idx_tx_hash ON btc_transactions(tx_hash);
CREATE INDEX IF NOT EXISTS idx_user_crypto_status ON btc_transactions(user_id, crypto_type, status);

-- Atualizar transações existentes com crypto_type BTC
UPDATE btc_transactions SET crypto_type = 'BTC' WHERE crypto_type IS NULL OR crypto_type = '';

-- Criar diretório de cache (será usado pelo PHP)
-- Nota: Este comando será executado pelo PHP, não pelo SQL