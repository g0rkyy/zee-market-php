<?php
/**
 * SCRIPT DE CORREÇÃO COMPLETA DO BANCO DE DADOS
 * Execute este arquivo UMA VEZ para corrigir todas as estruturas
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Incluir configuração
require_once 'includes/config.php';

echo "<!DOCTYPE html>
<html>
<head>
    <title>Correção Completa do Banco - ZeeMarket</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        .success { color: #28a745; background: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .info { color: #17a2b8; background: #d1ecf1; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .code { background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    </style>
</head>
<body>
<div class='container'>
<h1>🔧 Correção Completa do Banco de Dados ZeeMarket</h1>";

$sucessos = [];
$erros = [];

try {
    // Verificar conexão
    if (!$conn || $conn->connect_error) {
        throw new Exception("Erro na conexão: " . $conn->connect_error);
    }
    
    echo "<div class='success'>✓ Conexão com o banco estabelecida</div>";

    // TODAS as correções necessárias
    $correcoes = [
        [
            'nome' => 'Adicionar colunas multi-cripto na tabela users',
            'sql' => "ALTER TABLE users 
                     ADD COLUMN IF NOT EXISTS eth_balance DECIMAL(18,8) DEFAULT 0.00000000,
                     ADD COLUMN IF NOT EXISTS xmr_balance DECIMAL(18,8) DEFAULT 0.00000000,
                     ADD COLUMN IF NOT EXISTS eth_deposit_address VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS xmr_deposit_address VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS username VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS is_admin TINYINT(1) DEFAULT 0,
                     ADD COLUMN IF NOT EXISTS btc_private_key TEXT DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS eth_private_key TEXT DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS xmr_private_key TEXT DEFAULT NULL"
        ],
        [
            'nome' => 'Atualizar username baseado no name',
            'sql' => "UPDATE users SET username = name WHERE username IS NULL OR username = ''"
        ],
        [
            'nome' => 'Corrigir tabela btc_transactions',
            'sql' => "ALTER TABLE btc_transactions 
                     ADD COLUMN IF NOT EXISTS type ENUM('deposit','withdrawal') DEFAULT 'deposit',
                     ADD COLUMN IF NOT EXISTS crypto_type VARCHAR(10) DEFAULT 'BTC',
                     ADD COLUMN IF NOT EXISTS confirmations INT DEFAULT 0,
                     ADD COLUMN IF NOT EXISTS fee DECIMAL(18,8) DEFAULT 0.00000000,
                     ADD COLUMN IF NOT EXISTS to_address VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS block_height INT DEFAULT 0,
                     ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
        ],
        [
            'nome' => 'Criar tabela btc_balance_history',
            'sql' => "CREATE TABLE IF NOT EXISTS btc_balance_history (
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
                        INDEX idx_user_id (user_id),
                        INDEX idx_crypto_type (crypto_type),
                        INDEX idx_created_at (created_at)
                     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        ],
        [
            'nome' => 'Criar tabela eth_transactions',
            'sql' => "CREATE TABLE IF NOT EXISTS eth_transactions (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        tx_hash VARCHAR(100) NOT NULL,
                        amount DECIMAL(18,8) NOT NULL,
                        type ENUM('deposit','withdrawal') NOT NULL,
                        status ENUM('pending','completed','failed') DEFAULT 'pending',
                        address VARCHAR(100) DEFAULT NULL,
                        fee DECIMAL(18,8) DEFAULT 0.00000000,
                        block_height INT DEFAULT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        INDEX idx_user_id (user_id),
                        INDEX idx_tx_hash (tx_hash),
                        INDEX idx_status (status)
                     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        ],
        [
            'nome' => 'Criar tabela xmr_transactions',
            'sql' => "CREATE TABLE IF NOT EXISTS xmr_transactions (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        tx_hash VARCHAR(100) NOT NULL,
                        amount DECIMAL(18,8) NOT NULL,
                        type ENUM('deposit','withdrawal') NOT NULL,
                        status ENUM('pending','completed','failed') DEFAULT 'pending',
                        address VARCHAR(100) DEFAULT NULL,
                        fee DECIMAL(18,8) DEFAULT 0.00000000,
                        block_height INT DEFAULT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        INDEX idx_user_id (user_id),
                        INDEX idx_tx_hash (tx_hash)
                     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        ],
        [
            'nome' => 'Corrigir tabela vendedores - remover coluna carteira',
            'sql' => "ALTER TABLE vendedores DROP COLUMN IF EXISTS carteira"
        ],
        [
            'nome' => 'Atualizar crypto_type nas transações existentes',
            'sql' => "UPDATE btc_transactions SET crypto_type = 'BTC' WHERE crypto_type IS NULL OR crypto_type = ''"
        ],
        [
            'nome' => 'Atualizar type nas transações existentes',
            'sql' => "UPDATE btc_transactions SET type = 'deposit' WHERE type IS NULL"
        ],
        [
            'nome' => 'Criar tabela admin_logs',
            'sql' => "CREATE TABLE IF NOT EXISTS admin_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        action VARCHAR(100) NOT NULL,
                        details JSON DEFAULT NULL,
                        ip_address VARCHAR(45) DEFAULT NULL,
                        user_agent TEXT DEFAULT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_user_action (user_id, action),
                        INDEX idx_created_at (created_at)
                     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        ]
    ];

    echo "<h2>📊 Executando Correções</h2>";

    foreach ($correcoes as $correcao) {
        try {
            $resultado = $conn->query($correcao['sql']);
            if ($resultado !== false) {
                echo "<div class='success'>✓ {$correcao['nome']}</div>";
                $sucessos[] = $correcao['nome'];
            } else {
                echo "<div class='error'>✗ Erro em: {$correcao['nome']} - {$conn->error}</div>";
                $erros[] = $correcao['nome'] . ': ' . $conn->error;
            }
        } catch (Exception $e) {
            echo "<div class='error'>✗ Exceção em: {$correcao['nome']} - {$e->getMessage()}</div>";
            $erros[] = $correcao['nome'] . ': ' . $e->getMessage();
        }
    }

    // Criar diretórios necessários
    $dirs = ['cache', 'logs', 'assets/uploads'];
    foreach ($dirs as $dir) {
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
            echo "<div class='success'>✓ Diretório '$dir' criado</div>";
        }
    }

    // Verificação final
    echo "<h2>🔍 Verificação Final</h2>";
    
    $tabelas_verificar = ['users', 'btc_transactions', 'btc_balance_history', 'eth_transactions', 'xmr_transactions'];
    
    foreach ($tabelas_verificar as $tabela) {
        $resultado = $conn->query("SHOW TABLES LIKE '$tabela'");
        if ($resultado && $resultado->num_rows > 0) {
            echo "<div class='success'>✓ Tabela '$tabela' existe</div>";
            
            if ($tabela === 'users') {
                // Verificar colunas específicas
                $colunas_necessarias = ['eth_balance', 'xmr_balance', 'username', 'eth_deposit_address', 'xmr_deposit_address'];
                
                $describe = $conn->query("DESCRIBE users");
                $colunas_existentes = [];
                while ($row = $describe->fetch_assoc()) {
                    $colunas_existentes[] = $row['Field'];
                }
                
                foreach ($colunas_necessarias as $coluna) {
                    if (in_array($coluna, $colunas_existentes)) {
                        echo "<div class='success'>✓ Coluna users.$coluna encontrada</div>";
                    } else {
                        echo "<div class='error'>✗ Coluna users.$coluna não encontrada</div>";
                    }
                }
            }
            
            if ($tabela === 'btc_transactions') {
                $describe = $conn->query("DESCRIBE btc_transactions");
                $colunas_btc = [];
                while ($row = $describe->fetch_assoc()) {
                    $colunas_btc[] = $row['Field'];
                }
                
                $colunas_btc_necessarias = ['type', 'crypto_type', 'confirmations'];
                foreach ($colunas_btc_necessarias as $coluna) {
                    if (in_array($coluna, $colunas_btc)) {
                        echo "<div class='success'>✓ Coluna btc_transactions.$coluna encontrada</div>";
                    } else {
                        echo "<div class='error'>✗ Coluna btc_transactions.$coluna não encontrada</div>";
                    }
                }
            }
        } else {
            echo "<div class='error'>✗ Tabela '$tabela' não encontrada</div>";
        }
    }

    // Teste de funcionalidades
    echo "<h2>🧪 Teste de Funcionalidades</h2>";
    
    try {
        $stmt = $conn->prepare("SELECT id, name, eth_balance, xmr_balance, username FROM users LIMIT 1");
        if ($stmt && $stmt->execute()) {
            echo "<div class='success'>✓ Consulta multi-cripto funcionando</div>";
        } else {
            echo "<div class='error'>✗ Erro na consulta multi-cripto: " . $conn->error . "</div>";
        }
    } catch (Exception $e) {
        echo "<div class='error'>✗ Exceção na consulta: " . $e->getMessage() . "</div>";
    }

    // Resumo final
    echo "<h2>📋 Resumo da Correção</h2>";
    echo "<div class='info'><strong>Correções aplicadas:</strong> " . count($sucessos) . "</div>";
    echo "<div class='info'><strong>Erros encontrados:</strong> " . count($erros) . "</div>";
    
    if (count($erros) === 0) {
        echo "<div class='success'>
                <h3>🎉 Correção Concluída com Sucesso!</h3>
                <p>Agora você pode:</p>
                <ul>
                    <li><a href='login.php'>Fazer login</a></li>
                    <li><a href='dashboard.php'>Acessar o dashboard</a></li>
                    <li><a href='vendedores.php'>Registrar como vendedor</a></li>
                </ul>
                <p><strong>Próximo passo:</strong> Execute o arquivo generate_wallet.php</p>
              </div>";
    } else {
        echo "<div class='error'>
                <h3>⚠️ Algumas correções falharam</h3>
                <p>Execute novamente ou faça as correções manualmente via phpMyAdmin</p>
              </div>";
    }

} catch (Exception $e) {
    echo "<div class='error'>
            <h3>❌ Erro Crítico</h3>
            <p>Erro: " . $e->getMessage() . "</p>
          </div>";
}

echo "</div></body></html>";
?>