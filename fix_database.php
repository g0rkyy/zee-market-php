<?php
/**
 * SCRIPT DE CORREÇÃO AUTOMÁTICA DO BANCO DE DADOS
 * Execute este arquivo uma vez para corrigir todas as estruturas do banco
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Incluir configuração
require_once 'includes/config.php';

echo "<!DOCTYPE html>
<html>
<head>
    <title>Correção do Banco de Dados - ZeeMarket</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
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
<h1>🔧 Correção Automática do Banco de Dados ZeeMarket</h1>";

$erros = [];
$sucessos = [];

try {
    // Verificar conexão
    if (!$conn || $conn->connect_error) {
        throw new Exception("Erro na conexão: " . $conn->connect_error);
    }
    
    echo "<div class='success'>✓ Conexão com o banco estabelecida com sucesso</div>";

    // Array de correções para executar
    $correcoes = [
        [
            'nome' => 'Adicionar colunas multi-cripto na tabela users',
            'sql' => "ALTER TABLE users 
                     ADD COLUMN IF NOT EXISTS eth_balance DECIMAL(18,8) DEFAULT 0.00000000,
                     ADD COLUMN IF NOT EXISTS xmr_balance DECIMAL(18,8) DEFAULT 0.00000000,
                     ADD COLUMN IF NOT EXISTS eth_deposit_address VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS xmr_deposit_address VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS username VARCHAR(100) DEFAULT NULL,
                     ADD COLUMN IF NOT EXISTS is_admin TINYINT(1) DEFAULT 0"
        ],
        [
            'nome' => 'Atualizar username baseado no name',
            'sql' => "UPDATE users SET username = name WHERE username IS NULL OR username = ''"
        ],
        [
            'nome' => 'Adicionar colunas crypto na tabela btc_transactions',
            'sql' => "ALTER TABLE btc_transactions 
                     ADD COLUMN IF NOT EXISTS crypto_type VARCHAR(10) DEFAULT 'BTC',
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
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                     )"
        ],
        [
            'nome' => 'Atualizar crypto_type nas transações existentes',
            'sql' => "UPDATE btc_transactions SET crypto_type = 'BTC' WHERE crypto_type IS NULL OR crypto_type = ''"
        ]
    ];

    echo "<h2>📊 Executando Correções</h2>";

    foreach ($correcoes as $correcao) {
        try {
            $resultado = $conn->query($correcao['sql']);
            if ($resultado) {
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

    // Verificar estrutura final
    echo "<h2>🔍 Verificação Final</h2>";
    
    $tabelas_verificar = ['users', 'btc_transactions', 'btc_balance_history'];
    
    foreach ($tabelas_verificar as $tabela) {
        $resultado = $conn->query("DESCRIBE $tabela");
        if ($resultado) {
            echo "<div class='success'>✓ Tabela '$tabela' existe e está acessível</div>";
            
            if ($tabela === 'users') {
                // Verificar colunas específicas
                $colunas_necessarias = ['eth_balance', 'xmr_balance', 'username', 'eth_deposit_address'];
                
                $colunas_existentes = [];
                while ($row = $resultado->fetch_assoc()) {
                    $colunas_existentes[] = $row['Field'];
                }
                
                foreach ($colunas_necessarias as $coluna) {
                    if (in_array($coluna, $colunas_existentes)) {
                        echo "<div class='success'>✓ Coluna '$coluna' encontrada</div>";
                    } else {
                        echo "<div class='error'>✗ Coluna '$coluna' não encontrada</div>";
                    }
                }
            }
        } else {
            echo "<div class='error'>✗ Erro ao verificar tabela '$tabela': {$conn->error}</div>";
        }
    }

    // Testar funções críticas
    echo "<h2>🧪 Teste de Funcionalidades</h2>";
    
    // Teste 1: Verificar se podemos consultar usuários com as novas colunas
    try {
        $stmt = $conn->prepare("SELECT id, name, eth_balance, xmr_balance, username FROM users LIMIT 1");
        if ($stmt && $stmt->execute()) {
            echo "<div class='success'>✓ Consulta de usuários com colunas multi-cripto funcionando</div>";
        } else {
            echo "<div class='error'>✗ Erro na consulta de usuários: " . $conn->error . "</div>";
        }
    } catch (Exception $e) {
        echo "<div class='error'>✗ Exceção na consulta de usuários: " . $e->getMessage() . "</div>";
    }

    // Teste 2: Verificar tabela btc_balance_history
    try {
        $stmt = $conn->prepare("SELECT COUNT(*) FROM btc_balance_history");
        if ($stmt && $stmt->execute()) {
            echo "<div class='success'>✓ Tabela btc_balance_history acessível</div>";
        } else {
            echo "<div class='error'>✗ Erro ao acessar btc_balance_history: " . $conn->error . "</div>";
        }
    } catch (Exception $e) {
        echo "<div class='error'>✗ Exceção ao acessar btc_balance_history: " . $e->getMessage() . "</div>";
    }

    // Resumo final
    echo "<h2>📋 Resumo da Correção</h2>";
    echo "<div class='info'><strong>Correções aplicadas com sucesso:</strong> " . count($sucessos) . "</div>";
    echo "<div class='info'><strong>Erros encontrados:</strong> " . count($erros) . "</div>";
    
    if (count($erros) === 0) {
        echo "<div class='success'>
                <h3>🎉 Correção Concluída com Sucesso!</h3>
                <p>O banco de dados foi corrigido e agora está pronto para o sistema ZeeMarket multi-cripto.</p>
                <p><strong>Próximos passos:</strong></p>
                <ul>
                    <li>Acesse <a href='login.php'>login.php</a> para testar o login</li>
                    <li>Registre um novo usuário em <a href='signup.php'>signup.php</a></li>
                    <li>Acesse o <a href='dashboard.php'>dashboard.php</a> após o login</li>
                </ul>
                <p><em>Você pode excluir este arquivo após a correção.</em></p>
              </div>";
    } else {
        echo "<div class='error'>
                <h3>⚠️ Correção Parcial</h3>
                <p>Alguns erros foram encontrados. Verifique os logs acima e tente executar o script SQL manual.</p>
              </div>";
    }

} catch (Exception $e) {
    echo "<div class='error'>
            <h3>❌ Erro Crítico</h3>
            <p>Erro durante a correção: " . $e->getMessage() . "</p>
            <p>Verifique as configurações de conexão em includes/config.php</p>
          </div>";
}

echo "<h2>🛠️ Informações Técnicas</h2>";
echo "<div class='code'>
<strong>Versão do MySQL:</strong> " . $conn->server_info . "<br>
<strong>Charset:</strong> " . $conn->character_set_name() . "<br>
<strong>Banco de dados:</strong> zee_market<br>
<strong>Data/Hora:</strong> " . date('Y-m-d H:i:s') . "
</div>";

echo "</div></body></html>";
?>