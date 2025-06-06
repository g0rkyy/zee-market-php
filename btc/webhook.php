<?php
/**
 * WEBHOOK REAL PARA PROCESSAR PAGAMENTOS
 * Local: btc/webhook.php ou webhook.php
 */
// Adicione no início do arquivo
$webhookSecret = hash('sha256', 'ZeeMarket_' . $_SERVER['HTTP_HOST'] . '_2024');

// Verificar assinatura
$signature = $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';
if (!hash_equals($webhookSecret, $signature)) {
    http_response_code(403);
    die('Invalid signature');
}

error_reporting(0);
ini_set('display_errors', 0);

require_once 'includes/config.php';
require_once '../includes/blockchain_real.php';

// Headers de segurança
header('Content-Type: application/json');
header('X-Robots-Tag: noindex, nofollow');

// Função de log para debug
function logWebhook($message, $data = null) {
    $logFile = 'logs/webhook_real_' . date('Y-m-d') . '.log';
    if (!file_exists('logs')) {
        mkdir('logs', 0755, true);
    }
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] $message";
    if ($data) {
        $logMessage .= " | Data: " . json_encode($data);
    }
    file_put_contents($logFile, $logMessage . "\n", FILE_APPEND | LOCK_EX);
}

// SE É ACESSO PELO NAVEGADOR (GET), MOSTRA STATUS
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Verificar secret no GET também
    $secret = $_GET['secret'] ?? '';
    $expectedSecret = 'ZeeMarket_Webhook_2024_' . md5($_SERVER['HTTP_HOST'] ?? 'localhost');
    
    if (empty($secret)) {
        // Sem secret - mostrar página de status
        echo "<!DOCTYPE html>
        <html>
        <head>
            <title>Webhook Status - ZeeMarket</title>
            <style>
                body { font-family: Arial; background: #1a1a1a; color: #fff; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                .status-box { background: #2d2d2d; padding: 20px; border-radius: 10px; margin: 15px 0; }
                .success { border-left: 5px solid #28a745; }
                .warning { border-left: 5px solid #ffc107; }
                .error { border-left: 5px solid #dc3545; }
                .info { border-left: 5px solid #17a2b8; }
                .code { background: #333; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class='container'>
                <h1>🔗 Webhook Status - ZeeMarket</h1>
                
                <div class='status-box success'>
                    <h3>✅ Webhook Ativo e Funcionando</h3>
                    <p>O webhook está configurado corretamente e pronto para receber notificações blockchain.</p>
                </div>
                
                <div class='status-box info'>
                    <h3>📊 Configurações Atuais:</h3>
                    <div class='code'>
                        URL: " . (isset($_SERVER['HTTPS']) ? 'https' : 'http') . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}<br>
                        Método: POST (para receber dados)<br>
                        Secret: {$expectedSecret}<br>
                        Status: 🟢 ONLINE
                    </div>
                </div>
                
                <div class='status-box warning'>
                    <h3>⚠️ Como Funciona:</h3>
                    <ol>
                        <li><strong>BlockCypher/Etherscan</strong> detecta transação</li>
                        <li>Envia POST para este webhook</li>
                        <li>Webhook processa automaticamente</li>
                        <li>Credita saldo ou confirma compra</li>
                    </ol>
                </div>
                
                <div class='status-box info'>
                    <h3>🧪 Teste o Webhook:</h3>
                    <p>Para testar, envie uma requisição POST com o secret correto:</p>
                    <div class='code'>
                        curl -X POST '" . (isset($_SERVER['HTTPS']) ? 'https' : 'http') . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}?secret={$expectedSecret}' \\<br>
                        -H 'Content-Type: application/json' \\<br>
                        -d '{\"test\": true}'
                    </div>
                </div>
                
                <div class='status-box error'>
                    <h3>🔒 Segurança:</h3>
                    <p>Este webhook só aceita requisições autenticadas. Acesso direto pelo navegador é bloqueado por segurança.</p>
                </div>
                
                <div class='status-box success'>
                    <h3>📈 Logs Recentes:</h3>";
        
        // Mostrar logs recentes se existirem
        $logFile = 'logs/webhook_real_' . date('Y-m-d') . '.log';
        if (file_exists($logFile)) {
            $logs = array_slice(file($logFile), -10); // Últimas 10 linhas
            echo "<div class='code'>";
            foreach ($logs as $log) {
                echo htmlspecialchars(trim($log)) . "<br>";
            }
            echo "</div>";
        } else {
            echo "<p>Nenhum log encontrado hoje.</p>";
        }
        
        echo "      </div>
            </div>
        </body>
        </html>";
        exit();
    }
    
    if ($secret !== $expectedSecret) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid secret for GET request']);
        exit();
    }
    
    // Secret correto - mostrar status JSON
    echo json_encode([
        'status' => 'active',
        'webhook_url' => (isset($_SERVER['HTTPS']) ? 'https' : 'http') . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}",
        'method' => 'POST',
        'secret_required' => true,
        'last_check' => date('Y-m-d H:i:s')
    ]);
    exit();
}

// DAQUI PRA BAIXO - PROCESSAMENTO DE WEBHOOKS (POST)

// Verificação de segurança para POST
$secret = $_GET['secret'] ?? $_POST['secret'] ?? '';
$expectedSecret = 'ZeeMarket_Webhook_2024_' . md5($_SERVER['HTTP_HOST'] ?? 'localhost');

if ($secret !== $expectedSecret) {
    http_response_code(401);
    logWebhook("ACESSO NEGADO - Secret inválido", ['provided' => $secret]);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

try {
    // Capturar dados do webhook
    $rawInput = file_get_contents('php://input');
    $webhookData = json_decode($rawInput, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('JSON inválido: ' . json_last_error_msg());
    }

    logWebhook("Webhook REAL recebido", $webhookData);

    // Se é teste
    if (isset($webhookData['test']) && $webhookData['test'] === true) {
        logWebhook("Teste de webhook executado com sucesso");
        echo json_encode([
            'status' => 'success', 
            'message' => 'Webhook test successful',
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        exit();
    }

    // Processar diferentes tipos de webhook
    $source = detectWebhookSource($webhookData);
    
    switch ($source) {
        case 'blockcypher':
            processBlockCypherWebhook($webhookData);
            break;
            
        case 'etherscan':
            processEtherscanWebhook($webhookData);
            break;
            
        case 'manual':
            processManualWebhook($webhookData);
            break;
            
        default:
            logWebhook("Fonte de webhook desconhecida", $webhookData);
            break;
    }

    http_response_code(200);
    echo json_encode(['status' => 'success', 'processed' => true]);

} catch (Exception $e) {
    logWebhook("ERRO no webhook: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}

/**
 * FUNÇÕES DE PROCESSAMENTO
 */

function detectWebhookSource($data) {
    if (isset($data['hash']) && isset($data['addresses'])) {
        return 'blockcypher';
    }
    if (isset($data['result']) && isset($data['id'])) {
        return 'etherscan';
    }
    if (isset($_POST['manual_tx'])) {
        return 'manual';
    }
    return 'unknown';
}

function processBlockCypherWebhook($data) {
    global $conn;
    
    logWebhook("Processando webhook BlockCypher");
    
    $txHash = $data['hash'];
    $confirmations = intval($data['confirmations'] ?? 0);
    $blockHeight = intval($data['block_height'] ?? 0);
    
    // Processar cada endereço envolvido
    foreach ($data['addresses'] as $address) {
        // Verificar se o endereço pertence a um usuário
        $stmt = $conn->prepare("SELECT id, username FROM users WHERE btc_deposit_address = ?");
        $stmt->bind_param("s", $address);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        
        if ($user) {
            processDepositReal($user, $txHash, $address, $data);
        }
        
        // Verificar se é pagamento de compra
        $stmt = $conn->prepare("SELECT * FROM compras WHERE wallet_plataforma = ? AND pago = 0");
        $stmt->bind_param("s", $address);
        $stmt->execute();
        $purchases = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        foreach ($purchases as $purchase) {
            processPurchasePayment($purchase, $txHash, $data);
        }
    }
}

function processEtherscanWebhook($data) {
    logWebhook("Processando webhook Etherscan", $data);
    // Implementar processamento Ethereum
}

function processManualWebhook($data) {
    logWebhook("Processando webhook manual", $data);
    // Implementar processamento manual
}

function processDepositReal($user, $txHash, $address, $txData) {
    global $conn;
    
    // Verificar se já foi processado
    $stmt = $conn->prepare("SELECT id FROM btc_transactions WHERE tx_hash = ? AND user_id = ?");
    $stmt->bind_param("si", $txHash, $user['id']);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows > 0) {
        logWebhook("Transação já processada", ['tx_hash' => $txHash]);
        return;
    }
    
    // Calcular valor recebido no endereço
    $amount = 0;
    if (isset($txData['outputs'])) {
        foreach ($txData['outputs'] as $output) {
            if (in_array($address, $output['addresses'] ?? [])) {
                $amount += $output['value'];
            }
        }
    }
    
    $amountBTC = $amount / 100000000; // Satoshis para BTC
    
    // Validar valor mínimo
    if ($amountBTC < 0.0001) {
        logWebhook("Depósito abaixo do mínimo", ['amount' => $amountBTC]);
        return;
    }
    
    $confirmations = intval($txData['confirmations'] ?? 0);
    $status = $confirmations >= 1 ? 'confirmed' : 'pending';
    
    $conn->begin_transaction();
    
    try {
        // Inserir transação
        $stmt = $conn->prepare("
            INSERT INTO btc_transactions 
            (user_id, tx_hash, type, amount, confirmations, status, crypto_type, block_height, created_at) 
            VALUES (?, ?, 'deposit', ?, ?, ?, 'BTC', ?, NOW())
        ");
        $stmt->bind_param("isidsi", 
            $user['id'], 
            $txHash, 
            $amountBTC, 
            $confirmations, 
            $status,
            $txData['block_height'] ?? 0
        );
        $stmt->execute();
        
        // Se confirmado, creditar saldo
        if ($status === 'confirmed') {
            creditUserBalance($user['id'], $amountBTC, $txHash, 'BTC');
        }
        
        $conn->commit();
        
        logWebhook("Depósito REAL processado", [
            'user_id' => $user['id'],
            'amount' => $amountBTC,
            'status' => $status,
            'tx_hash' => $txHash
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
}

function processPurchasePayment($purchase, $txHash, $txData) {
    global $conn;
    
    // Calcular valor recebido
    $amount = 0;
    $platformWallet = $purchase['wallet_plataforma'];
    
    if (isset($txData['outputs'])) {
        foreach ($txData['outputs'] as $output) {
            if (in_array($platformWallet, $output['addresses'] ?? [])) {
                $amount += $output['value'];
            }
        }
    }
    
    $amountBTC = $amount / 100000000;
    $expectedAmount = floatval($purchase['valor_btc']);
    
    // Verificar se o valor está correto (com tolerância de 1%)
    $tolerance = $expectedAmount * 0.01;
    if (abs($amountBTC - $expectedAmount) <= $tolerance && $amountBTC >= $expectedAmount * 0.99) {
        
        $confirmations = intval($txData['confirmations'] ?? 0);
        
        $conn->begin_transaction();
        
        try {
            // Marcar compra como paga
            $stmt = $conn->prepare("
                UPDATE compras SET 
                    pago = 1, 
                    tx_hash = ?, 
                    confirmations = ?,
                    valor_recebido = ?
                WHERE id = ?
            ");
            $stmt->bind_param("sidi", $txHash, $confirmations, $amountBTC, $purchase['id']);
            $stmt->execute();
            
            $conn->commit();
            
            logWebhook("Pagamento de compra REAL processado", [
                'purchase_id' => $purchase['id'],
                'amount_received' => $amountBTC,
                'expected' => $expectedAmount,
                'tx_hash' => $txHash
            ]);
            
        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }
    }
}

function creditUserBalance($userId, $amount, $txHash, $crypto) {
    global $conn;
    
    $balanceField = strtolower($crypto) . '_balance';
    
    // Obter saldo atual
    $stmt = $conn->prepare("SELECT $balanceField FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $currentBalance = $stmt->get_result()->fetch_assoc()[$balanceField] ?? 0;
    
    $oldBalance = floatval($currentBalance);
    $newBalance = $oldBalance + $amount;
    
    // Atualizar saldo
    $stmt = $conn->prepare("UPDATE users SET $balanceField = ? WHERE id = ?");
    $stmt->bind_param("di", $newBalance, $userId);
    $stmt->execute();
    
    // Registrar no histórico
    $stmt = $conn->prepare("
        INSERT INTO btc_balance_history 
        (user_id, type, amount, balance_before, balance_after, description, tx_hash, crypto_type, created_at) 
        VALUES (?, 'credit', ?, ?, ?, 'Depósito confirmado', ?, ?, NOW())
    ");
    $stmt->bind_param("idddss", $userId, $amount, $oldBalance, $newBalance, $txHash, $crypto);
    $stmt->execute();
}
?>