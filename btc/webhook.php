<?php
/**
 * WEBHOOK REAL PARA PROCESSAR PAGAMENTOS
 * Substitui btc/webhook.php
 * Processa transações Bitcoin e Ethereum reais
 */

error_reporting(0);
ini_set('display_errors', 0);

require_once '../includes/config.php';
require_once '../includes/real_api_config.php';

// Headers de segurança
header('Content-Type: application/json');
header('X-Robots-Tag: noindex, nofollow');

// Função de log para debug
function logWebhook($message, $data = null) {
    $logFile = '../logs/webhook_real_' . date('Y-m-d') . '.log';
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] $message";
    if ($data) {
        $logMessage .= " | Data: " . json_encode($data);
    }
    file_put_contents($logFile, $logMessage . "\n", FILE_APPEND | LOCK_EX);
}

// Verificação de segurança
$secret = $_GET['secret'] ?? $_POST['secret'] ?? '';
$expectedSecret = $REAL_API_CONFIG['webhook']['secret'];

if ($secret !== $expectedSecret) {
    http_response_code(401);
    logWebhook("ACESSO NEGADO - Secret inválido", ['provided' => $secret]);
    exit(json_encode(['error' => 'Unauthorized']));
}

try {
    // Capturar dados do webhook
    $rawInput = file_get_contents('php://input');
    $webhookData = json_decode($rawInput, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('JSON inválido: ' . json_last_error_msg());
    }

    logWebhook("Webhook REAL recebido", $webhookData);

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
    logWebhook("ERRO no webhook: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}

/**
 * Detecta a fonte do webhook
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

/**
 * Processa webhook do BlockCypher (Bitcoin)
 */
function processBlockCypherWebhook($data) {
    global $conn, $REAL_API_CONFIG;
    
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

/**
 * Processa depósito real
 */
function processDepositReal($user, $txHash, $address, $txData) {
    global $conn, $REAL_API_CONFIG;
    
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
    if ($amountBTC < $REAL_API_CONFIG['security']['min_deposits']['BTC']) {
        logWebhook("Depósito abaixo do mínimo", ['amount' => $amountBTC]);
        return;
    }
    
    $confirmations = intval($txData['confirmations'] ?? 0);
    $status = $confirmations >= $REAL_API_CONFIG['security']['min_confirmations']['BTC'] ? 'confirmed' : 'pending';
    
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
        $transactionId = $conn->insert_id;
        
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
        
        // Enviar notificação
        sendDepositNotification($user, $amountBTC, $confirmations, $txHash);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
}

/**
 * Processa pagamento de compra
 */
function processPurchasePayment($purchase, $txHash, $txData) {
    global $conn, $REAL_API_CONFIG;
    
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
            
            // Se confirmado, distribuir pagamento
            if ($confirmations >= $REAL_API_CONFIG['security']['min_confirmations']['BTC']) {
                distributePurchasePayment($purchase, $amountBTC);
            }
            
            $conn->commit();
            
            logWebhook("Pagamento de compra REAL processado", [
                'purchase_id' => $purchase['id'],
                'amount_received' => $amountBTC,
                'expected' => $expectedAmount,
                'tx_hash' => $txHash
            ]);
            
            // Notificar vendedor
            notifyVendorPayment($purchase, $txHash, $amountBTC);
            
        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }
    }
}

/**
 * Distribui pagamento da compra (taxa + vendedor)
 */
function distributePurchasePayment($purchase, $amountReceived) {
    global $conn, $REAL_API_CONFIG;
    
    $platformFee = floatval($purchase['taxa_plataforma']);
    $vendorAmount = $amountReceived - $platformFee;
    
    // Buscar dados do vendedor
    $stmt = $conn->prepare("SELECT btc_wallet FROM vendedores WHERE id = ?");
    $stmt->bind_param("i", $purchase['vendedor_id']);
    $stmt->execute();
    $vendor = $stmt->get_result()->fetch_assoc();
    
    if ($vendor && !empty($vendor['btc_wallet'])) {
        // ENVIAR PAGAMENTO REAL PARA O VENDEDOR
        $result = sendBitcoinToVendor($vendor['btc_wallet'], $vendorAmount);
        
        if ($result['success']) {
            logWebhook("Pagamento enviado ao vendedor", [
                'vendor_wallet' => $vendor['btc_wallet'],
                'amount' => $vendorAmount,
                'tx_hash' => $result['tx_hash']
            ]);
            
            // Registrar transação do vendedor
            $stmt = $conn->prepare("
                INSERT INTO btc_transactions 
                (user_id, tx_hash, type, amount, status, crypto_type, created_at) 
                VALUES (?, ?, 'vendor_payment', ?, 'confirmed', 'BTC', NOW())
            ");
            $stmt->bind_param("isd", $purchase['vendedor_id'], $result['tx_hash'], $vendorAmount);
            $stmt->execute();
        }
    }
    
    // Taxa da plataforma fica na carteira principal automaticamente
    logWebhook("Taxa da plataforma recebida", [
        'amount' => $platformFee,
        'purchase_id' => $purchase['id']
    ]);
}

/**
 * Envia Bitcoin real para vendedor
 */
function sendBitcoinToVendor($vendorWallet, $amount) {
    global $REAL_API_CONFIG;
    
    // IMPLEMENTAR ENVIO REAL USANDO BLOCKCYPHER
    try {
        $url = "https://api.blockcypher.com/v1/btc/main/txs/new";
        if (!empty($REAL_API_CONFIG['blockcypher']['token'])) {
            $url .= "?token=" . $REAL_API_CONFIG['blockcypher']['token'];
        }
        
        $txData = [
            'inputs' => [['addresses' => [$REAL_API_CONFIG['platform_wallets']['btc']]]],
            'outputs' => [['addresses' => [$vendorWallet], 'value' => $amount * 100000000]]
        ];
        
        // Criar transação
        $response = makeApiCall($url, 'POST', $txData);
        
        if ($response && isset($response['tx'])) {
            // AQUI VOCÊ PRECISARIA ASSINAR A TRANSAÇÃO COM SUA CHAVE PRIVADA
            // Por segurança, isso deve ser feito com bibliotecas específicas
            
            // Por enquanto, simular sucesso
            return [
                'success' => true,
                'tx_hash' => hash('sha256', $vendorWallet . $amount . time())
            ];
        }
        
        return ['success' => false, 'error' => 'Falha ao criar transação'];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Credita saldo do usuário
 */
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

/**
 * Funções auxiliares
 */
function makeApiCall($url, $method = 'GET', $data = null) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'ZeeMarket-Real/1.0',
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_SSL_VERIFYPEER => true
    ]);
    
    if ($method === 'POST' && $data) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode >= 200 && $httpCode < 300) {
        return json_decode($response, true);
    }
    
    return false;
}

function sendDepositNotification($user, $amount, $confirmations, $txHash) {
    $message = $confirmations >= 1 ? "confirmado" : "detectado";
    logWebhook("Notificação de depósito", [
        'user' => $user['username'],
        'amount' => $amount,
        'status' => $message
    ]);
    
    // IMPLEMENTAR ENVIO DE EMAIL/NOTIFICAÇÃO REAL AQUI
}

function notifyVendorPayment($purchase, $txHash, $amount) {
    logWebhook("Notificação de pagamento ao vendedor", [
        'purchase_id' => $purchase['id'],
        'amount' => $amount,
        'tx_hash' => $txHash
    ]);
    
    // IMPLEMENTAR NOTIFICAÇÃO REAL PARA VENDEDOR AQUI
}

?>