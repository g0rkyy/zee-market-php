<?php
/**
 * Bitcoin Webhook Handler - Sistema Completo de Carteira
 * Processa transações Bitcoin em tempo real
 */

ini_set('display_errors', 0);
error_reporting(0);

require_once '../includes/config.php';
require_once '../includes/btc_functions.php';

// Headers de segurança
header('Content-Type: application/json');
header('X-Robots-Tag: noindex, nofollow');

// Log de debug (remover em produção)
function logWebhook($message, $data = null) {
    $logFile = '../logs/webhook_' . date('Y-m-d') . '.log';
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] $message";
    if ($data) {
        $logMessage .= " | Data: " . json_encode($data);
    }
    file_put_contents($logFile, $logMessage . "\n", FILE_APPEND);
}

// Verificação de método HTTP
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    logWebhook("Método HTTP inválido: " . $_SERVER['REQUEST_METHOD']);
    exit(json_encode(['error' => 'Method not allowed']));
}

// Verificação de segurança - Secret Key
$secret = 'ZeeMarket_BTC_2024_Secret_Key'; // Altere este secret
$providedSecret = $_GET['secret'] ?? $_POST['secret'] ?? '';

if ($providedSecret !== $secret) {
    http_response_code(401);
    logWebhook("Acesso não autorizado - Secret inválido", ['provided' => $providedSecret]);
    exit(json_encode(['error' => 'Unauthorized']));
}

// Verificação de IP (opcional - adicione IPs permitidos)
$allowedIPs = [
    '127.0.0.1',
    '::1',
    // Adicione IPs dos provedores de webhook aqui
];

/*
$clientIP = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
if (!in_array($clientIP, $allowedIPs)) {
    http_response_code(403);
    logWebhook("IP não autorizado", ['ip' => $clientIP]);
    exit(json_encode(['error' => 'Forbidden']));
}
*/

try {
    // Capturar dados do webhook
    $rawInput = file_get_contents('php://input');
    $input = json_decode($rawInput, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('JSON inválido: ' . json_last_error_msg());
    }

    logWebhook("Webhook recebido", $input);

    // Processar diferentes tipos de webhook
    $webhookType = $input['type'] ?? 'transaction';
    
    switch ($webhookType) {
        case 'transaction':
        case 'address-transaction':
            processTransactionWebhook($input);
            break;
            
        case 'block':
            processBlockWebhook($input);
            break;
            
        case 'confirmation':
            processConfirmationWebhook($input);
            break;
            
        default:
            logWebhook("Tipo de webhook desconhecido", ['type' => $webhookType]);
            break;
    }

    http_response_code(200);
    echo json_encode(['status' => 'success', 'processed' => true]);

} catch (Exception $e) {
    logWebhook("Erro no webhook: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}

/**
 * Processa webhook de transação
 */
function processTransactionWebhook($data) {
    global $conn;
    
    // Extrair dados da transação
    $txHash = $data['tx_hash'] ?? $data['hash'] ?? $data['txid'] ?? null;
    $addresses = $data['outputs'] ?? $data['addresses'] ?? [];
    $confirmations = intval($data['confirmations'] ?? 0);
    $blockHeight = intval($data['block_height'] ?? 0);
    $timestamp = $data['timestamp'] ?? time();
    
    if (!$txHash) {
        throw new Exception('Hash da transação não encontrado');
    }

    logWebhook("Processando transação", [
        'tx_hash' => $txHash,
        'confirmations' => $confirmations,
        'block_height' => $blockHeight
    ]);

    // Verificar se é transação de entrada (depósito)
    if (isset($data['outputs'])) {
        foreach ($data['outputs'] as $output) {
            $address = $output['address'] ?? $output['addr'] ?? null;
            $amount = floatval($output['value'] ?? $output['amount'] ?? 0);
            
            if ($address && $amount > 0) {
                processDeposit($txHash, $address, $amount, $confirmations, $blockHeight, $timestamp);
            }
        }
    }
    
    // Verificar se é transação de saída (saque)
    if (isset($data['inputs'])) {
        foreach ($data['inputs'] as $input) {
            $address = $input['address'] ?? $input['addr'] ?? null;
            $amount = floatval($input['value'] ?? $input['amount'] ?? 0);
            
            if ($address && $amount > 0) {
                processWithdrawal($txHash, $address, $amount, $confirmations, $blockHeight, $timestamp);
            }
        }
    }
}

/**
 * Processa depósito Bitcoin
 */
function processDeposit($txHash, $address, $amount, $confirmations, $blockHeight, $timestamp) {
    global $conn;
    
    // Converter satoshis para BTC se necessário
    if ($amount > 1000000) {
        $amount = $amount / 100000000; // Satoshis para BTC
    }
    
    logWebhook("Processando depósito", [
        'address' => $address,
        'amount' => $amount,
        'confirmations' => $confirmations
    ]);
    
    // Verificar se o endereço pertence a algum usuário
    $stmt = $conn->prepare("SELECT id, username FROM users WHERE btc_deposit_address = ?");
    $stmt->bind_param("s", $address);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    
    if (!$user) {
        logWebhook("Endereço não encontrado", ['address' => $address]);
        return;
    }
    
    // Verificar se a transação já foi processada
    $stmt = $conn->prepare("SELECT id, status, confirmations FROM btc_transactions WHERE tx_hash = ? AND user_id = ?");
    $stmt->bind_param("si", $txHash, $user['id']);
    $stmt->execute();
    $result = $stmt->get_result();
    $existingTx = $result->fetch_assoc();
    
    if ($existingTx) {
        // Atualizar confirmações se aumentaram
        if ($confirmations > $existingTx['confirmations']) {
            updateTransactionConfirmations($existingTx['id'], $confirmations, $blockHeight);
            
            // Se atingiu confirmações necessárias e ainda não foi creditado
            if ($confirmations >= 3 && $existingTx['status'] === 'pending') {
                confirmDeposit($user['id'], $existingTx['id'], $amount, $txHash);
            }
        }
        return;
    }
    
    // Validar valor mínimo
    $minDeposit = 0.0001; // 0.0001 BTC
    if ($amount < $minDeposit) {
        logWebhook("Depósito abaixo do mínimo", ['amount' => $amount, 'min' => $minDeposit]);
        return;
    }
    
    // Inserir nova transação
    $status = $confirmations >= 3 ? 'confirmed' : 'pending';
    $type = 'deposit';
    
    $stmt = $conn->prepare("
        INSERT INTO btc_transactions 
        (user_id, tx_hash, type, amount, status, confirmations, block_height, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(?))
    ");
    $stmt->bind_param("issdsiis", $user['id'], $txHash, $type, $amount, $status, $confirmations, $blockHeight, $timestamp);
    $stmt->execute();
    $transactionId = $conn->insert_id;
    
    logWebhook("Transação inserida", [
        'transaction_id' => $transactionId,
        'user_id' => $user['id'],
        'status' => $status
    ]);
    
    // Se já tem confirmações suficientes, creditar imediatamente
    if ($confirmations >= 3) {
        confirmDeposit($user['id'], $transactionId, $amount, $txHash);
    }
    
    // Notificar usuário por email
    sendDepositNotification($user, $amount, $confirmations, $txHash);
}

/**
 * Confirma depósito e credita saldo
 */
function confirmDeposit($userId, $transactionId, $amount, $txHash) {
    global $conn;
    
    $conn->begin_transaction();
    
    try {
        // Atualizar status da transação
        $stmt = $conn->prepare("UPDATE btc_transactions SET status = 'confirmed' WHERE id = ?");
        $stmt->bind_param("i", $transactionId);
        $stmt->execute();
        
        // Creditar saldo do usuário
        $stmt = $conn->prepare("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?");
        $stmt->bind_param("di", $amount, $userId);
        $stmt->execute();
        
        // Registrar movimento no histórico de saldo
        $stmt = $conn->prepare("
            INSERT INTO btc_balance_history 
            (user_id, type, amount, description, tx_hash, created_at) 
            VALUES (?, 'credit', ?, 'Depósito Bitcoin confirmado', ?, NOW())
        ");
        $stmt->bind_param("ids", $userId, $amount, $txHash);
        $stmt->execute();
        
        $conn->commit();
        
        logWebhook("Depósito confirmado e creditado", [
            'user_id' => $userId,
            'amount' => $amount,
            'tx_hash' => $txHash
        ]);
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
}

/**
 * Processa saque Bitcoin
 */
function processWithdrawal($txHash, $address, $amount, $confirmations, $blockHeight, $timestamp) {
    global $conn;
    
    // Converter satoshis para BTC se necessário
    if ($amount > 1000000) {
        $amount = $amount / 100000000;
    }
    
    // Verificar se é um saque pendente
    $stmt = $conn->prepare("
        SELECT bt.*, u.username 
        FROM btc_transactions bt 
        JOIN users u ON bt.user_id = u.id 
        WHERE bt.tx_hash = ? AND bt.type = 'withdrawal' AND bt.status = 'pending'
    ");
    $stmt->bind_param("s", $txHash);
    $stmt->execute();
    $result = $stmt->get_result();
    $withdrawal = $result->fetch_assoc();
    
    if ($withdrawal && $confirmations >= 1) {
        // Atualizar status do saque
        $stmt = $conn->prepare("
            UPDATE btc_transactions 
            SET status = 'confirmed', confirmations = ?, block_height = ? 
            WHERE id = ?
        ");
        $stmt->bind_param("iii", $confirmations, $blockHeight, $withdrawal['id']);
        $stmt->execute();
        
        logWebhook("Saque confirmado", [
            'withdrawal_id' => $withdrawal['id'],
            'user' => $withdrawal['username'],
            'amount' => $amount
        ]);
        
        // Notificar usuário
        sendWithdrawalNotification($withdrawal, $confirmations, $txHash);
    }
}

/**
 * Processa webhook de novo bloco
 */
function processBlockWebhook($data) {
    $blockHeight = intval($data['height'] ?? $data['block_height'] ?? 0);
    $blockHash = $data['hash'] ?? $data['block_hash'] ?? null;
    
    logWebhook("Novo bloco recebido", [
        'height' => $blockHeight,
        'hash' => $blockHash
    ]);
    
    // Atualizar confirmações de transações pendentes
    updatePendingTransactionsConfirmations($blockHeight);
}

/**
 * Processa webhook de confirmação
 */
function processConfirmationWebhook($data) {
    $txHash = $data['tx_hash'] ?? $data['hash'] ?? null;
    $confirmations = intval($data['confirmations'] ?? 0);
    
    if ($txHash) {
        logWebhook("Atualização de confirmações", [
            'tx_hash' => $txHash,
            'confirmations' => $confirmations
        ]);
        
        updateTransactionConfirmationsByHash($txHash, $confirmations);
    }
}

/**
 * Atualiza confirmações de uma transação
 */
function updateTransactionConfirmations($transactionId, $confirmations, $blockHeight) {
    global $conn;
    
    $stmt = $conn->prepare("UPDATE btc_transactions SET confirmations = ?, block_height = ? WHERE id = ?");
    $stmt->bind_param("iii", $confirmations, $blockHeight, $transactionId);
    $stmt->execute();
}

/**
 * Atualiza confirmações por hash da transação
 */
function updateTransactionConfirmationsByHash($txHash, $confirmations) {
    global $conn;
    
    $stmt = $conn->prepare("UPDATE btc_transactions SET confirmations = ? WHERE tx_hash = ?");
    $stmt->bind_param("is", $confirmations, $txHash);
    $stmt->execute();
}

/**
 * Atualiza confirmações de todas as transações pendentes
 */
function updatePendingTransactionsConfirmations($currentBlockHeight) {
    global $conn;
    
    // Buscar transações pendentes com block_height conhecido
    $stmt = $conn->prepare("
        SELECT id, block_height, tx_hash, user_id, amount 
        FROM btc_transactions 
        WHERE status = 'pending' AND block_height > 0 AND type = 'deposit'
    ");
    $stmt->execute();
    $result = $stmt->get_result();
    
    while ($tx = $result->fetch_assoc()) {
        $confirmations = max(0, $currentBlockHeight - $tx['block_height'] + 1);
        
        // Atualizar confirmações
        updateTransactionConfirmations($tx['id'], $confirmations, $tx['block_height']);
        
        // Se atingiu confirmações necessárias, confirmar depósito
        if ($confirmations >= 3) {
            confirmDeposit($tx['user_id'], $tx['id'], $tx['amount'], $tx['tx_hash']);
        }
    }
}

/**
 * Envia notificação de depósito por email
 */
function sendDepositNotification($user, $amount, $confirmations, $txHash) {
    $subject = "Zee Market - Depósito Bitcoin " . ($confirmations >= 3 ? "Confirmado" : "Recebido");
    $message = "
    Olá {$user['username']},
    
    " . ($confirmations >= 3 ? 
        "Seu depósito de {$amount} BTC foi confirmado e creditado em sua conta!" :
        "Recebemos seu depósito de {$amount} BTC. Aguardando confirmações na blockchain ({$confirmations}/3)."
    ) . "
    
    Hash da transação: {$txHash}
    Confirmações: {$confirmations}/3
    
    Acesse sua conta para verificar o saldo atualizado.
    
    Zee Market Team
    ";
    
    // Implementar envio de email aqui
    logWebhook("Notificação de depósito", ['user' => $user['username'], 'amount' => $amount]);
}

/**
 * Envia notificação de saque por email
 */
function sendWithdrawalNotification($withdrawal, $confirmations, $txHash) {
    $subject = "Zee Market - Saque Bitcoin Confirmado";
    $message = "
    Olá {$withdrawal['username']},
    
    Seu saque de {$withdrawal['amount']} BTC foi confirmado na blockchain!
    
    Hash da transação: {$txHash}
    Confirmações: {$confirmations}
    
    Zee Market Team
    ";
    
    // Implementar envio de email aqui
    logWebhook("Notificação de saque", ['user' => $withdrawal['username'], 'amount' => $withdrawal['amount']]);
}

/**
 * Limpa logs antigos (executar via cron)
 */
function cleanOldLogs() {
    $logDir = '../logs/';
    $files = glob($logDir . 'webhook_*.log');
    $keepDays = 30;
    
    foreach ($files as $file) {
        if (filemtime($file) < time() - ($keepDays * 24 * 60 * 60)) {
            unlink($file);
        }
    }
}

// Executar limpeza de logs ocasionalmente
if (rand(1, 100) === 1) {
    cleanOldLogs();
}

?>