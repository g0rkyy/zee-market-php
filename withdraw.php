<?php
/**
 * SISTEMA DE SAQUE DE CRIPTOMOEDAS
 * Processa saques de BTC, ETH, XMR
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'includes/config.php';
require_once 'includes/functions.php';

// Headers para AJAX
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Verificar login
if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Usuário não autenticado']);
    exit();
}

// Verificar método
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Método não permitido']);
    exit();
}

// Obter dados do POST
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    $input = $_POST;
}

$crypto_type = strtoupper(trim($input['crypto_type'] ?? ''));
$to_address = trim($input['to_address'] ?? '');
$amount = floatval($input['amount'] ?? 0);
$user_id = $_SESSION['user_id'];

try {
    // Validações básicas
    if (!in_array($crypto_type, ['BTC', 'ETH', 'XMR'])) {
        throw new Exception('Criptomoeda não suportada');
    }
    
    if (empty($to_address)) {
        throw new Exception('Endereço de destino é obrigatório');
    }
    
    if ($amount <= 0) {
        throw new Exception('Valor deve ser maior que zero');
    }
    
    // Validar endereço
    if (!isValidCryptoAddress($to_address, $crypto_type)) {
        throw new Exception("Endereço $crypto_type inválido");
    }
    
    // Verificar saldo do usuário
    $balance = getUserBalance($user_id, $crypto_type);
    if ($balance < $amount) {
        throw new Exception('Saldo insuficiente');
    }
    
    // Calcular taxa
    $withdrawal_fees = [
        'BTC' => 0.0001,
        'ETH' => 0.001,
        'XMR' => 0.01
    ];
    $fee = $withdrawal_fees[$crypto_type];
    $total_deduction = $amount + $fee;
    
    if ($balance < $total_deduction) {
        throw new Exception('Saldo insuficiente para cobrir taxas');
    }
    
    // Verificar limite diário
    $daily_limits = [
        'BTC' => 1.0,
        'ETH' => 10.0,
        'XMR' => 100.0
    ];
    $daily_limit = $daily_limits[$crypto_type];
    $today_withdrawals = getTodayWithdrawals($user_id, $crypto_type);
    
    if (($today_withdrawals + $amount) > $daily_limit) {
        throw new Exception("Limite diário excedido. Limite: $daily_limit $crypto_type");
    }
    
    // Processar saque
    $conn->begin_transaction();
    
    // Deduzir saldo
    $balance_field = strtolower($crypto_type) . '_balance';
    $stmt = $conn->prepare("UPDATE users SET $balance_field = $balance_field - ? WHERE id = ?");
    $stmt->bind_param("di", $total_deduction, $user_id);
    $stmt->execute();
    
    // Registrar transação
    $table = strtolower($crypto_type) . '_transactions';
    if ($crypto_type === 'BTC') {
        $table = 'btc_transactions';
    }
    
    // Para BTC usar tabela existente
    if ($crypto_type === 'BTC') {
        $stmt = $conn->prepare("
            INSERT INTO btc_transactions 
            (user_id, type, amount, fee, to_address, status, crypto_type, created_at) 
            VALUES (?, 'withdrawal', ?, ?, ?, 'pending', ?, NOW())
        ");
        $stmt->bind_param("iddss", $user_id, $amount, $fee, $to_address, $crypto_type);
    } else {
        // Para ETH e XMR usar suas tabelas específicas
        $stmt = $conn->prepare("
            INSERT INTO {$table} 
            (user_id, type, amount, fee, address, status, created_at) 
            VALUES (?, 'withdrawal', ?, ?, ?, 'pending', NOW())
        ");
        $stmt->bind_param("idds", $user_id, $amount, $fee, $to_address);
    }
    
    $stmt->execute();
    $withdrawal_id = $conn->insert_id;
    
    // Registrar no histórico de saldo
    $stmt = $conn->prepare("
        INSERT INTO btc_balance_history 
        (user_id, type, amount, description, crypto_type, created_at) 
        VALUES (?, 'debit', ?, ?, ?, NOW())
    ");
    $description = "Saque $crypto_type solicitado";
    $stmt->bind_param("idss", $user_id, $total_deduction, $description, $crypto_type);
    $stmt->execute();
    
    $conn->commit();
    
    // Simular processamento do saque (em produção, integrar com APIs blockchain)
    processWithdrawalSimulation($withdrawal_id, $crypto_type);
    
    // Log da operação
    error_log("Saque processado: $amount $crypto_type para usuário $user_id");
    
    echo json_encode([
        'success' => true,
        'withdrawal_id' => $withdrawal_id,
        'amount' => $amount,
        'fee' => $fee,
        'crypto' => $crypto_type,
        'message' => "Saque de $amount $crypto_type processado com sucesso!"
    ]);
    
} catch (Exception $e) {
    if ($conn->inTransaction) {
        $conn->rollback();
    }
    
    error_log("Erro no saque: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

/**
 * Obter saldo do usuário
 */
function getUserBalance($user_id, $crypto) {
    global $conn;
    
    $balance_field = strtolower($crypto) . '_balance';
    $stmt = $conn->prepare("SELECT $balance_field FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    return floatval($result[$balance_field] ?? 0);
}

/**
 * Obter saques do dia
 */
function getTodayWithdrawals($user_id, $crypto) {
    global $conn;
    
    if ($crypto === 'BTC') {
        $stmt = $conn->prepare("
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM btc_transactions 
            WHERE user_id = ? AND crypto_type = ? AND type = 'withdrawal' 
            AND DATE(created_at) = CURDATE() AND status != 'rejected'
        ");
        $stmt->bind_param("is", $user_id, $crypto);
    } else {
        $table = strtolower($crypto) . '_transactions';
        $stmt = $conn->prepare("
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM {$table} 
            WHERE user_id = ? AND type = 'withdrawal' 
            AND DATE(created_at) = CURDATE() AND status != 'failed'
        ");
        $stmt->bind_param("i", $user_id);
    }
    
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    return floatval($result['total']);
}

/**
 * Simular processamento do saque
 */
function processWithdrawalSimulation($withdrawal_id, $crypto) {
    global $conn;
    
    // Simular hash de transação
    $fake_hash = hash('sha256', 'withdrawal_' . $withdrawal_id . '_' . time());
    
    if ($crypto === 'BTC') {
        $stmt = $conn->prepare("
            UPDATE btc_transactions 
            SET status = 'confirmed', tx_hash = ?, updated_at = NOW() 
            WHERE id = ?
        ");
        $stmt->bind_param("si", $fake_hash, $withdrawal_id);
    } else {
        $table = strtolower($crypto) . '_transactions';
        $stmt = $conn->prepare("
            UPDATE {$table} 
            SET status = 'completed', tx_hash = ?, updated_at = NOW() 
            WHERE id = ?
        ");
        $stmt->bind_param("si", $fake_hash, $withdrawal_id);
    }
    
    $stmt->execute();
    
    error_log("Saque simulado processado: ID $withdrawal_id, Hash: $fake_hash");
}
?>