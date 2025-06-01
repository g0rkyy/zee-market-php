<?php
require_once '../includes/config.php';
require_once '../includes/btc_functions.php';

// Verificação básica de segurança
$secret = 'SEU_SECRET_AQUI';
if ($_GET['secret'] !== $secret) {
    http_response_code(401);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);

// Processar transação recebida
$txHash = $input['tx_hash'];
$address = $input['address'];
$amount = $input['amount'];
$confirmations = $input['confirmations'];

// Buscar usuário pelo endereço
$stmt = $conn->prepare("SELECT id FROM users WHERE btc_deposit_address = ?");
$stmt->bind_param("s", $address);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if ($user) {
    if ($confirmations >= 3) {
        // Transação confirmada
        addBtcTransaction($user['id'], $txHash, $amount);
        updateBtcBalance($user['id'], $amount);
        
        // Atualizar status da transação
        $stmt = $conn->prepare("UPDATE btc_transactions SET status = 'confirmed' WHERE tx_hash = ?");
        $stmt->bind_param("s", $txHash);
        $stmt->execute();
    } else {
        // Transação pendente
        addBtcTransaction($user['id'], $txHash, $amount);
    }
}

http_response_code(200);