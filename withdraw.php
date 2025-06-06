<?php
/**
 * SISTEMA DE SAQUE REAL - SUBSTITUI withdraw.php COMPLETAMENTE
 * Local: withdraw.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/secure_withdrawal.php'; // Usando o sistema seguro que você criou

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
    // Usar o sistema de saque seguro que você criou
    $secureWithdrawal = new SecureWithdrawalSystem($conn);
    
    $result = $secureWithdrawal->processWithdrawal(
        $user_id,
        $to_address, 
        $amount,
        $crypto_type
    );
    
    if ($result['success']) {
        // Atualizar saldo na sessão
        updateSessionBalances($user_id);
        
        echo json_encode([
            'success' => true,
            'withdrawal_id' => $result['withdrawal_id'],
            'txid' => $result['txid'],
            'amount' => $result['amount'],
            'fee' => $result['fee'],
            'crypto' => $crypto_type,
            'message' => $result['message']
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => $result['error']]);
    }
    
} catch (Exception $e) {
    error_log("Erro no saque: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>