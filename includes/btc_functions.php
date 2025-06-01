<?php
require_once 'config.php'; // Certifique-se que este caminho está correto

/**
 * Gera um endereço de depósito Bitcoin para o usuário usando a Blockchain.com API
 * @param int $userId ID do usuário
 * @return string Endereço Bitcoin gerado
 */
function generateDepositAddress($userId) {
    global $blockchainConfig; // Configurações da API (definidas em config.php)
    
    $label = 'user_' . $userId;
    $callbackUrl = $blockchainConfig['callback_url'] . '?secret=' . $blockchainConfig['secret'];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://api.blockchain.info/v2/receive?" . http_build_query([
        'xpub' => $blockchainConfig['xpub'],
        'key' => $blockchainConfig['api_key'],
        'callback' => $callbackUrl,
        'gap_limit' => 100
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        error_log("Erro ao gerar endereço BTC: HTTP $httpCode - $response");
        throw new Exception("Erro ao gerar endereço de depósito. Tente novamente mais tarde.");
    }
    
    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE || !isset($data['address'])) {
        error_log("Resposta inválida da API Blockchain: $response");
        throw new Exception("Erro ao processar resposta do serviço de pagamento.");
    }
    
    return $data['address'];
}

/**
 * Atualiza o endereço de depósito Bitcoin do usuário no banco de dados
 * @param int $userId ID do usuário
 * @param string $address Endereço Bitcoin
 * @return bool Sucesso da operação
 */
function updateUserDepositAddress($userId, $address) {
    global $conn;
    
    $stmt = $conn->prepare("UPDATE users SET btc_deposit_address = ?, last_deposit_check = NOW() WHERE id = ?");
    $stmt->bind_param("si", $address, $userId);
    
    if (!$stmt->execute()) {
        error_log("Erro ao atualizar endereço BTC: " . $stmt->error);
        return false;
    }
    
    return true;
}

/**
 * Obtém depósitos pendentes do usuário
 * @param int $userId ID do usuário
 * @return array Lista de transações pendentes
 */
function getPendingDeposits($userId) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT * FROM btc_transactions WHERE user_id = ? AND status = 'pending' ORDER BY created_at DESC");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    
    $result = $stmt->get_result();
    return $result->fetch_all(MYSQLI_ASSOC);
}

/**
 * Adiciona uma nova transação Bitcoin ao banco de dados
 * @param int $userId ID do usuário
 * @param string $txHash Hash da transação
 * @param float $amount Valor em BTC
 * @return bool Sucesso da operação
 */
function addBtcTransaction($userId, $txHash, $amount) {
    global $conn;
    
    // Verifica se a transação já existe
    $stmt = $conn->prepare("SELECT id FROM btc_transactions WHERE tx_hash = ?");
    $stmt->bind_param("s", $txHash);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows > 0) {
        return false; // Transação já existe
    }
    
    // Insere nova transação
    $stmt = $conn->prepare("INSERT INTO btc_transactions (user_id, tx_hash, amount, status) VALUES (?, ?, ?, 'pending')");
    $stmt->bind_param("isd", $userId, $txHash, $amount);
    
    if (!$stmt->execute()) {
        error_log("Erro ao registrar transação BTC: " . $stmt->error);
        return false;
    }
    
    return true;
}

/**
 * Atualiza o saldo Bitcoin do usuário
 * @param int $userId ID do usuário
 * @param float $amount Valor a ser adicionado (em BTC)
 * @return bool Sucesso da operação
 */
function updateBtcBalance($userId, $amount) {
    global $conn;
    
    $stmt = $conn->prepare("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?");
    $stmt->bind_param("di", $amount, $userId);
    
    if (!$stmt->execute()) {
        error_log("Erro ao atualizar saldo BTC: " . $stmt->error);
        return false;
    }
    
    return true;
}

/**
 * Verifica se o usuário tem saldo suficiente
 * @param int $userId ID do usuário
 * @param float $amount Valor necessário (em BTC)
 * @return bool True se tiver saldo suficiente
 */
function checkUserBalance($userId, $amount) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT btc_balance FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    
    return ($user && $user['btc_balance'] >= $amount);
}

/**
 * Processa notificação de depósito recebida via webhook
 * @param array $input Dados recebidos do webhook
 * @return bool Sucesso do processamento
 */
function processBtcDeposit($input) {
    global $conn;
    
    // Validação básica dos dados
    if (empty($input['tx_hash']) || empty($input['address']) || !isset($input['amount']) || !isset($input['confirmations'])) {
        error_log("Dados de depósito inválidos: " . print_r($input, true));
        return false;
    }
    
    // Busca usuário pelo endereço
    $stmt = $conn->prepare("SELECT id FROM users WHERE btc_deposit_address = ?");
    $stmt->bind_param("s", $input['address']);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    
    if (!$user) {
        error_log("Endereço BTC não encontrado: " . $input['address']);
        return false;
    }
    
    // Registra a transação
    addBtcTransaction($user['id'], $input['tx_hash'], $input['amount']);
    
    // Se tiver confirmações suficientes, atualiza o saldo
    if ($input['confirmations'] >= 3) {
        updateBtcBalance($user['id'], $input['amount']);
        
        // Atualiza status da transação
        $stmt = $conn->prepare("UPDATE btc_transactions SET status = 'confirmed' WHERE tx_hash = ?");
        $stmt->bind_param("s", $input['tx_hash']);
        $stmt->execute();
        
        // Registra no log
        error_log("Depósito confirmado: " . $input['amount'] . " BTC para usuário " . $user['id']);
    }
    
    return true;
}

/**
 * Obtém o saldo Bitcoin do usuário
 * @param int $userId ID do usuário
 * @return float Saldo em BTC
 */
function getUserBtcBalance($userId) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT btc_balance FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    
    return $user ? $user['btc_balance'] : 0;
}