<?php
/**
 * SISTEMA DE GERAÇÃO DE CARTEIRAS CRIPTOMOEDAS
 * Gera endereços de depósito para BTC, ETH, XMR
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'includes/config.php';
require_once 'includes/functions.php';

// Headers para AJAX
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
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

// Verificar CSRF token
if (empty($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Token CSRF inválido']);
    exit();
}

$crypto = strtoupper(trim($_POST['crypto'] ?? ''));
$user_id = $_SESSION['user_id'];

// Validar criptomoeda
$cryptos_suportadas = ['BTC', 'ETH', 'XMR'];
if (!in_array($crypto, $cryptos_suportadas)) {
    echo json_encode(['success' => false, 'error' => 'Criptomoeda não suportada']);
    exit();
}

try {
    $conn->begin_transaction();
    
    switch ($crypto) {
        case 'BTC':
            $result = generateBitcoinAddress($user_id);
            break;
        case 'ETH':
            $result = generateEthereumAddress($user_id);
            break;
        case 'XMR':
            $result = generateMoneroAddress($user_id);
            break;
        default:
            throw new Exception("Criptomoeda não implementada: $crypto");
    }
    
    if ($result['success']) {
        $conn->commit();
        
        // Log da ação
        error_log("Carteira $crypto gerada para usuário $user_id: " . $result['address']);
        
        echo json_encode([
            'success' => true,
            'crypto' => $crypto,
            'address' => $result['address'],
            'message' => "Endereço $crypto gerado com sucesso!"
        ]);
    } else {
        $conn->rollback();
        echo json_encode(['success' => false, 'error' => $result['error']]);
    }
    
} catch (Exception $e) {
    $conn->rollback();
    error_log("Erro ao gerar carteira $crypto: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => 'Erro interno do servidor']);
}

/**
 * Gera endereço Bitcoin
 */
function generateBitcoinAddress($user_id) {
    global $conn;
    
    try {
        // Verificar se já tem endereço
        $stmt = $conn->prepare("SELECT btc_deposit_address FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if (!empty($result['btc_deposit_address'])) {
            return [
                'success' => true,
                'address' => $result['btc_deposit_address'],
                'message' => 'Endereço já existente'
            ];
        }
        
        // Gerar novo endereço Bitcoin (simulado para desenvolvimento)
        $address = generateTestBitcoinAddress();
        $private_key = generateTestPrivateKey();
        
        // Criptografar chave privada
        $encrypted_key = encryptData($private_key);
        
        // Salvar no banco
        $stmt = $conn->prepare("
            UPDATE users SET 
                btc_deposit_address = ?, 
                btc_private_key = ?,
                last_deposit_check = NOW()
            WHERE id = ?
        ");
        $stmt->bind_param("ssi", $address, $encrypted_key, $user_id);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço Bitcoin: " . $stmt->error);
        }
        
        return [
            'success' => true,
            'address' => $address,
            'message' => 'Endereço Bitcoin gerado com sucesso'
        ];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Gera endereço Ethereum
 */
function generateEthereumAddress($user_id) {
    global $conn;
    
    try {
        // Verificar se já tem endereço
        $stmt = $conn->prepare("SELECT eth_deposit_address FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if (!empty($result['eth_deposit_address'])) {
            return [
                'success' => true,
                'address' => $result['eth_deposit_address'],
                'message' => 'Endereço já existente'
            ];
        }
        
        // Gerar endereço Ethereum
        $private_key = bin2hex(random_bytes(32));
        $address = '0x' . substr(hash('keccak256', $private_key), 24);
        
        // Garantir que o endereço tenha 42 caracteres (0x + 40 hex)
        while (strlen($address) < 42) {
            $address .= '0';
        }
        
        // Criptografar chave privada
        $encrypted_key = encryptData($private_key);
        
        // Salvar no banco
        $stmt = $conn->prepare("
            UPDATE users SET 
                eth_deposit_address = ?, 
                eth_private_key = ?,
                last_deposit_check = NOW()
            WHERE id = ?
        ");
        $stmt->bind_param("ssi", $address, $encrypted_key, $user_id);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço Ethereum: " . $stmt->error);
        }
        
        return [
            'success' => true,
            'address' => $address,
            'message' => 'Endereço Ethereum gerado com sucesso'
        ];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Gera endereço Monero
 */
function generateMoneroAddress($user_id) {
    global $conn;
    
    try {
        // Verificar se já tem endereço
        $stmt = $conn->prepare("SELECT xmr_deposit_address FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if (!empty($result['xmr_deposit_address'])) {
            return [
                'success' => true,
                'address' => $result['xmr_deposit_address'],
                'message' => 'Endereço já existente'
            ];
        }
        
        // Gerar endereço Monero (simulado)
        $address = '4' . bin2hex(random_bytes(47)); // Endereços Monero começam com '4'
        $private_key = bin2hex(random_bytes(32));
        
        // Criptografar chave privada
        $encrypted_key = encryptData($private_key);
        
        // Salvar no banco
        $stmt = $conn->prepare("
            UPDATE users SET 
                xmr_deposit_address = ?, 
                xmr_private_key = ?,
                last_deposit_check = NOW()
            WHERE id = ?
        ");
        $stmt->bind_param("ssi", $address, $encrypted_key, $user_id);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço Monero: " . $stmt->error);
        }
        
        return [
            'success' => true,
            'address' => $address,
            'message' => 'Endereço Monero gerado com sucesso'
        ];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Gera endereço Bitcoin de teste válido
 */
function generateTestBitcoinAddress() {
    // Prefixos válidos para Bitcoin
    $prefixes = ['bc1q', '1', '3'];
    $prefix = $prefixes[array_rand($prefixes)];
    
    if ($prefix === 'bc1q') {
        // Bech32 address
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $address = $prefix;
        for ($i = 0; $i < 32; $i++) {
            $address .= $chars[rand(0, strlen($chars) - 1)];
        }
    } else {
        // Legacy address
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789';
        $address = $prefix;
        $length = $prefix === '1' ? 26 : 25;
        for ($i = 0; $i < $length; $i++) {
            $address .= $chars[rand(0, strlen($chars) - 1)];
        }
    }
    
    return $address;
}

/**
 * Gera chave privada de teste
 */
function generateTestPrivateKey() {
    return bin2hex(random_bytes(32));
}
?>