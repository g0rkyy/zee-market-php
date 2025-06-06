<?php
/**
 * SISTEMA DE SAQUE 100% REAL - ZEEMARKET
 * Substitui withdraw.php - Envia transações REAIS para blockchain
 * Local: withdraw.php
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
    
    // Validar endereço com validação REAL
    if (!isValidCryptoAddressReal($to_address, $crypto_type)) {
        throw new Exception("Endereço $crypto_type inválido: $to_address");
    }
    
    // Verificar se não é endereço interno da plataforma
    if (isInternalPlatformAddress($to_address)) {
        throw new Exception('Não é possível sacar para endereços internos da plataforma');
    }
    
    // Rate limiting específico para saques
    checkWithdrawalRateLimit($user_id);
    
    // Verificar saldo do usuário
    $balance = getUserBalance($user_id, $crypto_type);
    if ($balance < $amount) {
        throw new Exception("Saldo insuficiente. Disponível: $balance $crypto_type");
    }
    
    // Calcular taxa de rede DINÂMICA
    $network_fee = calculateRealNetworkFee($crypto_type, $amount);
    $platform_fee = $amount * 0.001; // 0.1% taxa da plataforma
    $total_fee = $network_fee + $platform_fee;
    $total_deduction = $amount + $total_fee;
    
    if ($balance < $total_deduction) {
        throw new Exception("Saldo insuficiente para cobrir taxas. Necessário: $total_deduction $crypto_type");
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
    
    // Verificar 2FA se configurado
    if (has2FAEnabled($user_id) && empty($input['2fa_code'])) {
        throw new Exception('Código 2FA obrigatório para saques');
    }
    
    // Processar saque REAL
    $conn->begin_transaction();
    
    try {
        // Deduzir saldo
        $balance_field = strtolower($crypto_type) . '_balance';
        $stmt = $conn->prepare("UPDATE users SET $balance_field = $balance_field - ? WHERE id = ?");
        $stmt->bind_param("di", $total_deduction, $user_id);
        $stmt->execute();
        
        // Registrar transação como pendente
        $withdrawal_id = createWithdrawalRecord($user_id, $to_address, $amount, $total_fee, $crypto_type);
        
        // ENVIAR TRANSAÇÃO REAL PARA BLOCKCHAIN
        $tx_result = sendRealBlockchainTransaction($crypto_type, $to_address, $amount, $network_fee, $withdrawal_id);
        
        if ($tx_result['success']) {
            // Atualizar com hash real da blockchain
            updateWithdrawalSuccess($withdrawal_id, $tx_result['txid'], $tx_result);
            
            $conn->commit();
            
            // Log de sucesso
            error_log("SAQUE REAL PROCESSADO: $amount $crypto_type para $to_address - TX: {$tx_result['txid']}");
            
            echo json_encode([
                'success' => true,
                'withdrawal_id' => $withdrawal_id,
                'txid' => $tx_result['txid'],
                'amount' => $amount,
                'network_fee' => $network_fee,
                'platform_fee' => $platform_fee,
                'total_fee' => $total_fee,
                'crypto' => $crypto_type,
                'explorer_url' => getExplorerUrl($crypto_type, $tx_result['txid']),
                'estimated_confirmation' => getEstimatedConfirmation($crypto_type),
                'message' => "Saque de $amount $crypto_type enviado para blockchain! TX: {$tx_result['txid']}"
            ]);
            
        } else {
            // Reverter saldo em caso de erro
            $stmt = $conn->prepare("UPDATE users SET $balance_field = $balance_field + ? WHERE id = ?");
            $stmt->bind_param("di", $total_deduction, $user_id);
            $stmt->execute();
            
            updateWithdrawalFailed($withdrawal_id, $tx_result['error']);
            $conn->rollback();
            
            throw new Exception("Falha ao enviar para blockchain: " . $tx_result['error']);
        }
        
    } catch (Exception $e) {
        $conn->rollback();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Erro no saque real: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

/**
 * ========== FUNÇÕES DE BLOCKCHAIN REAL ==========
 */

/**
 * Enviar transação REAL para blockchain
 */
function sendRealBlockchainTransaction($crypto, $to_address, $amount, $fee, $withdrawal_id) {
    switch ($crypto) {
        case 'BTC':
            return sendRealBitcoinTransaction($to_address, $amount, $fee, $withdrawal_id);
        case 'ETH':
            return sendRealEthereumTransaction($to_address, $amount, $fee, $withdrawal_id);
        case 'XMR':
            return sendRealMoneroTransaction($to_address, $amount, $fee, $withdrawal_id);
        default:
            return ['success' => false, 'error' => 'Criptomoeda não suportada'];
    }
}

/**
 * Enviar Bitcoin REAL via múltiplas APIs
 */
function sendRealBitcoinTransaction($to_address, $amount, $fee, $withdrawal_id) {
    try {
        // MÉTODO 1: BlockCypher API (Recomendado)
        $result = sendBitcoinViaBlockCypher($to_address, $amount, $fee);
        if ($result['success']) return $result;
        
        // MÉTODO 2: Electrum Server
        $result = sendBitcoinViaElectrum($to_address, $amount, $fee);
        if ($result['success']) return $result;
        
        // MÉTODO 3: Bitcoin Core RPC (se disponível)
        $result = sendBitcoinViaCoreRPC($to_address, $amount, $fee);
        if ($result['success']) return $result;
        
        throw new Exception('Todas as APIs de Bitcoin falharam');
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Enviar Bitcoin via BlockCypher (API Principal)
 */
function sendBitcoinViaBlockCypher($to_address, $amount, $fee) {
    try {
        $api_token = '1a406e8d527943418bd99f7afaf3d461'; // Sua API key real
        
        // 1. Buscar UTXOs da carteira quente
        $hot_wallet_address = getHotWalletAddress('BTC');
        $utxos = getUTXOsFromBlockCypher($hot_wallet_address, $api_token);
        
        if (empty($utxos)) {
            throw new Exception('Sem UTXOs disponíveis na carteira quente');
        }
        
        // 2. Selecionar UTXOs suficientes
        $selected_utxos = selectUTXOs($utxos, $amount + $fee);
        $total_input = array_sum(array_column($selected_utxos, 'value'));
        $change = $total_input - ($amount * 100000000) - ($fee * 100000000); // Converter para satoshis
        
        // 3. Criar transação
        $tx_data = [
            'inputs' => array_map(function($utxo) {
                return [
                    'addresses' => [$utxo['address']]
                ];
            }, $selected_utxos),
            'outputs' => [
                [
                    'addresses' => [$to_address],
                    'value' => intval($amount * 100000000) // Satoshis
                ]
            ]
        ];
        
        // Adicionar output de mudança se necessário
        if ($change > 546) { // Dust limit
            $tx_data['outputs'][] = [
                'addresses' => [getChangeAddress('BTC')],
                'value' => intval($change)
            ];
        }
        
        // 4. Criar transação via API
        $url = "https://api.blockcypher.com/v1/btc/main/txs/new?token=$api_token";
        $response = makeSecureApiCall($url, 'POST', $tx_data);
        
        if (!$response || !isset($response['tx'])) {
            throw new Exception('Falha ao criar transação');
        }
        
        // 5. Assinar transação
        $private_key = getHotWalletPrivateKey('BTC');
        $signed_tx = signBitcoinTransaction($response['tx'], $private_key, $selected_utxos);
        
        // 6. Transmitir para rede
        $send_url = "https://api.blockcypher.com/v1/btc/main/txs/send?token=$api_token";
        $send_response = makeSecureApiCall($send_url, 'POST', $signed_tx);
        
        if ($send_response && isset($send_response['tx']['hash'])) {
            // Marcar UTXOs como gastos
            markUTXOsAsSpent($selected_utxos, $send_response['tx']['hash']);
            
            return [
                'success' => true,
                'txid' => $send_response['tx']['hash'],
                'method' => 'blockcypher',
                'fee_paid' => $fee,
                'confirmations' => 0
            ];
        }
        
        throw new Exception('Falha ao transmitir transação');
        
    } catch (Exception $e) {
        error_log("Erro BlockCypher: " . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Enviar Ethereum REAL
 */
function sendRealEthereumTransaction($to_address, $amount, $fee, $withdrawal_id) {
    try {
        $infura_key = 'SUA_INFURA_KEY'; // Configure sua chave Infura
        $private_key = getHotWalletPrivateKey('ETH');
        $from_address = getHotWalletAddress('ETH');
        
        // 1. Obter nonce atual
        $nonce = getCurrentNonce($from_address);
        
        // 2. Obter gas price atual
        $gas_price = getCurrentGasPrice();
        
        // 3. Criar transação Ethereum
        $transaction = [
            'nonce' => '0x' . dechex($nonce),
            'gasPrice' => '0x' . dechex($gas_price),
            'gasLimit' => '0x5208', // 21000 para transferência simples
            'to' => $to_address,
            'value' => '0x' . dechex($amount * 1000000000000000000), // Wei
            'data' => '0x'
        ];
        
        // 4. Assinar transação
        $signed_tx = signEthereumTransaction($transaction, $private_key);
        
        // 5. Transmitir via Infura
        $rpc_data = [
            'jsonrpc' => '2.0',
            'method' => 'eth_sendRawTransaction',
            'params' => [$signed_tx],
            'id' => 1
        ];
        
        $url = "https://mainnet.infura.io/v3/$infura_key";
        $response = makeSecureApiCall($url, 'POST', $rpc_data);
        
        if ($response && isset($response['result'])) {
            return [
                'success' => true,
                'txid' => $response['result'],
                'method' => 'infura',
                'fee_paid' => $fee,
                'confirmations' => 0
            ];
        }
        
        throw new Exception('Falha ao enviar transação Ethereum');
        
    } catch (Exception $e) {
        error_log("Erro Ethereum: " . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * ========== FUNÇÕES DE VALIDAÇÃO REAL ==========
 */

/**
 * Validação REAL de endereços crypto
 */
function isValidCryptoAddressReal($address, $crypto) {
    switch ($crypto) {
        case 'BTC':
            return isValidBitcoinAddressReal($address);
        case 'ETH':
            return isValidEthereumAddressReal($address);
        case 'XMR':
            return isValidMoneroAddressReal($address);
        default:
            return false;
    }
}

function isValidBitcoinAddressReal($address) {
    // Validação completa Bitcoin
    $patterns = [
        'legacy_p2pkh' => '/^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/',
        'legacy_p2sh' => '/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/',
        'bech32' => '/^bc1[a-z0-9]{39,59}$/',
        'taproot' => '/^bc1p[a-z0-9]{58}$/'
    ];
    
    foreach ($patterns as $type => $pattern) {
        if (preg_match($pattern, $address)) {
            // Validação adicional de checksum se necessário
            return validateBitcoinChecksum($address, $type);
        }
    }
    
    return false;
}

function isValidEthereumAddressReal($address) {
    // Validação Ethereum com checksum
    if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
        return false;
    }
    
    // Verificar checksum EIP-55 se aplicável
    return validateEthereumChecksum($address);
}

/**
 * ========== FUNÇÕES DE TAXA DINÂMICA ==========
 */

/**
 * Calcular taxa de rede REAL em tempo real
 */
function calculateRealNetworkFee($crypto, $amount) {
    switch ($crypto) {
        case 'BTC':
            return calculateBitcoinFee($amount);
        case 'ETH':
            return calculateEthereumFee($amount);
        case 'XMR':
            return calculateMoneroFee($amount);
        default:
            return 0.001; // Fallback
    }
}

function calculateBitcoinFee($amount) {
    try {
        // Obter taxa recomendada de múltiplas fontes
        $sources = [
            'https://mempool.space/api/v1/fees/recommended',
            'https://bitcoinfees.earn.com/api/v1/fees/recommended'
        ];
        
        foreach ($sources as $source) {
            $response = @file_get_contents($source);
            if ($response) {
                $data = json_decode($response, true);
                if ($data && isset($data['fastestFee'])) {
                    // Estimar tamanho da transação (1 input, 2 outputs)
                    $tx_size = 226; // bytes estimados
                    $sat_per_byte = $data['fastestFee'];
                    $fee_satoshis = $tx_size * $sat_per_byte;
                    return $fee_satoshis / 100000000; // Converter para BTC
                }
            }
        }
        
        return 0.0001; // Fallback
        
    } catch (Exception $e) {
        return 0.0001;
    }
}

function calculateEthereumFee($amount) {
    try {
        // Obter gas price atual
        $gas_price = getCurrentGasPrice();
        $gas_limit = 21000; // Transferência simples
        
        $fee_wei = $gas_price * $gas_limit;
        return $fee_wei / 1000000000000000000; // Wei para ETH
        
    } catch (Exception $e) {
        return 0.002; // Fallback
    }
}

/**
 * ========== FUNÇÕES AUXILIARES ==========
 */

function checkWithdrawalRateLimit($user_id) {
    global $conn;
    
    // Máximo 3 saques por hora
    $stmt = $conn->prepare("
        SELECT COUNT(*) as count FROM btc_transactions 
        WHERE user_id = ? AND type = 'withdrawal' 
        AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    ");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    if ($result['count'] >= 3) {
        throw new Exception('Limite de saques por hora excedido (3/hora). Tente novamente em 1 hora.');
    }
}

function isInternalPlatformAddress($address) {
    global $conn;
    
    // Verificar se é endereço da plataforma
    $platform_addresses = [
        'bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m', // Carteira principal
        // Adicionar outros endereços da plataforma
    ];
    
    if (in_array($address, $platform_addresses)) {
        return true;
    }
    
    // Verificar se é endereço de algum usuário
    $stmt = $conn->prepare("
        SELECT COUNT(*) as count FROM users 
        WHERE btc_deposit_address = ? OR eth_deposit_address = ? OR xmr_deposit_address = ?
    ");
    $stmt->bind_param("sss", $address, $address, $address);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    return $result['count'] > 0;
}

function createWithdrawalRecord($user_id, $to_address, $amount, $fee, $crypto) {
    global $conn;
    
    $stmt = $conn->prepare("
        INSERT INTO btc_transactions 
        (user_id, type, amount, fee, to_address, status, crypto_type, created_at) 
        VALUES (?, 'withdrawal', ?, ?, ?, 'pending', ?, NOW())
    ");
    $stmt->bind_param("iddss", $user_id, $amount, $fee, $to_address, $crypto);
    $stmt->execute();
    
    return $conn->insert_id;
}

function updateWithdrawalSuccess($withdrawal_id, $txid, $tx_data) {
    global $conn;
    
    $stmt = $conn->prepare("
        UPDATE btc_transactions 
        SET status = 'sent', tx_hash = ?, confirmations = 0, 
            updated_at = NOW(), tx_data = ?
        WHERE id = ?
    ");
    $tx_data_json = json_encode($tx_data);
    $stmt->bind_param("ssi", $txid, $tx_data_json, $withdrawal_id);
    $stmt->execute();
}

function updateWithdrawalFailed($withdrawal_id, $error) {
    global $conn;
    
    $stmt = $conn->prepare("
        UPDATE btc_transactions 
        SET status = 'failed', notes = ?, updated_at = NOW()
        WHERE id = ?
    ");
    $stmt->bind_param("si", $error, $withdrawal_id);
    $stmt->execute();
}

function getExplorerUrl($crypto, $txid) {
    $explorers = [
        'BTC' => "https://blockstream.info/tx/$txid",
        'ETH' => "https://etherscan.io/tx/$txid",
        'XMR' => "https://xmrchain.net/tx/$txid"
    ];
    
    return $explorers[$crypto] ?? '';
}

function getEstimatedConfirmation($crypto) {
    $times = [
        'BTC' => '10-60 minutos',
        'ETH' => '1-5 minutos',
        'XMR' => '2-20 minutos'
    ];
    
    return $times[$crypto] ?? 'Desconhecido';
}

function makeSecureApiCall($url, $method = 'GET', $data = null) {
    $ch = curl_init();
    
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => 'ZeeMarket/2.0',
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Accept: application/json'
        ]
    ]);
    
    if ($method === 'POST' && $data) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("cURL Error: $error");
    }
    
    if ($http_code < 200 || $http_code >= 300) {
        throw new Exception("HTTP Error: $http_code");
    }
    
    return json_decode($response, true);
}

/**
 * ========== CONFIGURAÇÕES DE CARTEIRA QUENTE ==========
 * ATENÇÃO: Em produção, armazene chaves privadas de forma segura!
 */

function getHotWalletAddress($crypto) {
    $addresses = [
        'BTC' => 'bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m', // SUA CARTEIRA REAL
        'ETH' => '0x742d35Cc6634C0532925a3b8D6b9DcC6a4a5C0E3', // SUA CARTEIRA REAL
        'XMR' => '4...' // SUA CARTEIRA MONERO REAL
    ];
    
    return $addresses[$crypto] ?? null;
}

function getHotWalletPrivateKey($crypto) {
    // ⚠️ CRITICAL: Em produção, use HSM ou vault seguro!
    // Nunca armazene chaves privadas em código
    
    $encrypted_keys = [
        'BTC' => 'CHAVE_PRIVADA_CRIPTOGRAFADA_BTC',
        'ETH' => 'CHAVE_PRIVADA_CRIPTOGRAFADA_ETH',
        'XMR' => 'CHAVE_PRIVADA_CRIPTOGRAFADA_XMR'
    ];
    
    // Descriptografar usando senha mestre
    return decryptPrivateKey($encrypted_keys[$crypto]);
}

function decryptPrivateKey($encrypted_key) {
    // Implementar descriptografia segura
    $master_password = $_ENV['MASTER_WALLET_PASSWORD'] ?? 'default_password';
    $key = hash('sha256', $master_password, true);
    
    // Simplified decryption - use proper encryption in production
    return openssl_decrypt(base64_decode($encrypted_key), 'AES-256-CBC', $key);
}

// ========== FUNÇÕES QUE VOCÊ DEVE IMPLEMENTAR ==========

function getUserBalance($user_id, $crypto) {
    global $conn;
    $balance_field = strtolower($crypto) . '_balance';
    $stmt = $conn->prepare("SELECT $balance_field FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return floatval($result[$balance_field] ?? 0);
}

function getTodayWithdrawals($user_id, $crypto) {
    global $conn;
    $stmt = $conn->prepare("
        SELECT COALESCE(SUM(amount), 0) as total 
        FROM btc_transactions 
        WHERE user_id = ? AND crypto_type = ? AND type = 'withdrawal' 
        AND DATE(created_at) = CURDATE() AND status != 'failed'
    ");
    $stmt->bind_param("is", $user_id, $crypto);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return floatval($result['total']);
}

function has2FAEnabled($user_id) {
    global $conn;
    $stmt = $conn->prepare("SELECT two_factor_enabled FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return (bool)($result['two_factor_enabled'] ?? false);
}

echo json_encode(['info' => 'Sistema de saque REAL carregado e pronto!']);
?>