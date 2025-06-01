<?php
require_once __DIR__ . '/config.php';

/**
 * Classe principal para gerenciar operações Bitcoin
 */
class BitcoinWallet {
    private $conn;
    private $config;
    
    public function __construct() {
        global $conn, $blockchainConfig;
        $this->conn = $conn;
        $this->config = $blockchainConfig;
    }

    /**
     * Gera um novo endereço Bitcoin usando HD Wallet
     * @param int $userId ID do usuário
     * @return array [success, address, error]
     */
    public function generateDepositAddress($userId) {
        try {
            // Gera uma nova chave privada/pública
            $privateKey = $this->generatePrivateKey();
            $publicKey = $this->getPublicKeyFromPrivate($privateKey);
            $address = $this->getAddressFromPublicKey($publicKey);
            
            // Criptografa a chave privada
            $encryptedPrivateKey = $this->encryptPrivateKey($privateKey);
            
            // Salva no banco
            $stmt = $this->conn->prepare("
                UPDATE users SET 
                    btc_deposit_address = ?, 
                    btc_private_key = ?, 
                    btc_public_key = ?,
                    last_deposit_check = NOW() 
                WHERE id = ?
            ");
            
            $stmt->bind_param("sssi", $address, $encryptedPrivateKey, $publicKey, $userId);
            
            if (!$stmt->execute()) {
                throw new Exception("Erro ao salvar endereço: " . $stmt->error);
            }
            
            // Configura webhook para monitorar o endereço
            $this->setupAddressWebhook($address);
            
            return [
                'success' => true, 
                'address' => $address,
                'message' => 'Endereço gerado com sucesso'
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao gerar endereço Bitcoin: " . $e->getMessage());
            return [
                'success' => false, 
                'error' => 'Erro interno do servidor'
            ];
        }
    }

    /**
     * Verifica saldo de um endereço Bitcoin
     * @param string $address Endereço Bitcoin
     * @return array [success, balance, unconfirmed_balance]
     */
    public function getAddressBalance($address) {
        try {
            // Tenta BlockCypher primeiro
            $balance = $this->getBalanceFromBlockCypher($address);
            
            if ($balance === false) {
                // Fallback para Blockstream
                $balance = $this->getBalanceFromBlockstream($address);
            }
            
            if ($balance === false) {
                throw new Exception("Falha ao obter saldo de todas as APIs");
            }
            
            return [
                'success' => true,
                'balance' => $balance['confirmed'],
                'unconfirmed_balance' => $balance['unconfirmed']
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao verificar saldo: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Obtém saldo via BlockCypher API
     */
    private function getBalanceFromBlockCypher($address) {
        $url = $this->config['blockcypher']['base_url'] . "/addrs/$address/balance";
        
        if (!empty($this->config['blockcypher']['api_key'])) {
            $url .= "?token=" . $this->config['blockcypher']['api_key'];
        }
        
        $response = $this->makeHttpRequest($url);
        
        if ($response && isset($response['balance'])) {
            return [
                'confirmed' => satoshiToBtc($response['balance']),
                'unconfirmed' => satoshiToBtc($response['unconfirmed_balance'])
            ];
        }
        
        return false;
    }

    /**
     * Obtém saldo via Blockstream API
     */
    private function getBalanceFromBlockstream($address) {
        $url = $this->config['blockstream']['base_url'] . "/address/$address";
        $response = $this->makeHttpRequest($url);
        
        if ($response && isset($response['chain_stats'])) {
            $confirmed = $response['chain_stats']['funded_txo_sum'] - $response['chain_stats']['spent_txo_sum'];
            $unconfirmed = $response['mempool_stats']['funded_txo_sum'] - $response['mempool_stats']['spent_txo_sum'];
            
            return [
                'confirmed' => satoshiToBtc($confirmed),
                'unconfirmed' => satoshiToBtc($unconfirmed)
            ];
        }
        
        return false;
    }

    /**
     * Obtém transações de um endereço
     * @param string $address Endereço Bitcoin
     * @param int $limit Limite de transações
     * @return array Lista de transações
     */
    public function getAddressTransactions($address, $limit = 50) {
        try {
            $url = $this->config['blockcypher']['base_url'] . "/addrs/$address/full?limit=$limit";
            
            if (!empty($this->config['blockcypher']['api_key'])) {
                $url .= "&token=" . $this->config['blockcypher']['api_key'];
            }
            
            $response = $this->makeHttpRequest($url);
            
            if (!$response || !isset($response['txs'])) {
                return [];
            }
            
            $transactions = [];
            foreach ($response['txs'] as $tx) {
                $transactions[] = $this->formatTransaction($tx, $address);
            }
            
            return $transactions;
            
        } catch (Exception $e) {
            error_log("Erro ao obter transações: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Formata dados da transação
     */
    private function formatTransaction($tx, $address) {
        $value = 0;
        $type = 'received';
        
        // Calcula valor recebido/enviado
        foreach ($tx['outputs'] as $output) {
            if (in_array($address, $output['addresses'] ?? [])) {
                $value += $output['value'];
            }
        }
        
        foreach ($tx['inputs'] as $input) {
            if (in_array($address, $input['addresses'] ?? [])) {
                $value -= $input['output_value'];
                $type = 'sent';
            }
        }
        
        return [
            'txid' => $tx['hash'],
            'confirmations' => $tx['confirmations'],
            'value' => satoshiToBtc(abs($value)),
            'type' => $type,
            'time' => strtotime($tx['received']),
            'block_height' => $tx['block_height'] ?? null
        ];
    }

    /**
     * Processa depósito Bitcoin
     * @param array $data Dados do webhook ou manual
     * @return bool Sucesso do processamento
     */
    public function processDeposit($data) {
        try {
            $this->conn->begin_transaction();
            
            // Validação dos dados
            if (empty($data['address']) || empty($data['txid']) || !isset($data['value'])) {
                throw new Exception("Dados de depósito inválidos");
            }
            
            $address = $data['address'];
            $txid = $data['txid'];
            $value = (float)$data['value'];
            $confirmations = (int)($data['confirmations'] ?? 0);
            
            // Verifica se é dust
            if ($value < $this->config['dust_limit']) {
                throw new Exception("Valor abaixo do limite mínimo");
            }
            
            // Busca usuário pelo endereço
            $stmt = $this->conn->prepare("SELECT id, name FROM users WHERE btc_deposit_address = ?");
            $stmt->bind_param("s", $address);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            
            if (!$user) {
                throw new Exception("Endereço não encontrado: $address");
            }
            
            // Verifica se transação já foi processada
            $stmt = $this->conn->prepare("SELECT id, status FROM btc_transactions WHERE tx_hash = ?");
            $stmt->bind_param("s", $txid);
            $stmt->execute();
            $existing = $stmt->get_result()->fetch_assoc();
            
            if ($existing) {
                // Atualiza confirmações se necessário
                if ($confirmations > 0 && $existing['status'] === 'pending') {
                    $this->updateTransactionStatus($txid, $confirmations);
                }
                return true;
            }
            
            // Registra nova transação
            $status = $confirmations >= $this->config['min_confirmations'] ? 'confirmed' : 'pending';
            
            $stmt = $this->conn->prepare("
                INSERT INTO btc_transactions (user_id, tx_hash, address, amount, confirmations, status, type, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, 'deposit', NOW())
            ");
            $stmt->bind_param("issdis", $user['id'], $txid, $address, $value, $confirmations, $status);
            
            if (!$stmt->execute()) {
                throw new Exception("Erro ao registrar transação: " . $stmt->error);
            }
            
            // Se confirmado, atualiza saldo
            if ($status === 'confirmed') {
                $this->updateUserBalance($user['id'], $value);
                $this->logTransaction($user['id'], 'deposit', $value, "Depósito confirmado - TX: $txid");
            }
            
            $this->conn->commit();
            
            error_log("Depósito processado: $value BTC para usuário {$user['name']} (ID: {$user['id']})");
            return true;
            
        } catch (Exception $e) {
            $this->conn->rollback();
            error_log("Erro ao processar depósito: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Processa saque Bitcoin
     * @param int $userId ID do usuário
     * @param string $toAddress Endereço de destino
     * @param float $amount Valor em BTC
     * @return array [success, txid, error]
     */
    public function processWithdrawal($userId, $toAddress, $amount) {
        try {
            $this->conn->begin_transaction();
            
            // Validações
            if (!$this->isValidBitcoinAddress($toAddress)) {
                throw new Exception("Endereço Bitcoin inválido");
            }
            
            if ($amount < $this->config['dust_limit']) {
                throw new Exception("Valor mínimo: " . $this->config['dust_limit'] . " BTC");
            }
            
            // Verifica saldo
            $userBalance = $this->getUserBalance($userId);
            if ($userBalance < $amount) {
                throw new Exception("Saldo insuficiente");
            }
            
            // Calcula taxa de rede
            $fee = $this->estimateTransactionFee();
            $totalAmount = $amount + $fee;
            
            if ($userBalance < $totalAmount) {
                throw new Exception("Saldo insuficiente para cobrir taxa de rede");
            }
            
            // Cria transação
            $txid = $this->createWithdrawalTransaction($userId, $toAddress, $amount, $fee);
            
            if (!$txid) {
                throw new Exception("Erro ao criar transação");
            }
            
            // Atualiza saldo
            $this->updateUserBalance($userId, -$totalAmount);
            
            // Registra transação
            $stmt = $this->conn->prepare("
                INSERT INTO btc_transactions (user_id, tx_hash, address, amount, fee, status, type, created_at) 
                VALUES (?, ?, ?, ?, ?, 'pending', 'withdrawal', NOW())
            ");
            $stmt->bind_param("issdd", $userId, $txid, $toAddress, $amount, $fee);
            $stmt->execute();
            
            $this->logTransaction($userId, 'withdrawal', $amount, "Saque para $toAddress - TX: $txid");
            
            $this->conn->commit();
            
            return [
                'success' => true,
                'txid' => $txid,
                'message' => 'Saque processado com sucesso'
            ];
            
        } catch (Exception $e) {
            $this->conn->rollback();
            error_log("Erro no saque: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Atualiza saldo do usuário
     */
    private function updateUserBalance($userId, $amount) {
        $stmt = $this->conn->prepare("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?");
        $stmt->bind_param("di", $amount, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao atualizar saldo: " . $stmt->error);
        }
        
        // Atualiza sessão se for o usuário logado
        if (isset($_SESSION['user_id']) && $_SESSION['user_id'] == $userId) {
            $_SESSION['btc_balance'] = $this->getUserBalance($userId);
        }
    }

    /**
     * Obtém saldo atual do usuário
     */
    public function getUserBalance($userId) {
        $stmt = $this->conn->prepare("SELECT btc_balance FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return $result ? (float)$result['btc_balance'] : 0.0;
    }

    /**
     * Atualiza status da transação
     */
    private function updateTransactionStatus($txid, $confirmations) {
        $status = $confirmations >= $this->config['min_confirmations'] ? 'confirmed' : 'pending';
        
        $stmt = $this->conn->prepare("
            UPDATE btc_transactions 
            SET confirmations = ?, status = ?, updated_at = NOW() 
            WHERE tx_hash = ?
        ");
        $stmt->bind_param("iss", $confirmations, $status, $txid);
        $stmt->execute();
        
        // Se foi confirmado agora, atualiza saldo
        if ($status === 'confirmed') {
            $stmt = $this->conn->prepare("
                SELECT user_id, amount, type 
                FROM btc_transactions 
                WHERE tx_hash = ? AND status = 'confirmed'
            ");
            $stmt->bind_param("s", $txid);
            $stmt->execute();
            $transaction = $stmt->get_result()->fetch_assoc();
            
            if ($transaction && $transaction['type'] === 'deposit') {
                $this->updateUserBalance($transaction['user_id'], $transaction['amount']);
                $this->logTransaction($transaction['user_id'], 'deposit_confirmed', $transaction['amount'], "Depósito confirmado - TX: $txid");
            }
        }
    }

    /**
     * Registra log de transação
     */
    private function logTransaction($userId, $type, $amount, $description) {
        $stmt = $this->conn->prepare("
            INSERT INTO transaction_logs (user_id, type, amount, description, created_at) 
            VALUES (?, ?, ?, ?, NOW())
        ");
        $stmt->bind_param("isds", $userId, $type, $amount, $description);
        $stmt->execute();
    }

    /**
     * Valida endereço Bitcoin
     */
    private function isValidBitcoinAddress($address) {
        // Regex para endereços Bitcoin válidos
        return preg_match('/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/', $address);
    }

    /**
     * Gera chave privada segura
     */
    private function generatePrivateKey() {
        return bin2hex(random_bytes(32));
    }

    /**
     * Deriva chave pública da chave privada
     */
    private function getPublicKeyFromPrivate($privateKey) {
        // Implementação simplificada - em produção use biblioteca secp256k1
        return hash('sha256', $privateKey . 'public_key_suffix');
    }

    /**
     * Deriva endereço da chave pública
     */
    private function getAddressFromPublicKey($publicKey) {
        // Implementação simplificada - em produção use bibliotecas adequadas
        $hash = hash('ripemd160', hash('sha256', $publicKey, true), true);
        $checksum = substr(hash('sha256', hash('sha256', '00' . bin2hex($hash), true), true), 0, 8);
        return $this->base58Encode('00' . bin2hex($hash) . $checksum);
    }

    /**
     * Codificação Base58
     */
    private function base58Encode($hex) {
        // Implementação simplificada do Base58
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $decoded = gmp_init($hex, 16);
        $result = '';
        
        while (gmp_cmp($decoded, 0) > 0) {
            $remainder = gmp_mod($decoded, 58);
            $result = $alphabet[gmp_intval($remainder)] . $result;
            $decoded = gmp_div($decoded, 58);
        }
        
        // Para desenvolvimento, retorna um endereço mock válido
        return '1' . substr(str_shuffle('23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'), 0, 33);
    }

    /**
     * Criptografa chave privada
     */
    private function encryptPrivateKey($privateKey) {
        $key = $this->config['encryption_key'];
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($privateKey, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Descriptografa chave privada
     */
    private function decryptPrivateKey($encryptedKey) {
        $key = $this->config['encryption_key'];
        $data = base64_decode($encryptedKey);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }

    /**
     * Configura webhook para monitorar endereço
     */
    private function setupAddressWebhook($address) {
        // Implementação do webhook com BlockCypher
        if (empty($this->config['blockcypher']['api_key'])) {
            return false; // Precisa de API key para webhooks
        }
        
        $webhookData = [
            'event' => 'unconfirmed-tx',
            'address' => $address,
            'url' => $this->config['blockcypher']['webhook_url']
        ];
        
        $url = $this->config['blockcypher']['base_url'] . '/hooks?token=' . $this->config['blockcypher']['api_key'];
        
        return $this->makeHttpRequest($url, 'POST', $webhookData);
    }

    /**
     * Estima taxa de transação
     */
    private function estimateTransactionFee() {
        // Taxa fixa para simplificação - em produção, use API de estimativa
        return 0.00001; // ~1000 satoshis
    }

    /**
     * Cria transação de saque (simplificado)
     */
    private function createWithdrawalTransaction($userId, $toAddress, $amount, $fee) {
        // Em produção, esta função criaria e assinaria uma transação real
        // Por enquanto, retorna um TXID mock
        return hash('sha256', $userId . $toAddress . $amount . time());
    }

    /**
     * Faz requisição HTTP
     */
    private function makeHttpRequest($url, $method = 'GET', $data = null) {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => 'ZeeMarket/1.0',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json']
        ]);
        
        if ($method === 'POST' && $data) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            error_log("HTTP Error $httpCode: $response");
            return false;
        }
        
        return json_decode($response, true);
    }

    /**
     * Sincroniza transações pendentes
     */
    public function syncPendingTransactions() {
        $stmt = $this->conn->prepare("
            SELECT DISTINCT tx_hash 
            FROM btc_transactions 
            WHERE status = 'pending' AND type = 'deposit'
            AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stmt->execute();
        $transactions = $stmt->get_result();
        
        while ($tx = $transactions->fetch_assoc()) {
            $this->checkTransactionStatus($tx['tx_hash']);
        }
    }

    /**
     * Verifica status de uma transação específica
     */
    private function checkTransactionStatus($txid) {
        $url = $this->config['blockcypher']['base_url'] . "/txs/$txid";
        $response = $this->makeHttpRequest($url);
        
        if ($response && isset($response['confirmations'])) {
            $this->updateTransactionStatus($txid, $response['confirmations']);
        }
    }
}

// Funções helper globais para compatibilidade
function generateDepositAddress($userId) {
    $wallet = new BitcoinWallet();
    return $wallet->generateDepositAddress($userId);
}

function getUserBtcBalance($userId) {
    $wallet = new BitcoinWallet();
    return $wallet->getUserBalance($userId);
}

function processWebhookDeposit($data) {
    $wallet = new BitcoinWallet();
    return $wallet->processDeposit($data);
}

function processBitcoinWithdrawal($userId, $address, $amount) {
    $wallet = new BitcoinWallet();
    return $wallet->processWithdrawal($userId, $address, $amount);
}
?>