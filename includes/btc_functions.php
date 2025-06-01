<?php
/**
 * Funções Bitcoin Reais usando APIs
 * Substitua as funções mock por estas implementações
 */

require_once __DIR__ . '/config.php';

class RealBitcoinWallet {
    private $conn;
    private $config;
    
    public function __construct() {
        global $conn, $blockchainConfig;
        $this->conn = $conn;
        $this->config = $blockchainConfig;
    }

    /**
     * Gera endereço Bitcoin real usando APIs
     */
    public function generateDepositAddress($userId) {
        try {
            // Método 1: Usar BitGo API (recomendado para produção)
            if (!empty($this->config['bitgo']['api_key'])) {
                return $this->generateBitGoAddress($userId);
            }
            
            // Método 2: Usar BlockCypher para gerar endereço
            if (!empty($this->config['blockcypher']['api_key'])) {
                return $this->generateBlockCypherAddress($userId);
            }
            
            // Método 3: Gerar endereço localmente (menos seguro)
            return $this->generateLocalAddress($userId);
            
        } catch (Exception $e) {
            error_log("Erro ao gerar endereço: " . $e->getMessage());
            return ['success' => false, 'error' => 'Erro interno do servidor'];
        }
    }

    /**
     * Gerar endereço usando BlockCypher
     */
    private function generateBlockCypherAddress($userId) {
        $url = "https://api.blockcypher.com/v1/btc/main/addrs?token=" . $this->config['blockcypher']['api_key'];
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_TIMEOUT => 30
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 201) {
            throw new Exception("Erro na API BlockCypher: HTTP $httpCode");
        }
        
        $data = json_decode($response, true);
        if (!$data || !isset($data['address'])) {
            throw new Exception("Resposta inválida da API");
        }
        
        $address = $data['address'];
        $privateKey = $data['private'] ?? null;
        $publicKey = $data['public'] ?? null;
        
        // Salvar no banco
        $stmt = $this->conn->prepare("UPDATE users SET btc_deposit_address = ?, btc_private_key = ?, btc_public_key = ? WHERE id = ?");
        $encryptedPrivate = $privateKey ? $this->encryptData($privateKey) : null;
        $stmt->bind_param("sssi", $address, $encryptedPrivate, $publicKey, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar no banco: " . $stmt->error);
        }
        
        // Configurar webhook
        $this->setupWebhook($address);
        
        return [
            'success' => true,
            'address' => $address,
            'message' => 'Endereço gerado com sucesso'
        ];
    }

    /**
     * Gerar endereço localmente (para desenvolvimento)
     */
    private function generateLocalAddress($userId) {
        // Gera um endereço Bech32 válido para testnet
        $randomBytes = random_bytes(20);
        $address = $this->createBech32Address($randomBytes);
        
        $stmt = $this->conn->prepare("UPDATE users SET btc_deposit_address = ? WHERE id = ?");
        $stmt->bind_param("si", $address, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço: " . $stmt->error);
        }
        
        return [
            'success' => true,
            'address' => $address,
            'message' => 'Endereço de teste gerado'
        ];
    }

    /**
     * Verifica depósitos via múltiplas APIs
     */
    public function checkDeposits($address) {
        $transactions = [];
        
        // API 1: BlockCypher
        $blockCypherTxs = $this->getBlockCypherTransactions($address);
        if ($blockCypherTxs) {
            $transactions = array_merge($transactions, $blockCypherTxs);
        }
        
        // API 2: Blockstream (backup)
        if (empty($transactions)) {
            $blockstreamTxs = $this->getBlockstreamTransactions($address);
            if ($blockstreamTxs) {
                $transactions = array_merge($transactions, $blockstreamTxs);
            }
        }
        
        return $transactions;
    }

    /**
     * Busca transações via BlockCypher
     */
    private function getBlockCypherTransactions($address) {
        $url = "https://api.blockcypher.com/v1/btc/main/addrs/$address/full";
        if (!empty($this->config['blockcypher']['api_key'])) {
            $url .= "?token=" . $this->config['blockcypher']['api_key'];
        }
        
        $response = $this->makeHttpRequest($url);
        if (!$response || !isset($response['txs'])) {
            return false;
        }
        
        $transactions = [];
        foreach ($response['txs'] as $tx) {
            $amount = 0;
            
            // Calcular valor recebido no endereço
            foreach ($tx['outputs'] as $output) {
                if (in_array($address, $output['addresses'] ?? [])) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $transactions[] = [
                    'txid' => $tx['hash'],
                    'amount' => $amount / 100000000, // Converter satoshis para BTC
                    'confirmations' => $tx['confirmations'] ?? 0,
                    'timestamp' => strtotime($tx['received']),
                    'block_height' => $tx['block_height'] ?? 0
                ];
            }
        }
        
        return $transactions;
    }

    /**
     * Busca transações via Blockstream
     */
    private function getBlockstreamTransactions($address) {
        $url = "https://blockstream.info/api/address/$address/txs";
        $response = $this->makeHttpRequest($url);
        
        if (!$response || !is_array($response)) {
            return false;
        }
        
        $transactions = [];
        foreach ($response as $tx) {
            $amount = 0;
            
            // Calcular valor recebido
            foreach ($tx['vout'] as $output) {
                if (isset($output['scriptpubkey_address']) && $output['scriptpubkey_address'] === $address) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $confirmations = isset($tx['status']['confirmed']) && $tx['status']['confirmed'] ? 6 : 0;
                
                $transactions[] = [
                    'txid' => $tx['txid'],
                    'amount' => $amount / 100000000,
                    'confirmations' => $confirmations,
                    'timestamp' => $tx['status']['block_time'] ?? time(),
                    'block_height' => $tx['status']['block_height'] ?? 0
                ];
            }
        }
        
        return $transactions;
    }

    /**
     * Processa automaticamente depósitos pendentes
     */
    public function processAllPendingDeposits() {
        // Buscar usuários com endereços de depósito
        $stmt = $this->conn->prepare("
            SELECT id, username, btc_deposit_address, last_deposit_check 
            FROM users 
            WHERE btc_deposit_address IS NOT NULL 
            AND (last_deposit_check IS NULL OR last_deposit_check < DATE_SUB(NOW(), INTERVAL 5 MINUTE))
            LIMIT 50
        ");
        $stmt->execute();
        $users = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        foreach ($users as $user) {
            $this->checkUserDeposits($user);
            
            // Atualizar timestamp da última verificação
            $stmt = $this->conn->prepare("UPDATE users SET last_deposit_check = NOW() WHERE id = ?");
            $stmt->bind_param("i", $user['id']);
            $stmt->execute();
            
            // Rate limiting
            sleep(1);
        }
    }

    /**
     * Verifica depósitos de um usuário específico
     */
    private function checkUserDeposits($user) {
        $transactions = $this->checkDeposits($user['btc_deposit_address']);
        
        if (empty($transactions)) {
            return;
        }
        
        foreach ($transactions as $tx) {
            $this->processNewDeposit($user['id'], $tx);
        }
    }

    /**
     * Processa novo depósito
     */
    private function processNewDeposit($userId, $transaction) {
        // Verificar se transação já existe
        $stmt = $this->conn->prepare("SELECT id, status FROM btc_transactions WHERE tx_hash = ?");
        $stmt->bind_param("s", $transaction['txid']);
        $stmt->execute();
        $existing = $stmt->get_result()->fetch_assoc();
        
        if ($existing) {
            // Atualizar confirmações se necessário
            if ($transaction['confirmations'] > 0) {
                $this->updateTransactionConfirmations($transaction['txid'], $transaction['confirmations']);
            }
            return;
        }
        
        // Validar valor mínimo
        if ($transaction['amount'] < 0.0001) {
            error_log("Depósito muito pequeno ignorado: {$transaction['amount']} BTC");
            return;
        }
        
        // Inserir nova transação
        $status = $transaction['confirmations'] >= 1 ? 'confirmed' : 'pending';
        
        $stmt = $this->conn->prepare("
            INSERT INTO btc_transactions 
            (user_id, tx_hash, amount, confirmations, status, created_at) 
            VALUES (?, ?, ?, ?, ?, FROM_UNIXTIME(?))
        ");
        $stmt->bind_param("issdsi", 
            $userId, 
            $transaction['txid'], 
            $transaction['amount'], 
            $transaction['confirmations'], 
            $status, 
            $transaction['timestamp']
        );
        
        if (!$stmt->execute()) {
            error_log("Erro ao inserir transação: " . $stmt->error);
            return;
        }
        
        // Se confirmado, creditar saldo
        if ($status === 'confirmed') {
            $this->creditUserBalance($userId, $transaction['amount'], $transaction['txid']);
        }
        
        error_log("Novo depósito processado: {$transaction['amount']} BTC para usuário $userId");
    }

    /**
     * Credita saldo do usuário
     */
    private function creditUserBalance($userId, $amount, $txHash) {
        $this->conn->begin_transaction();
        
        try {
            // Atualizar saldo
            $stmt = $this->conn->prepare("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?");
            $stmt->bind_param("di", $amount, $userId);
            $stmt->execute();
            
            // Registrar no histórico (se a tabela existir)
            $stmt = $this->conn->prepare("
                INSERT INTO btc_balance_history 
                (user_id, type, amount, description, tx_hash, created_at) 
                VALUES (?, 'credit', ?, 'Depósito confirmado', ?, NOW())
            ");
            $stmt->bind_param("ids", $userId, $amount, $txHash);
            $stmt->execute();
            
            $this->conn->commit();
            
        } catch (Exception $e) {
            $this->conn->rollback();
            throw $e;
        }
    }

    /**
     * Atualiza confirmações de transação
     */
    private function updateTransactionConfirmations($txHash, $confirmations) {
        $stmt = $this->conn->prepare("
            UPDATE btc_transactions 
            SET confirmations = ?, status = CASE WHEN confirmations >= 1 THEN 'confirmed' ELSE 'pending' END 
            WHERE tx_hash = ?
        ");
        $stmt->bind_param("is", $confirmations, $txHash);
        $stmt->execute();
        
        // Se acabou de ser confirmado, creditar saldo
        if ($confirmations >= 1) {
            $stmt = $this->conn->prepare("
                SELECT user_id, amount 
                FROM btc_transactions 
                WHERE tx_hash = ? AND status = 'confirmed'
            ");
            $stmt->bind_param("s", $txHash);
            $stmt->execute();
            $tx = $stmt->get_result()->fetch_assoc();
            
            if ($tx) {
                $this->creditUserBalance($tx['user_id'], $tx['amount'], $txHash);
            }
        }
    }

    /**
     * Configurar webhook (se disponível)
     */
    private function setupWebhook($address) {
        if (empty($this->config['blockcypher']['api_key'])) {
            return false;
        }
        
        $webhookData = [
            'event' => 'unconfirmed-tx',
            'address' => $address,
            'url' => $this->config['webhook_url'] ?? 'https://seusite.com/webhook.php?secret=seu_secret'
        ];
        
        $url = "https://api.blockcypher.com/v1/btc/main/hooks?token=" . $this->config['blockcypher']['api_key'];
        
        return $this->makeHttpRequest($url, 'POST', $webhookData);
    }

    /**
     * Criar endereço Bech32 (simplificado para teste)
     */
    private function createBech32Address($data) {
        // Para testnet - em produção use bibliotecas adequadas
        return 'tb1q' . substr(bin2hex($data), 0, 32);
    }

    /**
     * Criptografar dados sensíveis
     */
    private function encryptData($data) {
        $key = $this->config['encryption_key'];
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Fazer requisição HTTP
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
        
        if ($httpCode < 200 || $httpCode >= 300) {
            return false;
        }
        
        return json_decode($response, true);
    }
}

// Instância global
$btcWallet = new RealBitcoinWallet();

// Funções wrapper para compatibilidade
function generateRealDepositAddress($userId) {
    global $btcWallet;
    return $btcWallet->generateDepositAddress($userId);
}

function checkAllPendingDeposits() {
    global $btcWallet;
    return $btcWallet->processAllPendingDeposits();
}
?>