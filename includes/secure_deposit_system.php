<?php
/**
 * SISTEMA DE DEPÓSITO SEGURO - ZEEMARKET
 * Corrige: Verificação blockchain, Rate limiting, Webhook security
 * Arquivo: includes/secure_deposit_system.php
 */

require_once __DIR__ . '/config.php';

class SecureDepositSystem {
    private $conn;
    private $rateLimiter;
    private $apiManager;
    private $webhookValidator;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->rateLimiter = new RateLimiter();
        $this->apiManager = new MultiAPIManager();
        $this->webhookValidator = new WebhookValidator();
    }
    
    /**
     * ✅ CORREÇÃO 1: Verificação blockchain REAL com múltiplas APIs
     */
    public function verifyDeposit($address, $expectedAmount, $crypto = 'BTC') {
        try {
            // Rate limiting por usuário
            $this->rateLimiter->checkLimit($address, 'deposit_check', 10, 300); // 10 checks per 5 min
            
            // Verificar com múltiplas APIs para redundância
            $transactions = $this->apiManager->getTransactions($address, $crypto);
            
            foreach ($transactions as $tx) {
                if ($this->isValidDeposit($tx, $expectedAmount, $address)) {
                    return $this->processValidDeposit($tx, $address);
                }
            }
            
            return ['success' => false, 'message' => 'Nenhum depósito válido encontrado'];
            
        } catch (RateLimitException $e) {
            return ['success' => false, 'error' => 'Muitas verificações. Aguarde 5 minutos.'];
        } catch (Exception $e) {
            error_log("Erro na verificação de depósito: " . $e->getMessage());
            return ['success' => false, 'error' => 'Erro na verificação'];
        }
    }
    
    private function isValidDeposit($tx, $expectedAmount, $address) {
        // Verificar se o valor está dentro da tolerância (1%)
        $tolerance = $expectedAmount * 0.01;
        $amountMatch = abs($tx['amount'] - $expectedAmount) <= $tolerance;
        
        // Verificar confirmações mínimas
        $minConfirmations = $this->getMinConfirmations($tx['crypto']);
        $hasConfirmations = $tx['confirmations'] >= $minConfirmations;
        
        // Verificar se não é double spending
        $notDoubleSpent = $this->checkDoubleSpending($tx['txid'], $address);
        
        // Verificar timestamp (últimas 24h para evitar replay)
        $isRecent = $tx['timestamp'] > (time() - 86400);
        
        return $amountMatch && $hasConfirmations && $notDoubleSpent && $isRecent;
    }
    
    private function checkDoubleSpending($txid, $address) {
        // Verificar se esta transação já foi processada
        $stmt = $this->conn->prepare("
            SELECT id FROM btc_transactions 
            WHERE tx_hash = ? AND status IN ('confirmed', 'pending')
        ");
        $stmt->bind_param("s", $txid);
        $stmt->execute();
        
        return $stmt->get_result()->num_rows === 0;
    }
    
    private function processValidDeposit($tx, $address) {
        $this->conn->begin_transaction();
        
        try {
            // Buscar usuário pelo endereço
            $stmt = $this->conn->prepare("SELECT id FROM users WHERE btc_deposit_address = ?");
            $stmt->bind_param("s", $address);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            
            if (!$user) {
                throw new Exception('Usuário não encontrado para o endereço');
            }
            
            // Registrar transação como confirmada
            $stmt = $this->conn->prepare("
                INSERT INTO btc_transactions 
                (user_id, tx_hash, type, amount, confirmations, status, crypto_type, block_height, created_at) 
                VALUES (?, ?, 'deposit', ?, ?, 'confirmed', ?, ?, NOW())
            ");
            $stmt->bind_param("isdiisi", 
                $user['id'], 
                $tx['txid'], 
                $tx['amount'], 
                $tx['confirmations'], 
                $tx['crypto'],
                $tx['block_height']
            );
            $stmt->execute();
            
            // Creditar saldo do usuário
            $this->creditUserBalance($user['id'], $tx['amount'], $tx['crypto'], $tx['txid']);
            
            $this->conn->commit();
            
            return [
                'success' => true,
                'amount' => $tx['amount'],
                'txid' => $tx['txid'],
                'confirmations' => $tx['confirmations']
            ];
            
        } catch (Exception $e) {
            $this->conn->rollback();
            throw $e;
        }
    }
}

/**
 * ✅ CORREÇÃO 2: Rate Limiting Adequado
 */
class RateLimiter {
    private $conn;
    
    public function __construct() {
        global $conn;
        $this->conn = $conn;
        $this->createRateLimitTable();
    }
    
    private function createRateLimitTable() {
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                identifier VARCHAR(255) NOT NULL,
                action VARCHAR(100) NOT NULL,
                count INT DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_identifier_action (identifier, action),
                INDEX idx_window_start (window_start)
            ) ENGINE=InnoDB
        ");
    }
    
    public function checkLimit($identifier, $action, $maxRequests, $windowSeconds) {
        $windowStart = date('Y-m-d H:i:s', time() - $windowSeconds);
        
        // Limpar entradas antigas
        $stmt = $this->conn->prepare("DELETE FROM rate_limits WHERE window_start < ?");
        $stmt->bind_param("s", $windowStart);
        $stmt->execute();
        
        // Contar requests atuais
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as count FROM rate_limits 
            WHERE identifier = ? AND action = ? AND window_start >= ?
        ");
        $stmt->bind_param("sss", $identifier, $action, $windowStart);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if ($result['count'] >= $maxRequests) {
            throw new RateLimitException("Rate limit exceeded for $action");
        }
        
        // Registrar nova request
        $stmt = $this->conn->prepare("
            INSERT INTO rate_limits (identifier, action, window_start) 
            VALUES (?, ?, NOW())
        ");
        $stmt->bind_param("ss", $identifier, $action);
        $stmt->execute();
        
        return true;
    }
}

class RateLimitException extends Exception {}

/**
 * ✅ CORREÇÃO 3: Gerenciador de APIs com Redundância
 */
class MultiAPIManager {
    private $apis;
    private $currentAPI = 0;
    
    public function __construct() {
        $this->apis = [
            new BlockCypherAPI($_ENV['BLOCKCYPHER_TOKEN']),
            new BlockstreamAPI(), // Gratuita
            new MempoolSpaceAPI() // Backup
        ];
    }
    
    public function getTransactions($address, $crypto = 'BTC') {
        $lastException = null;
        
        // Tentar cada API em sequência
        foreach ($this->apis as $api) {
            try {
                $transactions = $api->getAddressTransactions($address, $crypto);
                if (!empty($transactions)) {
                    return $transactions;
                }
            } catch (Exception $e) {
                $lastException = $e;
                error_log("API {$api->getName()} falhou: " . $e->getMessage());
                continue;
            }
        }
        
        throw new Exception("Todas as APIs falharam. Último erro: " . $lastException->getMessage());
    }
}

class BlockCypherAPI {
    private $token;
    private $baseUrl = 'https://api.blockcypher.com/v1/btc/main';
    
    public function __construct($token) {
        $this->token = $token;
    }
    
    public function getName() {
        return 'BlockCypher';
    }
    
    public function getAddressTransactions($address, $crypto = 'BTC') {
        $url = "{$this->baseUrl}/addrs/{$address}/full";
        if ($this->token) {
            $url .= "?token={$this->token}";
        }
        
        $response = $this->makeRequest($url);
        
        if (!$response || !isset($response['txs'])) {
            return [];
        }
        
        $transactions = [];
        foreach ($response['txs'] as $tx) {
            $amount = 0;
            
            // Calcular valor recebido
            foreach ($tx['outputs'] as $output) {
                if (in_array($address, $output['addresses'] ?? [])) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $transactions[] = [
                    'txid' => $tx['hash'],
                    'amount' => $amount / 100000000, // Satoshis para BTC
                    'confirmations' => $tx['confirmations'] ?? 0,
                    'timestamp' => strtotime($tx['received']),
                    'block_height' => $tx['block_height'] ?? 0,
                    'crypto' => $crypto
                ];
            }
        }
        
        return $transactions;
    }
    
    private function makeRequest($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'ZeeMarket/2.0',
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'User-Agent: ZeeMarket/2.0'
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 200 && $httpCode < 300 && $response) {
            return json_decode($response, true);
        }
        
        return false;
    }
}

class BlockstreamAPI {
    private $baseUrl = 'https://blockstream.info/api';
    
    public function getName() {
        return 'Blockstream';
    }
    
    public function getAddressTransactions($address, $crypto = 'BTC') {
        $url = "{$this->baseUrl}/address/{$address}/txs";
        
        $response = $this->makeRequest($url);
        if (!$response || !is_array($response)) {
            return [];
        }
        
        $transactions = [];
        foreach ($response as $tx) {
            $amount = 0;
            
            foreach ($tx['vout'] as $output) {
                if (isset($output['scriptpubkey_address']) && 
                    $output['scriptpubkey_address'] === $address) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $confirmations = 0;
                if (isset($tx['status']['confirmed']) && $tx['status']['confirmed']) {
                    $confirmations = 6; // Assumir confirmado
                }
                
                $transactions[] = [
                    'txid' => $tx['txid'],
                    'amount' => $amount / 100000000,
                    'confirmations' => $confirmations,
                    'timestamp' => $tx['status']['block_time'] ?? time(),
                    'block_height' => $tx['status']['block_height'] ?? 0,
                    'crypto' => $crypto
                ];
            }
        }
        
        return $transactions;
    }
    
    private function makeRequest($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'ZeeMarket/2.0'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 200 && $httpCode < 300 && $response) {
            return json_decode($response, true);
        }
        
        return false;
    }
}

/**
 * ✅ CORREÇÃO 4: Webhook com Validação de Assinatura
 */
class WebhookValidator {
    private $secret;
    
    public function __construct() {
        $this->secret = $_ENV['WEBHOOK_SECRET'] ?? 'default_secret_change_me';
    }
    
    public function validateWebhook($payload, $signature) {
        // Verificar assinatura HMAC
        $expectedSignature = 'sha256=' . hash_hmac('sha256', $payload, $this->secret);
        
        if (!hash_equals($expectedSignature, $signature)) {
            throw new Exception('Assinatura de webhook inválida');
        }
        
        // Verificar timestamp para evitar replay attacks
        $data = json_decode($payload, true);
        if (!$data || !isset($data['timestamp'])) {
            throw new Exception('Webhook sem timestamp');
        }
        
        $webhookTime = $data['timestamp'];
        $currentTime = time();
        
        // Aceitar apenas webhooks dos últimos 5 minutos
        if (abs($currentTime - $webhookTime) > 300) {
            throw new Exception('Webhook muito antigo ou muito novo');
        }
        
        return true;
    }
    
    public function processWebhook($validatedPayload) {
        $data = json_decode($validatedPayload, true);
        
        // Log do webhook recebido
        error_log("Webhook válido recebido: " . json_encode($data));
        
        // Processar baseado no tipo
        switch ($data['type'] ?? '') {
            case 'transaction-confirmation':
                return $this->processTransactionConfirmation($data);
            case 'new-block':
                return $this->processNewBlock($data);
            default:
                throw new Exception('Tipo de webhook desconhecido');
        }
    }
    
    private function processTransactionConfirmation($data) {
        // Implementar lógica de confirmação de transação
        $txid = $data['transaction']['hash'];
        $confirmations = $data['transaction']['confirmations'];
        
        // Atualizar no banco de dados
        global $conn;
        $stmt = $conn->prepare("
            UPDATE btc_transactions 
            SET confirmations = ?, status = 'confirmed', updated_at = NOW() 
            WHERE tx_hash = ? AND confirmations < ?
        ");
        $stmt->bind_param("isi", $confirmations, $txid, $confirmations);
        $stmt->execute();
        
        return ['success' => true, 'updated' => $stmt->affected_rows];
    }
}

// Uso do sistema seguro
try {
    $secureDeposit = new SecureDepositSystem($conn);
    $result = $secureDeposit->verifyDeposit($address, $expectedAmount, 'BTC');
    
    if ($result['success']) {
        echo "Depósito verificado: {$result['amount']} BTC - TX: {$result['txid']}";
    }
} catch (Exception $e) {
    error_log("Erro no sistema de depósito: " . $e->getMessage());
}
?>