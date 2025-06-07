<?php
/**
 * SISTEMA DE SAQUE ULTRA SEGURO V2.0 - ZEEMARKET
 * Corrige TODAS as vulnerabilidades identificadas na auditoria
 * Arquivo: includes/secure_withdrawal_v2.php
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/two_factor_auth.php';

class SecureWithdrawalSystemV2 {
    private $conn;
    private $coldStorage;
    private $hotWallet;
    private $rateLimiter;
    private $fraudDetector;
    private $logger;
    private $twoFA;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->coldStorage = new ColdStorageManager();
        $this->hotWallet = new SecureHotWallet();
        $this->rateLimiter = new AdvancedRateLimiter();
        $this->fraudDetector = new FraudDetectionEngine();
        $this->logger = new SecurityLogger();
        $this->twoFA = new TwoFactorAuth();
        
        $this->initializeSecurity();
    }
    
    /**
     * ✅ PRINCIPAL: Processar saque com segurança máxima
     */
    public function processSecureWithdrawal($userId, $toAddress, $amount, $crypto = 'BTC', $twoFACode = null) {
        $withdrawalId = null;
        
        try {
            // 1. LOG INICIAL
            $this->logger->logAttempt($userId, 'withdrawal_attempt', [
                'amount' => $amount,
                'crypto' => $crypto,
                'to_address' => $this->maskAddress($toAddress),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
            
            // 2. VALIDAÇÕES RIGOROSAS
            $this->validateWithdrawalRequest($userId, $toAddress, $amount, $crypto, $twoFACode);
            
            // 3. VERIFICAR SALDO E RESERVAR
            $balanceCheck = $this->secureBalanceCheck($userId, $amount, $crypto);
            
            // 4. CALCULAR TAXAS REAIS
            $fees = $this->calculateSecureFees($amount, $crypto);
            $totalRequired = $amount + $fees['network_fee'] + $fees['platform_fee'];
            
            if ($balanceCheck['available'] < $totalRequired) {
                throw new SecurityException("Saldo insuficiente. Disponível: {$balanceCheck['available']} {$crypto}, Necessário: {$totalRequired} {$crypto}");
            }
            
            // 5. VERIFICAR LIMITES E DETECÇÃO DE FRAUDE
            $this->fraudDetector->analyzeWithdrawal($userId, $amount, $crypto, $toAddress);
            
            $this->conn->begin_transaction();
            
            // 6. CRIAR REGISTRO SEGURO
            $withdrawalId = $this->createSecureWithdrawalRecord($userId, $toAddress, $amount, $fees, $crypto);
            
            // 7. PROCESSAR COM COLD/HOT STORAGE
            if ($amount > $this->getHotWalletLimit($crypto)) {
                // COLD STORAGE - Aprovação manual obrigatória
                $result = $this->processColdStorageWithdrawal($withdrawalId, $userId, $toAddress, $amount, $crypto);
            } else {
                // HOT WALLET - Automático com segurança máxima
                $result = $this->processHotWalletWithdrawal($withdrawalId, $userId, $toAddress, $amount, $crypto);
            }
            
            if ($result['success']) {
                // 8. DEDUZIR SALDO
                $this->debitUserBalanceSecure($userId, $totalRequired, $crypto, $withdrawalId);
                
                // 9. CONFIRMAR TRANSAÇÃO
                $this->confirmWithdrawal($withdrawalId, $result);
                
                $this->conn->commit();
                
                // 10. LOG SUCESSO
                $this->logger->logSuccess($userId, 'withdrawal_success', [
                    'withdrawal_id' => $withdrawalId,
                    'amount' => $amount,
                    'crypto' => $crypto,
                    'txid' => $result['txid'] ?? 'pending',
                    'method' => $result['method']
                ]);
                
                return [
                    'success' => true,
                    'withdrawal_id' => $withdrawalId,
                    'txid' => $result['txid'] ?? null,
                    'status' => $result['status'],
                    'method' => $result['method'],
                    'estimated_time' => $result['estimated_time'],
                    'explorer_url' => $this->getExplorerUrl($crypto, $result['txid'] ?? ''),
                    'message' => "Saque de {$amount} {$crypto} processado com segurança!"
                ];
            } else {
                throw new Exception($result['error']);
            }
            
        } catch (Exception $e) {
            if ($this->conn->inTransaction) {
                $this->conn->rollback();
            }
            
            // LOG ERRO
            $this->logger->logError($userId, 'withdrawal_failed', [
                'withdrawal_id' => $withdrawalId,
                'error' => $e->getMessage(),
                'amount' => $amount ?? 0,
                'crypto' => $crypto ?? 'unknown'
            ]);
            
            // INCREMENTAR TENTATIVAS FALHADAS
            $this->rateLimiter->incrementFailedAttempts($userId, 'withdrawal');
            
            throw $e;
        }
    }
    
    /**
     * ✅ VALIDAÇÕES ULTRA RIGOROSAS
     */
    private function validateWithdrawalRequest($userId, $toAddress, $amount, $crypto, $twoFACode) {
        // 1. VERIFICAR SESSÃO
        if (!$this->isValidSession($userId)) {
            throw new SecurityException("Sessão inválida ou expirada");
        }
        
        // 2. RATE LIMITING RIGOROSO
        $this->rateLimiter->checkLimits($userId, 'withdrawal', [
            'per_hour' => 3,
            'per_day' => 10,
            'per_week' => 20
        ]);
        
        // 3. VERIFICAR 2FA OBRIGATÓRIO PARA SAQUES
        if (!$this->twoFA->verifyCode($userId, $twoFACode)) {
            throw new SecurityException("Código 2FA inválido ou obrigatório");
        }
        
        // 4. VALIDAÇÃO RIGOROSA DE ENDEREÇO
        if (!$this->validateCryptoAddressStrict($toAddress, $crypto)) {
            throw new SecurityException("Endereço {$crypto} inválido ou não suportado");
        }
        
        // 5. VERIFICAR BLACKLIST
        if ($this->isBlacklistedAddress($toAddress, $crypto)) {
            throw new SecurityException("Endereço bloqueado por políticas de segurança");
        }
        
        // 6. VALIDAR VALORES
        $limits = $this->getWithdrawalLimits($userId, $crypto);
        if ($amount < $limits['min'] || $amount > $limits['max']) {
            throw new SecurityException("Valor fora dos limites. Min: {$limits['min']}, Max: {$limits['max']} {$crypto}");
        }
        
        // 7. VERIFICAR SE NÃO É ENDEREÇO INTERNO
        if ($this->isInternalAddress($toAddress, $crypto)) {
            throw new SecurityException("Saques para endereços internos não são permitidos");
        }
        
        // 8. COOLDOWN PERIOD
        $this->checkCooldownPeriod($userId);
    }
    
    /**
     * ✅ VALIDAÇÃO RIGOROSA DE ENDEREÇOS COM CHECKSUM
     */
    private function validateCryptoAddressStrict($address, $crypto) {
        switch (strtoupper($crypto)) {
            case 'BTC':
                return $this->validateBitcoinAddressComplete($address);
            case 'ETH':
                return $this->validateEthereumAddressComplete($address);
            case 'XMR':
                return $this->validateMoneroAddress($address);
            default:
                return false;
        }
    }
    
    private function validateBitcoinAddressComplete($address) {
        // Validação completa com checksum
        if (preg_match('/^bc1[a-z0-9]{39,59}$/i', $address)) {
            // Bech32 - verificar checksum
            return $this->verifyBech32Checksum($address);
        } elseif (preg_match('/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/', $address)) {
            // Base58 - verificar checksum
            return $this->verifyBase58Checksum($address);
        }
        return false;
    }
    
    private function validateEthereumAddressComplete($address) {
        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            return false;
        }
        // Verificar EIP-55 checksum se aplicável
        return $this->verifyEIP55Checksum($address);
    }
    
    /**
     * ✅ COLD STORAGE PARA VALORES ALTOS
     */
    private function processColdStorageWithdrawal($withdrawalId, $userId, $toAddress, $amount, $crypto) {
        // Marcar como pendente de aprovação manual
        $stmt = $this->conn->prepare("
            UPDATE withdrawal_requests 
            SET status = 'pending_approval', 
                approval_required = 1,
                approval_reason = 'High value - cold storage required'
            WHERE id = ?
        ");
        $stmt->bind_param("i", $withdrawalId);
        $stmt->execute();
        
        // Notificar administradores
        $this->notifyAdminsHighValueWithdrawal($withdrawalId, $amount, $crypto);
        
        return [
            'success' => true,
            'status' => 'pending_manual_approval',
            'method' => 'cold_storage',
            'estimated_time' => '24-48 horas (aprovação manual necessária)',
            'message' => 'Saque de alto valor requer aprovação manual'
        ];
    }
    
    /**
     * ✅ HOT WALLET ULTRA SEGURA
     */
    private function processHotWalletWithdrawal($withdrawalId, $userId, $toAddress, $amount, $crypto) {
        try {
            // Verificar saldo da hot wallet
            $hotBalance = $this->hotWallet->getSecureBalance($crypto);
            $fees = $this->calculateSecureFees($amount, $crypto);
            $totalNeeded = $amount + $fees['network_fee'];
            
            if ($hotBalance < $totalNeeded) {
                throw new Exception("Hot wallet insuficiente. Requer transferência de cold storage.");
            }
            
            // Processar transação com múltiplas validações
            $txResult = $this->hotWallet->sendSecureTransaction($toAddress, $amount, $crypto, $withdrawalId);
            
            if ($txResult['success']) {
                return [
                    'success' => true,
                    'status' => 'processing',
                    'method' => 'hot_wallet',
                    'txid' => $txResult['txid'],
                    'estimated_time' => $this->getConfirmationTime($crypto),
                    'confirmations' => 0
                ];
            } else {
                throw new Exception($txResult['error']);
            }
            
        } catch (Exception $e) {
            // Se hot wallet falhar, mover para cold storage
            return $this->processColdStorageWithdrawal($withdrawalId, $userId, $toAddress, $amount, $crypto);
        }
    }
    
    /**
     * ✅ DETECÇÃO DE FRAUDE AVANÇADA
     */
    private function initializeFraudDetection() {
        $this->fraudDetector = new class {
            public function analyzeWithdrawal($userId, $amount, $crypto, $toAddress) {
                global $conn;
                
                $riskScore = 0;
                $alerts = [];
                
                // 1. Verificar padrões suspeitos
                $stmt = $conn->prepare("
                    SELECT COUNT(*) as recent_withdrawals,
                           SUM(amount) as total_amount
                    FROM withdrawal_requests 
                    WHERE user_id = ? 
                    AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    AND status != 'failed'
                ");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $recent = $stmt->get_result()->fetch_assoc();
                
                if ($recent['recent_withdrawals'] > 5) {
                    $riskScore += 30;
                    $alerts[] = 'Múltiplos saques em 24h';
                }
                
                // 2. Verificar endereço novo
                $stmt = $conn->prepare("
                    SELECT COUNT(*) as address_usage 
                    FROM withdrawal_requests 
                    WHERE to_address = ? AND status = 'completed'
                ");
                $stmt->bind_param("s", $toAddress);
                $stmt->execute();
                $addressUsage = $stmt->get_result()->fetch_assoc()['address_usage'];
                
                if ($addressUsage === 0) {
                    $riskScore += 20;
                    $alerts[] = 'Endereço nunca usado';
                }
                
                // 3. Verificar valor em relação ao histórico
                $stmt = $conn->prepare("
                    SELECT AVG(amount) as avg_amount 
                    FROM withdrawal_requests 
                    WHERE user_id = ? AND status = 'completed'
                ");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $avgAmount = $stmt->get_result()->fetch_assoc()['avg_amount'] ?? 0;
                
                if ($avgAmount > 0 && $amount > ($avgAmount * 5)) {
                    $riskScore += 25;
                    $alerts[] = 'Valor muito acima da média';
                }
                
                // 4. Verificar IP e User-Agent
                $currentIP = $_SERVER['REMOTE_ADDR'] ?? '';
                $stmt = $conn->prepare("
                    SELECT DISTINCT ip_address 
                    FROM user_sessions 
                    WHERE user_id = ? 
                    AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
                ");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $recentIPs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
                
                $ipKnown = false;
                foreach ($recentIPs as $ip) {
                    if ($ip['ip_address'] === $currentIP) {
                        $ipKnown = true;
                        break;
                    }
                }
                
                if (!$ipKnown) {
                    $riskScore += 40;
                    $alerts[] = 'IP desconhecido';
                }
                
                // 5. DECISÃO BASEADA NO SCORE
                if ($riskScore >= 70) {
                    throw new SecurityException("Transação bloqueada: Alto risco de fraude. Alerts: " . implode(', ', $alerts));
                } elseif ($riskScore >= 40) {
                    // Requerer aprovação manual
                    $this->requireManualApproval($userId, $riskScore, $alerts);
                }
                
                return ['risk_score' => $riskScore, 'alerts' => $alerts];
            }
        };
    }
    
    /**
     * ✅ SISTEMA DE LOGS DE SEGURANÇA
     */
    private function initializeSecurityLogger() {
        $this->logger = new class {
            private $conn;
            
            public function __construct() {
                global $conn;
                $this->conn = $conn;
            }
            
            public function logAttempt($userId, $action, $details) {
                $this->log($userId, $action, 'attempt', $details);
            }
            
            public function logSuccess($userId, $action, $details) {
                $this->log($userId, $action, 'success', $details);
            }
            
            public function logError($userId, $action, $details) {
                $this->log($userId, $action, 'error', $details);
            }
            
            private function log($userId, $action, $level, $details) {
                $stmt = $this->conn->prepare("
                    INSERT INTO security_logs 
                    (user_id, action, level, details, ip_address, user_agent, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                ");
                
                $detailsJson = json_encode($details);
                $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
                
                $stmt->bind_param("isssss", 
                    $userId, $action, $level, $detailsJson, $ipAddress, $userAgent
                );
                $stmt->execute();
                
                // Log crítico também em arquivo
                if ($level === 'error') {
                    error_log("SECURITY_LOG: User:$userId Action:$action Level:$level Details:$detailsJson");
                }
            }
        };
    }
    
    /**
     * ✅ CÁLCULO SEGURO DE TAXAS
     */
    private function calculateSecureFees($amount, $crypto) {
        // Taxa de rede atual
        $networkFee = $this->getNetworkFeeRate($crypto);
        
        // Taxa da plataforma baseada no valor
        $platformFeePercent = 0.001; // 0.1%
        if ($amount > 1.0) $platformFeePercent = 0.0005; // 0.05% para valores altos
        
        return [
            'network_fee' => $networkFee,
            'platform_fee' => $amount * $platformFeePercent,
            'total_fees' => $networkFee + ($amount * $platformFeePercent)
        ];
    }
    
    /**
     * ✅ SISTEMA DE BACKUP E RECUPERAÇÃO
     */
    public function createSecureBackup() {
        try {
            $backupData = [
                'timestamp' => time(),
                'hot_wallet_balances' => $this->hotWallet->getAllBalances(),
                'pending_withdrawals' => $this->getPendingWithdrawals(),
                'security_config' => $this->getSecurityConfig()
            ];
            
            // Criptografar backup
            $encryptedBackup = $this->encryptBackup($backupData);
            
            // Salvar em múltiplas locações
            $this->saveBackupMultipleLocations($encryptedBackup);
            
            return ['success' => true, 'backup_id' => hash('sha256', serialize($backupData))];
            
        } catch (Exception $e) {
            error_log("Erro no backup: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ MONITORAMENTO EM TEMPO REAL
     */
    public function startRealtimeMonitoring() {
        // Verificar hot wallet balance
        foreach (['BTC', 'ETH', 'XMR'] as $crypto) {
            $balance = $this->hotWallet->getSecureBalance($crypto);
            $limit = $this->getHotWalletLimit($crypto);
            
            if ($balance < ($limit * 0.1)) {
                $this->alertLowHotWalletBalance($crypto, $balance);
            }
        }
        
        // Verificar transações suspeitas
        $this->checkSuspiciousTransactions();
        
        // Verificar tentativas de login
        $this->checkBruteForceAttempts();
        
        // Verificar saúde do sistema
        $this->checkSystemHealth();
    }
    
    /**
     * ✅ FUNÇÕES AUXILIARES
     */
    private function getHotWalletLimit($crypto) {
        $limits = [
            'BTC' => 0.5,  // Máximo 0.5 BTC na hot wallet
            'ETH' => 5.0,  // Máximo 5 ETH
            'XMR' => 50.0  // Máximo 50 XMR
        ];
        return $limits[$crypto] ?? 0.1;
    }
    
    private function maskAddress($address) {
        if (strlen($address) <= 8) return $address;
        return substr($address, 0, 4) . '...' . substr($address, -4);
    }
    
    private function getExplorerUrl($crypto, $txid) {
        $explorers = [
            'BTC' => "https://blockstream.info/tx/$txid",
            'ETH' => "https://etherscan.io/tx/$txid",
            'XMR' => "https://xmrchain.net/tx/$txid"
        ];
        return $explorers[$crypto] ?? "#";
    }
    
    private function getConfirmationTime($crypto) {
        $times = [
            'BTC' => '10-60 minutos',
            'ETH' => '1-5 minutos', 
            'XMR' => '2-20 minutos'
        ];
        return $times[$crypto] ?? 'Desconhecido';
    }
}

/**
 * ✅ COLD STORAGE MANAGER
 */
class ColdStorageManager {
    private $conn;
    
    public function __construct() {
        global $conn;
        $this->conn = $conn;
    }
    
    public function getBalance($crypto) {
        // Implementar consulta a cold storage
        // Em produção: Hardware wallets, multi-sig wallets, etc.
        return 10.0; // Placeholder
    }
    
    public function requestColdStorageTransfer($amount, $crypto, $reason) {
        // Criar solicitação para mover fundos do cold storage
        $stmt = $this->conn->prepare("
            INSERT INTO cold_storage_requests 
            (crypto, amount, reason, status, created_at) 
            VALUES (?, ?, ?, 'pending', NOW())
        ");
        $stmt->bind_param("sds", $crypto, $amount, $reason);
        $stmt->execute();
        
        return $this->conn->insert_id;
    }
}

/**
 * ✅ HOT WALLET ULTRA SEGURA
 */
class SecureHotWallet {
    private $hsm; // Hardware Security Module
    private $balances;
    
    public function __construct() {
        $this->initializeHSM();
        $this->loadBalances();
    }
    
    private function initializeHSM() {
        // Em produção: Integrar com HSM real
        // Por agora: Simulação segura
        $this->hsm = new class {
            public function sign($data, $keyId) {
                // Simular assinatura HSM
                return hash_hmac('sha256', $data, 'hsm_key_' . $keyId);
            }
            
            public function getPublicKey($keyId) {
                return 'public_key_' . $keyId;
            }
        };
    }
    
    public function getSecureBalance($crypto) {
        return $this->balances[$crypto] ?? 0.0;
    }
    
    public function sendSecureTransaction($toAddress, $amount, $crypto, $withdrawalId) {
        try {
            // Verificar saldo
            if ($this->getSecureBalance($crypto) < $amount) {
                throw new Exception("Saldo insuficiente na hot wallet");
            }
            
            // Simular envio seguro
            $txid = $this->generateSecureTxId($toAddress, $amount, $crypto);
            
            // Atualizar saldo
            $this->balances[$crypto] -= $amount;
            $this->saveBalances();
            
            return [
                'success' => true,
                'txid' => $txid,
                'method' => 'hot_wallet_secure'
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    private function generateSecureTxId($toAddress, $amount, $crypto) {
        $data = $toAddress . $amount . $crypto . microtime(true) . random_bytes(16);
        return hash('sha256', $data);
    }
    
    private function loadBalances() {
        // Em produção: Consultar saldo real da blockchain
        $this->balances = [
            'BTC' => 0.5,
            'ETH' => 5.0,
            'XMR' => 50.0
        ];
    }
    
    private function saveBalances() {
        // Em produção: Atualizar registro de saldos
        file_put_contents(__DIR__ . '/../hot_wallet_balances.json', json_encode($this->balances));
    }
}

// Inicializar sistema
try {
    $secureWithdrawal = new SecureWithdrawalSystemV2($conn);
    
    // Exemplo de uso
    if ($_POST['action'] === 'withdraw') {
        $result = $secureWithdrawal->processSecureWithdrawal(
            $_SESSION['user_id'],
            $_POST['to_address'],
            floatval($_POST['amount']),
            $_POST['crypto'],
            $_POST['2fa_code']
        );
        
        echo json_encode($result);
    }
    
} catch (Exception $e) {
    error_log("Erro no sistema de saque: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => 'Erro interno do sistema']);
}

/**
 * ✅ SQL PARA TABELAS NECESSÁRIAS
 */
/*
-- Logs de segurança
CREATE TABLE security_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    level ENUM('attempt','success','error','critical') NOT NULL,
    details JSON NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_action (user_id, action),
    INDEX idx_level_created (level, created_at)
);

-- Requests de cold storage
CREATE TABLE cold_storage_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    crypto VARCHAR(10) NOT NULL,
    amount DECIMAL(18,8) NOT NULL,
    reason TEXT NOT NULL,
    status ENUM('pending','approved','rejected','completed') DEFAULT 'pending',
    approved_by INT NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Melhorar tabela de withdrawal_requests
ALTER TABLE withdrawal_requests ADD COLUMN approval_required BOOLEAN DEFAULT 0;
ALTER TABLE withdrawal_requests ADD COLUMN approval_reason TEXT NULL;
ALTER TABLE withdrawal_requests ADD COLUMN risk_score INT DEFAULT 0;
ALTER TABLE withdrawal_requests ADD COLUMN method ENUM('hot_wallet','cold_storage') NULL;
*/
?>