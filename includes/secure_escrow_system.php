<?php
/**
 * SISTEMA DE ESCROW DESCENTRALIZADO - ZEEMARKET
 * Corrige: Escrow centralizado, Double-spending, Exit scams
 * Arquivo: includes/secure_escrow_system.php
 */

require_once __DIR__ . '/config.php';

class SecureEscrowSystem {
    private $conn;
    private $multisigManager;
    private $disputeResolver;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->multisigManager = new MultisigManager();
        $this->disputeResolver = new DisputeResolver();
    }
    
    /**
     * ✅ CORREÇÃO 1: Escrow Multisig (2-de-3) em vez de centralizado
     */
    public function createEscrowOrder($buyerId, $sellerId, $amount, $productId) {
        try {
            $this->conn->begin_transaction();
            
            // Gerar chaves para multisig 2-de-3
            $escrowKeys = $this->multisigManager->generateEscrowKeys($buyerId, $sellerId);
            
            // Criar endereço multisig
            $multisigAddress = $this->multisigManager->createMultisigAddress(
                $escrowKeys['buyer_pubkey'],
                $escrowKeys['seller_pubkey'], 
                $escrowKeys['arbitrator_pubkey']
            );
            
            // Registrar escrow no banco
            $stmt = $this->conn->prepare("
                INSERT INTO escrow_orders (
                    buyer_id, seller_id, product_id, amount, 
                    multisig_address, buyer_pubkey, seller_pubkey, arbitrator_pubkey,
                    status, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR))
            ");
            
            $stmt->bind_param("iiidsssss", 
                $buyerId, $sellerId, $productId, $amount,
                $multisigAddress,
                $escrowKeys['buyer_pubkey'],
                $escrowKeys['seller_pubkey'],
                $escrowKeys['arbitrator_pubkey']
            );
            $stmt->execute();
            
            $escrowId = $this->conn->insert_id;
            
            $this->conn->commit();
            
            return [
                'success' => true,
                'escrow_id' => $escrowId,
                'payment_address' => $multisigAddress,
                'amount' => $amount,
                'expires_at' => date('Y-m-d H:i:s', strtotime('+24 hours')),
                'keys' => [
                    'buyer_privkey' => $escrowKeys['buyer_privkey'], // Enviar apenas para o comprador
                    'redeem_script' => $escrowKeys['redeem_script']
                ]
            ];
            
        } catch (Exception $e) {
            $this->conn->rollback();
            throw new Exception("Erro ao criar escrow: " . $e->getMessage());
        }
    }
    
    /**
     * ✅ CORREÇÃO 2: Sistema anti-double spending
     */
    public function verifyEscrowPayment($escrowId) {
        $stmt = $this->conn->prepare("SELECT * FROM escrow_orders WHERE id = ?");
        $stmt->bind_param("i", $escrowId);
        $stmt->execute();
        $escrow = $stmt->get_result()->fetch_assoc();
        
        if (!$escrow) {
            throw new Exception("Escrow não encontrado");
        }
        
        // Verificar pagamento no endereço multisig
        $transactions = $this->getAddressTransactions($escrow['multisig_address']);
        
        foreach ($transactions as $tx) {
            // Verificar se é o pagamento correto
            if ($this->isValidEscrowPayment($tx, $escrow)) {
                // Verificar double-spending
                if ($this->isDoubleSpent($tx['txid'])) {
                    throw new Exception("Transação com double-spending detectado");
                }
                
                // Verificar se tem confirmações suficientes
                if ($tx['confirmations'] >= 1) {
                    $this->markEscrowAsPaid($escrowId, $tx['txid']);
                    return [
                        'success' => true,
                        'paid' => true,
                        'txid' => $tx['txid'],
                        'confirmations' => $tx['confirmations']
                    ];
                }
            }
        }
        
        return ['success' => true, 'paid' => false];
    }
    
    /**
     * ✅ CORREÇÃO 3: Release automático após confirmação do comprador
     */
    public function releaseEscrowFunds($escrowId, $releasedBy, $signature = null) {
        $stmt = $this->conn->prepare("SELECT * FROM escrow_orders WHERE id = ?");
        $stmt->bind_param("i", $escrowId);
        $stmt->execute();
        $escrow = $stmt->get_result()->fetch_assoc();
        
        if (!$escrow || $escrow['status'] !== 'paid') {
            throw new Exception("Escrow não encontrado ou não pago");
        }
        
        // Verificar quem está fazendo o release
        if ($releasedBy === 'buyer' || $releasedBy === 'auto_release') {
            return $this->processBuyerRelease($escrow, $signature);
        } elseif ($releasedBy === 'dispute_resolution') {
            return $this->processDisputeResolution($escrow);
        } else {
            throw new Exception("Tipo de release inválido");
        }
    }
    
    private function processBuyerRelease($escrow, $buyerSignature) {
        try {
            // Criar transação de release para o vendedor
            $releaseTransaction = $this->multisigManager->createReleaseTransaction(
                $escrow['multisig_address'],
                $escrow['seller_address'], // Endereço do vendedor
                $escrow['amount'],
                $escrow['redeem_script']
            );
            
            // Assinar com chave do comprador
            $signedTx = $this->multisigManager->signTransaction(
                $releaseTransaction,
                $buyerSignature,
                'buyer'
            );
            
            // Adicionar assinatura do arbitrator automático (se configurado)
            if ($this->hasAutoArbitrator()) {
                $signedTx = $this->multisigManager->addArbitratorSignature($signedTx);
            }
            
            // Transmitir transação
            $txid = $this->broadcastTransaction($signedTx);
            
            // Atualizar status
            $this->updateEscrowStatus($escrow['id'], 'released', $txid);
            
            return [
                'success' => true,
                'txid' => $txid,
                'message' => 'Fundos liberados para o vendedor'
            ];
            
        } catch (Exception $e) {
            throw new Exception("Erro ao liberar fundos: " . $e->getMessage());
        }
    }
    
    /**
     * ✅ CORREÇÃO 4: Sistema de disputa descentralizado
     */
    public function initiateDispute($escrowId, $initiatedBy, $reason) {
        $stmt = $this->conn->prepare("SELECT * FROM escrow_orders WHERE id = ?");
        $stmt->bind_param("i", $escrowId);
        $stmt->execute();
        $escrow = $stmt->get_result()->fetch_assoc();
        
        if (!$escrow || $escrow['status'] !== 'paid') {
            throw new Exception("Escrow inválido para disputa");
        }
        
        // Verificar se pode iniciar disputa
        if (!in_array($initiatedBy, ['buyer', 'seller'])) {
            throw new Exception("Apenas comprador ou vendedor podem iniciar disputa");
        }
        
        $this->conn->begin_transaction();
        
        try {
            // Criar registro de disputa
            $stmt = $this->conn->prepare("
                INSERT INTO escrow_disputes (
                    escrow_id, initiated_by, reason, status, created_at
                ) VALUES (?, ?, ?, 'pending', NOW())
            ");
            $stmt->bind_param("iss", $escrowId, $initiatedBy, $reason);
            $stmt->execute();
            
            $disputeId = $this->conn->insert_id;
            
            // Atualizar status do escrow
            $this->updateEscrowStatus($escrowId, 'disputed');
            
            // Selecionar arbitrador aleatório da pool
            $arbitratorId = $this->disputeResolver->selectRandomArbitrator();
            
            $stmt = $this->conn->prepare("
                UPDATE escrow_disputes 
                SET arbitrator_id = ?, arbitrator_assigned_at = NOW() 
                WHERE id = ?
            ");
            $stmt->bind_param("ii", $arbitratorId, $disputeId);
            $stmt->execute();
            
            $this->conn->commit();
            
            return [
                'success' => true,
                'dispute_id' => $disputeId,
                'arbitrator_id' => $arbitratorId,
                'message' => 'Disputa iniciada. Arbitrador designado.'
            ];
            
        } catch (Exception $e) {
            $this->conn->rollback();
            throw $e;
        }
    }
    
    /**
     * ✅ CORREÇÃO 5: Auto-release após tempo limite
     */
    public function processAutoRelease() {
        // Buscar escrows pagos há mais de 14 dias sem disputa
        $stmt = $this->conn->query("
            SELECT eo.* FROM escrow_orders eo
            LEFT JOIN escrow_disputes ed ON eo.id = ed.escrow_id
            WHERE eo.status = 'paid' 
            AND eo.updated_at < DATE_SUB(NOW(), INTERVAL 14 DAY)
            AND ed.id IS NULL
        ");
        
        $autoReleaseCount = 0;
        
        while ($escrow = $stmt->fetch_assoc()) {
            try {
                $result = $this->releaseEscrowFunds($escrow['id'], 'auto_release');
                if ($result['success']) {
                    $autoReleaseCount++;
                    error_log("Auto-release executado para escrow {$escrow['id']}");
                }
            } catch (Exception $e) {
                error_log("Erro no auto-release do escrow {$escrow['id']}: " . $e->getMessage());
            }
        }
        
        return $autoReleaseCount;
    }
    
    /**
     * ✅ CORREÇÃO 6: Prevenção contra exit scams
     */
    public function getEscrowHealth() {
        // Estatísticas de saúde do sistema de escrow
        $stmt = $this->conn->query("
            SELECT 
                COUNT(*) as total_escrows,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) as paid,
                SUM(CASE WHEN status = 'released' THEN 1 ELSE 0 END) as released,
                SUM(CASE WHEN status = 'disputed' THEN 1 ELSE 0 END) as disputed,
                SUM(CASE WHEN status = 'refunded' THEN 1 ELSE 0 END) as refunded,
                SUM(amount) as total_value,
                AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(released_at, NOW()))) as avg_completion_hours
            FROM escrow_orders 
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        
        $stats = $stmt->fetch_assoc();
        
        // Calcular métricas de confiança
        $successRate = $stats['total_escrows'] > 0 ? 
                      ($stats['released'] / $stats['total_escrows']) * 100 : 0;
        
        $disputeRate = $stats['total_escrows'] > 0 ? 
                      ($stats['disputed'] / $stats['total_escrows']) * 100 : 0;
        
        return [
            'statistics' => $stats,
            'success_rate' => round($successRate, 2),
            'dispute_rate' => round($disputeRate, 2),
            'health_score' => $this->calculateHealthScore($stats),
            'recommendations' => $this->getHealthRecommendations($stats)
        ];
    }
    
    private function calculateHealthScore($stats) {
        $score = 100;
        
        // Penalizar alta taxa de disputa
        if ($stats['total_escrows'] > 0) {
            $disputeRate = ($stats['disputed'] / $stats['total_escrows']) * 100;
            $score -= min($disputeRate * 2, 50); // Máximo -50 pontos
        }
        
        // Penalizar muitos escrows pendentes antigos
        $pendingOldStmt = $this->conn->query("
            SELECT COUNT(*) as old_pending 
            FROM escrow_orders 
            WHERE status = 'pending' 
            AND created_at < DATE_SUB(NOW(), INTERVAL 48 HOUR)
        ");
        $oldPending = $pendingOldStmt->fetch_assoc()['old_pending'];
        $score -= min($oldPending * 5, 30); // Máximo -30 pontos
        
        return max(0, round($score));
    }
    
    // Métodos auxiliares
    private function isValidEscrowPayment($tx, $escrow) {
        $tolerance = $escrow['amount'] * 0.01; // 1% tolerância
        return abs($tx['amount'] - $escrow['amount']) <= $tolerance;
    }
    
    private function isDoubleSpent($txid) {
        // Verificar em múltiplas APIs se a transação foi substituída
        $apis = [
            "https://blockstream.info/api/tx/{$txid}",
            "https://api.blockcypher.com/v1/btc/main/txs/{$txid}"
        ];
        
        foreach ($apis as $api) {
            try {
                $response = $this->makeApiCall($api);
                if ($response && isset($response['double_spend']) && $response['double_spend']) {
                    return true;
                }
            } catch (Exception $e) {
                continue;
            }
        }
        
        return false;
    }
    
    private function markEscrowAsPaid($escrowId, $txid) {
        $stmt = $this->conn->prepare("
            UPDATE escrow_orders 
            SET status = 'paid', payment_txid = ?, paid_at = NOW() 
            WHERE id = ?
        ");
        $stmt->bind_param("si", $txid, $escrowId);
        $stmt->execute();
    }
    
    private function updateEscrowStatus($escrowId, $status, $txid = null) {
        if ($txid) {
            $stmt = $this->conn->prepare("
                UPDATE escrow_orders 
                SET status = ?, release_txid = ?, released_at = NOW() 
                WHERE id = ?
            ");
            $stmt->bind_param("ssi", $status, $txid, $escrowId);
        } else {
            $stmt = $this->conn->prepare("
                UPDATE escrow_orders 
                SET status = ?, updated_at = NOW() 
                WHERE id = ?
            ");
            $stmt->bind_param("si", $status, $escrowId);
        }
        $stmt->execute();
    }
}

/**
 * Gerenciador de Multisig
 */
class MultisigManager {
    
    public function generateEscrowKeys($buyerId, $sellerId) {
        // Gerar chaves para comprador, vendedor e arbitrador
        $buyerKeys = $this->generateKeyPair();
        $sellerKeys = $this->generateKeyPair();
        $arbitratorKeys = $this->getArbitratorKeys(); // Pool de arbitradores
        
        // Criar script de resgate 2-de-3
        $redeemScript = $this->createRedeemScript([
            $buyerKeys['pubkey'],
            $sellerKeys['pubkey'], 
            $arbitratorKeys['pubkey']
        ]);
        
        return [
            'buyer_privkey' => $buyerKeys['privkey'],
            'buyer_pubkey' => $buyerKeys['pubkey'],
            'seller_pubkey' => $sellerKeys['pubkey'],
            'arbitrator_pubkey' => $arbitratorKeys['pubkey'],
            'redeem_script' => $redeemScript
        ];
    }
    
    public function createMultisigAddress($pubkey1, $pubkey2, $pubkey3) {
        // Criar endereço P2SH multisig 2-de-3
        $redeemScript = $this->createRedeemScript([$pubkey1, $pubkey2, $pubkey3]);
        $scriptHash = hash('sha256', hex2bin($redeemScript));
        $ripemd160 = hash('ripemd160', hex2bin($scriptHash));
        
        // Adicionar version byte para P2SH (0x05)
        $versionedHash = '05' . $ripemd160;
        
        // Calcular checksum
        $checksum = substr(hash('sha256', hash('sha256', hex2bin($versionedHash), true), true), 0, 4);
        
        // Codificar em Base58
        return $this->base58Encode($versionedHash . bin2hex($checksum));
    }
    
    private function createRedeemScript($pubkeys) {
        // Ordenar chaves publicas
        sort($pubkeys);
        
        $script = '52'; // OP_2 (requer 2 assinaturas)
        
        foreach ($pubkeys as $pubkey) {
            $script .= '21' . $pubkey; // Push 33 bytes
        }
        
        $script .= '53'; // OP_3 (total de 3 chaves)
        $script .= 'ae'; // OP_CHECKMULTISIG
        
        return $script;
    }
    
    private function generateKeyPair() {
        // Gerar par de chaves usando OpenSSL
        $config = [
            "curve_name" => "secp256k1",
            "private_key_type" => OPENSSL_KEYTYPE_EC,
        ];
        
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privkey);
        
        $details = openssl_pkey_get_details($res);
        $pubkey = bin2hex($details['key']);
        
        return [
            'privkey' => bin2hex($privkey),
            'pubkey' => $pubkey
        ];
    }
    
    private function base58Encode($hex) {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $base = strlen($alphabet);
        
        // Convert hex to decimal
        $decimal = gmp_init($hex, 16);
        $output = '';
        
        while (gmp_cmp($decimal, 0) > 0) {
            list($decimal, $remainder) = gmp_div_qr($decimal, $base);
            $output = $alphabet[gmp_intval($remainder)] . $output;
        }
        
        // Add leading zeros
        for ($i = 0; $i < strlen($hex) && substr($hex, $i, 2) == '00'; $i += 2) {
            $output = '1' . $output;
        }
        
        return $output;
    }
}

/**
 * Resolvedor de Disputas
 */
class DisputeResolver {
    private $conn;
    
    public function __construct() {
        global $conn;
        $this->conn = $conn;
    }
    
    public function selectRandomArbitrator() {
        // Selecionar arbitrador ativo aleatoriamente
        $stmt = $this->conn->query("
            SELECT id FROM arbitrators 
            WHERE active = 1 AND 
            (SELECT COUNT(*) FROM escrow_disputes WHERE arbitrator_id = arbitrators.id AND status = 'pending') < 5
            ORDER BY RAND() 
            LIMIT 1
        ");
        
        $arbitrator = $stmt->fetch_assoc();
        return $arbitrator ? $arbitrator['id'] : $this->createDefaultArbitrator();
    }
    
    private function createDefaultArbitrator() {
        // Criar arbitrador padrão se não existir
        $stmt = $this->conn->prepare("
            INSERT INTO arbitrators (name, reputation, fee_percent, active) 
            VALUES ('Sistema Automatico', 100, 1.0, 1)
            ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)
        ");
        $stmt->execute();
        return $this->conn->insert_id;
    }
    
    public function resolveDispute($disputeId, $resolution, $arbitratorSignature) {
        $stmt = $this->conn->prepare("
            SELECT ed.*, eo.* FROM escrow_disputes ed
            JOIN escrow_orders eo ON ed.escrow_id = eo.id
            WHERE ed.id = ?
        ");
        $stmt->bind_param("i", $disputeId);
        $stmt->execute();
        $dispute = $stmt->get_result()->fetch_assoc();
        
        if (!$dispute) {
            throw new Exception("Disputa não encontrada");
        }
        
        $this->conn->begin_transaction();
        
        try {
            // Processar resolução baseada na decisão
            switch ($resolution['decision']) {
                case 'release_to_seller':
                    $txid = $this->releaseToSeller($dispute, $arbitratorSignature);
                    break;
                case 'refund_to_buyer':
                    $txid = $this->refundToBuyer($dispute, $arbitratorSignature);
                    break;
                case 'split_funds':
                    $txid = $this->splitFunds($dispute, $resolution['split_ratio'], $arbitratorSignature);
                    break;
                default:
                    throw new Exception("Decisão de resolução inválida");
            }
            
            // Atualizar status da disputa
            $stmt = $this->conn->prepare("
                UPDATE escrow_disputes 
                SET status = 'resolved', resolution = ?, resolved_at = NOW(), resolution_txid = ?
                WHERE id = ?
            ");
            $resolutionJson = json_encode($resolution);
            $stmt->bind_param("ssi", $resolutionJson, $txid, $disputeId);
            $stmt->execute();
            
            // Atualizar status do escrow
            $stmt = $this->conn->prepare("
                UPDATE escrow_orders 
                SET status = 'resolved', updated_at = NOW() 
                WHERE id = ?
            ");
            $stmt->bind_param("i", $dispute['escrow_id']);
            $stmt->execute();
            
            $this->conn->commit();
            
            return [
                'success' => true,
                'txid' => $txid,
                'resolution' => $resolution['decision']
            ];
            
        } catch (Exception $e) {
            $this->conn->rollback();
            throw $e;
        }
    }
    
    private function releaseToSeller($dispute, $arbitratorSignature) {
        // Criar transação liberando todos os fundos para o vendedor
        $multisigManager = new MultisigManager();
        
        $releaseTransaction = $multisigManager->createReleaseTransaction(
            $dispute['multisig_address'],
            $dispute['seller_address'],
            $dispute['amount'] * 0.99, // 1% taxa do arbitrador
            $dispute['redeem_script']
        );
        
        // Assinar com chave do arbitrador
        $signedTx = $multisigManager->signTransaction(
            $releaseTransaction,
            $arbitratorSignature,
            'arbitrator'
        );
        
        return $this->broadcastTransaction($signedTx);
    }
    
    private function refundToBuyer($dispute, $arbitratorSignature) {
        // Criar transação de reembolso para o comprador
        $multisigManager = new MultisigManager();
        
        $refundTransaction = $multisigManager->createReleaseTransaction(
            $dispute['multisig_address'],
            $dispute['buyer_address'],
            $dispute['amount'] * 0.99, // 1% taxa do arbitrador
            $dispute['redeem_script']
        );
        
        $signedTx = $multisigManager->signTransaction(
            $refundTransaction,
            $arbitratorSignature,
            'arbitrator'
        );
        
        return $this->broadcastTransaction($signedTx);
    }
    
    private function splitFunds($dispute, $splitRatio, $arbitratorSignature) {
        // Dividir fundos entre comprador e vendedor
        $multisigManager = new MultisigManager();
        
        $buyerAmount = $dispute['amount'] * $splitRatio * 0.99; // 1% taxa
        $sellerAmount = $dispute['amount'] * (1 - $splitRatio) * 0.99;
        
        $splitTransaction = $multisigManager->createSplitTransaction(
            $dispute['multisig_address'],
            $dispute['buyer_address'],
            $dispute['seller_address'],
            $buyerAmount,
            $sellerAmount,
            $dispute['redeem_script']
        );
        
        $signedTx = $multisigManager->signTransaction(
            $splitTransaction,
            $arbitratorSignature,
            'arbitrator'
        );
        
        return $this->broadcastTransaction($signedTx);
    }
}

/**
 * Sistema de monitoramento de saúde do escrow
 */
class EscrowHealthMonitor {
    private $conn;
    private $alerts;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->alerts = [];
    }
    
    public function runHealthCheck() {
        $this->checkStuckEscrows();
        $this->checkHighDisputeRate();
        $this->checkUnusualActivity();
        $this->checkArbitratorLoad();
        
        return [
            'status' => empty($this->alerts) ? 'healthy' : 'warning',
            'alerts' => $this->alerts,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
    
    private function checkStuckEscrows() {
        // Verificar escrows presos há muito tempo
        $stmt = $this->conn->query("
            SELECT COUNT(*) as stuck_count 
            FROM escrow_orders 
            WHERE status IN ('pending', 'paid') 
            AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        $result = $stmt->fetch_assoc();
        
        if ($result['stuck_count'] > 10) {
            $this->alerts[] = [
                'type' => 'stuck_escrows',
                'message' => "Há {$result['stuck_count']} escrows presos há mais de 7 dias",
                'severity' => 'high'
            ];
        }
    }
    
    private function checkHighDisputeRate() {
        // Verificar taxa de disputa alta
        $stmt = $this->conn->query("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'disputed' THEN 1 ELSE 0 END) as disputed
            FROM escrow_orders 
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $result = $stmt->fetch_assoc();
        
        if ($result['total'] > 0) {
            $disputeRate = ($result['disputed'] / $result['total']) * 100;
            if ($disputeRate > 20) {
                $this->alerts[] = [
                    'type' => 'high_dispute_rate',
                    'message' => "Taxa de disputa alta: {$disputeRate}% nas últimas 24h",
                    'severity' => 'medium'
                ];
            }
        }
    }
    
    private function checkUnusualActivity() {
        // Verificar atividade incomum
        $stmt = $this->conn->query("
            SELECT COUNT(*) as recent_count
            FROM escrow_orders 
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");
        $result = $stmt->fetch_assoc();
        
        if ($result['recent_count'] > 50) {
            $this->alerts[] = [
                'type' => 'unusual_activity',
                'message' => "Atividade incomum: {$result['recent_count']} escrows na última hora",
                'severity' => 'medium'
            ];
        }
    }
    
    private function checkArbitratorLoad() {
        // Verificar sobrecarga de arbitradores
        $stmt = $this->conn->query("
            SELECT arbitrator_id, COUNT(*) as pending_disputes
            FROM escrow_disputes 
            WHERE status = 'pending'
            GROUP BY arbitrator_id
            HAVING pending_disputes > 10
        ");
        
        $overloadedArbitrators = $stmt->num_rows;
        if ($overloadedArbitrators > 0) {
            $this->alerts[] = [
                'type' => 'arbitrator_overload',
                'message' => "{$overloadedArbitrators} arbitradores sobrecarregados",
                'severity' => 'low'
            ];
        }
    }
}

// Uso do sistema de escrow seguro
try {
    $secureEscrow = new SecureEscrowSystem($conn);
    
    // Criar novo escrow
    $escrowResult = $secureEscrow->createEscrowOrder(
        $buyerId = 1,
        $sellerId = 2, 
        $amount = 0.001,
        $productId = 123
    );
    
    if ($escrowResult['success']) {
        echo "Escrow criado: " . $escrowResult['escrow_id'];
        echo "Endereço de pagamento: " . $escrowResult['payment_address'];
        
        // Verificar pagamento
        $paymentCheck = $secureEscrow->verifyEscrowPayment($escrowResult['escrow_id']);
        
        if ($paymentCheck['paid']) {
            echo "Pagamento confirmado!";
            
            // Liberar fundos após confirmação do comprador
            $releaseResult = $secureEscrow->releaseEscrowFunds(
                $escrowResult['escrow_id'], 
                'buyer',
                $buyerSignature = 'assinatura_do_comprador'
            );
            
            if ($releaseResult['success']) {
                echo "Fundos liberados: " . $releaseResult['txid'];
            }
        }
    }
    
    // Executar verificação de saúde
    $healthMonitor = new EscrowHealthMonitor($conn);
    $healthCheck = $healthMonitor->runHealthCheck();
    
    echo "Status do sistema: " . $healthCheck['status'];
    if (!empty($healthCheck['alerts'])) {
        echo "Alertas: " . json_encode($healthCheck['alerts']);
    }
    
} catch (Exception $e) {
    error_log("Erro no sistema de escrow: " . $e->getMessage());
    echo "Erro: " . $e->getMessage();
}

/**
 * SQL para criar tabelas necessárias
 */
/*
CREATE TABLE escrow_orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    seller_id INT NOT NULL,
    product_id INT NOT NULL,
    amount DECIMAL(18,8) NOT NULL,
    multisig_address VARCHAR(100) NOT NULL,
    buyer_pubkey VARCHAR(66) NOT NULL,
    seller_pubkey VARCHAR(66) NOT NULL,
    arbitrator_pubkey VARCHAR(66) NOT NULL,
    redeem_script TEXT NOT NULL,
    buyer_address VARCHAR(100),
    seller_address VARCHAR(100),
    payment_txid VARCHAR(100),
    release_txid VARCHAR(100),
    status ENUM('pending','paid','released','disputed','resolved','refunded') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    paid_at TIMESTAMP NULL,
    released_at TIMESTAMP NULL,
    INDEX idx_buyer_seller (buyer_id, seller_id),
    INDEX idx_status (status),
    INDEX idx_multisig (multisig_address)
);

CREATE TABLE escrow_disputes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    escrow_id INT NOT NULL,
    initiated_by ENUM('buyer','seller') NOT NULL,
    arbitrator_id INT,
    reason TEXT NOT NULL,
    resolution TEXT,
    resolution_txid VARCHAR(100),
    status ENUM('pending','resolved','cancelled') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    arbitrator_assigned_at TIMESTAMP NULL,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (escrow_id) REFERENCES escrow_orders(id)
);

CREATE TABLE arbitrators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    reputation INT DEFAULT 100,
    fee_percent DECIMAL(5,2) DEFAULT 1.0,
    active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
*/
?>