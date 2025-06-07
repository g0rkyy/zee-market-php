<?php
/**
 * SISTEMA DE COMPRAS ULTRA SEGURO V2.0 - ZEEMARKET
 * Corrige vulnerabilidades e implementa escrow real
 * Arquivo: secure_purchase_v2.php
 */

require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/secure_escrow_system.php';

class SecurePurchaseSystemV2 {
    private $conn;
    private $escrowSystem;
    private $paymentVerifier;
    private $fraudDetector;
    private $logger;
    private $priceOracle;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->escrowSystem = new SecureEscrowSystem($conn);
        $this->paymentVerifier = new PaymentVerificationEngine();
        $this->fraudDetector = new PurchaseFraudDetector();
        $this->logger = new PurchaseLogger();
        $this->priceOracle = new CryptoPriceOracle();
    }
    
    /**
     * ✅ PRINCIPAL: Processar compra com segurança máxima
     */
    public function processSecurePurchase($purchaseData) {
        $purchaseId = null;
        
        try {
            // 1. SANITIZAR E VALIDAR DADOS
            $cleanData = $this->sanitizeAndValidatePurchaseData($purchaseData);
            
            // 2. VERIFICAR PRODUTO E VENDEDOR
            $productInfo = $this->getSecureProductInfo($cleanData['produto_id']);
            
            // 3. CALCULAR PREÇOS COM ORACLE REAL
            $pricing = $this->calculateSecurePricing($productInfo, $cleanData['payment_method']);
            
            // 4. VERIFICAR FRAUDE
            $this->fraudDetector->analyzePurchase($cleanData, $productInfo, $pricing);
            
            // 5. INICIAR TRANSAÇÃO
            $this->conn->begin_transaction();
            
            // 6. CRIAR COMPRA SEGURA
            $purchaseId = $this->createSecurePurchaseRecord($cleanData, $productInfo, $pricing);
            
            // 7. PROCESSAR PAGAMENTO BASEADO NO MÉTODO
            $paymentResult = $this->processPaymentSecure($cleanData, $pricing, $purchaseId);
            
            // 8. CRIAR ESCROW SE PAGAMENTO EXTERNO
            if ($cleanData['payment_method'] === 'external') {
                $escrowResult = $this->escrowSystem->createEscrowOrder(
                    $cleanData['user_id'] ?? 0,
                    $productInfo['vendedor_id'],
                    $pricing['total_btc'],
                    $cleanData['produto_id']
                );
                
                if (!$escrowResult['success']) {
                    throw new Exception("Erro ao criar escrow: " . $escrowResult['error']);
                }
                
                // Atualizar compra com dados do escrow
                $this->updatePurchaseWithEscrow($purchaseId, $escrowResult);
            }
            
            // 9. FINALIZAR TRANSAÇÃO
            $this->conn->commit();
            
            // 10. LOG SUCESSO
            $this->logger->logPurchaseSuccess($purchaseId, $cleanData, $pricing);
            
            // 11. PREPARAR RESPOSTA
            return $this->preparePurchaseResponse($purchaseId, $paymentResult, $cleanData);
            
        } catch (Exception $e) {
            if ($this->conn->inTransaction) {
                $this->conn->rollback();
            }
            
            $this->logger->logPurchaseError($purchaseId, $cleanData ?? [], $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * ✅ SANITIZAÇÃO E VALIDAÇÃO RIGOROSA
     */
    private function sanitizeAndValidatePurchaseData($data) {
        // 1. VALIDAR CSRF TOKEN
        if (empty($data['csrf_token']) || !$this->validateCSRFToken($data['csrf_token'])) {
            throw new SecurityException("Token CSRF inválido ou ausente");
        }
        
        // 2. SANITIZAR DADOS
        $clean = [
            'produto_id' => $this->sanitizeInt($data['produto_id'] ?? 0),
            'nome' => $this->sanitizeString($data['nome'] ?? '', 100),
            'endereco' => $this->sanitizeString($data['endereco'] ?? '', 500),
            'payment_method' => $this->sanitizeEnum($data['payment_method'] ?? '', ['external', 'balance']),
            'btc_wallet' => $this->sanitizeString($data['btc_wallet'] ?? '', 100),
            'user_id' => $_SESSION['user_id'] ?? null,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        // 3. VALIDAÇÕES OBRIGATÓRIAS
        if ($clean['produto_id'] <= 0) {
            throw new ValidationException("ID do produto inválido");
        }
        
        if (empty($clean['nome']) || strlen($clean['nome']) < 2) {
            throw new ValidationException("Nome deve ter pelo menos 2 caracteres");
        }
        
        if (empty($clean['endereco']) || strlen($clean['endereco']) < 10) {
            throw new ValidationException("Endereço deve ter pelo menos 10 caracteres");
        }
        
        // 4. VALIDAÇÕES ESPECÍFICAS POR MÉTODO DE PAGAMENTO
        if ($clean['payment_method'] === 'balance') {
            if (!$clean['user_id']) {
                throw new ValidationException("Login obrigatório para pagamento com saldo");
            }
        } elseif ($clean['payment_method'] === 'external') {
            if (empty($clean['btc_wallet'])) {
                throw new ValidationException("Carteira Bitcoin obrigatória para pagamento externo");
            }
            
            if (!$this->isValidBitcoinAddress($clean['btc_wallet'])) {
                throw new ValidationException("Carteira Bitcoin inválida");
            }
        }
        
        return $clean;
    }
    
    /**
     * ✅ OBTER INFORMAÇÕES SEGURAS DO PRODUTO
     */
    private function getSecureProductInfo($productId) {
        $stmt = $this->conn->prepare("
            SELECT 
                p.id, p.nome, p.preco, p.descricao, p.imagem, p.ativo,
                p.vendedor_id, p.categoria_id, p.created_at,
                v.id as vendor_id, v.nome as vendor_nome, v.email as vendor_email,
                v.btc_wallet as vendor_wallet, v.ativo as vendor_ativo,
                v.reputacao, v.vendas_total,
                c.nome as categoria_nome
            FROM produtos p
            INNER JOIN vendedores v ON p.vendedor_id = v.id
            LEFT JOIN categorias c ON p.categoria_id = c.id
            WHERE p.id = ? AND p.ativo = 1 AND v.ativo = 1
        ");
        
        $stmt->bind_param("i", $productId);
        $stmt->execute();
        $product = $stmt->get_result()->fetch_assoc();
        
        if (!$product) {
            throw new ValidationException("Produto não encontrado ou indisponível");
        }
        
        // Verificar se produto não foi removido recentemente
        if (strtotime($product['created_at']) > (time() - 3600)) {
            throw new SecurityException("Produto muito recente. Aguarde 1 hora.");
        }
        
        // Verificar reputação do vendedor
        if ($product['reputacao'] < 1.0) {
            throw new SecurityException("Vendedor com reputação muito baixa");
        }
        
        return $product;
    }
    
    /**
     * ✅ CÁLCULO SEGURO DE PREÇOS COM ORACLE
     */
    private function calculateSecurePricing($product, $paymentMethod) {
        // 1. OBTER COTAÇÃO REAL E ATUAL
        $btcPrice = $this->priceOracle->getCurrentBTCPrice();
        
        if (!$btcPrice || $btcPrice <= 0) {
            throw new Exception("Erro ao obter cotação do Bitcoin");
        }
        
        // 2. CALCULAR VALORES EM BTC
        $priceUSD = floatval($product['preco']);
        $totalBTC = $priceUSD / $btcPrice;
        
        // 3. CALCULAR TAXAS
        $platformFeePercent = $this->getPlatformFeePercent($paymentMethod, $totalBTC);
        $platformFeeBTC = $totalBTC * $platformFeePercent;
        $vendorAmountBTC = $totalBTC - $platformFeeBTC;
        
        // 4. VALIDAR VALORES MÍNIMOS
        $minValueBTC = 0.00001; // 1000 satoshis
        if ($totalBTC < $minValueBTC) {
            throw new ValidationException("Valor mínimo: {$minValueBTC} BTC");
        }
        
        if ($vendorAmountBTC <= 0) {
            throw new ValidationException("Valor insuficiente para cobrir taxas");
        }
        
        return [
            'price_usd' => $priceUSD,
            'btc_price_usd' => $btcPrice,
            'total_btc' => $totalBTC,
            'platform_fee_percent' => $platformFeePercent,
            'platform_fee_btc' => $platformFeeBTC,
            'vendor_amount_btc' => $vendorAmountBTC,
            'calculated_at' => time()
        ];
    }
    
    /**
     * ✅ ORACLE DE PREÇOS CONFIÁVEL
     */
    private function initializePriceOracle() {
        $this->priceOracle = new class {
            private $cache;
            private $cacheTime = 300; // 5 minutos
            
            public function getCurrentBTCPrice() {
                // Verificar cache
                if ($this->isCacheValid()) {
                    return $this->cache['btc_usd'];
                }
                
                // Tentar múltiplas APIs
                $apis = [
                    'coingecko' => 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd',
                    'coinbase' => 'https://api.coinbase.com/v2/exchange-rates?currency=BTC',
                    'binance' => 'https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT'
                ];
                
                foreach ($apis as $name => $url) {
                    try {
                        $price = $this->fetchPriceFromAPI($name, $url);
                        if ($price > 0) {
                            $this->updateCache($price);
                            return $price;
                        }
                    } catch (Exception $e) {
                        error_log("Erro na API $name: " . $e->getMessage());
                        continue;
                    }
                }
                
                // Fallback: usar preço do banco (última cotação válida)
                return $this->getFallbackPrice();
            }
            
            private function fetchPriceFromAPI($apiName, $url) {
                $context = stream_context_create([
                    'http' => [
                        'timeout' => 10,
                        'user_agent' => 'ZeeMarket/2.0'
                    ]
                ]);
                
                $response = @file_get_contents($url, false, $context);
                if (!$response) {
                    throw new Exception("Falha na requisição");
                }
                
                $data = json_decode($response, true);
                if (!$data) {
                    throw new Exception("Resposta JSON inválida");
                }
                
                switch ($apiName) {
                    case 'coingecko':
                        return $data['bitcoin']['usd'] ?? 0;
                    case 'coinbase':
                        return floatval($data['data']['rates']['USD'] ?? 0);
                    case 'binance':
                        return floatval($data['price'] ?? 0);
                    default:
                        return 0;
                }
            }
            
            private function isCacheValid() {
                return $this->cache && 
                       isset($this->cache['timestamp']) && 
                       (time() - $this->cache['timestamp']) < $this->cacheTime;
            }
            
            private function updateCache($price) {
                $this->cache = [
                    'btc_usd' => $price,
                    'timestamp' => time()
                ];
                
                // Salvar no banco para fallback
                global $conn;
                $stmt = $conn->prepare("
                    INSERT INTO crypto_rates (btc_usd, created_at) 
                    VALUES (?, NOW())
                ");
                $stmt->bind_param("d", $price);
                $stmt->execute();
            }
            
            private function getFallbackPrice() {
                global $conn;
                $stmt = $conn->query("
                    SELECT btc_usd FROM crypto_rates 
                    ORDER BY created_at DESC 
                    LIMIT 1
                ");
                $result = $stmt->fetch_assoc();
                
                return $result ? floatval($result['btc_usd']) : 50000.00; // Fallback conservador
            }
        };
    }
    
    /**
     * ✅ PROCESSAMENTO SEGURO DE PAGAMENTO
     */
    private function processPaymentSecure($purchaseData, $pricing, $purchaseId) {
        if ($purchaseData['payment_method'] === 'balance') {
            return $this->processBalancePayment($purchaseData, $pricing, $purchaseId);
        } else {
            return $this->processExternalPayment($purchaseData, $pricing, $purchaseId);
        }
    }
    
    /**
     * ✅ PAGAMENTO COM SALDO INTERNO
     */
    private function processBalancePayment($purchaseData, $pricing, $purchaseId) {
        $userId = $purchaseData['user_id'];
        $requiredAmount = $pricing['total_btc'];
        
        // 1. VERIFICAR SALDO COM LOCK
        $stmt = $this->conn->prepare("
            SELECT btc_balance 
            FROM users 
            WHERE id = ? 
            FOR UPDATE
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        
        if (!$user) {
            throw new Exception("Usuário não encontrado");
        }
        
        $currentBalance = floatval($user['btc_balance']);
        if ($currentBalance < $requiredAmount) {
            throw new Exception("Saldo insuficiente. Disponível: {$currentBalance} BTC, Necessário: {$requiredAmount} BTC");
        }
        
        // 2. DEDUZIR SALDO
        $newBalance = $currentBalance - $requiredAmount;
        $stmt = $this->conn->prepare("
            UPDATE users 
            SET btc_balance = ?, updated_at = NOW() 
            WHERE id = ?
        ");
        $stmt->bind_param("di", $newBalance, $userId);
        $stmt->execute();
        
        // 3. REGISTRAR TRANSAÇÃO
        $txHash = 'internal_' . $purchaseId . '_' . time();
        $this->recordBalanceTransaction($userId, $requiredAmount, $currentBalance, $newBalance, $txHash, $purchaseId);
        
        // 4. MARCAR COMPRA COMO PAGA
        $this->markPurchaseAsPaid($purchaseId, $txHash);
        
        // 5. ATUALIZAR SESSÃO
        $_SESSION['btc_balance'] = $newBalance;
        
        return [
            'method' => 'balance',
            'status' => 'completed',
            'tx_hash' => $txHash,
            'message' => 'Pagamento processado com saldo interno'
        ];
    }
    
    /**
     * ✅ PAGAMENTO EXTERNO COM ESCROW
     */
    private function processExternalPayment($purchaseData, $pricing, $purchaseId) {
        // Gerar endereço único para esta compra
        $paymentAddress = $this->generateUniquePaymentAddress($purchaseId);
        
        // Configurar monitoramento
        $this->setupPaymentMonitoring($purchaseId, $paymentAddress, $pricing['total_btc']);
        
        return [
            'method' => 'external',
            'status' => 'pending_payment',
            'payment_address' => $paymentAddress,
            'amount_btc' => $pricing['total_btc'],
            'amount_usd' => $pricing['price_usd'],
            'expires_at' => date('Y-m-d H:i:s', strtotime('+24 hours')),
            'message' => 'Envie o pagamento para o endereço fornecido'
        ];
    }
    
    /**
     * ✅ DETECÇÃO DE FRAUDE EM COMPRAS
     */
    private function initializeFraudDetector() {
        $this->fraudDetector = new class {
            public function analyzePurchase($purchaseData, $productInfo, $pricing) {
                global $conn;
                
                $riskScore = 0;
                $alerts = [];
                $userId = $purchaseData['user_id'];
                
                // 1. Verificar compras recentes do mesmo usuário
                if ($userId) {
                    $stmt = $conn->prepare("
                        SELECT COUNT(*) as recent_purchases,
                               SUM(valor_btc) as total_spent
                        FROM compras 
                        WHERE (user_id = ? OR btc_wallet_comprador = ?)
                        AND data_compra > DATE_SUB(NOW(), INTERVAL 1 HOUR)
                    ");
                    $stmt->bind_param("is", $userId, $purchaseData['btc_wallet']);
                    $stmt->execute();
                    $recent = $stmt->get_result()->fetch_assoc();
                    
                    if ($recent['recent_purchases'] > 3) {
                        $riskScore += 40;
                        $alerts[] = 'Múltiplas compras em 1 hora';
                    }
                    
                    if ($recent['total_spent'] > 1.0) {
                        $riskScore += 30;
                        $alerts[] = 'Alto volume de compras recentes';
                    }
                }
                
                // 2. Verificar IP suspeito
                $ip = $purchaseData['ip_address'];
                $stmt = $conn->prepare("
                    SELECT COUNT(*) as ip_purchases
                    FROM compras 
                    WHERE ip_address = ? 
                    AND data_compra > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                ");
                $stmt->bind_param("s", $ip);
                $stmt->execute();
                $ipPurchases = $stmt->get_result()->fetch_assoc()['ip_purchases'];
                
                if ($ipPurchases > 5) {
                    $riskScore += 50;
                    $alerts[] = 'IP com muitas compras';
                }
                
                // 3. Verificar produto muito novo
                if (strtotime($productInfo['created_at']) > (time() - 86400)) {
                    $riskScore += 20;
                    $alerts[] = 'Produto muito recente';
                }
                
                // 4. Verificar valor alto para novo usuário
                if ($userId) {
                    $stmt = $conn->prepare("
                        SELECT created_at 
                        FROM users 
                        WHERE id = ?
                    ");
                    $stmt->bind_param("i", $userId);
                    $stmt->execute();
                    $userCreated = $stmt->get_result()->fetch_assoc()['created_at'];
                    
                    if (strtotime($userCreated) > (time() - 86400) && $pricing['total_btc'] > 0.01) {
                        $riskScore += 35;
                        $alerts[] = 'Usuário novo com compra alta';
                    }
                }
                
                // 5. DECISÃO
                if ($riskScore >= 80) {
                    throw new SecurityException("Compra bloqueada: Alto risco de fraude. Alerts: " . implode(', ', $alerts));
                } elseif ($riskScore >= 50) {
                    // Marcar para revisão manual
                    $this->flagForManualReview($purchaseData, $riskScore, $alerts);
                }
                
                return ['risk_score' => $riskScore, 'alerts' => $alerts];
            }
            
            private function flagForManualReview($purchaseData, $riskScore, $alerts) {
                global $conn;
                
                $stmt = $conn->prepare("
                    INSERT INTO purchase_reviews 
                    (user_id, ip_address, risk_score, alerts, status, created_at) 
                    VALUES (?, ?, ?, ?, 'pending', NOW())
                ");
                $alertsJson = json_encode($alerts);
                $stmt->bind_param("isis", 
                    $purchaseData['user_id'], 
                    $purchaseData['ip_address'], 
                    $riskScore, 
                    $alertsJson
                );
                $stmt->execute();
            }
        };
    }
    
    /**
     * ✅ CRIAR REGISTRO SEGURO DA COMPRA
     */
    private function createSecurePurchaseRecord($purchaseData, $productInfo, $pricing) {
        $stmt = $this->conn->prepare("
            INSERT INTO compras_seguras (
                produto_id, vendedor_id, user_id, nome, endereco, 
                btc_wallet_comprador, payment_method,
                preco_usd, preco_btc_cotacao, valor_btc_total,
                taxa_plataforma_percent, taxa_plataforma_btc, valor_vendedor_btc,
                ip_address, user_agent, risk_score,
                status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())
        ");
        
        $stmt->bind_param("iiisisssdddddsssi",
            $productInfo['id'],
            $productInfo['vendedor_id'],
            $purchaseData['user_id'],
            $purchaseData['nome'],
            $purchaseData['endereco'],
            $purchaseData['btc_wallet'],
            $purchaseData['payment_method'],
            $pricing['price_usd'],
            $pricing['btc_price_usd'],
            $pricing['total_btc'],
            $pricing['platform_fee_percent'],
            $pricing['platform_fee_btc'],
            $pricing['vendor_amount_btc'],
            $purchaseData['ip_address'],
            $purchaseData['user_agent'],
            0 // risk_score será atualizado depois
        );
        
        $stmt->execute();
        $purchaseId = $this->conn->insert_id;
        
        if (!$purchaseId) {
            throw new Exception("Erro ao criar registro da compra");
        }
        
        return $purchaseId;
    }
    
    /**
     * ✅ SISTEMA DE MONITORAMENTO DE PAGAMENTO
     */
    private function setupPaymentMonitoring($purchaseId, $paymentAddress, $expectedAmount) {
        $stmt = $this->conn->prepare("
            INSERT INTO payment_monitoring (
                purchase_id, payment_address, expected_amount, status, created_at
            ) VALUES (?, ?, ?, 'monitoring', NOW())
        ");
        $stmt->bind_param("isd", $purchaseId, $paymentAddress, $expectedAmount);
        $stmt->execute();
    }
    
    /**
     * ✅ GERAR ENDEREÇO ÚNICO PARA PAGAMENTO
     */
    private function generateUniquePaymentAddress($purchaseId) {
        // Em produção: Usar HD wallets para gerar endereços únicos
        // Por agora: Endereço simulado mas único
        $seed = $purchaseId . time() . random_bytes(16);
        $hash = hash('sha256', $seed);
        
        // Simular endereço Bitcoin válido
        return 'bc1q' . substr($hash, 0, 40);
    }
    
    /**
     * ✅ FUNÇÕES AUXILIARES DE SEGURANÇA
     */
    private function sanitizeInt($value) {
        return filter_var($value, FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE) ?? 0;
    }
    
    private function sanitizeString($value, $maxLength) {
        $clean = trim(strip_tags($value));
        return substr($clean, 0, $maxLength);
    }
    
    private function sanitizeEnum($value, $allowedValues) {
        return in_array($value, $allowedValues) ? $value : '';
    }
    
    private function isValidBitcoinAddress($address) {
        $patterns = [
            '/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/',  // Legacy
            '/^bc1[a-z0-9]{39,59}$/i',              // Bech32
            '/^bc1p[a-z0-9]{58}$/i'                 // Taproot
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $address)) {
                return true;
            }
        }
        return false;
    }
    
    private function validateCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && 
               hash_equals($_SESSION['csrf_token'], $token);
    }
    
    private function getPlatformFeePercent($paymentMethod, $totalBTC) {
        $baseFee = 0.025; // 2.5%
        
        // Desconto para pagamento com saldo
        if ($paymentMethod === 'balance') {
            $baseFee = 0.020; // 2.0%
        }
        
        // Desconto para valores altos
        if ($totalBTC > 0.1) {
            $baseFee *= 0.8; // 20% desconto
        }
        
        return $baseFee;
    }
    
    /**
     * ✅ PREPARAR RESPOSTA FINAL
     */
    private function preparePurchaseResponse($purchaseId, $paymentResult, $purchaseData) {
        $response = [
            'success' => true,
            'purchase_id' => $purchaseId,
            'payment_method' => $paymentResult['method'],
            'status' => $paymentResult['status']
        ];
        
        if ($paymentResult['method'] === 'balance') {
            $response['redirect'] = 'compra_confirmada.php?id=' . $purchaseId;
            $response['message'] = 'Compra realizada com sucesso!';
        } else {
            $response['redirect'] = 'pagamento_btc.php?id=' . $purchaseId;
            $response['payment_address'] = $paymentResult['payment_address'];
            $response['amount_btc'] = $paymentResult['amount_btc'];
            $response['expires_at'] = $paymentResult['expires_at'];
            $response['message'] = 'Envie o pagamento para confirmar a compra';
        }
        
        return $response;
    }
}

/**
 * ✅ LOGGER ESPECÍFICO PARA COMPRAS
 */
class PurchaseLogger {
    private $conn;
    
    public function __construct() {
        global $conn;
        $this->conn = $conn;
    }
    
    public function logPurchaseSuccess($purchaseId, $data, $pricing) {
        $this->log('purchase_success', [
            'purchase_id' => $purchaseId,
            'product_id' => $data['produto_id'],
            'payment_method' => $data['payment_method'],
            'amount_btc' => $pricing['total_btc'],
            'amount_usd' => $pricing['price_usd']
        ]);
    }
    
    public function logPurchaseError($purchaseId, $data, $error) {
        $this->log('purchase_error', [
            'purchase_id' => $purchaseId,
            'product_id' => $data['produto_id'] ?? 0,
            'error' => $error
        ]);
    }
    
    private function log($action, $details) {
        $stmt = $this->conn->prepare("
            INSERT INTO purchase_logs 
            (user_id, action, details, ip_address, created_at) 
            VALUES (?, ?, ?, ?, NOW())
        ");
        
        $userId = $_SESSION['user_id'] ?? 0;
        $detailsJson = json_encode($details);
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $stmt->bind_param("isss", $userId, $action, $detailsJson, $ip);
        $stmt->execute();
    }
}

/**
 * ✅ EXCEÇÕES PERSONALIZADAS
 */
class ValidationException extends Exception {}
class SecurityException extends Exception {}

// Inicializar sistema
try {
    $securePurchase = new SecurePurchaseSystemV2($conn);
    
    // Processar compra se for POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $result = $securePurchase->processSecurePurchase($_POST);
        
        if ($result['success']) {
            header("Location: " . $result['redirect']);
            exit();
        }
    }
    
} catch (Exception $e) {
    error_log("Erro no sistema de compras: " . $e->getMessage());
    $_SESSION['error_message'] = $e->getMessage();
    header("Location: index.php");
    exit();
}

/**
 * ✅ SQL PARA TABELAS NECESSÁRIAS
 */
/*
-- Tabela de compras seguras (substitui a antiga)
CREATE TABLE compras_seguras (
    id INT AUTO_INCREMENT PRIMARY KEY,
    produto_id INT NOT NULL,
    vendedor_id INT NOT NULL,
    user_id INT NULL,
    nome VARCHAR(100) NOT NULL,
    endereco TEXT NOT NULL,
    btc_wallet_comprador VARCHAR(100),
    payment_method ENUM('balance','external') NOT NULL,
    
    preco_usd DECIMAL(10,2) NOT NULL,
    preco_btc_cotacao DECIMAL(15,2) NOT NULL,
    valor_btc_total DECIMAL(18,8) NOT NULL,
    taxa_plataforma_percent DECIMAL(5,4) NOT NULL,
    taxa_plataforma_btc DECIMAL(18,8) NOT NULL,
    valor_vendedor_btc DECIMAL(18,8) NOT NULL,
    
    payment_address VARCHAR(100) NULL,
    tx_hash VARCHAR(100) NULL,
    confirmations INT DEFAULT 0,
    
    escrow_id INT NULL,
    risk_score INT DEFAULT 0,
    
    ip_address VARCHAR(45),
    user_agent TEXT,
    
    status ENUM('pending','paid','confirmed','shipped','completed','cancelled') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_user_status (user_id, status),
    INDEX idx_vendor_status (vendedor_id, status),
    INDEX idx_payment_address (payment_address),
    INDEX idx_created (created_at)
);

-- Logs de compras
CREATE TABLE purchase_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    details JSON NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_action (user_id, action)
);

-- Monitoramento de pagamentos
CREATE TABLE payment_monitoring (
    id INT AUTO_INCREMENT PRIMARY KEY,
    purchase_id INT NOT NULL,
    payment_address VARCHAR(100) NOT NULL,
    expected_amount DECIMAL(18,8) NOT NULL,
    received_amount DECIMAL(18,8) DEFAULT 0,
    confirmations INT DEFAULT 0,
    status ENUM('monitoring','received','confirmed','expired') DEFAULT 'monitoring',
    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_address (payment_address),
    INDEX idx_status_check (status, last_check)
);

-- Reviews manuais
CREATE TABLE purchase_reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    ip_address VARCHAR(45),
    risk_score INT NOT NULL,
    alerts JSON NOT NULL,
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    reviewed_by INT NULL,
    reviewed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
*/
?>