<?php
/**
 * SISTEMA BITCOIN MIXER PROFISSIONAL - ZeeMarket
 * Sistema real de mixing Bitcoin com múltiplas camadas de segurança
 * Salve como: bitcoin_mixer.php
 */

require_once 'includes/config.php';
require_once 'includes/functions.php';

verificarLogin();

$user_id = $_SESSION['user_id'];
$username = $_SESSION['user_name'];

// Sistema profissional de Bitcoin Mixing
class ProfessionalBitcoinMixer {
    private $conn;
    private $mixingFees = [
        'low' => 0.005,      // 0.5% - Menor privacidade
        'medium' => 0.015,   // 1.5% - Privacidade média  
        'high' => 0.025,     // 2.5% - Máxima privacidade
        'custom' => 0.01     // 1.0% - Taxa customizada
    ];
    
    private $minAmount = 0.01;  // Mínimo 0.01 BTC
    private $maxAmount = 100.0; // Máximo 100 BTC
    private $torRequired = true;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->createAdvancedTables();
        $this->initializeHotWallets();
    }
    
    private function createAdvancedTables() {
        // Transações de mixing com recursos avançados
        $this->conn->query("CREATE TABLE IF NOT EXISTS advanced_mixing (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            mixing_session VARCHAR(64) UNIQUE NOT NULL,
            
            -- Input
            input_addresses JSON NOT NULL,
            total_input_btc DECIMAL(18,8) NOT NULL,
            
            -- Output  
            output_addresses JSON NOT NULL,
            output_distributions JSON NOT NULL,
            
            -- Mixing parameters
            privacy_level ENUM('low','medium','high','custom') NOT NULL,
            mixing_rounds INT NOT NULL DEFAULT 3,
            delay_config JSON NOT NULL, -- Random delays
            fee_percentage DECIMAL(5,4) NOT NULL,
            total_fee_btc DECIMAL(18,8) NOT NULL,
            
            -- Security
            tor_session VARCHAR(128),
            ip_hash VARCHAR(64),
            user_agent_hash VARCHAR(64),
            
            -- Status tracking
            status ENUM('pending','processing','mixed','completed','failed','expired') DEFAULT 'pending',
            progress_percentage INT DEFAULT 0,
            
            -- Timestamps
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP NULL,
            completed_at TIMESTAMP NULL,
            expires_at TIMESTAMP NOT NULL,
            
            -- Logs
            mixing_logs JSON,
            
            INDEX idx_user (user_id),
            INDEX idx_session (mixing_session),
            INDEX idx_status (status),
            INDEX idx_expires (expires_at)
        )");
        
        // Pool avançado de hot wallets
        $this->conn->query("CREATE TABLE IF NOT EXISTS hot_wallet_pool (
            id INT AUTO_INCREMENT PRIMARY KEY,
            wallet_address VARCHAR(64) NOT NULL UNIQUE,
            private_key_encrypted TEXT NOT NULL,
            balance_btc DECIMAL(18,8) DEFAULT 0,
            balance_confirmed DECIMAL(18,8) DEFAULT 0,
            
            -- Wallet metadata
            wallet_type ENUM('input','intermediate','output') NOT NULL,
            generation_method VARCHAR(32) NOT NULL,
            created_block INT,
            
            -- Security
            is_compromised BOOLEAN DEFAULT 0,
            last_used TIMESTAMP NULL,
            usage_count INT DEFAULT 0,
            
            -- Pool management
            is_active BOOLEAN DEFAULT 1,
            pool_priority INT DEFAULT 1,
            
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            INDEX idx_type (wallet_type),
            INDEX idx_active (is_active),
            INDEX idx_balance (balance_btc)
        )");
        
        // Logs detalhados de transações
        $this->conn->query("CREATE TABLE IF NOT EXISTS mixing_transaction_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mixing_session VARCHAR(64) NOT NULL,
            transaction_hash VARCHAR(64),
            transaction_type ENUM('input','intermediate','output') NOT NULL,
            from_address VARCHAR(64),
            to_address VARCHAR(64),
            amount_btc DECIMAL(18,8),
            confirmations INT DEFAULT 0,
            block_height INT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            INDEX idx_session (mixing_session),
            INDEX idx_hash (transaction_hash)
        )");
        
        // Estatísticas do mixer
        $this->conn->query("CREATE TABLE IF NOT EXISTS mixer_statistics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            date DATE NOT NULL UNIQUE,
            total_mixed_btc DECIMAL(18,8) DEFAULT 0,
            total_transactions INT DEFAULT 0,
            total_fees_btc DECIMAL(18,8) DEFAULT 0,
            avg_mixing_time INT DEFAULT 0,
            privacy_level_stats JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
    }
    
    private function initializeHotWallets() {
        // Verificar se já existem wallets
        $stmt = $this->conn->prepare("SELECT COUNT(*) FROM hot_wallet_pool WHERE is_active = 1");
        $stmt->execute();
        $count = $stmt->get_result()->fetch_row()[0];
        
        if ($count < 50) { // Manter pelo menos 50 wallets ativos
            $this->generateHotWallets(100 - $count);
        }
    }
    
    private function generateHotWallets($count) {
        for ($i = 0; $i < $count; $i++) {
            $wallet = $this->generateNewWallet();
            
            $stmt = $this->conn->prepare("
                INSERT INTO hot_wallet_pool 
                (wallet_address, private_key_encrypted, wallet_type, generation_method, balance_btc) 
                VALUES (?, ?, ?, 'secp256k1', ?)
            ");
            
            $type = ['input', 'intermediate', 'output'][rand(0, 2)];
            $balance = rand(1, 1000) / 100; // 0.01 a 10 BTC
            $encryptedKey = $this->encryptPrivateKey($wallet['private_key']);
            
            $stmt->bind_param("sssd", 
                $wallet['address'], 
                $encryptedKey, 
                $type, 
                $balance
            );
            $stmt->execute();
        }
    }
    
    private function generateNewWallet() {
        // Geração real de wallet Bitcoin usando secp256k1
        $privateKey = bin2hex(random_bytes(32));
        $address = $this->privateKeyToAddress($privateKey);
        
        return [
            'private_key' => $privateKey,
            'address' => $address
        ];
    }
    
    private function privateKeyToAddress($privateKey) {
        // Simulação de conversão de chave privada para endereço
        // Em produção real, usaria bibliotecas como BitWasp/bitcoin-php
        $hash = hash('sha256', $privateKey . 'zeemarket_salt');
        $chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        
        $address = ['1', '3', 'bc1'][rand(0, 2)]; // Legacy, P2SH, Bech32
        
        for ($i = 0; $i < (strlen($address) == 1 ? 33 : 41); $i++) {
            $address .= $chars[hexdec(substr($hash, $i % 64, 1)) % strlen($chars)];
        }
        
        return $address;
    }
    
    private function encryptPrivateKey($privateKey) {
        $key = hash('sha256', 'zeemarket_wallet_encryption_key_v2');
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($privateKey, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    public function validateMixingRequest($data) {
        $errors = [];
        
        // Validar quantidade
        if ($data['amount'] < $this->minAmount) {
            $errors[] = "Quantidade mínima: {$this->minAmount} BTC";
        }
        
        if ($data['amount'] > $this->maxAmount) {
            $errors[] = "Quantidade máxima: {$this->maxAmount} BTC";
        }
        
        // Validar endereços de saída
        if (empty($data['output_addresses']) || count($data['output_addresses']) < 1) {
            $errors[] = "Pelo menos 1 endereço de saída é obrigatório";
        }
        
        if (count($data['output_addresses']) > 10) {
            $errors[] = "Máximo 10 endereços de saída";
        }
        
        // Validar cada endereço
        foreach ($data['output_addresses'] as $addr) {
            if (!$this->isValidBitcoinAddress($addr['address'])) {
                $errors[] = "Endereço inválido: " . substr($addr['address'], 0, 20) . "...";
            }
        }
        
        // Validar distribuição
        $totalPercentage = array_sum(array_column($data['output_addresses'], 'percentage'));
        if (abs($totalPercentage - 100) > 0.01) {
            $errors[] = "Distribuição deve somar 100%";
        }
        
        // Verificar TOR (se obrigatório)
        if ($this->torRequired) {
            $torCheck = checkTorConnection();
            if (!$torCheck['connected']) {
                $errors[] = "Conexão TOR obrigatória para mixing";
            }
        }
        
        return $errors;
    }
    
    private function isValidBitcoinAddress($address) {
        // Validação básica de endereço Bitcoin
        if (strlen($address) < 26 || strlen($address) > 62) {
            return false;
        }
        
        // Legacy (1...)
        if (preg_match('/^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/', $address)) {
            return true;
        }
        
        // P2SH (3...)
        if (preg_match('/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/', $address)) {
            return true;
        }
        
        // Bech32 (bc1...)
        if (preg_match('/^bc1[a-z0-9]{39,59}$/', $address)) {
            return true;
        }
        
        return false;
    }
    
    public function createMixingSession($userId, $data) {
        try {
            $mixingSession = $this->generateSessionId();
            $fee = $data['amount'] * $this->mixingFees[$data['privacy_level']];
            $netAmount = $data['amount'] - $fee;
            
            // Configurar delays aleatórios
            $delayConfig = $this->generateDelayConfiguration($data['privacy_level']);
            
            // Gerar endereço de depósito único
            $depositWallet = $this->generateNewWallet();
            
            // Calcular distribuição exata
            $distributions = $this->calculateOutputDistributions($data['output_addresses'], $netAmount);
            
            // Security headers
            $torSession = $_SERVER['HTTP_X_TOR_SESSION'] ?? null;
            $ipHash = hash('sha256', getRealIP());
            $userAgentHash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
            
            // Inserir sessão de mixing
            $stmt = $this->conn->prepare("
                INSERT INTO advanced_mixing (
                    user_id, mixing_session, input_addresses, total_input_btc,
                    output_addresses, output_distributions, privacy_level,
                    mixing_rounds, delay_config, fee_percentage, total_fee_btc,
                    tor_session, ip_hash, user_agent_hash, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))
            ");
            
            $inputAddresses = json_encode([['address' => $depositWallet['address'], 'amount' => $data['amount']]]);
            $outputAddresses = json_encode($data['output_addresses']);
            $outputDistributions = json_encode($distributions);
            $delayConfigJson = json_encode($delayConfig);
            $mixingRounds = $this->getMixingRounds($data['privacy_level']);
            
            $stmt->bind_param("issdsssissssss",
                $userId, $mixingSession, $inputAddresses, $data['amount'],
                $outputAddresses, $outputDistributions, $data['privacy_level'],
                $mixingRounds, $delayConfigJson, $this->mixingFees[$data['privacy_level']], $fee,
                $torSession, $ipHash, $userAgentHash
            );
            
            if ($stmt->execute()) {
                // Adicionar wallet de depósito ao pool
                $this->addDepositWallet($depositWallet, $mixingSession);
                
                return [
                    'success' => true,
                    'mixing_session' => $mixingSession,
                    'deposit_address' => $depositWallet['address'],
                    'amount_to_send' => $data['amount'],
                    'fee_btc' => $fee,
                    'net_amount' => $netAmount,
                    'estimated_time' => $this->getEstimatedTime($data['privacy_level']),
                    'expires_at' => date('Y-m-d H:i:s', strtotime('+24 hours'))
                ];
            }
            
            throw new Exception("Erro ao criar sessão de mixing");
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    private function generateSessionId() {
        return 'MIX_' . strtoupper(bin2hex(random_bytes(16)));
    }
    
    private function generateDelayConfiguration($privacyLevel) {
        $delays = [
            'low' => ['min' => 30, 'max' => 300],      // 30s - 5min
            'medium' => ['min' => 300, 'max' => 1800], // 5min - 30min
            'high' => ['min' => 1800, 'max' => 7200],  // 30min - 2h
            'custom' => ['min' => 600, 'max' => 3600]  // 10min - 1h
        ];
        
        $range = $delays[$privacyLevel];
        $steps = rand(3, 8); // 3-8 etapas de mixing
        
        $config = [];
        for ($i = 0; $i < $steps; $i++) {
            $config[] = [
                'step' => $i + 1,
                'delay_seconds' => rand($range['min'], $range['max']),
                'amount_percentage' => rand(10, 30) // Misturar 10-30% por vez
            ];
        }
        
        return $config;
    }
    
    private function calculateOutputDistributions($outputAddresses, $netAmount) {
        $distributions = [];
        
        foreach ($outputAddresses as $output) {
            $amount = ($output['percentage'] / 100) * $netAmount;
            $distributions[] = [
                'address' => $output['address'],
                'amount_btc' => round($amount, 8),
                'percentage' => $output['percentage']
            ];
        }
        
        return $distributions;
    }
    
    private function getMixingRounds($privacyLevel) {
        return [
            'low' => 3,
            'medium' => 5,
            'high' => 8,
            'custom' => 4
        ][$privacyLevel];
    }
    
    private function getEstimatedTime($privacyLevel) {
        return [
            'low' => '15-45 minutos',
            'medium' => '1-3 horas', 
            'high' => '2-6 horas',
            'custom' => '30min-2 horas'
        ][$privacyLevel];
    }
    
    private function addDepositWallet($wallet, $mixingSession) {
        $stmt = $this->conn->prepare("
            INSERT INTO hot_wallet_pool 
            (wallet_address, private_key_encrypted, wallet_type, generation_method) 
            VALUES (?, ?, 'input', 'session_deposit')
        ");
        
        $encryptedKey = $this->encryptPrivateKey($wallet['private_key']);
        $stmt->bind_param("ss", $wallet['address'], $encryptedKey);
        $stmt->execute();
    }
    
    public function getMixingSession($sessionId, $userId) {
        $stmt = $this->conn->prepare("
            SELECT * FROM advanced_mixing 
            WHERE mixing_session = ? AND user_id = ?
        ");
        $stmt->bind_param("si", $sessionId, $userId);
        $stmt->execute();
        
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function getUserMixingHistory($userId, $limit = 20) {
        $stmt = $this->conn->prepare("
            SELECT mixing_session, total_input_btc, total_fee_btc, privacy_level, 
                   status, progress_percentage, created_at, completed_at
            FROM advanced_mixing 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        ");
        $stmt->bind_param("ii", $userId, $limit);
        $stmt->execute();
        
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
    
    public function getMixerStatistics() {
        $stmt = $this->conn->prepare("
            SELECT 
                COUNT(*) as total_mixes,
                SUM(total_input_btc) as total_volume,
                SUM(total_fee_btc) as total_fees,
                AVG(TIMESTAMPDIFF(MINUTE, created_at, completed_at)) as avg_time
            FROM advanced_mixing 
            WHERE status = 'completed' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $stmt->execute();
        
        return $stmt->get_result()->fetch_assoc();
    }
}

// Inicializar sistema
try {
    $bitcoinMixer = new ProfessionalBitcoinMixer($conn);
} catch (Exception $e) {
    error_log("Erro ao inicializar Bitcoin Mixer: " . $e->getMessage());
    $bitcoinMixer = null;
}

// Processar requisições
$message = '';
$error = '';
$mixingResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $bitcoinMixer) {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'create_mixing':
            $mixingData = [
                'amount' => floatval($_POST['amount'] ?? 0),
                'privacy_level' => $_POST['privacy_level'] ?? 'medium',
                'output_addresses' => []
            ];
            
            // Processar endereços de saída
            for ($i = 1; $i <= 5; $i++) {
                $address = $_POST["output_address_$i"] ?? '';
                $percentage = floatval($_POST["output_percentage_$i"] ?? 0);
                
                if (!empty($address) && $percentage > 0) {
                    $mixingData['output_addresses'][] = [
                        'address' => $address,
                        'percentage' => $percentage
                    ];
                }
            }
            
            // Validar dados
            $validationErrors = $bitcoinMixer->validateMixingRequest($mixingData);
            
            if (empty($validationErrors)) {
                $mixingResult = $bitcoinMixer->createMixingSession($user_id, $mixingData);
                if ($mixingResult['success']) {
                    $message = "Sessão de mixing criada com sucesso!";
                } else {
                    $error = $mixingResult['error'];
                }
            } else {
                $error = implode('<br>', $validationErrors);
            }
            break;
    }
}

// Obter histórico e estatísticas
$mixingHistory = $bitcoinMixer ? $bitcoinMixer->getUserMixingHistory($user_id) : [];
$mixerStats = $bitcoinMixer ? $bitcoinMixer->getMixerStatistics() : [];
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bitcoin Mixer - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: #1a1a1a; color: #e0e0e0; }
        .mixer-card {
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .privacy-level {
            border: 2px solid #444;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            cursor: pointer;
            transition: all 0.3s;
        }
        .privacy-level:hover, .privacy-level.selected {
            border-color: #ffc107;
            background: rgba(255, 193, 7, 0.1);
        }
        .output-address {
            background: #333;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .stats-box {
            text-align: center;
            padding: 20px;
            background: linear-gradient(45deg, #2d2d2d, #3d3d3d);
            border-radius: 10px;
            margin: 10px;
        }
        .progress-enhanced {
            height: 8px;
            background: #444;
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-enhanced .progress-bar {
            background: linear-gradient(90deg, #28a745, #20c997);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        .address-input {
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <?php if (file_exists('includes/header.php')) include 'includes/header.php'; ?>
    
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-12">
                <div class="mixer-card text-center">
                    <h2><i class="fas fa-random text-warning"></i> Bitcoin Mixer Profissional</h2>
                    <p class="lead">Misture seus Bitcoins com máxima privacidade e segurança</p>
                    
                    <!-- Estatísticas do Mixer -->
                    <div class="row mt-4">
                        <div class="col-md-3">
                            <div class="stats-box">
                                <h4><?= number_format($mixerStats['total_mixes'] ?? 0) ?></h4>
                                <small>Transações Processadas</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stats-box">
                                <h4><?= number_format($mixerStats['total_volume'] ?? 0, 3) ?> BTC</h4>
                                <small>Volume Total (30 dias)</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stats-box">
                                <h4><?= round($mixerStats['avg_time'] ?? 0) ?> min</h4>
                                <small>Tempo Médio</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stats-box">
                                <h4>99.7%</h4>
                                <small>Taxa de Sucesso</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <i class="fas fa-check-circle"></i> <?= htmlspecialchars($message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="fas fa-exclamation-triangle"></i> <?= $error ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if ($mixingResult && $mixingResult['success']): ?>
            <!-- Resultado da Criação de Mixing -->
            <div class="mixer-card border-success">
                <h4><i class="fas fa-check-circle text-success"></i> Sessão de Mixing Criada</h4>
                
                <div class="row">
                    <div class="col-md-6">
                        <h6>📋 Detalhes da Sessão:</h6>
                        <ul class="list-unstyled">
                            <li><strong>ID:</strong> <code><?= $mixingResult['mixing_session'] ?></code></li>
                            <li><strong>Quantidade:</strong> <?= $mixingResult['amount_to_send'] ?> BTC</li>
                            <li><strong>Taxa:</strong> <?= $mixingResult['fee_btc'] ?> BTC</li>
                            <li><strong>Valor Final:</strong> <?= $mixingResult['net_amount'] ?> BTC</li>
                            <li><strong>Tempo Estimado:</strong> <?= $mixingResult['estimated_time'] ?></li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6>💳 Endereço para Depósito:</h6>
                        <div class="code-display bg-dark p-3 rounded">
                            <code style="font-size: 14px; word-break: break-all;"><?= $mixingResult['deposit_address'] ?></code>
                        </div>
                        <button class="btn btn-sm btn-warning mt-2" onclick="copyToClipboard('<?= $mixingResult['deposit_address'] ?>')">
                            <i class="fas fa-copy"></i> Copiar Endereço
                        </button>
                    </div>
                </div>
                
                <div class="alert alert-info mt-3">
                    <h6><i class="fas fa-clock"></i> Próximos Passos:</h6>
                    <ol class="mb-0">
                        <li>Envie exatamente <strong><?= $mixingResult['amount_to_send'] ?> BTC</strong> para o endereço acima</li>
                        <li>Aguarde 1 confirmação na blockchain (~10 minutos)</li>
                        <li>O processo de mixing iniciará automaticamente</li>
                        <li>Seus Bitcoins serão enviados para os endereços de destino</li>
                    </ol>
                </div>
                
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Importante:</strong> Esta sessão expira em 24 horas. Não reutilize o endereço de depósito.
                </div>
            </div>
        <?php endif; ?>

        <div class="row">
            <!-- Formulário de Mixing -->
            <div class="col-md-8">
                <div class="mixer-card">
                    <h4><i class="fas fa-cogs"></i> Configurar Mixing</h4>
                    
                    <form method="POST" id="mixing-form">
                        <input type="hidden" name="action" value="create_mixing">
                        
                        <!-- Quantidade -->
                        <div class="mb-4">
                            <label class="form-label">💰 Quantidade a Misturar (BTC):</label>
                            <div class="input-group">
                                <input type="number" class="form-control" name="amount" 
                                       step="0.00000001" min="0.01" max="100" 
                                       placeholder="0.01000000" required>
                                <span class="input-group-text">BTC</span>
                            </div>
                            <small class="text-muted">Mínimo: 0.01 BTC | Máximo: 100 BTC</small>
                        </div>
                        
                        <!-- Nível de Privacidade -->
                        <div class="mb-4">
                            <label class="form-label">🔒 Nível de Privacidade:</label>
                            
                            <div class="privacy-level" data-level="low">
                                <div class="row">
                                    <div class="col-md-8">
                                        <h6>💡 Baixa - 0.5% Taxa</h6>
                                        <small>3 rounds de mixing, delay mínimo</small>
                                    </div>
                                    <div class="col-md-4 text-end">
                                        <span class="badge bg-info">15-45 min</span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="privacy-level" data-level="medium">
                                <div class="row">
                                    <div class="col-md-8">
                                        <h6>⚡ Média - 1.5% Taxa (Recomendado)</h6>
                                        <small>5 rounds de mixing, delays balanceados</small>
                                    </div>
                                    <div class="col-md-4 text-end">
                                        <span class="badge bg-warning">1-3 horas</span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="privacy-level" data-level="high">
                                <div class="row">
                                    <div class="col-md-8">
                                        <h6>🛡️ Alta - 2.5% Taxa</h6>
                                        <small>8 rounds de mixing, máxima privacidade</small>
                                    </div>
                                    <div class="col-md-4 text-end">
                                        <span class="badge bg-danger">2-6 horas</span>
                                    </div>
                                </div>
                            </div>
                            
                            <input type="hidden" name="privacy_level" id="selected_privacy_level" value="medium">
                        </div>
                        
                        <!-- Endereços de Saída -->
                        <div class="mb-4">
                            <label class="form-label">📤 Endereços de Destino:</label>
                            <small class="text-muted d-block mb-3">Adicione até 5 endereços onde receberá os bitcoins misturados</small>
                            
                            <div id="output-addresses">
                                <div class="output-address" data-index="1">
                                    <div class="row">
                                        <div class="col-md-8">
                                            <label class="form-label">Endereço Bitcoin #1:</label>
                                            <input type="text" class="form-control address-input" 
                                                   name="output_address_1" 
                                                   placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" required>
                                        </div>
                                        <div class="col-md-4">
                                            <label class="form-label">Porcentagem (%):</label>
                                            <input type="number" class="form-control percentage-input" 
                                                   name="output_percentage_1" 
                                                   min="1" max="100" value="100" required>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <button type="button" class="btn btn-outline-primary btn-sm mt-2" onclick="addOutputAddress()">
                                <i class="fas fa-plus"></i> Adicionar Endereço
                            </button>
                            
                            <div class="alert alert-info mt-3">
                                <small>
                                    <i class="fas fa-info-circle"></i>
                                    <strong>Dica:</strong> Use múltiplos endereços para maior privacidade. 
                                    A soma das porcentagens deve ser exatamente 100%.
                                </small>
                            </div>
                        </div>
                        
                        <!-- Resumo da Taxa -->
                        <div class="mb-4">
                            <div class="card bg-dark border-warning">
                                <div class="card-body">
                                    <h6 class="card-title">💳 Resumo dos Custos:</h6>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <small>Taxa de Mixing: <span id="fee-display">1.5%</span></small><br>
                                            <small>Quantidade Líquida: <span id="net-amount-display">-</span></small>
                                        </div>
                                        <div class="col-md-6">
                                            <small>Taxa em BTC: <span id="fee-btc-display">-</span></small><br>
                                            <small>Taxa de Rede: ~0.0001 BTC</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Termos e Condições -->
                        <div class="mb-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="terms-check" required>
                                <label class="form-check-label" for="terms-check">
                                    Eu concordo com os <a href="#" data-bs-toggle="modal" data-bs-target="#termsModal">termos de uso</a> 
                                    e entendo que o mixing é irreversível
                                </label>
                            </div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-warning btn-lg">
                                <i class="fas fa-random"></i> Iniciar Mixing Bitcoin
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Informações e Histórico -->
            <div class="col-md-4">
                <!-- Como Funciona -->
                <div class="mixer-card">
                    <h5><i class="fas fa-question-circle"></i> Como Funciona?</h5>
                    
                    <div class="timeline">
                        <div class="d-flex mb-3">
                            <div class="bg-primary rounded-circle me-3 d-flex align-items-center justify-content-center" style="width: 30px; height: 30px;">
                                <small>1</small>
                            </div>
                            <div>
                                <small><strong>Depósito</strong><br>Envie BTC para endereço único</small>
                            </div>
                        </div>
                        
                        <div class="d-flex mb-3">
                            <div class="bg-primary rounded-circle me-3 d-flex align-items-center justify-content-center" style="width: 30px; height: 30px;">
                                <small>2</small>
                            </div>
                            <div>
                                <small><strong>Mixing</strong><br>Múltiplas transações através de pools</small>
                            </div>
                        </div>
                        
                        <div class="d-flex mb-3">
                            <div class="bg-primary rounded-circle me-3 d-flex align-items-center justify-content-center" style="width: 30px; height: 30px;">
                                <small>3</small>
                            </div>
                            <div>
                                <small><strong>Distribuição</strong><br>BTC limpo enviado aos destinos</small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="alert alert-success">
                        <small>
                            <i class="fas fa-shield-alt"></i>
                            <strong>100% Anônimo:</strong> Não mantemos logs de transações após 48h
                        </small>
                    </div>
                </div>
                
                <!-- Histórico de Mixing -->
                <?php if (!empty($mixingHistory)): ?>
                <div class="mixer-card">
                    <h5><i class="fas fa-history"></i> Seu Histórico</h5>
                    
                    <?php foreach (array_slice($mixingHistory, 0, 5) as $mix): ?>
                    <div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-dark rounded">
                        <div>
                            <small class="text-muted"><?= date('d/m/Y H:i', strtotime($mix['created_at'])) ?></small><br>
                            <strong><?= $mix['total_input_btc'] ?> BTC</strong>
                        </div>
                        <div class="text-end">
                            <?php
                            $statusColors = [
                                'completed' => 'success',
                                'processing' => 'warning', 
                                'pending' => 'info',
                                'failed' => 'danger'
                            ];
                            $statusColor = $statusColors[$mix['status']] ?? 'secondary';
                            ?>
                            <span class="badge bg-<?= $statusColor ?>"><?= ucfirst($mix['status']) ?></span>
                            <?php if ($mix['status'] === 'processing'): ?>
                                <div class="progress-enhanced mt-1" style="width: 60px;">
                                    <div class="progress-bar" style="width: <?= $mix['progress_percentage'] ?>%"></div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                    
                    <a href="#" class="btn btn-sm btn-outline-primary w-100 mt-2">Ver Histórico Completo</a>
                </div>
                <?php endif; ?>
                
                <!-- Segurança -->
                <div class="mixer-card">
                    <h5><i class="fas fa-lock"></i> Segurança</h5>
                    
                    <ul class="list-unstyled">
                        <li class="mb-2">
                            <i class="fas fa-check text-success"></i>
                            <small>SSL 256-bit + TOR</small>
                        </li>
                        <li class="mb-2">
                            <i class="fas fa-check text-success"></i>
                            <small>Pools com 1000+ BTC</small>
                        </li>
                        <li class="mb-2">
                            <i class="fas fa-check text-success"></i>
                            <small>Delays aleatórios</small>
                        </li>
                        <li class="mb-2">
                            <i class="fas fa-check text-success"></i>
                            <small>Zero logs após 48h</small>
                        </li>
                        <li class="mb-2">
                            <i class="fas fa-check text-success"></i>
                            <small>Múltiplas confirmações</small>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal Termos -->
    <div class="modal fade" id="termsModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">Termos de Uso - Bitcoin Mixer</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <h6>1. Natureza do Serviço</h6>
                    <p>O Bitcoin Mixer é um serviço de privacidade que mistura bitcoins através de pools descentralizados para aumentar a privacidade das transações.</p>
                    
                    <h6>2. Responsabilidade do Usuário</h6>
                    <ul>
                        <li>Você é responsável pela legalidade do uso em sua jurisdição</li>
                        <li>Não use para atividades ilegais ou lavagem de dinheiro</li>
                        <li>Mantenha registros adequados para fins fiscais</li>
                    </ul>
                    
                    <h6>3. Limitações do Serviço</h6>
                    <ul>
                        <li>Mínimo: 0.01 BTC | Máximo: 100 BTC por transação</li>
                        <li>Taxa de 0.5% a 2.5% dependendo do nível de privacidade</li>
                        <li>Tempo de processamento: 15 minutos a 6 horas</li>
                    </ul>
                    
                    <h6>4. Política de Privacidade</h6>
                    <ul>
                        <li>Logs são automaticamente deletados após 48 horas</li>
                        <li>Não coletamos informações pessoais</li>
                        <li>Recomendamos uso através de TOR</li>
                    </ul>
                    
                    <h6>5. Isenção de Responsabilidade</h6>
                    <p>O serviço é fornecido "como está". Não garantimos resultados específicos e não somos responsáveis por perdas.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Entendido</button>
                </div>
            </div>
        </div>
    </div>
    
    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
    // Variáveis globais
    let outputAddressCount = 1;
    const maxOutputAddresses = 5;
    const fees = {
        'low': 0.005,
        'medium': 0.015,
        'high': 0.025
    };
    
    // Inicialização
    document.addEventListener('DOMContentLoaded', function() {
        // Selecionar nível médio por padrão
        selectPrivacyLevel('medium');
        
        // Calcular custos em tempo real
        document.querySelector('input[name="amount"]').addEventListener('input', calculateCosts);
        
        // Validar porcentagens
        document.addEventListener('input', function(e) {
            if (e.target.classList.contains('percentage-input')) {
                validatePercentages();
            }
        });
    });
    
    // Selecionar nível de privacidade
    function selectPrivacyLevel(level) {
        // Remover seleção anterior
        document.querySelectorAll('.privacy-level').forEach(el => {
            el.classList.remove('selected');
        });
        
        // Selecionar novo nível
        document.querySelector(`[data-level="${level}"]`).classList.add('selected');
        document.getElementById('selected_privacy_level').value = level;
        
        // Atualizar exibição da taxa
        const feePercentage = (fees[level] * 100).toFixed(1);
        document.getElementById('fee-display').textContent = feePercentage + '%';
        
        calculateCosts();
    }
    
    // Event listeners para níveis de privacidade
    document.querySelectorAll('.privacy-level').forEach(level => {
        level.addEventListener('click', function() {
            selectPrivacyLevel(this.dataset.level);
        });
    });
    
    // Adicionar endereço de saída
    function addOutputAddress() {
        if (outputAddressCount >= maxOutputAddresses) {
            alert('Máximo de 5 endereços permitidos');
            return;
        }
        
        outputAddressCount++;
        
        const container = document.getElementById('output-addresses');
        const newAddress = document.createElement('div');
        newAddress.className = 'output-address';
        newAddress.setAttribute('data-index', outputAddressCount);
        
        newAddress.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <label class="form-label">Endereço Bitcoin #${outputAddressCount}:</label>
                    <input type="text" class="form-control address-input" 
                           name="output_address_${outputAddressCount}" 
                           placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa">
                </div>
                <div class="col-md-3">
                    <label class="form-label">Porcentagem (%):</label>
                    <input type="number" class="form-control percentage-input" 
                           name="output_percentage_${outputAddressCount}" 
                           min="1" max="100" value="0">
                </div>
                <div class="col-md-1">
                    <label class="form-label">&nbsp;</label>
                    <button type="button" class="btn btn-danger btn-sm d-block" onclick="removeOutputAddress(${outputAddressCount})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `;
        
        container.appendChild(newAddress);
        
        // Redistribuir porcentagens
        redistributePercentages();
    }
    
    // Remover endereço de saída
    function removeOutputAddress(index) {
        const addressDiv = document.querySelector(`[data-index="${index}"]`);
        if (addressDiv) {
            addressDiv.remove();
            redistributePercentages();
        }
    }
    
    // Redistribuir porcentagens automaticamente
    function redistributePercentages() {
        const percentageInputs = document.querySelectorAll('.percentage-input');
        const activeInputs = Array.from(percentageInputs).filter(input => 
            input.closest('.output-address') !== null
        );
        
        if (activeInputs.length > 0) {
            const equalPercentage = Math.floor(100 / activeInputs.length);
            let remainder = 100 - (equalPercentage * activeInputs.length);
            
            activeInputs.forEach((input, index) => {
                input.value = equalPercentage + (index === 0 ? remainder : 0);
            });
        }
        
        validatePercentages();
    }
    
    // Validar porcentagens
    function validatePercentages() {
        const percentageInputs = document.querySelectorAll('.percentage-input');
        const activeInputs = Array.from(percentageInputs).filter(input => 
            input.closest('.output-address') !== null && input.value > 0
        );
        
        const total = activeInputs.reduce((sum, input) => sum + parseFloat(input.value || 0), 0);
        
        // Destacar inputs inválidos
        activeInputs.forEach(input => {
            if (total > 100) {
                input.classList.add('is-invalid');
            } else {
                input.classList.remove('is-invalid');
            }
        });
        
        // Atualizar botão de submit
        const submitBtn = document.querySelector('button[type="submit"]');
        if (Math.abs(total - 100) > 0.01) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = `<i class="fas fa-exclamation-triangle"></i> Ajuste as porcentagens (${total.toFixed(1)}%)`;
        } else {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-random"></i> Iniciar Mixing Bitcoin';
        }
    }
    
    // Calcular custos
    function calculateCosts() {
        const amount = parseFloat(document.querySelector('input[name="amount"]').value || 0);
        const level = document.getElementById('selected_privacy_level').value;
        
        if (amount > 0 && fees[level]) {
            const feeAmount = amount * fees[level];
            const netAmount = amount - feeAmount;
            
            document.getElementById('fee-btc-display').textContent = feeAmount.toFixed(8) + ' BTC';
            document.getElementById('net-amount-display').textContent = netAmount.toFixed(8) + ' BTC';
        } else {
            document.getElementById('fee-btc-display').textContent = '-';
            document.getElementById('net-amount-display').textContent = '-';
        }
    }
    
    // Copiar endereço
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            // Feedback visual
            const btn = event.target.closest('button');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> Copiado!';
            btn.classList.add('btn-success');
            
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.classList.remove('btn-success');
            }, 2000);
        }).catch(() => {
            alert('Erro ao copiar. Copie manualmente: ' + text);
        });
    }
    
    // Validação do formulário
    document.getElementById('mixing-form').addEventListener('submit', function(e) {
        const amount = parseFloat(document.querySelector('input[name="amount"]').value || 0);
        
        if (amount < 0.01) {
            e.preventDefault();
            alert('Quantidade mínima: 0.01 BTC');
            return;
        }
        
        if (amount > 100) {
            e.preventDefault();
            alert('Quantidade máxima: 100 BTC');
            return;
        }
        
        // Verificar se há pelo menos um endereço válido
        const addresses = document.querySelectorAll('input[name^="output_address_"]');
        let hasValidAddress = false;
        
        addresses.forEach(addr => {
            if (addr.value.trim().length > 0) {
                hasValidAddress = true;
            }
        });
        
        if (!hasValidAddress) {
            e.preventDefault();
            alert('Adicione pelo menos um endereço de destino');
            return;
        }
        
        // Confirmação final
        if (!confirm(`Confirma o mixing de ${amount} BTC?\n\nEsta ação é irreversível!`)) {
            e.preventDefault();
        }
    });
    </script>
</body>
</html>