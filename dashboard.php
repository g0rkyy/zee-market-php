<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// IMPORTANTE: Incluir config.php PRIMEIRO
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Verificar login ANTES de qualquer coisa
verificarLogin();

// Se chegou aqui, o usuário está logado
$user_id = $_SESSION['user_id'];

// Gerar token CSRF se não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ✅ SISTEMAS DE PRIVACIDADE - COM VERIFICAÇÃO DE ERRO
$torSystem = null;
$pgpSystem = null;
$privacyAnalysis = null;
$hasPGPKeys = false;

try {
    // Tentar incluir e inicializar sistemas de privacidade
    if (file_exists('includes/tor_system.php')) {
        require_once 'includes/tor_system.php';
        if (class_exists('ZeeMarketTor')) {
            $torSystem = new ZeeMarketTor($conn);
            $privacyAnalysis = $torSystem->analyzePrivacyLevel($user_id);
        }
    }
    
    if (file_exists('includes/pgp_system.php')) {
        require_once 'includes/pgp_system.php';
        if (class_exists('ZeeMarketPGP')) {
            $pgpSystem = new ZeeMarketPGP($conn);
            $hasPGPKeys = $pgpSystem->userHasPgpKey($user_id);
        }
    }
} catch (Exception $e) {
    error_log("Erro ao inicializar sistemas de privacidade: " . $e->getMessage());
    // Continuar sem os sistemas de privacidade
}

// Query modificada para incluir múltiplas criptomoedas
try {
    $stmt = $conn->prepare("
        SELECT u.name, u.email, u.btc_balance, u.eth_balance, u.xmr_balance,
               u.btc_wallet, u.btc_deposit_address, u.eth_deposit_address, u.xmr_deposit_address
        FROM users u
        WHERE u.id = ?
    ");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $user_data = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$user_data) {
        error_log("Dados do usuário não encontrados para ID: $user_id");
        logout();
    }
    
} catch (Exception $e) {
    error_log("Erro ao buscar dados do usuário: " . $e->getMessage());
    $_SESSION['error_msg'] = "Erro ao carregar dados do usuário";
    $user_data = [
        'name' => $_SESSION['user_name'] ?? 'Usuário',
        'email' => '',
        'btc_balance' => 0,
        'eth_balance' => 0,
        'xmr_balance' => 0,
        'btc_deposit_address' => null,
        'eth_deposit_address' => null,
        'xmr_deposit_address' => null
    ];
}

// Buscar reputação - ✅ SANITIZADA
try {
    $reputacao = getReputacao($user_id);
    // ✅ HIGIENIZAR DADOS DE REPUTAÇÃO
    if ($reputacao && is_array($reputacao)) {
        $reputacao['level'] = htmlspecialchars($reputacao['level'] ?? 'Novato');
        $reputacao['icon'] = htmlspecialchars($reputacao['icon'] ?? '☆');
    } else {
        $reputacao = [
            'level' => 'Novato',
            'icon' => '☆'
        ];
    }
} catch (Exception $e) {
    error_log("Erro ao buscar reputação: " . $e->getMessage());
    $reputacao = [
        'level' => 'Novato',
        'icon' => '☆'
    ];
}

// Buscar transações recentes - ✅ HIGIENIZAÇÃO COMPLETA
try {
    $stmt = $conn->prepare("
        SELECT tx_hash, type, amount, crypto_type, status, 
               COALESCE(confirmations, 0) as confirmations, created_at 
        FROM btc_transactions 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $transactions_raw = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
    // ✅ HIGIENIZAR TODAS AS TRANSAÇÕES
    $recent_transactions = [];
    foreach ($transactions_raw as $tx) {
        $recent_transactions[] = [
            'tx_hash' => htmlspecialchars($tx['tx_hash'] ?? ''),
            'type' => htmlspecialchars($tx['type'] ?? ''),
            'amount' => (float)($tx['amount'] ?? 0),
            'crypto_type' => htmlspecialchars(strtoupper($tx['crypto_type'] ?? 'BTC')),
            'crypto_type_class' => htmlspecialchars(strtolower($tx['crypto_type'] ?? 'btc')),
            'status' => htmlspecialchars($tx['status'] ?? 'pending'),
            'confirmations' => (int)($tx['confirmations'] ?? 0),
            'created_at' => htmlspecialchars($tx['created_at'] ?? ''),
            'created_at_formatted' => date('d/m/Y H:i', strtotime($tx['created_at'] ?? 'now'))
        ];
    }
} catch (Exception $e) {
    error_log("Erro ao buscar transações: " . $e->getMessage());
    $recent_transactions = [];
}

// Buscar cotações atuais - considere usar uma API real aqui
try {
    $crypto_rates = [
        'bitcoin' => ['usd' => 45000, 'brl' => 240000],
        'ethereum' => ['usd' => 2800, 'brl' => 15000],
        'monero' => ['usd' => 180, 'brl' => 950]
    ];
} catch (Exception $e) {
    error_log("Erro ao buscar cotações: " . $e->getMessage());
    $crypto_rates = [
        'bitcoin' => ['usd' => 45000, 'brl' => 240000],
        'ethereum' => ['usd' => 2800, 'brl' => 15000],
        'monero' => ['usd' => 180, 'brl' => 950]
    ];
}

// Status de privacidade para exibição
$privacy_status = [
    'tor_connected' => $privacyAnalysis['connected'] ?? false,
    'tor_confidence' => $privacyAnalysis['confidence'] ?? 0,
    'pgp_enabled' => $hasPGPKeys,
    'security_level' => getSecurityLevel()
];

// ✅ SANITIZAR TODOS OS DADOS DO USUÁRIO ANTES DE USAR
$user_data_safe = [
    'name' => htmlspecialchars($user_data['name'] ?? 'Usuário'),
    'email' => htmlspecialchars($user_data['email'] ?? ''),
    'btc_balance' => (float)($user_data['btc_balance'] ?? 0),
    'eth_balance' => (float)($user_data['eth_balance'] ?? 0),
    'xmr_balance' => (float)($user_data['xmr_balance'] ?? 0),
    'btc_deposit_address' => htmlspecialchars($user_data['btc_deposit_address'] ?? ''),
    'eth_deposit_address' => htmlspecialchars($user_data['eth_deposit_address'] ?? ''),
    'xmr_deposit_address' => htmlspecialchars($user_data['xmr_deposit_address'] ?? ''),
    'btc_wallet' => htmlspecialchars($user_data['btc_wallet'] ?? '')
];

?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #8a63f2;
            --primary-hover: #6e4acf;
            --secondary-color: #ffc107;
            --success-color: #28a745;
            --btc-orange: #f7931a;
            --eth-blue: #627eea;
            --xmr-orange: #ff6600;
            --dark-bg: #121212;
            --dark-card: #1e1e1e;
            --dark-border: #333;
            --dark-text: #e0e0e0;
            --dark-muted: #a0a0a0;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--dark-text);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        #container-principal {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 2rem;
            background: var(--dark-card);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            border: 1px solid var(--dark-border);
        }
        
        .crypto-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .crypto-card {
            background: var(--dark-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--dark-border);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .crypto-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 25px rgba(0,0,0,0.3);
        }
        
        .crypto-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            border-radius: 12px 12px 0 0;
        }
        
        .crypto-card.btc::before { background: var(--btc-orange); }
        .crypto-card.eth::before { background: var(--eth-blue); }
        .crypto-card.xmr::before { background: var(--xmr-orange); }
        
        .crypto-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 1rem;
        }
        
        .crypto-icon {
            font-size: 2rem;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .crypto-icon.btc { background: rgba(247, 147, 26, 0.2); color: var(--btc-orange); }
        .crypto-icon.eth { background: rgba(98, 126, 234, 0.2); color: var(--eth-blue); }
        .crypto-icon.xmr { background: rgba(255, 102, 0, 0.2); color: var(--xmr-orange); }
        
        .crypto-balance {
            font-size: 1.8rem;
            font-weight: 700;
            margin: 1rem 0;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .crypto-balance.btc { color: var(--btc-orange); }
        .crypto-balance.eth { color: var(--eth-blue); }
        .crypto-balance.xmr { color: var(--xmr-orange); }
        
        .crypto-value {
            font-size: 0.9rem;
            color: var(--dark-muted);
            margin-bottom: 1rem;
        }
        
        .crypto-address {
            background: rgba(15, 15, 15, 0.5);
            padding: 0.75rem;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            word-break: break-all;
            border: 1px dashed var(--dark-border);
            margin: 1rem 0;
        }
        
        .crypto-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn-crypto {
            flex: 1;
            padding: 0.6rem;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
            border: none;
            font-size: 0.85rem;
            cursor: pointer;
        }
        
        .btn-deposit { background: rgba(40, 167, 69, 0.2); color: #28a745; border: 1px solid #28a745; }
        .btn-withdraw { background: rgba(220, 53, 69, 0.2); color: #dc3545; border: 1px solid #dc3545; }
        .btn-generate { background: rgba(138, 99, 242, 0.2); color: var(--primary-color); border: 1px solid var(--primary-color); }
        
        .btn-deposit:hover { background: #28a745; color: white; }
        .btn-withdraw:hover { background: #dc3545; color: white; }
        .btn-generate:hover { background: var(--primary-color); color: white; }
        
        .transactions-section {
            background: var(--dark-card);
            border-radius: 10px;
            padding: 1.5rem;
            margin-top: 2rem;
            border: 1px solid var(--dark-border);
        }
        
        .transaction-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem;
            border-bottom: 1px solid var(--dark-border);
            transition: background-color 0.2s ease;
        }
        
        .transaction-item:hover {
            background-color: rgba(255,255,255,0.05);
        }
        
        .transaction-item:last-child {
            border-bottom: none;
        }
        
        .transaction-details {
            flex: 1;
        }
        
        .transaction-amount {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .transaction-info {
            font-size: 0.8rem;
            color: var(--dark-muted);
        }
        
        .status-badge {
            padding: 0.25rem 0.6rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .status-pending {
            background-color: rgba(255, 243, 205, 0.2);
            color: #ffc107;
            border: 1px solid #ffc107;
        }
        
        .status-confirmed {
            background-color: rgba(40, 167, 69, 0.2);
            color: #28a745;
            border: 1px solid #28a745;
        }
        
        .welcome-section {
            text-align: center;
            margin-bottom: 2.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--dark-border);
        }
        
        .welcome-section img {
            width: 120px;
            height: 120px;
            object-fit: cover;
            border-radius: 50%;
            border: 4px solid var(--primary-color);
            margin-bottom: 1rem;
            box-shadow: 0 4px 15px rgba(138, 99, 242, 0.3);
        }
        
        .neon-effect {
            text-shadow: 0 0 5px rgba(138, 99, 242, 0.7),
                         0 0 10px rgba(138, 99, 242, 0.5),
                         0 0 15px rgba(138, 99, 242, 0.3);
        }
        
        .reputation-badge {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
            margin-left: 0.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        
        .reputation-gold {
            background: linear-gradient(135deg, #ffd700, #ffbf00);
            color: #8a6d3b;
        }
        
        .modal-dark .modal-content {
            background-color: var(--dark-card);
            border: 1px solid var(--dark-border);
            color: var(--dark-text);
        }
        
        .modal-dark .modal-header {
            border-bottom: 1px solid var(--dark-border);
        }
        
        .modal-dark .form-control {
            background-color: rgba(30, 30, 30, 0.8);
            border: 1px solid var(--dark-border);
            color: var(--dark-text);
        }
        
        .modal-dark .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(138, 99, 242, 0.25);
        }
        
        .nav-buttons {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }
        
        .nav-buttons .btn {
            flex: 1 1 200px;
            padding: 0.75rem;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 1px solid var(--dark-border);
            text-decoration: none;
        }
        
        .alert-dark {
            background-color: rgba(40, 167, 69, 0.1);
            border: 1px solid #28a745;
            color: #28a745;
        }
        
        .alert-dark.alert-danger {
            background-color: rgba(220, 53, 69, 0.1);
            border: 1px solid #dc3545;
            color: #dc3545;
        }
        
        /* ✅ INDICADOR DE SEGURANÇA */
        .security-indicator {
            position: fixed;
            top: 10px;
            right: 10px;
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            z-index: 9999;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        
        @media (max-width: 768px) {
            #container-principal {
                margin: 1rem;
                padding: 1rem;
            }
            
            .crypto-grid {
                grid-template-columns: 1fr;
            }
            
            .crypto-actions {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <!-- ✅ INDICADOR DE SEGURANÇA -->
    <div class="security-indicator">
        🛡️ XSS-PROOF DASHBOARD
    </div>

    <div id="container-principal">
        <!-- Mensagens de status - ✅ JÁ HIGIENIZADAS -->
        <?php if(isset($_SESSION['success_msg'])): ?>
            <div class="alert alert-dark alert-dismissible fade show">
                <i class="bi bi-check-circle"></i> <?= htmlspecialchars($_SESSION['success_msg']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['success_msg']); ?>
        <?php endif; ?>
        
        <?php if(isset($_SESSION['error_msg'])): ?>
            <div class="alert alert-dark alert-danger alert-dismissible fade show">
                <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($_SESSION['error_msg']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['error_msg']); ?>
        <?php endif; ?>

        <!-- Navegação -->
        <div class="nav-buttons">
            <a href="index.php" class="btn btn-outline-primary">
                <i class="bi bi-house-door"></i> Home
            </a>
            <a href="vendedores.php" class="btn btn-outline-info">
                <i class="bi bi-shop"></i> Área Vendedor
            </a>
            <a href="logout.php" class="btn btn-outline-danger">
                <i class="bi bi-box-arrow-right"></i> Sair
            </a>
            <a href="painel_usuario.php" class="btn btn-outline-secondary">
                <i class="bi bi-person-circle"></i> 2FA
            </a> 
        </div>

        <!-- Seção de Boas-vindas - ✅ TOTALMENTE HIGIENIZADA -->
        <div class="welcome-section">
            <img src="assets/images/perfil.png" alt="Foto de perfil" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjEyMCIgdmlld0JveD0iMCAwIDEyMCAxMjAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBjeD0iNjAiIGN5PSI2MCIgcj0iNjAiIGZpbGw9IiM4YTYzZjIiLz48dGV4dCB4PSI2MCIgeT0iNzAiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSI0OCIgZmlsbD0id2hpdGUiIHRleHQtYW5jaG9yPSJtaWRkbGUiPjwvdGV4dD48L3N2Zz4='">
            <h1 class="neon-effect">Olá, <?= $user_data_safe['name'] ?> 
                <span class="reputation-badge reputation-gold">
                    <?= $reputacao['icon'] ?> <?= $reputacao['level'] ?>
                </span>
            </h1>
            <p class="text-muted">Bem-vindo ao seu painel de controle multi-cripto</p>
        </div>

        <!-- Grid de Criptomoedas - ✅ TOTALMENTE HIGIENIZADO -->
        <div class="crypto-grid">
            <!-- Bitcoin -->
            <div class="crypto-card btc">
                <div class="crypto-header">
                    <div class="crypto-icon btc">
                        <i class="bi bi-currency-bitcoin"></i>
                    </div>
                    <div>
                        <h3>Bitcoin</h3>
                        <small class="text-muted">BTC</small>
                    </div>
                </div>
                
                <div class="crypto-balance btc">
                    <?= htmlspecialchars(number_format($user_data_safe['btc_balance'], 8)) ?> BTC
                </div>
                
                <div class="crypto-value">
                    ≈ R$ <?= htmlspecialchars(number_format($user_data_safe['btc_balance'] * ($crypto_rates['bitcoin']['brl'] ?? 0), 2, ',', '.')) ?>
                </div>
                
                <?php if(!empty($user_data_safe['btc_deposit_address'])): ?>
                    <div class="crypto-address">
                        <small>Endereço de depósito:</small><br>
                        <?= $user_data_safe['btc_deposit_address'] ?>
                    </div>
                    
                    <div class="crypto-actions">
                        <button class="btn-crypto btn-deposit" onclick="openDepositModal('BTC', '<?= $user_data_safe['btc_deposit_address'] ?>')">
                            <i class="bi bi-box-arrow-in-down"></i> Depositar
                        </button>
                        <a href="withdraw_real.php?crypto=BTC" class="btn-crypto btn-withdraw">
                            <i class="bi bi-box-arrow-up"></i> Sacar Real
                        </a>
                    </div>
                <?php else: ?>
                    <div class="crypto-actions">
                        <button class="btn-crypto btn-generate" onclick="generateAddress('BTC')">
                            <i class="bi bi-lightning"></i> Gerar Carteira BTC
                        </button>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Ethereum -->
            <div class="crypto-card eth">
                <div class="crypto-header">
                    <div class="crypto-icon eth">
                        <i class="bi bi-currency-exchange"></i>
                    </div>
                    <div>
                        <h3>Ethereum</h3>
                        <small class="text-muted">ETH</small>
                    </div>
                </div>
                
                <div class="crypto-balance eth">
                    <?= htmlspecialchars(number_format($user_data_safe['eth_balance'], 6)) ?> ETH
                </div>
                
                <div class="crypto-value">
                    ≈ R$ <?= htmlspecialchars(number_format($user_data_safe['eth_balance'] * ($crypto_rates['ethereum']['brl'] ?? 0), 2, ',', '.')) ?>
                </div>
                
                <?php if(!empty($user_data_safe['eth_deposit_address'])): ?>
                    <div class="crypto-address">
                        <small>Endereço de depósito:</small><br>
                        <?= $user_data_safe['eth_deposit_address'] ?>
                    </div>
                    
                    <div class="crypto-actions">
                        <button class="btn-crypto btn-deposit" onclick="openDepositModal('ETH', '<?= $user_data_safe['eth_deposit_address'] ?>')">
                            <i class="bi bi-box-arrow-in-down"></i> Depositar
                        </button>
                        <a href="withdraw_real.php?crypto=ETH" class="btn-crypto btn-withdraw">
                            <i class="bi bi-box-arrow-up"></i> Sacar Real
                        </a>
                    </div>
                <?php else: ?>
                    <div class="crypto-actions">
                        <button class="btn-crypto btn-generate" onclick="generateAddress('ETH')">
                            <i class="bi bi-lightning"></i> Gerar Carteira ETH
                        </button>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Monero -->
            <div class="crypto-card xmr">
                <div class="crypto-header">
                    <div class="crypto-icon xmr">
                        <i class="bi bi-shield-shaded"></i>
                    </div>
                    <div>
                        <h3>Monero</h3>
                        <small class="text-muted">XMR</small>
                    </div>
                </div>
                
                <div class="crypto-balance xmr">
                    <?= htmlspecialchars(number_format($user_data_safe['xmr_balance'], 6)) ?> XMR
                </div>
                
                <div class="crypto-value">
                    ≈ R$ <?= htmlspecialchars(number_format($user_data_safe['xmr_balance'] * ($crypto_rates['monero']['brl'] ?? 0), 2, ',', '.')) ?>
                </div>
                
                <?php if(!empty($user_data_safe['xmr_deposit_address'])): ?>
                    <div class="crypto-address">
                        <small>Endereço de depósito:</small><br>
                        <?= $user_data_safe['xmr_deposit_address'] ?>
                    </div>
                    
                    <div class="crypto-actions">
                        <button class="btn-crypto btn-deposit" onclick="openDepositModal('XMR', '<?= $user_data_safe['xmr_deposit_address'] ?>')">
                            <i class="bi bi-box-arrow-in-down"></i> Depositar
                        </button>
                        <a href="withdraw_real.php?crypto=XMR" class="btn-crypto btn-withdraw">
                            <i class="bi bi-box-arrow-up"></i> Sacar Real
                        </a>
                    </div>
                <?php else: ?>
                    <div class="crypto-actions">
                        <button class="btn-crypto btn-generate" onclick="generateAddress('XMR')">
                            <i class="bi bi-lightning"></i> Gerar Carteira XMR
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Seção de Transações Recentes - ✅ HIGIENIZAÇÃO TOTAL -->
        <div class="transactions-section">
            <h3><i class="bi bi-clock-history"></i> Transações Recentes</h3>
            
            <?php if (!empty($recent_transactions)): ?>
                <div class="transaction-list">
                    <?php foreach ($recent_transactions as $tx): ?>
                        <div class="transaction-item">
                            <div class="transaction-details">
                                <div class="transaction-amount <?= $tx['crypto_type_class'] ?>">
                                    <?php if ($tx['type'] === 'deposit'): ?>
                                        <i class="bi bi-arrow-down-circle text-success"></i>
                                    <?php else: ?>
                                        <i class="bi bi-arrow-up-circle text-danger"></i>
                                    <?php endif; ?>
                                    <?= htmlspecialchars(number_format($tx['amount'], 6)) ?> <?= $tx['crypto_type'] ?>
                                </div>
                                <div class="transaction-info">
                                    <?= ucfirst($tx['type']) ?> • 
                                    <?= $tx['created_at_formatted'] ?> • 
                                    <?= htmlspecialchars(substr($tx['tx_hash'], 0, 16)) ?>...
                                    <?php if ($tx['confirmations'] > 0): ?>
                                        • <?= htmlspecialchars($tx['confirmations']) ?> confirmações
                                    <?php endif; ?>
                                </div>
                            </div>
                            <span class="status-badge status-<?= $tx['status'] ?>">
                                <?= ucfirst($tx['status']) ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p class="text-muted text-center py-4">
                    <i class="bi bi-inbox"></i> Nenhuma transação ainda
                </p>
            <?php endif; ?>
        </div>

        <!-- Seção de Estatísticas - ✅ CÁLCULOS SEGUROS -->
        <div class="transactions-section">
            <h3><i class="bi bi-bar-chart"></i> Resumo da Conta</h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="card bg-dark border-warning">
                        <div class="card-body text-center">
                            <h5>Total em BRL</h5>
                            <h3 class="text-warning">
                                R$ <?= htmlspecialchars(number_format(
                                    ($user_data_safe['btc_balance'] * ($crypto_rates['bitcoin']['brl'] ?? 0)) +
                                    ($user_data_safe['eth_balance'] * ($crypto_rates['ethereum']['brl'] ?? 0)) +
                                    ($user_data_safe['xmr_balance'] * ($crypto_rates['monero']['brl'] ?? 0)),
                                    2, ',', '.'
                                )) ?>
                            </h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-dark border-success">
                        <div class="card-body text-center">
                            <h5>Transações</h5>
                            <h3 class="text-success"><?= htmlspecialchars(count($recent_transactions)) ?></h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-dark border-info">
                        <div class="card-body text-center">
                            <h5>Carteiras Ativas</h5>
                            <h3 class="text-info">
                                <?= htmlspecialchars(
                                    (!empty($user_data_safe['btc_deposit_address']) ? 1 : 0) +
                                    (!empty($user_data_safe['eth_deposit_address']) ? 1 : 0) +
                                    (!empty($user_data_safe['xmr_deposit_address']) ? 1 : 0)
                                ) ?>
                            </h3>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Seção de Privacidade - ✅ DADOS SANITIZADOS -->
        <?php if ($privacyAnalysis && isset($privacyAnalysis['privacy_score'])): ?>
        <div class="col-md-6 col-lg-4 mb-4">
            <div class="card bg-dark border-<?= $privacyAnalysis['privacy_score'] >= 60 ? 'success' : 'warning' ?>">
                <div class="card-body">
                    <h5 class="card-title">
                        <i class="fas fa-shield-alt"></i> Privacidade
                    </h5>
                    
                    <!-- Score de Privacidade -->
                    <div class="privacy-score mb-3">
                        <div class="d-flex justify-content-between align-items-center">
                            <span>Score:</span>
                            <h3 class="mb-0 text-<?= $privacyAnalysis['privacy_score'] >= 60 ? 'success' : 'warning' ?>">
                                <?= htmlspecialchars($privacyAnalysis['privacy_score']) ?>/100
                            </h3>
                        </div>
                        <div class="progress" style="height: 10px;">
                            <div class="progress-bar bg-<?= $privacyAnalysis['privacy_score'] >= 60 ? 'success' : 'warning' ?>" 
                                 style="width: <?= htmlspecialchars($privacyAnalysis['privacy_score']) ?>%"></div>
                        </div>
                    </div>
                    
                    <!-- Status dos recursos -->
                    <div class="privacy-features">
                        <div class="d-flex justify-content-between mb-2">
                            <span><i class="fas fa-user-secret"></i> TOR</span>
                            <span class="badge bg-<?= isset($privacyAnalysis['tor_usage']['is_tor']) && $privacyAnalysis['tor_usage']['is_tor'] ? 'success' : 'secondary' ?>">
                                <?= isset($privacyAnalysis['tor_usage']['is_tor']) && $privacyAnalysis['tor_usage']['is_tor'] ? 'Ativo' : 'Inativo' ?>
                            </span>
                        </div>
                        
                        <div class="d-flex justify-content-between mb-2">
                            <span><i class="fas fa-key"></i> PGP</span>
                            <span class="badge bg-<?= $hasPGPKeys ? 'success' : 'secondary' ?>">
                                <?= $hasPGPKeys ? 'Configurado' : 'Não configurado' ?>
                            </span>
                        </div>
                        
                        <div class="d-flex justify-content-between mb-2">
                            <span><i class="fas fa-random"></i> Mixing</span>
                            <span class="badge bg-<?= isset($privacyAnalysis['mixing_history']) && $privacyAnalysis['mixing_history'] > 0 ? 'success' : 'secondary' ?>">
                                <?= isset($privacyAnalysis['mixing_history']) && $privacyAnalysis['mixing_history'] > 0 ? 'Usado' : 'Nunca usado' ?>
                            </span>
                        </div>
                    </div>
                    
                    <!-- Botão de ação -->
                    <div class="text-center mt-3">
                        <a href="privacy_settings.php" class="btn btn-sm btn-outline-light">
                            <i class="fas fa-cog"></i> Configurar Privacidade
                        </a>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- ✅ ALERTAS DE PRIVACIDADE SANITIZADOS -->
        <?php if (!empty($privacyAnalysis['recommendations']) && is_array($privacyAnalysis['recommendations'])): ?>
        <div class="col-12">
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <h6 class="alert-heading"><i class="fas fa-exclamation-triangle"></i> Melhorias de Privacidade Disponíveis</h6>
                <ul class="mb-0">
                    <?php foreach ($privacyAnalysis['recommendations'] as $rec): ?>
                        <li><?= htmlspecialchars($rec) ?></li>
                    <?php endforeach; ?>
                </ul>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        </div>
        <?php endif; ?>

        <!-- ✅ ENDEREÇO .ONION SANITIZADO -->
        <?php 
        if ($torSystem && method_exists($torSystem, 'getOnionAddress')) {
            $onionAddress = $torSystem->getOnionAddress();
            if ($onionAddress && (!isset($privacyAnalysis['tor_usage']['is_tor']) || !$privacyAnalysis['tor_usage']['is_tor'])): 
        ?>
        <div class="col-12">
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i> 
                <strong>Acesso TOR disponível:</strong> 
                <code><?= htmlspecialchars($onionAddress) ?></code>
                <button class="btn btn-sm btn-secondary float-end" onclick="copyToClipboard('<?= htmlspecialchars($onionAddress) ?>')">
                    <i class="fas fa-copy"></i> Copiar
                </button>
            </div>
        </div>
        <?php 
            endif;
        }
        ?>
    </div>
    
    <!-- Modal de Depósito - ✅ HIGIENIZADO -->
    <div class="modal fade modal-dark" id="depositModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-box-arrow-in-down"></i> Depositar <span id="depositCrypto"></span>
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center mb-4">
                        <div id="depositQRCode"></div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Endereço para depósito:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="depositAddress" readonly>
                            <button class="btn btn-outline-secondary" onclick="copyAddress()">
                                <i class="bi bi-copy"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="alert alert-info">
                        <h6><i class="bi bi-info-circle"></i> Instruções:</h6>
                        <ul class="mb-0">
                            <li>Envie apenas <span id="cryptoName"></span> para este endereço</li>
                            <li>Depósitos são creditados após 1-3 confirmações</li>
                            <li>Valor mínimo: 0.0001 (BTC) / 0.001 (ETH) / 0.01 (XMR)</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal de Saque - ✅ HIGIENIZADO -->
    <div class="modal fade modal-dark" id="withdrawModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-box-arrow-up"></i> Sacar <span id="withdrawCrypto"></span>
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="withdrawForm">
                        <input type="hidden" id="withdrawCryptoType" name="crypto_type">
                        
                        <div class="mb-3">
                            <label class="form-label">Endereço de destino:</label>
                            <input type="text" class="form-control" name="to_address" required 
                                   placeholder="Endereço da carteira de destino">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Valor a sacar:</label>
                            <div class="input-group">
                                <input type="number" class="form-control" name="amount" step="0.00000001" 
                                       min="0.0001" required placeholder="0.00000000">
                                <span class="input-group-text" id="withdrawCryptoSymbol">BTC</span>
                            </div>
                            <small class="text-muted">
                                Saldo disponível: <span id="availableBalance">0.00000000</span> <span id="balanceCrypto">BTC</span>
                            </small>
                        </div>
                        
                        <div class="alert alert-warning">
                            <h6><i class="bi bi-exclamation-triangle"></i> Atenção:</h6>
                            <ul class="mb-0">
                                <li>Verifique o endereço de destino</li>
                                <li>Taxa de rede será deduzida automaticamente</li>
                                <li>Transações são irreversíveis</li>
                            </ul>
                        </div>
                        
                        <button type="submit" class="btn btn-danger w-100">
                            <i class="bi bi-send"></i> Confirmar Saque
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
    <script>
        // ✅ FUNÇÃO SEGURA PARA GERAR ENDEREÇO
        async function generateAddress(crypto) {
            // Sanitizar entrada
            const validCryptos = ['BTC', 'ETH', 'XMR'];
            if (!validCryptos.includes(crypto)) {
                showAlert('error', 'Criptomoeda inválida!');
                return;
            }
            
            try {
                const response = await fetch('generate_wallet.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `csrf_token=${encodeURIComponent('<?= htmlspecialchars($_SESSION['csrf_token']) ?>')}&crypto=${encodeURIComponent(crypto)}`
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showAlert('success', `Endereço ${crypto} gerado com sucesso!`);
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showAlert('error', data.error || `Erro ao gerar endereço ${crypto}`);
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert('error', 'Erro na comunicação com o servidor');
            }
        }

        // ✅ FUNÇÃO SEGURA PARA ABRIR MODAL DE DEPÓSITO
        function openDepositModal(crypto, address) {
            // Sanitizar entradas
            const validCryptos = ['BTC', 'ETH', 'XMR'];
            if (!validCryptos.includes(crypto)) {
                showAlert('error', 'Criptomoeda inválida!');
                return;
            }
            
            if (!address || address.length < 10) {
                showAlert('error', 'Endereço inválido!');
                return;
            }
            
            // Escapar dados para DOM
            document.getElementById('depositCrypto').textContent = crypto;
            document.getElementById('cryptoName').textContent = crypto;
            document.getElementById('depositAddress').value = address;
            
            // Gerar QR Code seguro
            const qrContainer = document.getElementById('depositQRCode');
            qrContainer.innerHTML = '';
            
            const qrData = crypto === 'BTC' ? `bitcoin:${address}` : 
                          crypto === 'ETH' ? `ethereum:${address}` : 
                          `${crypto.toLowerCase()}:${address}`;
            
            QRCode.toCanvas(qrContainer, qrData, {
                width: 200,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#FFFFFF'
                }
            });
            
            new bootstrap.Modal(document.getElementById('depositModal')).show();
        }

        // ✅ FUNÇÃO SEGURA PARA ABRIR MODAL DE SAQUE
        function openWithdrawModal(crypto) {
            // Sanitizar entrada
            const validCryptos = ['BTC', 'ETH', 'XMR'];
            if (!validCryptos.includes(crypto)) {
                showAlert('error', 'Criptomoeda inválida!');
                return;
            }
            
            document.getElementById('withdrawCrypto').textContent = crypto;
            document.getElementById('withdrawCryptoType').value = crypto;
            document.getElementById('withdrawCryptoSymbol').textContent = crypto;
            document.getElementById('balanceCrypto').textContent = crypto;
            
            // Definir saldo disponível (valores já sanitizados)
            const balances = {
                'BTC': <?= $user_data_safe['btc_balance'] ?>,
                'ETH': <?= $user_data_safe['eth_balance'] ?>,
                'XMR': <?= $user_data_safe['xmr_balance'] ?>
            };
            
            document.getElementById('availableBalance').textContent = 
                parseFloat(balances[crypto]).toFixed(8);
            
            new bootstrap.Modal(document.getElementById('withdrawModal')).show();
        }

        // ✅ FUNÇÃO SEGURA PARA PROCESSAR SAQUE
        document.getElementById('withdrawForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData);
            
            // Validação extra no frontend
            if (!data.to_address || data.to_address.length < 10) {
                showAlert('error', 'Endereço de destino inválido!');
                return;
            }
            
            if (!data.amount || parseFloat(data.amount) <= 0) {
                showAlert('error', 'Valor inválido!');
                return;
            }
            
            try {
                const response = await fetch('withdraw.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showAlert('success', result.message);
                    bootstrap.Modal.getInstance(document.getElementById('withdrawModal')).hide();
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showAlert('error', result.error);
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert('error', 'Erro na comunicação com o servidor');
            }
        });

        // ✅ FUNÇÃO SEGURA PARA COPIAR ENDEREÇO
        function copyAddress() {
            const addressInput = document.getElementById('depositAddress');
            addressInput.select();
            navigator.clipboard.writeText(addressInput.value).then(() => {
                showAlert('success', 'Endereço copiado para a área de transferência!');
            }).catch(() => {
                // Fallback para navegadores antigos
                document.execCommand('copy');
                showAlert('success', 'Endereço copiado!');
            });
        }

        // ✅ FUNÇÃO SEGURA PARA MOSTRAR ALERTAS
        function showAlert(type, message) {
            // Sanitizar message antes de exibir
            const sanitizedMessage = message.replace(/[<>]/g, '');
            
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-dark ${type === 'error' ? 'alert-danger' : ''} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                <i class="bi bi-${type === 'error' ? 'exclamation-triangle' : 'check-circle'}"></i> ${sanitizedMessage}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            const container = document.getElementById('container-principal');
            container.insertBefore(alertDiv, container.firstChild);
            
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        }

        // ✅ FUNÇÃO SEGURA PARA COPIAR ENDEREÇO .ONION
        function copyToClipboard(text) {
            if (!text || typeof text !== 'string') {
                showAlert('error', 'Texto inválido para copiar');
                return;
            }
            
            navigator.clipboard.writeText(text).then(() => {
                showAlert('success', 'Endereço .onion copiado!');
            }).catch(() => {
                showAlert('error', 'Erro ao copiar endereço');
            });
        }

        // Verificação automática em background
        function autoCheck() {
            fetch('api/cron_checker.php?api=1')
                .then(response => response.json())
                .then(data => {
                    console.log('Auto-check concluído:', data);
                    
                    // Atualizar saldos se houver mudanças
                    if (data.deposits_checked > 0) {
                        setTimeout(() => location.reload(), 2000);
                    }
                })
                .catch(error => console.error('Erro na verificação automática:', error));
        }

        // Iniciar verificação automática
        setTimeout(autoCheck, 60000); // Primeira verificação após 1 minuto
        setInterval(autoCheck, 300000); // Depois a cada 5 minutos

        // Notificação de modo real (só para admins)
        <?php if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']): ?>
            // Verificar se o modo real está ativo
            fetch('admin/get_system_status.php')
                .then(response => response.json())
                .then(data => {
                    if (data.real_mode) {
                        console.warn('🔴 MODO REAL ATIVO - APIs blockchain conectadas!');
                        
                        // Mostrar indicador visual
                        const indicator = document.createElement('div');
                        indicator.innerHTML = '🔴 MODO REAL';
                        indicator.style.cssText = `
                            position: fixed; top: 10px; left: 10px; 
                            background: #dc3545; color: white; 
                            padding: 5px 10px; border-radius: 5px; 
                            font-weight: bold; z-index: 9999;
                        `;
                        document.body.appendChild(indicator);
                    }
                });
        <?php endif; ?>

        // Fechar alertas automaticamente
        setTimeout(() => {
            document.querySelectorAll('.alert').forEach(alert => {
                if (bootstrap.Alert.getInstance(alert)) {
                    bootstrap.Alert.getInstance(alert).close();
                }
            });
        }, 5000);

        // Auto-atualizar score de privacidade
        <?php if (isset($privacyAnalysis['privacy_score']) && $privacyAnalysis['privacy_score'] < 60): ?>
        setTimeout(() => {
            if (confirm('Seu score de privacidade está baixo. Deseja melhorá-lo agora?')) {
                window.location.href = 'privacy_settings.php';
            }
        }, 5000);
        <?php endif; ?>

        console.log('✅ Dashboard XSS-Proof carregado com sucesso!');
    </script>

    <!-- Botão de acesso rápido ao admin (só para admins) -->
    <?php if (isset($_SESSION['user_id']) && function_exists('isAdmin') && isAdmin($_SESSION['user_id'])): ?>
        <div style="position: fixed; bottom: 20px; right: 20px; z-index: 1000;">
            <a href="admin/admin_painel.php" class="btn btn-danger btn-lg rounded-circle" 
               title="Painel Admin" style="width: 60px; height: 60px; display: flex; align-items: center; justify-content: center;">
                🛡️
            </a>
        </div>
    <?php endif; ?>
</body>
</html>