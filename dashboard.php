<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// IMPORTANTE: Incluir config.php PRIMEIRO
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Verificar login ANTES de qualquer coisa
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Se chegou aqui, o usuário está logado
$user_id = $_SESSION['user_id'];

// Gerar token CSRF se não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Query modificada para incluir múltiplas criptomoedas
try {
    $stmt = $conn->prepare("
        SELECT u.name, u.email, u.btc_balance, u.eth_balance, u.xmr_balance,
               u.btc_wallet, u.btc_deposit_address, u.eth_deposit_address, u.xmr_deposit_address, u.created_at
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
        'xmr_deposit_address' => null,
        'created_at' => date('Y-m-d H:i:s')
    ];
}

// Buscar transações recentes
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
    
    $recent_transactions = [];
    foreach ($transactions_raw as $tx) {
        $recent_transactions[] = [
            'tx_hash' => htmlspecialchars($tx['tx_hash'] ?? ''),
            'type' => htmlspecialchars($tx['type'] ?? ''),
            'amount' => (float)($tx['amount'] ?? 0),
            'crypto_type' => htmlspecialchars(strtoupper($tx['crypto_type'] ?? 'BTC')),
            'status' => htmlspecialchars($tx['status'] ?? 'pending'),
            'confirmations' => (int)($tx['confirmations'] ?? 0),
            'created_at_formatted' => date('d/m/Y H:i', strtotime($tx['created_at'] ?? 'now'))
        ];
    }
} catch (Exception $e) {
    error_log("Erro ao buscar transações: " . $e->getMessage());
    $recent_transactions = [];
}

// Sanitizar dados do usuário
$user_data_safe = [
    'name' => htmlspecialchars($user_data['name'] ?? 'Usuário'),
    'email' => htmlspecialchars($user_data['email'] ?? ''),
    'btc_balance' => (float)($user_data['btc_balance'] ?? 0),
    'eth_balance' => (float)($user_data['eth_balance'] ?? 0),
    'xmr_balance' => (float)($user_data['xmr_balance'] ?? 0),
    'btc_deposit_address' => htmlspecialchars($user_data['btc_deposit_address'] ?? ''),
    'eth_deposit_address' => htmlspecialchars($user_data['eth_deposit_address'] ?? ''),
    'xmr_deposit_address' => htmlspecialchars($user_data['xmr_deposit_address'] ?? ''),
    'created_at' => htmlspecialchars($user_data['created_at'] ?? '')
];

?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeeMarket - Deep Web Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: #000;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            line-height: 1.4;
            overflow-x: hidden;
        }
        
        /* Matrix effect background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(90deg, transparent 79px, #001100 81px, #001100 82px, transparent 84px),
                linear-gradient(0deg, transparent 79px, #001100 81px, #001100 82px, transparent 84px),
                radial-gradient(circle at 10% 20%, #003300 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, #002200 0%, transparent 50%);
            background-size: 80px 80px, 80px 80px, 100% 100%, 100% 100%;
            opacity: 0.1;
            z-index: -1;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            border: 2px solid #00ff00;
            background: rgba(0, 51, 0, 0.3);
            margin-bottom: 20px;
            padding: 15px;
            text-align: center;
            position: relative;
        }
        
        .header::before {
            content: '◄ SECURE CONNECTION ESTABLISHED ►';
            position: absolute;
            top: -12px;
            left: 50%;
            transform: translateX(-50%);
            background: #000;
            padding: 0 10px;
            font-size: 12px;
            color: #00ff00;
        }
        
        .header h1 {
            font-size: 24px;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff00;
        }
        
        .user-info {
            font-size: 14px;
            color: #33ff33;
        }
        
        /* Navigation */
        .nav-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav-btn {
            display: block;
            padding: 15px;
            border: 1px solid #00ff00;
            background: rgba(0, 51, 0, 0.2);
            color: #00ff00;
            text-decoration: none;
            text-align: center;
            transition: all 0.3s ease;
            font-family: inherit;
            font-size: 14px;
            position: relative;
        }
        
        .nav-btn:hover {
            background: rgba(0, 255, 0, 0.1);
            box-shadow: 0 0 15px #00ff00;
            color: #00ff00;
        }
        
        .nav-btn::before {
            content: '> ';
        }
        
        /* Crypto Cards */
        .crypto-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .crypto-card {
            border: 2px solid #00ff00;
            background: rgba(0, 51, 0, 0.2);
            padding: 20px;
            position: relative;
        }
        
        .crypto-card.btc { border-color: #ffaa00; }
        .crypto-card.eth { border-color: #627eea; }
        .crypto-card.xmr { border-color: #ff6600; }
        
        .crypto-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #00ff00;
        }
        
        .crypto-icon {
            font-size: 24px;
            font-weight: bold;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid;
        }
        
        .crypto-icon.btc { color: #ffaa00; border-color: #ffaa00; }
        .crypto-icon.eth { color: #627eea; border-color: #627eea; }
        .crypto-icon.xmr { color: #ff6600; border-color: #ff6600; }
        
        .crypto-balance {
            font-size: 20px;
            font-weight: bold;
            margin: 15px 0;
        }
        
        .crypto-balance.btc { color: #ffaa00; }
        .crypto-balance.eth { color: #627eea; }
        .crypto-balance.xmr { color: #ff6600; }
        
        .crypto-address {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #333;
            padding: 10px;
            margin: 15px 0;
            font-size: 12px;
            word-break: break-all;
            color: #cccccc;
        }
        
        .crypto-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 12px 15px;
            border: 1px solid #00ff00;
            background: rgba(0, 51, 0, 0.3);
            color: #00ff00;
            text-decoration: none;
            text-align: center;
            font-family: inherit;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: block;
        }
        
        .btn:hover {
            background: rgba(0, 255, 0, 0.2);
            box-shadow: 0 0 10px #00ff00;
        }
        
        .btn-generate { border-color: #00ff00; color: #00ff00; }
        .btn-deposit { border-color: #33ff33; color: #33ff33; }
        .btn-withdraw { border-color: #ff3333; color: #ff3333; }
        
        /* Transactions */
        .transactions-section {
            border: 2px solid #00ff00;
            background: rgba(0, 51, 0, 0.2);
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 18px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #00ff00;
        }
        
        .transaction-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #333;
            font-size: 12px;
        }
        
        .transaction-item:last-child {
            border-bottom: none;
        }
        
        .transaction-details {
            flex: 1;
        }
        
        .transaction-amount {
            font-weight: bold;
            color: #33ff33;
        }
        
        .transaction-info {
            color: #666;
            font-size: 11px;
        }
        
        .status-badge {
            padding: 5px 10px;
            border: 1px solid;
            font-size: 10px;
            text-transform: uppercase;
        }
        
        .status-pending { border-color: #ffaa00; color: #ffaa00; }
        .status-confirmed { border-color: #33ff33; color: #33ff33; }
        .status-failed { border-color: #ff3333; color: #ff3333; }
        
        /* Alerts */
        .alert {
            border: 1px solid;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-success { border-color: #33ff33; color: #33ff33; background: rgba(51, 255, 51, 0.1); }
        .alert-danger { border-color: #ff3333; color: #ff3333; background: rgba(255, 51, 51, 0.1); }
        .alert-info { border-color: #3399ff; color: #3399ff; background: rgba(51, 153, 255, 0.1); }
        
        /* Footer */
        .footer {
            border: 1px solid #333;
            text-align: center;
            padding: 20px;
            margin-top: 30px;
            font-size: 12px;
            color: #666;
        }
        
        /* Security indicator */
        .security-status {
            position: fixed;
            top: 10px;
            right: 10px;
            background: rgba(0, 51, 0, 0.8);
            border: 1px solid #00ff00;
            padding: 10px;
            font-size: 12px;
            z-index: 1000;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .crypto-grid {
                grid-template-columns: 1fr;
            }
            
            .nav-grid {
                grid-template-columns: 1fr;
            }
            
            .transaction-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }
        }
        
        /* Terminal effect */
        .terminal-text {
            animation: terminal-blink 2s infinite;
        }
        
        @keyframes terminal-blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.5; }
        }
        
        /* Glitch effect for errors */
        .glitch {
            animation: glitch 0.3s ease-in-out infinite alternate;
        }
        
        @keyframes glitch {
            0% { transform: translateX(0); }
            20% { transform: translateX(-2px); }
            40% { transform: translateX(2px); }
            60% { transform: translateX(-2px); }
            80% { transform: translateX(2px); }
            100% { transform: translateX(0); }
        }
        
        /* No JavaScript notice */
        .no-js-notice {
            background: rgba(255, 51, 51, 0.2);
            border: 1px solid #ff3333;
            color: #ff3333;
            padding: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="security-status">
        ◄ ENCRYPTED ► TOR READY
    </div>

    <div class="container">
        <?php if(isset($_SESSION['success_msg'])): ?>
            <div class="alert alert-success">
                ► SUCCESS: <?= htmlspecialchars($_SESSION['success_msg'], ENT_QUOTES, 'UTF-8') ?>
            </div>
            <?php unset($_SESSION['success_msg']); ?>
        <?php endif; ?>
        
        <?php if(isset($_SESSION['error_msg'])): ?>
            <div class="alert alert-danger glitch">
                ► ERROR: <?= htmlspecialchars($_SESSION['error_msg'], ENT_QUOTES, 'UTF-8') ?>
            </div>
            <?php unset($_SESSION['error_msg']); ?>
        <?php endif; ?>

        <div class="no-js-notice">
            ► NOTICE: JavaScript disabled for maximum security. Pure HTML interface active.
        </div>

        <!-- Header -->
        <div class="header">
            <h1>ZEE MARKET</h1>
            <div class="user-info">
                USER: <?= $user_data_safe['name'] ?> | 
                MEMBER SINCE: <?= date('Y', strtotime($user_data_safe['created_at'])) ?> |
                SESSION: ACTIVE
            </div>
        </div>

        <!-- Navigation -->
        <div class="nav-grid">
            <a href="index.php" class="nav-btn">MARKETPLACE</a>
            <a href="vendedores.php" class="nav-btn">VENDOR AREA</a>
            <a href="privacy_settings.php" class="nav-btn">PRIVACY CONFIG</a>
            <a href="painel_usuario.php" class="nav-btn">2FA SECURITY</a>
            <a href="alterar_senha.php" class="nav-btn">CHANGE PASSWORD</a>
            <a href="excluir_conta.php" class="nav-btn">DELETE ACCOUNT</a>
            <a href="logout.php" class="nav-btn">LOGOUT</a>
        </div>

        <!-- Crypto Wallets -->
        <div class="crypto-grid">
            <!-- Bitcoin -->
            <div class="crypto-card btc">
                <div class="crypto-header">
                    <div class="crypto-icon btc">₿</div>
                    <div>
                        <h3>BITCOIN</h3>
                        <div>BTC WALLET</div>
                    </div>
                </div>
                
                <div class="crypto-balance btc">
                    <?= number_format($user_data_safe['btc_balance'], 8) ?> BTC
                </div>
                
                <?php if(!empty($user_data_safe['btc_deposit_address'])): ?>
                    <div class="crypto-address">
                        DEPOSIT ADDRESS:<br>
                        <?= $user_data_safe['btc_deposit_address'] ?>
                    </div>
                    
                    <div class="crypto-actions">
                        <a href="deposit.php?crypto=BTC" class="btn btn-deposit">DEPOSIT</a>
                        <a href="withdraw.php?crypto=BTC" class="btn btn-withdraw">WITHDRAW</a>
                    </div>
                <?php else: ?>
                    <div class="crypto-actions">
                        <form method="POST" action="generate_wallet.php" style="display: inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                            <input type="hidden" name="crypto" value="BTC">
                            <button type="submit" class="btn btn-generate">GENERATE WALLET</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Ethereum -->
            <div class="crypto-card eth">
                <div class="crypto-header">
                    <div class="crypto-icon eth">Ξ</div>
                    <div>
                        <h3>ETHEREUM</h3>
                        <div>ETH WALLET</div>
                    </div>
                </div>
                
                <div class="crypto-balance eth">
                    <?= number_format($user_data_safe['eth_balance'], 6) ?> ETH
                </div>
                
                <?php if(!empty($user_data_safe['eth_deposit_address'])): ?>
                    <div class="crypto-address">
                        DEPOSIT ADDRESS:<br>
                        <?= $user_data_safe['eth_deposit_address'] ?>
                    </div>
                    
                    <div class="crypto-actions">
                        <a href="deposit.php?crypto=ETH" class="btn btn-deposit">DEPOSIT</a>
                        <a href="withdraw.php?crypto=ETH" class="btn btn-withdraw">WITHDRAW</a>
                    </div>
                <?php else: ?>
                    <div class="crypto-actions">
                        <form method="POST" action="generate_wallet.php" style="display: inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                            <input type="hidden" name="crypto" value="ETH">
                            <button type="submit" class="btn btn-generate">GENERATE WALLET</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Monero -->
            <div class="crypto-card xmr">
                <div class="crypto-header">
                    <div class="crypto-icon xmr">ɱ</div>
                    <div>
                        <h3>MONERO</h3>
                        <div>XMR WALLET</div>
                    </div>
                </div>
                
                <div class="crypto-balance xmr">
                    <?= number_format($user_data_safe['xmr_balance'], 6) ?> XMR
                </div>
                
                <?php if(!empty($user_data_safe['xmr_deposit_address'])): ?>
                    <div class="crypto-address">
                        DEPOSIT ADDRESS:<br>
                        <?= $user_data_safe['xmr_deposit_address'] ?>
                    </div>
                    
                    <div class="crypto-actions">
                        <a href="deposit.php?crypto=XMR" class="btn btn-deposit">DEPOSIT</a>
                        <a href="withdraw.php?crypto=XMR" class="btn btn-withdraw">WITHDRAW</a>
                    </div>
                <?php else: ?>
                    <div class="crypto-actions">
                        <form method="POST" action="generate_wallet.php" style="display: inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                            <input type="hidden" name="crypto" value="XMR">
                            <button type="submit" class="btn btn-generate">GENERATE WALLET</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Transactions -->
        <div class="transactions-section">
            <h3 class="section-title">► RECENT TRANSACTIONS</h3>
            
            <?php if (!empty($recent_transactions)): ?>
                <?php foreach ($recent_transactions as $tx): ?>
                    <div class="transaction-item">
                        <div class="transaction-details">
                            <div class="transaction-amount">
                                <?= number_format($tx['amount'], 6) ?> <?= $tx['crypto_type'] ?>
                            </div>
                            <div class="transaction-info">
                                <?= strtoupper($tx['type']) ?> | 
                                <?= $tx['created_at_formatted'] ?> | 
                                <?= substr($tx['tx_hash'], 0, 16) ?>...
                                <?php if ($tx['confirmations'] > 0): ?>
                                    | <?= $tx['confirmations'] ?> CONF
                                <?php endif; ?>
                            </div>
                        </div>
                        <span class="status-badge status-<?= $tx['status'] ?>">
                            <?= strtoupper($tx['status']) ?>
                        </span>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <div style="text-align: center; padding: 40px; color: #666;">
                    ► NO TRANSACTIONS YET
                </div>
            <?php endif; ?>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div class="terminal-text">
                ► ZEE MARKET v2.0 | ANONYMOUS | SECURE | UNTRACEABLE ◄
            </div>
            <div style="margin-top: 10px; font-size: 10px;">
                CONNECTION ENCRYPTED | SESSION EXPIRES IN 60 MINUTES
            </div>
        </div>
    </div>

    <script>
        // Minimal JavaScript for form handling - no external dependencies
        document.addEventListener('DOMContentLoaded', function() {
            // Remove no-js notice if JS is enabled
            const noJsNotice = document.querySelector('.no-js-notice');
            if (noJsNotice) {
                noJsNotice.style.display = 'none';
            }
            
            // Add confirmation for wallet generation
            const generateForms = document.querySelectorAll('form[action="generate_wallet.php"]');
            generateForms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    const crypto = this.querySelector('input[name="crypto"]').value;
                    if (!confirm('Generate new ' + crypto + ' wallet address? This action cannot be undone.')) {
                        e.preventDefault();
                    }
                });
            });
            
            // Simple session timer
            let sessionTime = 3600; // 60 minutes
            setInterval(function() {
                sessionTime--;
                if (sessionTime <= 0) {
                    alert('Session expired. You will be redirected to login.');
                    window.location.href = 'logout.php';
                }
            }, 1000);
            
            console.log('ZeeMarket Deep Web Interface Loaded');
        });
    </script>
</body>
</html>