<?php
/**
 * GUIA DE INTEGRAÇÃO - SISTEMA DE SAQUE REAL
 * Como integrar o secure_withdrawal.php no seu projeto ZeeMarket
 */

// ============================================
// 1. SUBSTITUIR O REQUIRE QUEBRADO
// ============================================

// ❌ NO ARQUIVO paste.txt você tem isto (QUEBRADO):
// require_once __DIR__ . '/real_withdrawal_system.php';

// ✅ SUBSTITUA POR:
require_once __DIR__ . '/includes/secure_withdrawal.php';

// ============================================
// 2. CRIAR PÁGINA DE SAQUE (withdraw_real.php)
// ============================================
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Saque de Criptomoedas - ZeeMarket</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
</head>
<body>
<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/secure_withdrawal.php';

// Verificar se está logado
verificarLogin();

$message = '';
$messageType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $userId = $_SESSION['user_id'];
        $crypto = sanitizeInput($_POST['crypto']);
        $toAddress = sanitizeInput($_POST['to_address']);
        $amount = floatval($_POST['amount']);
        
        // Processar saque real
        $realWithdrawal = new RealWithdrawalSystem($conn);
        $result = $realWithdrawal->processRealWithdrawal($userId, $toAddress, $amount, $crypto);
        
        if ($result['success']) {
            $message = "✅ " . $result['message'] . "<br>";
            $message .= "🔗 <a href='" . $result['explorer_url'] . "' target='_blank'>Ver na Blockchain</a><br>";
            $message .= "⏱️ Confirmação estimada: " . $result['estimated_confirmation'];
            $messageType = 'success';
        } else {
            $message = "❌ " . $result['error'];
            $messageType = 'danger';
        }
        
    } catch (Exception $e) {
        $message = "❌ Erro: " . $e->getMessage();
        $messageType = 'danger';
    }
}

// Obter saldos do usuário
$userBalance = getUserWalletInfo($_SESSION['user_id']);
?>

<div class="container mt-4">
    <h2>💰 Saque de Criptomoedas</h2>
    
    <?php if ($message): ?>
    <div class="alert alert-<?= $messageType ?>" role="alert">
        <?= $message ?>
    </div>
    <?php endif; ?>
    
    <!-- Saldos Disponíveis -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card">
                <div class="card-body text-center">
                    <h5>Bitcoin (BTC)</h5>
                    <h3><?= number_format($userBalance['btc_balance'], 8) ?> BTC</h3>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
                <div class="card-body text-center">
                    <h5>Ethereum (ETH)</h5>
                    <h3><?= number_format($userBalance['eth_balance'], 6) ?> ETH</h3>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
                <div class="card-body text-center">
                    <h5>Monero (XMR)</h5>
                    <h3><?= number_format($userBalance['xmr_balance'], 6) ?> XMR</h3>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Formulário de Saque -->
    <div class="card">
        <div class="card-header">
            <h4>🚀 Realizar Saque</h4>
        </div>
        <div class="card-body">
            <form method="POST" action="">
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="crypto" class="form-label">Criptomoeda</label>
                            <select class="form-select" id="crypto" name="crypto" required>
                                <option value="BTC">Bitcoin (BTC)</option>
                                <option value="ETH">Ethereum (ETH)</option>
                                <option value="XMR">Monero (XMR)</option>
                            </select>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="amount" class="form-label">Valor</label>
                            <input type="number" step="0.00000001" class="form-control" 
                                   id="amount" name="amount" required>
                            <div class="form-text">
                                Mínimo: BTC 0.0001, ETH 0.001, XMR 0.01
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <label for="to_address" class="form-label">Endereço de Destino</label>
                    <input type="text" class="form-control" id="to_address" 
                           name="to_address" required 
                           placeholder="Digite o endereço da carteira de destino">
                </div>
                
                <div class="alert alert-warning">
                    <h6>⚠️ Importante:</h6>
                    <ul class="mb-0">
                        <li>Verifique o endereço com cuidado - transações são irreversíveis</li>
                        <li>Taxa de rede será deduzida automaticamente</li>
                        <li>Limite: 5 saques por hora</li>
                        <li>Processamento pode levar alguns minutos</li>
                    </ul>
                </div>
                
                <button type="submit" class="btn btn-primary btn-lg">
                    🚀 Processar Saque
                </button>
            </form>
        </div>
    </div>
</div>

<script src="assets/js/bootstrap.bundle.min.js"></script>
</body>
</html>

<?php