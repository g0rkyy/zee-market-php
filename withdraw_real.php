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
require_once __DIR__ . '/includes/secure_withdrawal_v2.php';

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
    <style>
        /* Adicione isso no seu arquivo CSS existente ou crie um novo */
:root {
  --primary: #6c5ce7;
  --secondary: #a29bfe;
  --dark: #1e272e;
  --darker: #0f1519;
  --light: #f5f6fa;
  --success: #00b894;
  --danger: #d63031;
  --warning: #fdcb6e;
  --info: #0984e3;
}

body {
  background-color: var(--darker);
  color: var(--light);
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.container {
  max-width: 1200px;
}

.card {
  background-color: var(--dark);
  border: none;
  border-radius: 10px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
  transition: transform 0.3s ease;
  margin-bottom: 20px;
}

.card:hover {
  transform: translateY(-5px);
}

.card-header {
  background-color: rgba(108, 92, 231, 0.1);
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  font-weight: 600;
}

.card-body {
  padding: 1.5rem;
}

h2, h3, h4, h5 {
  color: var(--light);
  font-weight: 600;
}

h2 {
  margin-bottom: 1.5rem;
  position: relative;
  padding-bottom: 10px;
}

h2::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  width: 50px;
  height: 3px;
  background: var(--primary);
}

.form-control, .form-select {
  background-color: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: var(--light);
  padding: 10px 15px;
}

.form-control:focus, .form-select:focus {
  background-color: rgba(255, 255, 255, 0.1);
  border-color: var(--primary);
  color: var(--light);
  box-shadow: 0 0 0 0.25rem rgba(108, 92, 231, 0.25);
}

.form-text {
  color: rgba(255, 255, 255, 0.6) !important;
}

.btn-primary {
  background-color: var(--primary);
  border: none;
  padding: 10px 25px;
  font-weight: 600;
  transition: all 0.3s ease;
}

.btn-primary:hover {
  background-color: #5649c0;
  transform: translateY(-2px);
  box-shadow: 0 4px 15px rgba(108, 92, 231, 0.4);
}

.alert {
  border: none;
  border-left: 4px solid;
}

.alert-success {
  background-color: rgba(0, 184, 148, 0.1);
  border-left-color: var(--success);
  color: #b8f2e6;
}

.alert-danger {
  background-color: rgba(214, 48, 49, 0.1);
  border-left-color: var(--danger);
  color: #f8c3c3;
}

.alert-info {
  background-color: rgba(9, 132, 227, 0.1);
  border-left-color: var(--info);
  color: #c3e3f8;
}

.alert-warning {
  background-color: rgba(253, 203, 110, 0.1);
  border-left-color: var(--warning);
  color: #f8e8c3;
}

/* Efeitos para os cards de saldo */
.card .card-body {
  transition: all 0.3s ease;
}

.card .card-body:hover {
  background-color: rgba(108, 92, 231, 0.05);
}

/* Animação suave para o formulário */
form {
  animation: fadeIn 0.5s ease;
}
.form-label{
    color: white;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Responsividade */
@media (max-width: 768px) {
  .card {
    margin-bottom: 15px;
  }
  
  h2 {
    font-size: 1.8rem;
  }
}
    </style>
</head>
<body>
<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/secure_withdrawal_v2.php';

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
        $secureWithdrawal = new SecureWithdrawalSystemV2($conn);
        $result = $secureWithdrawal->processSecureWithdrawal(
            $userId,
            $toAddress,
            $amount,
            $crypto,
            $_POST['2fa_code'] // Adicione campo 2FA no formulário
        );
        
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
    <h2>Saque de Criptomoedas</h2>
    
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
            <h4>Realizar Saque</h4>
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
                <div class="mb-3">
    <label for="2fa_code" class="form-label">Código 2FA</label>
    <input type="text" class="form-control" id="2fa_code" 
           name="2fa_code" required 
           placeholder="Digite o código do seu autenticador">
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
                    Processar Saque
                </button>
            </form>
        </div>
    </div>
</div>

<script src="assets/js/bootstrap.bundle.min.js"></script>
</body>
</html>

<?php