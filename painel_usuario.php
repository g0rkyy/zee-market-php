<?php
/**
 * PAINEL DO USUÁRIO CORRIGIDO - ZEEMARKET
 * Corrige erro de QR Code 2FA e implementa geração inline
 */

session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/two_factor_auth.php';

// Verificar se está logado
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['user_id'];
$message = '';
$messageType = 'info';

// Inicializar sistema 2FA
$twoFA = new TwoFactorAuth();

// Verificar se 2FA já está ativo
$is2FAEnabled = $twoFA->isUserTwoFAEnabled($userId);

// Buscar dados do usuário
$stmt = $conn->prepare("SELECT name, email, btc_balance, eth_balance, xmr_balance, created_at FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$userData = $stmt->get_result()->fetch_assoc();

if (!$userData) {
    $message = "Erro ao carregar dados do usuário";
    $messageType = 'danger';
}

// Processar ações
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'setup_2fa':
            if (!$is2FAEnabled) {
                $result = $twoFA->generateUserSecret($userId, $userData['name']);
                if ($result['success']) {
                    $_SESSION['temp_2fa_secret'] = $result['secret'];
                    $_SESSION['temp_backup_codes'] = $result['backup_codes'];
                    $message = "QR Code gerado! Configure seu app e digite o código para ativar.";
                    $messageType = 'success';
                } else {
                    $message = "Erro ao gerar 2FA: " . $result['error'];
                    $messageType = 'danger';
                }
            }
            break;
            
        case 'activate_2fa':
            $code = $_POST['verification_code'] ?? '';
            if (!empty($code) && isset($_SESSION['temp_2fa_secret'])) {
                $result = $twoFA->activateTwoFA($userId, $code);
                if ($result['success']) {
                    unset($_SESSION['temp_2fa_secret'], $_SESSION['temp_backup_codes']);
                    $is2FAEnabled = true;
                    $message = "2FA ativado com sucesso!";
                    $messageType = 'success';
                } else {
                    $message = "Código inválido: " . $result['error'];
                    $messageType = 'danger';
                }
            }
            break;
            
        case 'disable_2fa':
            $code = $_POST['disable_code'] ?? '';
            $password = $_POST['current_password'] ?? '';
            if (!empty($code) && !empty($password)) {
                $result = $twoFA->deactivateTwoFA($userId, $code, $password);
                if ($result['success']) {
                    $is2FAEnabled = false;
                    $message = "2FA desativado com sucesso!";
                    $messageType = 'success';
                } else {
                    $message = "Erro ao desativar: " . $result['error'];
                    $messageType = 'danger';
                }
            }
            break;
    }
}

// Buscar transações recentes
$stmt = $conn->prepare("
    SELECT type, amount, status, crypto_type, tx_hash, created_at 
    FROM btc_transactions 
    WHERE user_id = ? 
    ORDER BY created_at DESC 
    LIMIT 10
");
$stmt->bind_param("i", $userId);
$stmt->execute();
$recentTransactions = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Função para gerar QR Code inline com múltiplas opções
function generateQRCodeInline($secret, $issuer, $accountName) {
    // Limpar e formatar dados
    $secret = trim($secret);
    $issuer = trim($issuer);
    $accountName = trim($accountName);
    
    // Criar URL TOTP padrão
    $otpauth_url = sprintf(
        "otpauth://totp/%s:%s?secret=%s&issuer=%s",
        urlencode($issuer),
        urlencode($accountName),
        $secret,
        urlencode($issuer)
    );
    
    // Tentar múltiplas APIs de QR Code
    $qr_apis = [
        // API do Google Charts (mais confiável)
        "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=" . urlencode($otpauth_url),
        // API alternativa qr-server.com
        "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" . urlencode($otpauth_url),
        // API alternativa quickchart.io
        "https://quickchart.io/qr?text=" . urlencode($otpauth_url) . "&size=200"
    ];
    
    return $qr_apis[0]; // Usar primeira opção por padrão
}

// Função para debug - mostra a URL TOTP
function getOTPAuthURL($secret, $issuer, $accountName) {
    $secret = trim($secret);
    $issuer = trim($issuer);
    $accountName = trim($accountName);
    
    return sprintf(
        "otpauth://totp/%s:%s?secret=%s&issuer=%s",
        urlencode($issuer),
        urlencode($accountName),
        $secret,
        urlencode($issuer)
    );
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel do Usuário - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: #1a1a1a;
            color: #e0e0e0;
        }
        .card {
            background: #2d2d2d;
            border: 1px solid #444;
        }
        .card-header {
            background: #333;
            border-bottom: 1px solid #444;
        }
        .balance-card {
            background: linear-gradient(135deg, #f7931a, #e67e22);
            color: white;
            border: none;
        }
        .qr-container {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            display: inline-block;
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        .qr-container img {
            display: block;
            max-width: 100%;
            height: auto;
        }
        .backup-codes {
            background: #333;
            padding: 1rem;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.9rem;
            border: 1px solid #555;
        }
        .secret-key {
            background: #444;
            padding: 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            word-break: break-all;
            border: 1px solid #666;
        }
        .alert-2fa {
            border-left: 4px solid #28a745;
            background: rgba(40, 167, 69, 0.1);
        }
        .form-label {
            color: white;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-shield-alt"></i> ZeeMarket
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    Olá, <?= htmlspecialchars($userData['name']) ?>
                </span>
                <a href="logout.php" class="btn btn-outline-danger btn-sm">
                    <i class="fas fa-sign-out-alt"></i> Sair
                </a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if ($message): ?>
        <div class="alert alert-<?= $messageType ?> alert-dismissible fade show" role="alert">
            <?= $message ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>

        <div class="row">
            <!-- Saldos -->
            <div class="col-md-4 mb-4">
                <div class="card balance-card">
                    <div class="card-body text-center">
                        <h5><i class="fab fa-bitcoin"></i> Saldos</h5>
                        <hr>
                        <div class="mb-2">
                            <strong>BTC:</strong> <?= number_format($userData['btc_balance'], 8) ?>
                        </div>
                        <div class="mb-2">
                            <strong>ETH:</strong> <?= number_format($userData['eth_balance'], 6) ?>
                        </div>
                        <div class="mb-2">
                            <strong>XMR:</strong> <?= number_format($userData['xmr_balance'], 6) ?>
                        </div>
                        <hr>
                        <a href="btc/deposit.php" class="btn btn-light btn-sm me-2">
                            <i class="fas fa-plus"></i> Depositar
                        </a>
                        <a href="withdraw_real.php" class="btn btn-outline-light btn-sm">
                            <i class="fas fa-minus"></i> Sacar
                        </a>
                    </div>
                </div>
            </div>

            <!-- Configurações 2FA -->
            <div class="col-md-8 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-shield-alt"></i> Autenticação de Dois Fatores (2FA)</h5>
                    </div>
                    <div class="card-body">
                        <?php if (!$is2FAEnabled): ?>
                            <?php if (!isset($_SESSION['temp_2fa_secret'])): ?>
                                <!-- Ativar 2FA -->
                                <div class="alert alert-warning">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <strong>Recomendado:</strong> Ative o 2FA para proteger sua conta
                                </div>
                                <p class="text-muted mb-3">
                                    O 2FA adiciona uma camada extra de segurança à sua conta, 
                                    exigindo um código do seu celular além da senha.
                                </p>
                                <form method="POST">
                                    <input type="hidden" name="action" value="setup_2fa">
                                    <button type="submit" class="btn btn-success">
                                        <i class="fas fa-qrcode"></i> Configurar 2FA
                                    </button>
                                </form>
                            <?php else: ?>
                                <!-- Mostrar QR Code -->
                                <div class="alert alert-2fa">
                                    <h6><i class="fas fa-info-circle"></i> Configure seu Autenticador</h6>
                                    Siga os passos abaixo para ativar o 2FA na sua conta.
                                </div>
                                
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6><i class="fas fa-mobile-alt"></i> 1. Escaneie o QR Code:</h6>
                                        <div class="text-center mb-3">
                                            <div class="qr-container">
                                                <?php 
                                                $qr_url = generateQRCodeInline($_SESSION['temp_2fa_secret'], 'ZeeMarket', $userData['name']);
                                                $debug_url = getOTPAuthURL($_SESSION['temp_2fa_secret'], 'ZeeMarket', $userData['name']);
                                                ?>
                                                <img src="<?= $qr_url ?>" 
                                                     alt="QR Code 2FA" 
                                                     id="qrcode-img"
                                                     style="width: 200px; height: 200px;"
                                                     onerror="tryAlternativeQR(this)">
                                            </div>
                                            
                                            <!-- Debug info -->
                                            
                                        </div>
                                        <p class="text-muted small text-center form-label">
                                            <i class="fas fa-download form-label"></i> 
                                            Use <strong>Google Authenticator</strong>, <strong>Authy</strong> ou app similar
                                        </p>
                                        
                                        <!-- Chave manual -->
                                        <div class="mb-3">
                                            <label class="form-label small">
                                                <i class="fas fa-key"></i> Ou insira manualmente:
                                            </label>
                                            <div class="secret-key">
                                                <?= chunk_split($_SESSION['temp_2fa_secret'], 4, ' ') ?>
                                            </div>
                                            <button type="button" class="btn btn-sm btn-outline-secondary mt-1" 
                                                    onclick="copySecret()">
                                                <i class="fas fa-copy"></i> Copiar
                                            </button>
                                        </div>
                                    </div>
                                    
                                    <div class="col-md-6">
                                        <h6><i class="fas fa-keyboard"></i> 2. Digite o código do app:</h6>
                                        <form method="POST" id="activate2FA">
                                            <input type="hidden" name="action" value="activate_2fa">
                                            <div class="mb-3">
                                                <input type="text" class="form-control form-control-lg text-center" 
                                                       name="verification_code" 
                                                       placeholder="000000" 
                                                       maxlength="6" 
                                                       pattern="[0-9]{6}"
                                                       autocomplete="off"
                                                       required>
                                                <div class="form-text">
                                                    Digite o código de 6 dígitos do seu app
                                                </div>
                                            </div>
                                            <button type="submit" class="btn btn-success btn-lg w-100">
                                                <i class="fas fa-check-circle"></i> Ativar 2FA
                                            </button>
                                        </form>
                                        
                                        <?php if (isset($_SESSION['temp_backup_codes']) && !empty($_SESSION['temp_backup_codes'])): ?>
                                        <div class="mt-4">
                                            <h6><i class="fas fa-life-ring"></i> 3. Códigos de Backup:</h6>
                                            <div class="backup-codes">
                                                <?= implode('<br>', $_SESSION['temp_backup_codes']) ?>
                                            </div>
                                            <div class="alert alert-warning mt-2 p-2">
                                                <small>
                                                    <i class="fas fa-exclamation-triangle"></i>
                                                    <strong>Importante:</strong> Guarde estes códigos em local seguro! 
                                                    Eles podem ser usados se você perder acesso ao seu celular.
                                                </small>
                                            </div>
                                            <button type="button" class="btn btn-sm btn-outline-info" 
                                                    onclick="downloadBackupCodes()">
                                                <i class="fas fa-download"></i> Baixar códigos
                                            </button>
                                        </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endif; ?>
                        <?php else: ?>
                            <!-- 2FA Ativo -->
                            <div class="alert alert-success">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-shield-check fa-2x me-3"></i>
                                    <div>
                                        <h6 class="mb-1">2FA Ativo</h6>
                                        <small>Sua conta está protegida com autenticação de dois fatores</small>
                                    </div>
                                </div>
                            </div>
                            
                            <button class="btn btn-warning" type="button" 
                                    data-bs-toggle="collapse" data-bs-target="#disable2FA">
                                <i class="fas fa-times-circle"></i> Desativar 2FA
                            </button>
                            
                            <div class="collapse mt-3" id="disable2FA">
                                <div class="card border-warning">
                                    <div class="card-body">
                                        <h6 class="text-warning">
                                            <i class="fas fa-exclamation-triangle"></i> Desativar 2FA
                                        </h6>
                                        <p class="text-muted small mb-3">
                                            Desativar o 2FA tornará sua conta menos segura.
                                        </p>
                                        <form method="POST">
                                            <input type="hidden" name="action" value="disable_2fa">
                                            <div class="mb-3">
                                                <label class="form-label">Senha atual:</label>
                                                <input type="password" class="form-control" 
                                                       name="current_password" required>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">Código 2FA atual:</label>
                                                <input type="text" class="form-control" 
                                                       name="disable_code" 
                                                       maxlength="6" 
                                                       pattern="[0-9]{6}"
                                                       required>
                                            </div>
                                            <button type="submit" class="btn btn-danger">
                                                <i class="fas fa-times"></i> Confirmar Desativação
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Transações Recentes -->
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-history"></i> Transações Recentes</h5>
            </div>
            <div class="card-body">
                <?php if ($recentTransactions): ?>
                <div class="table-responsive">
                    <table class="table table-dark table-hover">
                        <thead>
                            <tr>
                                <th>Tipo</th>
                                <th>Valor</th>
                                <th>Moeda</th>
                                <th>Status</th>
                                <th>Data</th>
                                <th>TX Hash</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recentTransactions as $tx): ?>
                            <tr>
                                <td>
                                    <i class="fas fa-<?= $tx['type'] === 'deposit' ? 'arrow-down text-success' : 'arrow-up text-warning' ?>"></i>
                                    <?= ucfirst($tx['type']) ?>
                                </td>
                                <td><?= number_format($tx['amount'], 8) ?></td>
                                <td>
                                    <span class="badge bg-secondary">
                                        <?= strtoupper($tx['crypto_type']) ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge bg-<?= $tx['status'] === 'confirmed' ? 'success' : ($tx['status'] === 'pending' ? 'warning' : 'danger') ?>">
                                        <?= ucfirst($tx['status']) ?>
                                    </span>
                                </td>
                                <td><?= date('d/m/Y H:i', strtotime($tx['created_at'])) ?></td>
                                <td>
                                    <?php if ($tx['tx_hash']): ?>
                                    <a href="#" class="text-info" data-bs-toggle="tooltip" 
                                       title="<?= $tx['tx_hash'] ?>" onclick="copyToClipboard('<?= $tx['tx_hash'] ?>')">
                                        <?= substr($tx['tx_hash'], 0, 8) ?>...
                                    </a>
                                    <?php else: ?>
                                    <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php else: ?>
                <div class="text-center text-muted py-4">
                    <i class="fas fa-info-circle fa-2x mb-2"></i>
                    <p>Nenhuma transação encontrada</p>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Links Rápidos -->
        <div class="row mt-4 mb-4">
            <div class="col-md-3 mb-2">
                <a href="index.php" class="btn btn-outline-primary w-100">
                    <i class="fas fa-home"></i> Início
                </a>
            </div>
            <div class="col-md-3 mb-2">
                <a href="btc/deposit.php" class="btn btn-outline-success w-100">
                    <i class="fas fa-plus"></i> Depositar
                </a>
            </div>
            <div class="col-md-3 mb-2">
                <a href="withdraw_real.php" class="btn btn-outline-warning w-100">
                    <i class="fas fa-minus"></i> Sacar
                </a>
            </div>
            <div class="col-md-3 mb-2">
                <a href="index.php" class="btn btn-outline-info w-100">
                    <i class="fas fa-shopping-cart"></i> Comprar
                </a>
            </div>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const qrImg = document.getElementById('qrcode-img');
            if (qrImg) {
                // Verificar se QR carregou corretamente após 3 segundos
                setTimeout(() => {
                    if (qrImg.naturalWidth === 0 || qrImg.complete === false) {
                        console.log('QR Code não carregou, tentando alternativas...');
                        tryAlternativeQR(qrImg);
                    }
                }, 3000);
            }
        });

       

        // Inicializar tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });

        // Função para copiar chave secreta
        function copySecret() {
            const secretText = document.querySelector('.secret-key').textContent.replace(/\s/g, '');
            navigator.clipboard.writeText(secretText).then(function() {
                showToast('Chave copiada para a área de transferência!', 'success');
            }).catch(function() {
                showToast('Erro ao copiar chave', 'error');
            });
        }

        // Função para copiar hash de transação
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                showToast('Hash copiado!', 'success');
            }).catch(function() {
                showToast('Erro ao copiar hash', 'error');
            });
        }

        // Função para baixar códigos de backup
        function downloadBackupCodes() {
            const codes = <?= isset($_SESSION['temp_backup_codes']) ? json_encode($_SESSION['temp_backup_codes']) : '[]' ?>;
            const content = 'ZeeMarket - Códigos de Backup 2FA\n' +
                           'Data: ' + new Date().toLocaleDateString('pt-BR') + '\n' +
                           'Usuário: <?= htmlspecialchars($userData['name']) ?>\n\n' +
                           'CÓDIGOS DE BACKUP:\n' +
                           codes.join('\n') + '\n\n' +
                           'IMPORTANTE: Guarde estes códigos em local seguro!\n' +
                           'Eles podem ser usados se você perder acesso ao seu celular.';
            
            const element = document.createElement('a');
            element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
            element.setAttribute('download', 'zeemarket-backup-codes-' + Date.now() + '.txt');
            element.style.display = 'none';
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);
            
            showToast('Códigos de backup baixados!', 'success');
        }

        // Sistema de toast notifications
        function showToast(message, type = 'info') {
            const toastContainer = document.querySelector('.toast-container') || createToastContainer();
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type === 'success' ? 'success' : (type === 'error' ? 'danger' : 'info')} border-0`;
            toast.setAttribute('role', 'alert');
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            toastContainer.appendChild(toast);
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            
            toast.addEventListener('hidden.bs.toast', function() {
                toast.remove();
            });
        }

        function createToastContainer() {
            const container = document.createElement('div');
            container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            document.body.appendChild(container);
            return container;
        }

        // Auto-format código 2FA
        document.addEventListener('DOMContentLoaded', function() {
            const codeInput = document.querySelector('input[name="verification_code"]');
            if (codeInput) {
                codeInput.addEventListener('input', function(e) {
                    // Remove caracteres não numéricos
                    e.target.value = e.target.value.replace(/\D/g, '');
                });
                
                codeInput.addEventListener('paste', function(e) {
                    setTimeout(() => {
                        e.target.value = e.target.value.replace(/\D/g, '').substring(0, 6);
                    }, 10);
                });
            }
        });

        // Função para tentar APIs alternativas de QR Code
        function tryAlternativeQR(imgElement) {
            const qrAPIs = [
                'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=',
                'https://quickchart.io/qr?text=',
                'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl='
            ];
            
            // Extrair a URL TOTP do atributo data ou recriar
            const secret = '<?= isset($_SESSION["temp_2fa_secret"]) ? $_SESSION["temp_2fa_secret"] : "" ?>';
            const issuer = 'ZeeMarket';
            const account = '<?= htmlspecialchars($userData["name"] ?? "") ?>';
            
            if (!secret) return;
            
            const otpauthURL = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
            
            let currentAPI = 0;
            const tryNextAPI = () => {
                if (currentAPI < qrAPIs.length) {
                    console.log(`Tentando API ${currentAPI + 1}: ${qrAPIs[currentAPI]}`);
                    imgElement.src = qrAPIs[currentAPI] + encodeURIComponent(otpauthURL);
                    currentAPI++;
                } else {
                    // Se todas as APIs falharam, mostrar QR Code manual
                    showManualQR(otpauthURL);
                }
            };
            
            // Remover event listener anterior e adicionar novo
            imgElement.onerror = null;
            imgElement.addEventListener('error', tryNextAPI, { once: true });
            
            // Tentar próxima API
            tryNextAPI();
        }

        // Função para mostrar QR Code manual (ASCII ou link)
        function showManualQR(otpauthURL) {
            const qrContainer = document.querySelector('.qr-container');
            if (qrContainer) {
                qrContainer.innerHTML = `
                    <div class="alert alert-warning">
                        <h6><i class="fas fa-exclamation-triangle"></i> QR Code indisponível</h6>
                        <p class="mb-2">Use uma das opções abaixo:</p>
                        <div class="mb-2">
                            <button class="btn btn-sm btn-primary" onclick="openQRGenerator()">
                                <i class="fas fa-external-link-alt"></i> Gerar QR Online
                            </button>
                        </div>
                        <div class="mb-2">
                            <button class="btn btn-sm btn-secondary" onclick="copyOTPAuthURL()">
                                <i class="fas fa-copy"></i> Copiar URL TOTP
                            </button>
                        </div>
                        <small class="text-muted">
                            Configure manualmente no seu app usando a chave secreta acima.
                        </small>
                    </div>
                `;
            }
        }

        // Função para abrir gerador de QR online
        function openQRGenerator() {
            const secret = '<?= isset($_SESSION["temp_2fa_secret"]) ? $_SESSION["temp_2fa_secret"] : "" ?>';
            const issuer = 'ZeeMarket';
            const account = '<?= htmlspecialchars($userData["name"] ?? "") ?>';
            
            const otpauthURL = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
            const qrURL = `https://www.qr-code-generator.com/a1/?data=${encodeURIComponent(otpauthURL)}`;
            
            window.open(qrURL, '_blank');
        }

        // Função para copiar URL TOTP
        function copyOTPAuthURL() {
            const secret = '<?= isset($_SESSION["temp_2fa_secret"]) ? $_SESSION["temp_2fa_secret"] : "" ?>';
            const issuer = 'ZeeMarket';
            const account = '<?= htmlspecialchars($userData["name"] ?? "") ?>';
            
            const otpauthURL = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
            
            navigator.clipboard.writeText(otpauthURL).then(function() {
                showToast('URL TOTP copiada! Cole no seu app autenticador.', 'success');
            }).catch(function() {
                showToast('Erro ao copiar URL', 'error');
            });
        }
    </script>
</body>
</html><?php