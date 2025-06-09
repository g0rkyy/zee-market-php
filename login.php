<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'includes/functions.php';
require_once 'includes/tor_system.php';
require_once 'includes/pgp_system.php';

// Se já estiver logado, redireciona
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

// Inicializar sistemas Tor e PGP
try {
    $torSystem = new ZeeMarketTor($conn);
    $pgpSystem = new ZeeMarketPGP($conn);
    $torMiddleware = new TorMiddleware($torSystem);
    
    // Executar middleware Tor
    $torDetection = $torMiddleware->handle();
    
} catch (Exception $e) {
    error_log("Erro ao inicializar sistemas: " . $e->getMessage());
    $torDetection = ['is_tor' => false, 'confidence' => 0];
}

$erro = ""; // Inicializa a variável de erro
$success = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $senha = trim($_POST['senha']);
    $use_pgp = isset($_POST['use_pgp']) && $_POST['use_pgp'] == '1';
    $pgp_message = trim($_POST['pgp_message'] ?? '');
    $pgp_passphrase = trim($_POST['pgp_passphrase'] ?? '');
    
    // Validação básica
    if (empty($email) || empty($senha)) {
        $erro = "Email e senha são obrigatórios.";
    } else {
        try {
            // Login normal primeiro
            $resultado = login($email, $senha);
            
            if ($resultado === true) {
                $userId = $_SESSION['user_id'];
                
                // Verificar se usuário quer usar PGP
                if ($use_pgp) {
                    if (empty($pgp_message) || empty($pgp_passphrase)) {
                        $erro = "Mensagem PGP e passphrase são obrigatórias quando PGP está habilitado.";
                    } else {
                        // Verificar se usuário tem chaves PGP
                        if (!$pgpSystem->userHasPgpKey($userId)) {
                            $erro = "Você não possui chaves PGP configuradas. Configure primeiro no dashboard.";
                        } else {
                            // Verificar assinatura PGP
                            $pgpVerification = $pgpSystem->verifySignature(
                                ['login_attempt' => $email, 'timestamp' => time()],
                                $pgp_message,
                                $userId
                            );
                            
                            if (!$pgpVerification['success'] || !$pgpVerification['valid']) {
                                $erro = "Assinatura PGP inválida. Verifique sua mensagem e passphrase.";
                                // Fazer logout em caso de falha PGP
                                session_destroy();
                            } else {
                                // Login PGP bem-sucedido
                                $_SESSION['pgp_authenticated'] = true;
                                $_SESSION['pgp_login_time'] = time();
                                $success = "Login com PGP realizado com sucesso!";
                            }
                        }
                    }
                }
                
                // Log da atividade de login
                if (empty($erro)) {
                    $loginData = [
                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                        'tor_used' => $torDetection['is_tor'],
                        'tor_confidence' => $torDetection['confidence'],
                        'pgp_used' => $use_pgp,
                        'login_method' => $use_pgp ? 'pgp' : 'standard'
                    ];
                    
                    // Salvar log de login
                    $stmt = $conn->prepare("
                        INSERT INTO login_logs 
                        (user_id, ip_address, user_agent, tor_used, tor_confidence, pgp_used, login_method, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
                    ");
                    $stmt->bind_param("isiisss", 
                        $userId,
                        $loginData['ip'],
                        $loginData['user_agent'],
                        $loginData['tor_used'],
                        $loginData['tor_confidence'],
                        $loginData['pgp_used'],
                        $loginData['login_method']
                    );
                    $stmt->execute();
                    
                    // Redirecionar após sucesso
                    if (empty($erro)) {
                        header("Location: dashboard.php");
                        exit();
                    }
                }
            } else {
                $erro = "Email ou senha incorretos, ou email não cadastrado.";
            }
            
        } catch (Exception $e) {
            error_log("Erro no login: " . $e->getMessage());
            $erro = "Erro interno. Tente novamente.";
        }
    }
}

// Verificar status do Tor
$torStatus = false;
try {
    $torStatusCheck = $torSystem->checkTorStatus();
    $torStatus = $torStatusCheck['running'] ?? false;
} catch (Exception $e) {
    error_log("Erro ao verificar status Tor: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="utf-8">
    <title>Login Seguro - ZeeMarket</title>
    <link rel="stylesheet" type="text/css" href="assets/css/signup.css">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="/js/login.js" defer></script>
    <style>
        .security-indicators {
            margin-bottom: 20px;
            padding: 10px;
            border-radius: 5px;
            background: #f8f9fa;
        }
        .indicator {
            display: inline-block;
            margin: 5px;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
        }
        .indicator.active { background: #28a745; color: white; }
        .indicator.inactive { background: #6c757d; color: white; }
        .pgp-section {
            margin-top: 15px;
            padding: 15px;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            background: #f8f9fa;
        }
        .hidden { display: none; }
        .success-message {
            color: #28a745;
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div id="menu">
        <a href="index.php">home</a>
        <a href="signup.php">registro</a>
        <a href="FAQ.html">faq</a>
    </div>
    
    <div id="loginContainer">
        <div class="container-login">
            <img src="assets/images/perfil.png" alt="Imagem de perfil">
            <h1>Login Seguro</h1>
            
            <!-- Indicadores de Segurança -->
            <div class="security-indicators">
                <div class="indicator <?= $torDetection['is_tor'] ? 'active' : 'inactive' ?>">
                    <i class="fas fa-user-secret"></i> 
                    Tor: <?= $torDetection['is_tor'] ? 'Ativo' : 'Inativo' ?>
                    <?php if ($torDetection['is_tor']): ?>
                        (<?= $torDetection['confidence'] ?>% confiança)
                    <?php endif; ?>
                </div>
                <div class="indicator <?= $torStatus ? 'active' : 'inactive' ?>">
                    <i class="fas fa-shield-alt"></i> 
                    Serviço Tor: <?= $torStatus ? 'Online' : 'Offline' ?>
                </div>
                <div class="indicator active">
                    <i class="fas fa-lock"></i> 
                    HTTPS: Ativo
                </div>
            </div>
            
            <form id="loginForm" method="post">
                <div>
                    <input class="form-control input-btn" type="text" name="email" id="user" placeholder="Email" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"><br>
                    <input class="form-control input-btn" type="password" name="senha" id="password" placeholder="Digite sua senha" required><br>
                    
                    <!-- Opção PGP -->
                    <div class="form-check text-start my-3">
                        <input type="checkbox" class="form-check-input" id="usePgp" name="use_pgp" value="1" 
                               <?= isset($_POST['use_pgp']) ? 'checked' : '' ?> onchange="togglePgpSection()">
                        <label class="form-check-label" for="usePgp">
                            <i class="fas fa-key"></i> Usar Autenticação PGP
                        </label>
                    </div>
                    
                    <!-- Seção PGP -->
                    <div class="pgp-section <?= !isset($_POST['use_pgp']) ? 'hidden' : '' ?>" id="pgpSection">
                        <h6><i class="fas fa-signature"></i> Autenticação PGP</h6>
                        <div class="mb-2">
                            <label class="form-label" style="font-size: 12px;">Mensagem/Assinatura PGP:</label>
                            <textarea class="form-control" name="pgp_message" rows="4" 
                                      placeholder="Cole aqui sua mensagem assinada PGP..."><?= htmlspecialchars($_POST['pgp_message'] ?? '') ?></textarea>
                        </div>
                        <div class="mb-2">
                            <label class="form-label" style="font-size: 12px;">Passphrase da Chave:</label>
                            <input type="password" class="form-control" name="pgp_passphrase" 
                                   placeholder="Senha da sua chave PGP">
                        </div>
                        <small class="text-muted">
                            <i class="fas fa-info-circle"></i> 
                            A autenticação PGP adiciona uma camada extra de segurança ao seu login.
                        </small>
                    </div>
                    
                    <div class="form-check text-start my-3">
                        <input type="checkbox" class="form-check-input" id="flexCheckDefault">
                        <label class="form-check-label" for="flexCheckDefault">Lembre-se de Mim</label>
                    </div>

                    <input class="submit btn btn-primary w-100" type="submit" value="Login Seguro">
                </div>
            </form>
            
            <!-- Mensagens de Status -->
            <?php if (!empty($success)): ?>
                <div class="success-message">
                    <i class="fas fa-check-circle"></i> <?= htmlspecialchars($success) ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($erro)): ?>
                <div id="errorContainer" style="color: red; margin-top: 10px;">
                    <i class="fas fa-exclamation-triangle"></i> <?= htmlspecialchars($erro) ?>
                </div>
            <?php endif; ?>
            
            <!-- Dicas de Segurança -->
            <div style="margin-top: 20px; font-size: 12px; color: #6c757d;">
                <h6>Dicas de Segurança:</h6>
                <ul style="text-align: left; padding-left: 20px;">
                    <?php if (!$torDetection['is_tor']): ?>
                        <li>Use Tor Browser para maior privacidade</li>
                    <?php endif; ?>
                    <li>Configure chaves PGP para autenticação segura</li>
                    <li>Sempre verifique o endereço .onion</li>
                    <li>Nunca compartilhe suas credenciais</li>
                </ul>
            </div>
        </div>
    </div>

    <script>
        function togglePgpSection() {
            const pgpSection = document.getElementById('pgpSection');
            const usePgp = document.getElementById('usePgp');
            
            if (usePgp.checked) {
                pgpSection.classList.remove('hidden');
            } else {
                pgpSection.classList.add('hidden');
            }
        }
        
        // Inicializar na carga da página
        document.addEventListener('DOMContentLoaded', function() {
            togglePgpSection();
            
            // Auto-hide success message
            const successMsg = document.querySelector('.success-message');
            if (successMsg) {
                setTimeout(() => {
                    successMsg.style.display = 'none';
                }, 5000);
            }
        });
        
        // Validação do formulário
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const usePgp = document.getElementById('usePgp').checked;
            const pgpMessage = document.querySelector('textarea[name="pgp_message"]').value;
            const pgpPassphrase = document.querySelector('input[name="pgp_passphrase"]').value;
            
            if (usePgp && (!pgpMessage.trim() || !pgpPassphrase.trim())) {
                e.preventDefault();
                alert('Para usar PGP, você deve preencher a mensagem e a passphrase.');
                return false;
            }
        });
    </script>
</body>
</html>