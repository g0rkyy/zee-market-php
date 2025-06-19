<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Inicializar sistema de segurança
ensureSecurityTablesExist();

// Se já estiver logado, redirecionar
if (isLoggedIn()) {
    header("Location: dashboard.php");
    exit();
}

// Gerar token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$erro = '';
$sucesso = '';
$client_fingerprint = getClientFingerprint();

// Verificar rate limiting
if (!checkRateLimitAdvanced($client_fingerprint, 5, 900)) {
    $erro = "Muitas tentativas de login. Tente novamente em 15 minutos.";
    recordLoginAttempt($client_fingerprint, '', false, 'rate_limited');
    sleep(2);
}

// Processar login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login']) && empty($erro)) {
    
    // Verificar CSRF
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $erro = "Token de segurança inválido.";
        recordLoginAttempt($client_fingerprint, '', false, 'invalid_csrf');
    } else {
        
        $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
        $senha = $_POST['senha'] ?? '';
        
        if (empty($email) || empty($senha)) {
            $erro = "Email e senha são obrigatórios!";
            recordLoginAttempt($client_fingerprint, $email, false, 'empty_fields');
        } elseif (!validateEmailSecure($email)) {
            $erro = "Email inválido!";
            recordLoginAttempt($client_fingerprint, $email, false, 'invalid_email');
        } else {
            
            // Tentar login
            $login_result = loginSecure($email, $senha);
            
            if ($login_result === true) {
                recordLoginAttempt($client_fingerprint, $email, true, 'successful_login');
                header("Location: dashboard.php");
                exit();
            } else {
                $erro = $login_result;
                recordLoginAttempt($client_fingerprint, $email, false, 'failed_login');
                secureTimingDelay(0.5);
            }
        }
    }
    
    // Regenerar token CSRF
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Processar cadastro
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cadastrar']) && empty($erro)) {
    
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $erro = "Token de segurança inválido.";
    } else {
        
        $nome = trim($_POST['nome'] ?? '');
        $email = filter_input(INPUT_POST, 'email_cadastro', FILTER_SANITIZE_EMAIL);
        $senha = $_POST['senha_cadastro'] ?? '';
        $confirmar_senha = $_POST['confirmar_senha'] ?? '';
        
        if (empty($nome) || empty($email) || empty($senha)) {
            $erro = "Todos os campos são obrigatórios!";
        } elseif (!validateNameSecure($nome)) {
            $erro = "Nome deve ter entre 2 e 100 caracteres e conter apenas letras!";
        } elseif (!validateEmailSecure($email)) {
            $erro = "Email inválido!";
        } elseif ($senha !== $confirmar_senha) {
            $erro = "Senhas não coincidem!";
        } else {
            
            $password_check = validatePasswordStrength($senha);
            if (!$password_check['valid']) {
                $erro = $password_check['message'];
            } else {
                
                $cadastro_result = cadastrarUsuarioSeguro($nome, $email, $senha);
                
                if ($cadastro_result === true) {
                    $sucesso = "Conta criada com sucesso! Faça login para continuar.";
                    recordLoginAttempt($client_fingerprint, $email, true, 'account_created');
                    $_POST = []; // Limpar formulário
                } else {
                    $erro = $cadastro_result;
                }
            }
        }
    }
    
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$torStatus = checkTorConnection();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeeMarket - Secure Access</title>
    
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier Prime', monospace;
            background: #0a0a0a;
            color: #00ff00;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }
        
        /* Matrix-like background effect */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 0, 0.02) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(0, 255, 0, 0.02) 0%, transparent 50%);
            z-index: -1;
        }
        
        .terminal-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
        }
        
        .terminal-window {
            background: #111111;
            border: 2px solid #00ff00;
            border-radius: 0;
            max-width: 500px;
            width: 100%;
            box-shadow: 
                0 0 20px rgba(0, 255, 0, 0.3),
                inset 0 0 20px rgba(0, 255, 0, 0.05);
            position: relative;
            animation: terminalGlow 2s ease-in-out infinite alternate;
        }
        
        @keyframes terminalGlow {
            from { box-shadow: 0 0 20px rgba(0, 255, 0, 0.3), inset 0 0 20px rgba(0, 255, 0, 0.05); }
            to { box-shadow: 0 0 30px rgba(0, 255, 0, 0.5), inset 0 0 30px rgba(0, 255, 0, 0.1); }
        }
        
        .terminal-header {
            background: #000;
            padding: 10px 15px;
            border-bottom: 1px solid #00ff00;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .terminal-dots {
            display: flex;
            gap: 5px;
        }
        
        .dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #333;
        }
        
        .dot.red { background: #ff0000; }
        .dot.yellow { background: #ffff00; }
        .dot.green { background: #00ff00; }
        
        .terminal-title {
            flex: 1;
            text-align: center;
            color: #00ff00;
            font-weight: bold;
        }
        
        .terminal-body {
            padding: 20px;
            background: #000;
        }
        
        .ascii-logo {
            text-align: center;
            font-size: 10px;
            line-height: 1;
            margin-bottom: 20px;
            color: #00ff00;
            font-weight: bold;
        }
        
        .status-line {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
            font-size: 12px;
            color: #666;
        }
        
        .status-indicator {
            color: #00ff00;
        }
        
        .tab-container {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #333;
        }
        
        .tab-btn {
            background: none;
            border: none;
            color: #666;
            padding: 10px 20px;
            cursor: pointer;
            font-family: 'Courier Prime', monospace;
            border-bottom: 2px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab-btn.active {
            color: #00ff00;
            border-bottom-color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }
        
        .tab-btn:hover {
            color: #00ff00;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 5px;
            color: #00ff00;
            font-size: 12px;
        }
        
        .form-input {
            width: 100%;
            padding: 10px;
            background: #000;
            border: 1px solid #333;
            color: #00ff00;
            font-family: 'Courier Prime', monospace;
            font-size: 14px;
            outline: none;
            transition: all 0.3s ease;
        }
        
        .form-input:focus {
            border-color: #00ff00;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
            text-shadow: 0 0 5px #00ff00;
        }
        
        .form-input::placeholder {
            color: #444;
        }
        
        .btn {
            background: #000;
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 12px 20px;
            font-family: 'Courier Prime', monospace;
            font-size: 14px;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        
        .btn:hover {
            background: #00ff00;
            color: #000;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.5);
            text-shadow: none;
        }
        
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid;
            font-size: 12px;
        }
        
        .alert-success {
            border-color: #00ff00;
            background: rgba(0, 255, 0, 0.1);
            color: #00ff00;
        }
        
        .alert-danger {
            border-color: #ff0000;
            background: rgba(255, 0, 0, 0.1);
            color: #ff0000;
        }
        
        .alert-warning {
            border-color: #ffff00;
            background: rgba(255, 255, 0, 0.1);
            color: #ffff00;
        }
        
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 15px 0;
        }
        
        .checkbox {
            width: 15px;
            height: 15px;
            background: #000;
            border: 1px solid #00ff00;
            position: relative;
            cursor: pointer;
        }
        
        .checkbox input {
            opacity: 0;
            position: absolute;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .checkbox input:checked + .checkmark::after {
            content: '✓';
            position: absolute;
            top: -2px;
            left: 2px;
            color: #00ff00;
            font-size: 12px;
        }
        
        .footer-info {
            text-align: center;
            margin-top: 20px;
            font-size: 10px;
            color: #444;
            border-top: 1px solid #333;
            padding-top: 15px;
        }
        
        .blinking {
            animation: blink 1s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        
        /* Responsive */
        @media (max-width: 600px) {
            .terminal-window {
                margin: 10px;
            }
            
            .ascii-logo {
                font-size: 8px;
            }
            
            .tab-btn {
                padding: 8px 15px;
                font-size: 12px;
            }
        }
    </style>
</head>
<body>
    
    <div class="terminal-container">
        <div class="terminal-window">
            <div class="terminal-header">
                <div class="terminal-dots">
                    <div class="dot red"></div>
                    <div class="dot yellow"></div>
                    <div class="dot green"></div>
                </div>
                <div class="terminal-title">root@zeemarket:~$</div>
            </div>
            
            <div class="terminal-body">
                <div class="ascii-logo">
                                [ZEE-MARKET]
                         [SECURE AUTHENTICATION TERMINAL]
                </div>
                
                <div class="status-line">
                    <span>STATUS: <span class="status-indicator">ONLINE</span></span>
                    <span>SECURITY: <span class="status-indicator">MAX</span></span>
                    <span>TOR: <span class="status-indicator"><?= $torStatus['connected'] ? 'ACTIVE' : 'INACTIVE' ?></span></span>
                </div>
                
                <?php if ($torStatus['connected']): ?>
                    <div class="alert alert-success">
                        [TOR] Conexão anônima detectada - Confiança: <?= htmlspecialchars($torStatus['confidence']) ?>%
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning">
                        [WARNING] Tor Browser recomendado para máxima privacidade
                    </div>
                <?php endif; ?>
                
                <?php if ($erro): ?>
                    <div class="alert alert-danger">
                        [ERROR] <?= htmlspecialchars($erro) ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($sucesso): ?>
                    <div class="alert alert-success">
                        [SUCCESS] <?= htmlspecialchars($sucesso) ?>
                    </div>
                <?php endif; ?>
                
                <div class="tab-container">
                    <button class="tab-btn active" onclick="switchTab('login')">LOGIN</button>
                    <button class="tab-btn" onclick="switchTab('register')">REGISTER</button>
                </div>
                
                <!-- LOGIN TAB -->
                <div id="login-tab" class="tab-content active">
                    <form method="POST" id="loginForm">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        
                        <div class="form-group">
                            <label class="form-label">root@email:</label>
                            <input type="email" 
                                   name="email" 
                                   class="form-input" 
                                   placeholder="user@domain.onion" 
                                   required
                                   maxlength="255"
                                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">root@password:</label>
                            <input type="password" 
                                   name="senha" 
                                   class="form-input" 
                                   placeholder="Enter secure passphrase" 
                                   required
                                   maxlength="255">
                        </div>
                        
                        <button type="submit" name="login" class="btn">
                            [AUTHENTICATE] <span class="blinking">_</span>
                        </button>
                    </form>
                </div>
                
                <!-- REGISTER TAB -->
                <div id="register-tab" class="tab-content">
                    <form method="POST" id="registerForm">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        
                        <div class="form-group">
                            <label class="form-label">username:</label>
                            <input type="text" 
                                   name="nome" 
                                   class="form-input" 
                                   placeholder="Enter alias" 
                                   required
                                   minlength="2"
                                   maxlength="100"
                                   value="<?= htmlspecialchars($_POST['nome'] ?? '') ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">email:</label>
                            <input type="email" 
                                   name="email_cadastro" 
                                   class="form-input" 
                                   placeholder="user@secure.onion" 
                                   required
                                   maxlength="255"
                                   value="<?= htmlspecialchars($_POST['email_cadastro'] ?? '') ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">password:</label>
                            <input type="password" 
                                   name="senha_cadastro" 
                                   class="form-input" 
                                   placeholder="Strong passphrase (min 8 chars)" 
                                   required
                                   minlength="8"
                                   maxlength="255">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">confirm:</label>
                            <input type="password" 
                                   name="confirmar_senha" 
                                   class="form-input" 
                                   placeholder="Repeat passphrase" 
                                   required
                                   maxlength="255">
                        </div>
                        
                        <div class="checkbox-container">
                            <label class="checkbox">
                                <input type="checkbox" id="acceptTerms" required>
                                <span class="checkmark"></span>
                            </label>
                            <label for="acceptTerms" style="color: #666; font-size: 12px;">
                                I accept the terms and conditions
                            </label>
                        </div>
                        
                        <button type="submit" name="cadastrar" class="btn">
                            [CREATE ACCOUNT] <span class="blinking">_</span>
                        </button>
                    </form>
                </div>
                
                <div class="footer-info">
                    <div>ENCRYPTION: AES-256 | HASH: Argon2ID | RATE-LIMIT: 5/15min</div>
                    <div>CSRF PROTECTION: ACTIVE | SESSION: SECURE | XSS: BLOCKED</div>
                    <div style="margin-top: 10px;">
                        <span class="blinking">█</span> SYSTEM SECURED <span class="blinking">█</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Proteção contra clickjacking
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }
        
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const loginForm = document.getElementById('loginForm');
            const registerForm = document.getElementById('registerForm');
            
            if (loginForm) {
                loginForm.addEventListener('submit', function(e) {
                    const email = document.querySelector('input[name="email"]').value;
                    const senha = document.querySelector('input[name="senha"]').value;
                    
                    if (!email || !senha) {
                        e.preventDefault();
                        alert('[ERROR] Email and password required!');
                        return false;
                    }
                    
                    if (!isValidEmail(email)) {
                        e.preventDefault();
                        alert('[ERROR] Invalid email format!');
                        return false;
                    }
                });
            }
            
            if (registerForm) {
                registerForm.addEventListener('submit', function(e) {
                    const nome = document.querySelector('input[name="nome"]').value;
                    const email = document.querySelector('input[name="email_cadastro"]').value;
                    const senha = document.querySelector('input[name="senha_cadastro"]').value;
                    const confirmarSenha = document.querySelector('input[name="confirmar_senha"]').value;
                    const acceptTerms = document.getElementById('acceptTerms').checked;
                    
                    if (!nome || !email || !senha || !confirmarSenha) {
                        e.preventDefault();
                        alert('[ERROR] All fields required!');
                        return false;
                    }
                    
                    if (nome.length < 2 || nome.length > 100) {
                        e.preventDefault();
                        alert('[ERROR] Username must be 2-100 characters!');
                        return false;
                    }
                    
                    if (!isValidEmail(email)) {
                        e.preventDefault();
                        alert('[ERROR] Invalid email format!');
                        return false;
                    }
                    
                    if (senha.length < 8) {
                        e.preventDefault();
                        alert('[ERROR] Password must be at least 8 characters!');
                        return false;
                    }
                    
                    if (senha !== confirmarSenha) {
                        e.preventDefault();
                        alert('[ERROR] Passwords do not match!');
                        return false;
                    }
                    
                    if (!acceptTerms) {
                        e.preventDefault();
                        alert('[ERROR] You must accept the terms!');
                        return false;
                    }
                    
                    if (!checkPasswordStrength(senha)) {
                        e.preventDefault();
                        alert('[ERROR] Password too weak! Use uppercase, lowercase and numbers.');
                        return false;
                    }
                });
            }
        });
        
        function isValidEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email) && email.length <= 255;
        }
        
        function checkPasswordStrength(password) {
            return /[a-z]/.test(password) && 
                   /[A-Z]/.test(password) && 
                   /[0-9]/.test(password) && 
                   password.length >= 8;
        }
        
        // Terminal startup effect
        console.log('████████████████████████████████████████████████████████████████████████████████');
        console.log('█ ZeeMarket Security Terminal v2.0 - Authentication Module Loaded               █');
        console.log('█ Security Level: MAXIMUM | Encryption: Active | Tor Support: Ready            █');
        console.log('█ Rate Limiting: 5/15min | CSRF: Protected | Session: Hardened                █');
        console.log('████████████████████████████████████████████████████████████████████████████████');
    </script>
</body>
</html>