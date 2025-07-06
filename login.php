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
if (!checkRateLimitAdvanced($client_fingerprint, 5, 900)) { // 5 tentativas a cada 15 minutos
    $erro = "Muitas tentativas de login. Tente novamente em 15 minutos.";
    recordLoginAttempt($client_fingerprint, '', false, 'rate_limited');
    sleep(2); // Dificulta ataques de timing
}

// Processar login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login']) && empty($erro)) {
    
    // Verificar CSRF
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $erro = "Token de segurança inválido. Operação bloqueada.";
        recordLoginAttempt($client_fingerprint, '', false, 'invalid_csrf');
    } else {
        
        $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
        $senha = $_POST['senha'] ?? '';
        
        if (empty($email) || empty($senha)) {
            $erro = "Email e senha são obrigatórios!";
            recordLoginAttempt($client_fingerprint, $email, false, 'empty_fields');
        } elseif (!validateEmailSecure($email)) {
            $erro = "Formato de email inválido!";
            recordLoginAttempt($client_fingerprint, $email, false, 'invalid_email');
        } else {
            
            // Tentar login via função segura
            $login_result = loginSecure($email, $senha);
            
            if ($login_result === true) {
                recordLoginAttempt($client_fingerprint, $email, true, 'successful_login');
                header("Location: dashboard.php");
                exit();
            } else {
                $erro = $login_result;
                recordLoginAttempt($client_fingerprint, $email, false, 'failed_login');
                secureTimingDelay(0.5); // Atraso para mitigar ataques de enumeração de usuário
            }
        }
    }
    
    // Regenerar token CSRF após a tentativa
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
        
        if (empty($nome) || empty($email) || empty($senha) || empty($confirmar_senha)) {
            $erro = "Todos os campos de cadastro são obrigatórios!";
        } elseif (!validateNameSecure($nome)) {
            $erro = "Nome inválido. Use apenas letras e espaços (2-100 caracteres).";
        } elseif (!validateEmailSecure($email)) {
            $erro = "Email inválido!";
        } elseif ($senha !== $confirmar_senha) {
            $erro = "As senhas não coincidem!";
        } else {
            
            $password_check = validatePasswordStrength($senha);
            if (!$password_check['valid']) {
                $erro = $password_check['message'];
            } else {
                
                // A função cadastrarUsuarioSeguro deve usar password_hash com PASSWORD_ARGON2ID
                // e inserir 'is_vendor' = 0 e 'tipo' = 'cliente' por padrão na tabela 'users'.
                $cadastro_result = cadastrarUsuarioSeguro($nome, $email, $senha);
                
                if ($cadastro_result === true) {
                    $sucesso = "Conta criada com sucesso! Faça login para continuar.";
                    recordLoginAttempt($client_fingerprint, $email, true, 'account_created');
                    $_POST = []; // Limpar campos do formulário para evitar reenvio
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
        
        .terminal-dots { display: flex; gap: 5px; }
        .dot { width: 12px; height: 12px; border-radius: 50%; background: #333; }
        .dot.red { background: #ff0000; }
        .dot.yellow { background: #ffff00; }
        .dot.green { background: #00ff00; }
        .terminal-title { flex: 1; text-align: center; color: #00ff00; font-weight: bold; }
        .terminal-body { padding: 20px; background: #000; }
        
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
        
        .status-indicator { color: #00ff00; }
        
        .tab-container { display: flex; margin-bottom: 20px; border-bottom: 1px solid #333; }
        .tab-btn { background: none; border: none; color: #666; padding: 10px 20px; cursor: pointer; font-family: 'Courier Prime', monospace; border-bottom: 2px solid transparent; transition: all 0.3s ease; }
        .tab-btn.active { color: #00ff00; border-bottom-color: #00ff00; text-shadow: 0 0 10px #00ff00; }
        .tab-btn:hover { color: #00ff00; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .form-group { margin-bottom: 15px; }
        .form-label { display: block; margin-bottom: 5px; color: #00ff00; font-size: 12px; }
        .form-input { width: 100%; padding: 10px; background: #000; border: 1px solid #333; color: #00ff00; font-family: 'Courier Prime', monospace; font-size: 14px; outline: none; transition: all 0.3s ease; }
        .form-input:focus { border-color: #00ff00; box-shadow: 0 0 10px rgba(0, 255, 0, 0.3); }
        .form-input::placeholder { color: #444; }
        
        .btn { background: #000; border: 1px solid #00ff00; color: #00ff00; padding: 12px 20px; font-family: 'Courier Prime', monospace; font-size: 14px; cursor: pointer; width: 100%; transition: all 0.3s ease; margin-top: 10px; }
        .btn:hover { background: #00ff00; color: #000; box-shadow: 0 0 20px rgba(0, 255, 0, 0.5); text-shadow: none; }
        
        .alert { padding: 10px; margin-bottom: 15px; border: 1px solid; font-size: 12px; }
        .alert-success { border-color: #00ff00; background: rgba(0, 255, 0, 0.1); color: #00ff00; }
        .alert-danger { border-color: #ff0000; background: rgba(255, 0, 0, 0.1); color: #ff0000; }
        .alert-warning { border-color: #ffff00; background: rgba(255, 255, 0, 0.1); color: #ffff00; }
        
        .footer-info { text-align: center; margin-top: 20px; font-size: 10px; color: #444; border-top: 1px solid #333; padding-top: 15px; }
        .blinking { animation: blink 1s infinite; }
        @keyframes blink { 0%, 50% { opacity: 1; } 51%, 100% { opacity: 0; } }
    </style>
</head>
<body>
    
    <div class="terminal-container">
        <div class="terminal-window">
            <div class="terminal-header">
                <div class="terminal-dots"><div class="dot red"></div><div class="dot yellow"></div><div class="dot green"></div></div>
                <div class="terminal-title">root@zeemarket:~$</div>
            </div>
            
            <div class="terminal-body">
                <div class="ascii-logo" aria-hidden="true">
[ZEE-MARKET]
[SECURE AUTHENTICATION TERMINAL]
                </div>
                
                <div class="status-line">
                    <span>STATUS: <span class="status-indicator">ONLINE</span></span>
                    <span>SECURITY: <span class="status-indicator">MAX</span></span>
                    <span>TOR: <span class="status-indicator"><?= $torStatus['connected'] ? 'ACTIVE' : 'INACTIVE' ?></span></span>
                </div>
                
                <?php if (!$torStatus['connected']): ?>
                    <div class="alert alert-warning">[WARNING] Tor Browser recomendado para máxima privacidade</div>
                <?php endif; ?>
                
                <?php if ($erro): ?>
                    <div class="alert alert-danger">[ERROR] <?= htmlspecialchars($erro) ?></div>
                <?php endif; ?>
                
                <?php if ($sucesso): ?>
                    <div class="alert alert-success">[SUCCESS] <?= htmlspecialchars($sucesso) ?></div>
                <?php endif; ?>
                
                <div class="tab-container">
                    <button class="tab-btn active" onclick="switchTab('login')">LOGIN</button>
                    <button class="tab-btn" onclick="switchTab('register')">REGISTER</button>
                </div>
                
                <div id="login-tab" class="tab-content active">
                    <form method="POST" id="loginForm" action="login.php">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="form-group">
                            <label for="email" class="form-label">root@email:</label>
                            <input type="email" id="email" name="email" class="form-input" placeholder="user@domain.onion" required maxlength="255" value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                        </div>
                        <div class="form-group">
                            <label for="senha" class="form-label">root@password:</label>
                            <input type="password" id="senha" name="senha" class="form-input" placeholder="Enter secure passphrase" required maxlength="255">
                        </div>
                        <button type="submit" name="login" class="btn">[AUTHENTICATE] <span class="blinking">_</span></button>
                    </form>
                </div>
                
                <div id="register-tab" class="tab-content">
                    <form method="POST" id="registerForm" action="login.php">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="form-group">
                            <label for="nome" class="form-label">username:</label>
                            <input type="text" id="nome" name="nome" class="form-input" placeholder="Enter alias" required minlength="2" maxlength="100" pattern="[a-zA-Z\s]+" value="<?= htmlspecialchars($_POST['nome'] ?? '') ?>">
                        </div>
                        <div class="form-group">
                            <label for="email_cadastro" class="form-label">email:</label>
                            <input type="email" id="email_cadastro" name="email_cadastro" class="form-input" placeholder="user@secure.onion" required maxlength="255" value="<?= htmlspecialchars($_POST['email_cadastro'] ?? '') ?>">
                        </div>
                        <div class="form-group">
                            <label for="senha_cadastro" class="form-label">password:</label>
                            <input type="password" id="senha_cadastro" name="senha_cadastro" class="form-input" placeholder="Strong passphrase (min 8 chars)" required minlength="8" maxlength="255">
                        </div>
                        <div class="form-group">
                            <label for="confirmar_senha" class="form-label">confirm:</label>
                            <input type="password" id="confirmar_senha" name="confirmar_senha" class="form-input" placeholder="Repeat passphrase" required maxlength="255">
                        </div>
                        <button type="submit" name="cadastrar" class="btn">[CREATE ACCOUNT] <span class="blinking">_</span></button>
                    </form>
                </div>
                
                <div class="footer-info">
                    <div>ENCRYPTION: AES-256 | HASH: Argon2ID | RATE-LIMIT: 5/15min</div>
                    <div>CSRF: ACTIVE | XSS: BLOCKED | TIMING ATTACK: MITIGATED</div>
                    <div style="margin-top: 10px;"><span class="blinking">█</span> SYSTEM SECURED <span class="blinking">█</span></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        if (window.top !== window.self) { window.top.location = window.self.location; }
        
        function switchTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(tabName + '-tab').classList.add('active');
            event.currentTarget.classList.add('active');
        }
    </script>
</body>
</html>