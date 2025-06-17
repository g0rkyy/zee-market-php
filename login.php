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
    <title>Login Seguro - ZeeMarket</title>
    
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <style>
        body {
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d30 100%);
            min-height: 100vh;
            color: #fff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-card {
            background: rgba(40, 40, 40, 0.95);
            border: 1px solid #555;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.5);
            max-width: 450px;
            width: 100%;
            position: relative;
        }
        
        .login-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #28a745, #20c997, #17a2b8);
            border-radius: 15px 15px 0 0;
        }
        
        .login-header {
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border-radius: 15px 15px 0 0;
            text-align: center;
            padding: 2rem;
        }
        
        .security-badge {
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(40, 167, 69, 0.9);
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.7em;
            font-weight: bold;
        }
        
        .login-body {
            padding: 2rem;
        }
        
        .form-control {
            background: rgba(60, 60, 60, 0.8);
            border: 1px solid #555;
            color: #fff;
            border-radius: 8px;
            padding: 12px;
        }
        
        .form-control:focus {
            background: rgba(70, 70, 70, 0.9);
            border-color: #6366f1;
            box-shadow: 0 0 0 0.2rem rgba(99, 102, 241, 0.25);
            color: #fff;
        }
        
        .form-control::placeholder {
            color: #aaa;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border: none;
            border-radius: 8px;
            padding: 12px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(99, 102, 241, 0.4);
        }
        
        .nav-tabs {
            border-bottom: 2px solid #444;
        }
        
        .nav-tabs .nav-link {
            color: #aaa;
            border: none;
            border-bottom: 2px solid transparent;
        }
        
        .nav-tabs .nav-link.active {
            color: #6366f1;
            background: none;
            border-bottom-color: #6366f1;
        }
        
        .alert {
            border-radius: 8px;
            border: none;
        }
        
        .alert-success {
            background: rgba(25, 135, 84, 0.2);
            color: #28a745;
            border: 1px solid #28a745;
        }
        
        .alert-danger {
            background: rgba(220, 53, 69, 0.2);
            color: #dc3545;
            border: 1px solid #dc3545;
        }
        
        .alert-warning {
            background: rgba(255, 193, 7, 0.2);
            color: #ffc107;
            border: 1px solid #ffc107;
        }
    </style>
</head>
<body>
    
    <div class="login-container">
        <div class="login-card">
            <div class="security-badge">
                🛡️ ULTRA-SEGURO
            </div>
            
            <div class="login-header">
                <h2><i class="fas fa-shield-alt"></i> ZeeMarket</h2>
                <p class="mb-0">Sistema de Autenticação Blindado</p>
            </div>
            
            <div class="login-body">
                
                <?php if ($torStatus['connected']): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-shield-alt"></i> 
                        <strong>Conexão Tor Detectada</strong><br>
                        <small>Confiança: <?= htmlspecialchars($torStatus['confidence']) ?>% | Navegação anônima ativa</small>
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i> 
                        <strong>Tor não detectado</strong><br>
                        <small>Recomendamos usar Tor Browser para máxima privacidade</small>
                    </div>
                <?php endif; ?>
                
                <?php if ($erro): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($erro) ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($sucesso): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i> <?= htmlspecialchars($sucesso) ?>
                    </div>
                <?php endif; ?>
                
                <ul class="nav nav-tabs mb-4" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="login-tab" data-bs-toggle="tab" data-bs-target="#login" type="button">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="register-tab" data-bs-toggle="tab" data-bs-target="#register" type="button">
                            <i class="fas fa-user-plus"></i> Cadastrar
                        </button>
                    </li>
                </ul>
                
                <div class="tab-content">
                    <!-- LOGIN -->
                    <div class="tab-pane fade show active" id="login" role="tabpanel">
                        <form method="POST" id="loginForm">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-envelope"></i> Email
                                </label>
                                <input type="email" 
                                       name="email" 
                                       class="form-control" 
                                       placeholder="seu@email.com" 
                                       required
                                       maxlength="255"
                                       value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-lock"></i> Senha
                                </label>
                                <input type="password" 
                                       name="senha" 
                                       class="form-control" 
                                       placeholder="Sua senha" 
                                       required
                                       maxlength="255">
                            </div>
                            
                            <button type="submit" name="login" class="btn btn-primary w-100 mb-3">
                                <i class="fas fa-sign-in-alt"></i> Entrar com Segurança
                            </button>
                            
                            <div class="text-center">
                                <small class="text-muted">
                                    <i class="fas fa-shield-check"></i> 
                                    Conexão criptografada | Rate limiting ativo | Proteção CSRF
                                </small>
                            </div>
                        </form>
                    </div>
                    
                    <!-- CADASTRO -->
                    <div class="tab-pane fade" id="register" role="tabpanel">
                        <form method="POST" id="registerForm">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-user"></i> Nome Completo
                                </label>
                                <input type="text" 
                                       name="nome" 
                                       class="form-control" 
                                       placeholder="Seu nome" 
                                       required
                                       minlength="2"
                                       maxlength="100"
                                       value="<?= htmlspecialchars($_POST['nome'] ?? '') ?>">
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-envelope"></i> Email
                                </label>
                                <input type="email" 
                                       name="email_cadastro" 
                                       class="form-control" 
                                       placeholder="seu@email.com" 
                                       required
                                       maxlength="255"
                                       value="<?= htmlspecialchars($_POST['email_cadastro'] ?? '') ?>">
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-lock"></i> Senha
                                </label>
                                <input type="password" 
                                       name="senha_cadastro" 
                                       class="form-control" 
                                       placeholder="Mínimo 8 caracteres" 
                                       required
                                       minlength="8"
                                       maxlength="255">
                                <small class="text-muted">
                                    Deve conter: letra minúscula, maiúscula e número
                                </small>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-lock"></i> Confirmar Senha
                                </label>
                                <input type="password" 
                                       name="confirmar_senha" 
                                       class="form-control" 
                                       placeholder="Confirme sua senha" 
                                       required
                                       maxlength="255">
                            </div>
                            
                            <div class="form-check mb-3">
                                <input class="form-check-input" type="checkbox" id="acceptTerms" required>
                                <label class="form-check-label" for="acceptTerms">
                                    Aceito os termos de uso e política de privacidade
                                </label>
                            </div>
                            
                            <button type="submit" name="cadastrar" class="btn btn-primary w-100 mb-3">
                                <i class="fas fa-user-plus"></i> Criar Conta Segura
                            </button>
                            
                            <div class="text-center">
                                <small class="text-muted">
                                    <i class="fas fa-user-shield"></i> 
                                    Seus dados são criptografados | Hash Argon2ID | Proteção total
                                </small>
                            </div>
                        </form>
                    </div>
                </div>
                
                <div class="text-center mt-4">
                    <small class="text-muted">
                        <i class="fas fa-server text-success"></i> Sistema Online | 
                        <i class="fas fa-shield-alt text-success"></i> Conexão Segura |
                        <i class="fas fa-clock"></i> Rate Limiting Ativo
                    </small>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Proteção contra clickjacking
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            // Validação de formulários
            const loginForm = document.getElementById('loginForm');
            const registerForm = document.getElementById('registerForm');
            
            if (loginForm) {
                loginForm.addEventListener('submit', function(e) {
                    const email = document.querySelector('input[name="email"]').value;
                    const senha = document.querySelector('input[name="senha"]').value;
                    
                    if (!email || !senha) {
                        e.preventDefault();
                        alert('❌ Email e senha são obrigatórios!');
                        return false;
                    }
                    
                    if (!isValidEmail(email)) {
                        e.preventDefault();
                        alert('❌ Email inválido!');
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
                        alert('❌ Todos os campos são obrigatórios!');
                        return false;
                    }
                    
                    if (nome.length < 2 || nome.length > 100) {
                        e.preventDefault();
                        alert('❌ Nome deve ter entre 2 e 100 caracteres!');
                        return false;
                    }
                    
                    if (!isValidEmail(email)) {
                        e.preventDefault();
                        alert('❌ Email inválido!');
                        return false;
                    }
                    
                    if (senha.length < 8) {
                        e.preventDefault();
                        alert('❌ Senha deve ter pelo menos 8 caracteres!');
                        return false;
                    }
                    
                    if (senha !== confirmarSenha) {
                        e.preventDefault();
                        alert('❌ Senhas não coincidem!');
                        return false;
                    }
                    
                    if (!acceptTerms) {
                        e.preventDefault();
                        alert('❌ Você deve aceitar os termos de uso!');
                        return false;
                    }
                    
                    // Verificar força da senha
                    if (!checkPasswordStrength(senha)) {
                        e.preventDefault();
                        alert('❌ Senha muito fraca! Use letras maiúsculas, minúsculas e números.');
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
        
        console.log('✅ ZeeMarket Login - Sistema de segurança carregado!');
        console.log('🛡️ Proteções: Rate Limiting, CSRF, XSS, Timing Attack, Session Fixation');
        console.log('🔒 Hash: Argon2ID | Rate Limit: 5/15min | CSRF: Token único');
    </script>
</body>
</html>