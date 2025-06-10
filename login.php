<?php
/**
 * 🚀 LOGIN SIMPLIFICADO - SEM PGP
 * PGP agora é só para mensagens/contato
 */

require_once 'includes/config.php';
require_once 'includes/functions.php';

// Se já estiver logado, redirecionar
if (isLoggedIn()) {
    header("Location: index.php");
    exit();
}

$erro = '';
$sucesso = '';

// Processar login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email'] ?? '');
    $senha = $_POST['senha'] ?? '';
    
    // Validações básicas
    if (empty($email) || empty($senha)) {
        $erro = "Preencha todos os campos!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = "Email inválido!";
    } else {
        // Verificar rate limiting
        if (!checkLoginAttempts($email)) {
            $erro = "Muitas tentativas de login. Tente novamente em 5 minutos.";
        } else {
            // Tentar login
            $resultado = login($email, $senha);
            
            if ($resultado === true) {
                // Login bem-sucedido
                
                // Detectar se está usando Tor
                $torDetection = checkTorConnection();
                $_SESSION['is_tor'] = $torDetection['connected'];
                $_SESSION['tor_confidence'] = $torDetection['confidence'];
                
                // Log da atividade
                logActivity($_SESSION['user_id'], 'login', [
                    'method' => 'standard',
                    'tor_detected' => $torDetection['connected'],
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
                ]);
                
                // Redirecionar
                $redirectUrl = $_SESSION['redirect_after_login'] ?? 'index.php';
                unset($_SESSION['redirect_after_login']);
                
                header("Location: " . $redirectUrl);
                exit();
            } else {
                // Login falhou
                $erro = $resultado;
                error_log("Falha no login para: " . $email . " - " . $resultado);
            }
        }
    }
}

// Processar cadastro
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cadastrar'])) {
    $nome = trim($_POST['nome'] ?? '');
    $email = trim($_POST['email_cadastro'] ?? '');
    $senha = $_POST['senha_cadastro'] ?? '';
    $confirmar_senha = $_POST['confirmar_senha'] ?? '';
    
    // Validações
    if (empty($nome) || empty($email) || empty($senha)) {
        $erro = "Preencha todos os campos!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = "Email inválido!";
    } elseif (strlen($senha) < 8) {
        $erro = "Senha deve ter pelo menos 8 caracteres!";
    } elseif ($senha !== $confirmar_senha) {
        $erro = "Senhas não coincidem!";
    } else {
        $resultado = cadastrarUsuario($nome, $email, $senha);
        
        if ($resultado === true) {
            $sucesso = "Cadastro realizado com sucesso! Faça login.";
        } else {
            $erro = $resultado;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - ZeeMarket</title>
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
            max-width: 400px;
            width: 100%;
        }
        
        .login-header {
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border-radius: 15px 15px 0 0;
            text-align: center;
            padding: 2rem;
        }
        
        .login-header h2 {
            margin: 0;
            font-weight: 700;
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
        
        .btn-outline-light {
            border-color: #6c757d;
            color: #adb5bd;
        }
        
        .btn-outline-light:hover {
            background: #6c757d;
            border-color: #6c757d;
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
        
        .security-info {
            background: rgba(25, 135, 84, 0.1);
            border: 1px solid rgba(25, 135, 84, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
        }
        
        .tor-status {
            font-size: 0.9rem;
            margin-top: 1rem;
        }
        
        .alert {
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <h2><i class="fas fa-shield-alt"></i> ZeeMarket</h2>
                <p class="mb-0">Acesso Seguro</p>
            </div>
            
            <div class="login-body">
                <!-- Mostrar status do Tor -->
                <?php
                $torStatus = checkTorConnection();
                if ($torStatus['connected']): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-shield-alt"></i> 
                        <strong>Conexão Tor Detectada</strong><br>
                        <small>Confiança: <?= $torStatus['confidence'] ?>%</small>
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i> 
                        <strong>Tor não detectado</strong><br>
                        <small>Recomendamos usar Tor Browser para maior segurança</small>
                    </div>
                <?php endif; ?>
                
                <!-- Mensagens de erro/sucesso -->
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
                
                <!-- Abas de Login e Cadastro -->
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
                    <!-- Formulário de Login -->
                    <div class="tab-pane fade show active" id="login" role="tabpanel">
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-envelope"></i> Email
                                </label>
                                <input type="email" name="email" class="form-control" 
                                       placeholder="seu@email.com" required
                                       value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-lock"></i> Senha
                                </label>
                                <input type="password" name="senha" class="form-control" 
                                       placeholder="Sua senha" required>
                            </div>
                            
                            <button type="submit" name="login" class="btn btn-primary w-100">
                                <i class="fas fa-sign-in-alt"></i> Entrar
                            </button>
                        </form>
                    </div>
                    
                    <!-- Formulário de Cadastro -->
                    <div class="tab-pane fade" id="register" role="tabpanel">
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-user"></i> Nome
                                </label>
                                <input type="text" name="nome" class="form-control" 
                                       placeholder="Seu nome" required
                                       value="<?= htmlspecialchars($_POST['nome'] ?? '') ?>">
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-envelope"></i> Email
                                </label>
                                <input type="email" name="email_cadastro" class="form-control" 
                                       placeholder="seu@email.com" required
                                       value="<?= htmlspecialchars($_POST['email_cadastro'] ?? '') ?>">
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-lock"></i> Senha
                                </label>
                                <input type="password" name="senha_cadastro" class="form-control" 
                                       placeholder="Mínimo 8 caracteres" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="fas fa-lock"></i> Confirmar Senha
                                </label>
                                <input type="password" name="confirmar_senha" class="form-control" 
                                       placeholder="Confirme sua senha" required>
                            </div>
                            
                            <button type="submit" name="cadastrar" class="btn btn-primary w-100">
                                <i class="fas fa-user-plus"></i> Cadastrar
                            </button>
                        </form>
                    </div>
                </div>
                
                <!-- Informações de Segurança -->
                <div class="security-info">
                    <h6><i class="fas fa-info-circle"></i> Comunicação Segura</h6>
                    <p class="mb-2">Para enviar mensagens criptografadas, use nossa página de contato com PGP.</p>
                    <a href="contact.php" class="btn btn-sm btn-outline-light">
                        <i class="fas fa-key"></i> Contato PGP
                    </a>
                </div>
                
                <!-- Status do sistema -->
                <div class="tor-status text-center text-muted">
                    <small>
                        <i class="fas fa-server"></i> Sistema Online | 
                        <i class="fas fa-shield-alt"></i> Conexão Segura
                    </small>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Detectar se está no Tor (básico)
        if (navigator.userAgent.includes('Firefox') && 
            !navigator.userAgent.includes('Chrome') && 
            !navigator.userAgent.includes('Safari')) {
            console.log('Possível Tor Browser detectado');
        }
        
        // Auto-focus no primeiro campo
        document.addEventListener('DOMContentLoaded', function() {
            const firstInput = document.querySelector('input[name="email"]');
            if (firstInput) {
                firstInput.focus();
            }
        });
    </script>
</body>
</html>