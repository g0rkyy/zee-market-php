<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

// ✅ VERIFICAR LOGIN - CORRIGIDO
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// ✅ PROTEÇÃO CSRF APRIMORADA
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = generateSecureCSRFToken();
}

$mensagem = '';
$erro = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ✅ VERIFICAÇÃO CSRF ROBUSTA
    if (empty($_POST['csrf_token']) || !validateSecureCSRFToken($_POST['csrf_token'])) {
        error_log("Tentativa de CSRF detectada - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - User ID: " . ($_SESSION['user_id'] ?? 'none'));
        die("🛡️ ERRO DE SEGURANÇA: Token CSRF inválido. Ação bloqueada por segurança.");
    }

    // ✅ SANITIZAÇÃO DE ENTRADA
    $senha_atual = trim($_POST['senha_atual'] ?? '');
    $nova_senha = trim($_POST['nova_senha'] ?? '');
    $confirmar_senha = trim($_POST['confirmar_senha'] ?? '');

    // ✅ VALIDAÇÕES ROBUSTAS
    if (empty($senha_atual) || empty($nova_senha) || empty($confirmar_senha)) {
        $erro = "Todos os campos são obrigatórios.";
    } elseif ($nova_senha !== $confirmar_senha) {
        $erro = "As senhas não coincidem.";
    } elseif (strlen($nova_senha) < 8) {
        $erro = "A nova senha deve ter pelo menos 8 caracteres.";
    } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/', $nova_senha)) {
        $erro = "A nova senha deve conter pelo menos: 1 letra minúscula, 1 maiúscula e 1 número.";
    } elseif ($senha_atual === $nova_senha) {
        $erro = "A nova senha deve ser diferente da senha atual.";
    } else {
        try {
            // ✅ VERIFICAR SENHA ATUAL COM PREPARED STATEMENT
            $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->bind_param("i", $_SESSION['user_id']);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();

            if (!$user || !password_verify($senha_atual, $user['password'])) {
                $erro = "Senha atual incorreta.";
                // ✅ LOG DE TENTATIVA SUSPEITA
                error_log("Tentativa de alteração de senha com senha incorreta - User ID: " . $_SESSION['user_id'] . " - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            } else {
                // ✅ ATUALIZAR SENHA COM HASH SEGURO
                $senha_hash = password_hash($nova_senha, PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536, // 64 MB
                    'time_cost' => 4,       // 4 iterações
                    'threads' => 3          // 3 threads
                ]);
                
                $stmt = $conn->prepare("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?");
                $stmt->bind_param("si", $senha_hash, $_SESSION['user_id']);
                
                if ($stmt->execute()) {
                    $mensagem = "Senha alterada com sucesso!";
                    
                    // ✅ LOG DE SUCESSO
                    error_log("Senha alterada com sucesso - User ID: " . $_SESSION['user_id'] . " - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                    
                    // ✅ REGENERAR TOKEN CSRF APÓS SUCESSO
                    $_SESSION['csrf_token'] = generateSecureCSRFToken();
                    
                    // ✅ INVALIDAR OUTRAS SESSÕES (OPCIONAL)
                    // session_regenerate_id(true);
                    
                } else {
                    $erro = "Erro interno. Tente novamente.";
                    error_log("Erro ao atualizar senha no banco - User ID: " . $_SESSION['user_id']);
                }
                $stmt->close();
            }
        } catch (Exception $e) {
            $erro = "Erro interno. Tente novamente.";
            error_log("Exceção ao alterar senha: " . $e->getMessage());
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeeMarket - Alterar Senha</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <style>
        :root {
            --primary-color: #8a63f2;
            --dark-bg: #121212;
            --dark-card: #1e1e1e;
            --dark-border: #333;
            --dark-text: #e0e0e0;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--dark-text);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .card {
            background-color: var(--dark-card);
            border: 1px solid var(--dark-border);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        
        .card-header {
            background-color: rgba(138, 99, 242, 0.1);
            border-bottom: 1px solid var(--dark-border);
            border-radius: 12px 12px 0 0 !important;
        }
        
        .form-control {
            background-color: rgba(30, 30, 30, 0.8);
            border: 1px solid var(--dark-border);
            color: var(--dark-text);
            border-radius: 8px;
        }
        
        .form-control:focus {
            background-color: rgba(30, 30, 30, 0.9);
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(138, 99, 242, 0.25);
            color: var(--dark-text);
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 8px;
            font-weight: 500;
        }
        
        .btn-primary:hover {
            background-color: #6e4acf;
            border-color: #6e4acf;
        }
        
        .btn-secondary {
            background-color: rgba(108, 117, 125, 0.2);
            border-color: #6c757d;
            color: var(--dark-text);
            border-radius: 8px;
        }
        
        .btn-secondary:hover {
            background-color: #6c757d;
            border-color: #6c757d;
            color: white;
        }
        
        .password-requirements {
            font-size: 0.85em;
            color: #a0a0a0;
            margin-top: 8px;
        }
        
        .password-strength {
            margin-top: 5px;
        }
        
        .strength-bar {
            height: 4px;
            border-radius: 2px;
            background-color: var(--dark-border);
            overflow: hidden;
        }
        
        .strength-fill {
            height: 100%;
            transition: all 0.3s ease;
        }
        
        .strength-weak { background-color: #dc3545; width: 25%; }
        .strength-fair { background-color: #ffc107; width: 50%; }
        .strength-good { background-color: #28a745; width: 75%; }
        .strength-strong { background-color: #20c997; width: 100%; }
        
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
        
        .alert {
            border-radius: 8px;
            border: none;
        }
        
        .alert-success {
            background-color: rgba(40, 167, 69, 0.1);
            color: #28a745;
            border: 1px solid #28a745;
        }
        
        .alert-danger {
            background-color: rgba(220, 53, 69, 0.1);
            color: #dc3545;
            border: 1px solid #dc3545;
        }
    </style>
</head>
<body>
    <div class="security-indicator">
        🛡️ CSRF-PROTECTED
    </div>

    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="mb-0">
                            <i class="bi bi-shield-lock"></i> Alterar Senha
                        </h3>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($mensagem)): ?>
                            <div class="alert alert-success">
                                <i class="bi bi-check-circle"></i> <?= htmlspecialchars($mensagem, ENT_QUOTES, 'UTF-8') ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($erro)): ?>
                            <div class="alert alert-danger">
                                <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($erro, ENT_QUOTES, 'UTF-8') ?>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST" id="passwordForm">
                            <!-- ✅ TOKEN CSRF SEGURO -->
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                            
                            <div class="mb-3">
                                <label for="senha_atual" class="form-label">
                                    <i class="bi bi-lock"></i> Senha Atual
                                </label>
                                <input type="password" id="senha_atual" name="senha_atual" class="form-control" required autocomplete="current-password">
                            </div>
                            
                            <div class="mb-3">
                                <label for="nova_senha" class="form-label">
                                    <i class="bi bi-key"></i> Nova Senha
                                </label>
                                <input type="password" id="nova_senha" name="nova_senha" class="form-control" required minlength="8" autocomplete="new-password">
                                <div class="password-requirements">
                                    <small>
                                        <i class="bi bi-info-circle"></i> 
                                        Mínimo de 8 caracteres, incluindo: letra minúscula, maiúscula e número
                                    </small>
                                </div>
                                <div class="password-strength">
                                    <div class="strength-bar">
                                        <div class="strength-fill" id="strengthBar"></div>
                                    </div>
                                    <small id="strengthText" class="text-muted"></small>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="confirmar_senha" class="form-label">
                                    <i class="bi bi-check-square"></i> Confirmar Nova Senha
                                </label>
                                <input type="password" id="confirmar_senha" name="confirmar_senha" class="form-control" required minlength="8" autocomplete="new-password">
                                <small id="matchText" class="text-muted"></small>
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-primary" id="submitBtn" disabled>
                                    <i class="bi bi-shield-check"></i> Alterar Senha
                                </button>
                                <a href="dashboard.php" class="btn btn-secondary">
                                    <i class="bi bi-arrow-left"></i> Voltar ao Dashboard
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // ✅ VALIDAÇÃO DE FORÇA DA SENHA
        function checkPasswordStrength(password) {
            let score = 0;
            let feedback = [];
            
            if (password.length >= 8) score++;
            if (password.length >= 12) score++;
            if (/[a-z]/.test(password)) score++;
            if (/[A-Z]/.test(password)) score++;
            if (/[0-9]/.test(password)) score++;
            if (/[^A-Za-z0-9]/.test(password)) score++;
            
            const strengthBar = document.getElementById('strengthBar');
            const strengthText = document.getElementById('strengthText');
            
            if (score < 3) {
                strengthBar.className = 'strength-fill strength-weak';
                strengthText.textContent = 'Fraca';
                strengthText.style.color = '#dc3545';
            } else if (score < 4) {
                strengthBar.className = 'strength-fill strength-fair';
                strengthText.textContent = 'Razoável';
                strengthText.style.color = '#ffc107';
            } else if (score < 5) {
                strengthBar.className = 'strength-fill strength-good';
                strengthText.textContent = 'Boa';
                strengthText.style.color = '#28a745';
            } else {
                strengthBar.className = 'strength-fill strength-strong';
                strengthText.textContent = 'Forte';
                strengthText.style.color = '#20c997';
            }
            
            return score >= 4;
        }
        
        // ✅ VALIDAÇÃO EM TEMPO REAL
        document.getElementById('nova_senha').addEventListener('input', function() {
            const isStrong = checkPasswordStrength(this.value);
            validateForm();
        });
        
        document.getElementById('confirmar_senha').addEventListener('input', function() {
            const nova = document.getElementById('nova_senha').value;
            const confirmar = this.value;
            const matchText = document.getElementById('matchText');
            
            if (confirmar.length > 0) {
                if (nova === confirmar) {
                    matchText.textContent = '✓ Senhas coincidem';
                    matchText.style.color = '#28a745';
                    this.setCustomValidity('');
                } else {
                    matchText.textContent = '✗ Senhas não coincidem';
                    matchText.style.color = '#dc3545';
                    this.setCustomValidity('As senhas não coincidem');
                }
            } else {
                matchText.textContent = '';
            }
            
            validateForm();
        });
        
        // ✅ VALIDAÇÃO COMPLETA DO FORMULÁRIO
        function validateForm() {
            const senhaAtual = document.getElementById('senha_atual').value;
            const novaSenha = document.getElementById('nova_senha').value;
            const confirmarSenha = document.getElementById('confirmar_senha').value;
            const submitBtn = document.getElementById('submitBtn');
            
            const isValid = senhaAtual.length > 0 &&
                           novaSenha.length >= 8 &&
                           confirmarSenha === novaSenha &&
                           checkPasswordStrength(novaSenha);
            
            submitBtn.disabled = !isValid;
        }
        
        // ✅ ADICIONAR VALIDAÇÃO AOS CAMPOS
        document.getElementById('senha_atual').addEventListener('input', validateForm);
        
        // ✅ LIMPAR FORMULÁRIO EM CASO DE ERRO
        <?php if (!empty($mensagem)): ?>
        setTimeout(() => {
            document.getElementById('passwordForm').reset();
            document.getElementById('strengthBar').className = 'strength-fill';
            document.getElementById('strengthText').textContent = '';
            document.getElementById('matchText').textContent = '';
            validateForm();
        }, 3000);
        <?php endif; ?>
        
        console.log('✅ Sistema de alteração de senha CSRF-Protected carregado!');
    </script>
</body>
</html>