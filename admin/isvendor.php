<?php
/**
 * SISTEMA DE VENDEDOR - OTIMIZADO E SIMPLIFICADO
 * ✅ ARQUITETURA LIMPA - USA APENAS users.is_vendor
 * ✅ LÓGICA SIMPLIFICADA E EFICIENTE
 * ✅ PROTEÇÃO CSRF E VALIDAÇÕES COMPLETAS
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../includes/config.php';
require_once '../includes/functions.php';

// ✅ VERIFICAR LOGIN
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit();
}

$user_id = (int)$_SESSION['user_id'];
$message = '';
$error = '';

// ✅ BUSCAR DADOS ATUAIS DO USUÁRIO
try {
    $stmt = $conn->prepare("SELECT name, email, is_vendor, created_at, btc_wallet FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$user) {
        die("❌ Usuário não encontrado!");
    }
    
} catch (Exception $e) {
    die("❌ Erro no sistema: " . $e->getMessage());
}

// ✅ SE JÁ É VENDEDOR, REDIRECIONAR
if ($user['is_vendor'] == 1) {
    $_SESSION['is_vendor'] = 1;
    header("Location: ../dashboard.php?sucesso=" . urlencode("✅ Você já é um vendedor autorizado!"));
    exit();
}

// ✅ GERAR TOKEN CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ✅ PROCESSAR FORMULÁRIO DE APROVAÇÃO VENDEDOR
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['virar_vendedor'])) {
    
    // ✅ VALIDAR CSRF
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "❌ Token de segurança inválido!";
        error_log("🚨 CSRF ATTACK - isvendor.php - User: $user_id - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    } else {
        
        // ✅ VALIDAR CHECKBOXES
        $termos_aceitos = isset($_POST['aceitar_termos']) && $_POST['aceitar_termos'] == '1';
        $maior_idade = isset($_POST['maior_idade']) && $_POST['maior_idade'] == '1';
        $dados_verdadeiros = isset($_POST['dados_verdadeiros']) && $_POST['dados_verdadeiros'] == '1';
        
        if (!$termos_aceitos || !$maior_idade || !$dados_verdadeiros) {
            $error = "❌ Você deve aceitar TODOS os termos para se tornar vendedor!";
        } else {
            
            try {
                // ✅ VERIFICAÇÃO DE RACE CONDITION
                $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $current_user = $stmt->get_result()->fetch_assoc();
                $stmt->close();
                
                if ($current_user['is_vendor'] == 1) {
                    $_SESSION['is_vendor'] = 1;
                    header("Location: ../dashboard.php?sucesso=" . urlencode("✅ Você já é um vendedor autorizado!"));
                    exit();
                }
                
                // ✅ ATUALIZAR PARA VENDEDOR - QUERY SIMPLES E EFICIENTE
                $stmt = $conn->prepare("UPDATE users SET is_vendor = 1, updated_at = NOW() WHERE id = ? AND is_vendor = 0");
                $stmt->bind_param("i", $user_id);
                $success = $stmt->execute();
                $affected_rows = $stmt->affected_rows;
                $stmt->close();
                
                if (!$success || $affected_rows == 0) {
                    throw new Exception("Falha ao atualizar usuário para vendedor");
                }
                
                // ✅ VERIFICAÇÃO FINAL
                $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $check_result = $stmt->get_result()->fetch_assoc();
                $stmt->close();
                
                if ($check_result['is_vendor'] != 1) {
                    throw new Exception("Verificação final falhou");
                }
                
                // ✅ LOG DE AUDITORIA SIMPLIFICADO
                try {
                    $details = json_encode([
                        'user_id' => $user_id, 
                        'name' => $user['name'], 
                        'email' => $user['email'],
                        'timestamp' => date('Y-m-d H:i:s'),
                        'action' => 'became_vendor_simplified'
                    ]);
                    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                    
                    $stmt = $conn->prepare("INSERT INTO admin_logs (user_id, action, details, ip_address, created_at) VALUES (?, 'became_vendor', ?, ?, NOW())");
                    $stmt->bind_param("iss", $user_id, $details, $ip);
                    $stmt->execute();
                    $stmt->close();
                } catch (Exception $log_error) {
                    error_log("⚠️ Erro no log (não crítico): " . $log_error->getMessage());
                }
                
                // ✅ ATUALIZAR SESSÃO
                $_SESSION['is_vendor'] = 1;
                
                error_log("🎉 VENDEDOR CRIADO COM SUCESSO! User: $user_id");
                
                // ✅ REDIRECIONAR COM SUCESSO
                header("Location: ../dashboard.php?sucesso=" . urlencode("🎉 PARABÉNS! Você agora é um VENDEDOR autorizado! Pode cadastrar produtos imediatamente."));
                exit();
                
            } catch (Exception $e) {
                error_log("❌ ERRO ao tornar vendedor - User: $user_id - Erro: " . $e->getMessage());
                $error = "❌ Erro interno do sistema. Tente novamente em alguns minutos.";
            }
        }
    }
    
    // ✅ REGENERAR TOKEN CSRF
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 Virar Vendedor - ZeeMarket</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
        }
        .vendor-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            margin: 2rem auto;
            max-width: 900px;
        }
        .vendor-header {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        .benefits-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }
        .benefit-card {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 1rem;
            text-align: center;
            transition: transform 0.3s ease;
        }
        .benefit-card:hover {
            transform: translateY(-5px);
        }
        .form-section {
            padding: 2rem;
        }
        .terms-card {
            border: 2px solid #e9ecef;
            border-radius: 15px;
            padding: 1.5rem;
            margin: 1rem 0;
            transition: all 0.3s ease;
        }
        .terms-card:hover {
            border-color: #28a745;
            box-shadow: 0 5px 15px rgba(40, 167, 69, 0.1);
        }
        .custom-checkbox {
            transform: scale(1.2);
            margin-right: 0.75rem;
        }
        .btn-vendor {
            background: linear-gradient(135deg, #28a745, #20c997);
            border: none;
            color: white;
            padding: 15px 30px;
            font-weight: bold;
            border-radius: 50px;
            font-size: 1.2rem;
            width: 100%;
            transition: all 0.3s ease;
        }
        .btn-vendor:hover {
            background: linear-gradient(135deg, #20c997, #28a745);
            color: white;
            transform: translateY(-3px);
            box-shadow: 0 10px 25px rgba(40, 167, 69, 0.3);
        }
        .btn-vendor:disabled {
            opacity: 0.6;
            transform: none;
            cursor: not-allowed;
        }
        .status-current {
            background: linear-gradient(135deg, #ffc107, #fd7e14);
            color: white;
            padding: 1rem;
            border-radius: 15px;
            margin: 1rem 0;
        }
        .alert-enhanced {
            border: none;
            border-radius: 15px;
            padding: 1rem 1.5rem;
            border-left: 5px solid;
        }
        .pulse {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        .breadcrumb-nav {
            background: linear-gradient(135deg, #6c757d, #495057);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        .breadcrumb-nav a {
            color: #ffc107;
            text-decoration: none;
        }
        .breadcrumb-nav a:hover {
            color: white;
        }
        .fix-notice {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 0.75rem 1rem;
            border-radius: 10px;
            font-size: 0.9rem;
            margin-bottom: 1rem;
            border: 1px solid rgba(255,255,255,0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="vendor-container">
            <!-- ✅ NAVEGAÇÃO BREADCRUMB -->
            <div class="form-section">
                <nav class="breadcrumb-nav">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-house-door me-2"></i>
                        <a href="../index.php">Home</a>
                        <span class="mx-2">></span>
                        <a href="../dashboard.php">Dashboard</a>
                        <span class="mx-2">></span>
                        <span>Virar Vendedor</span>
                    </div>
                </nav>

                <!-- ✅ AVISO DE OTIMIZAÇÃO -->
                <div class="fix-notice">
                    <i class="bi bi-shield-check-fill"></i> 
                    <strong>Sistema Otimizado:</strong> Processo simplificado e mais eficiente. Aprovação instantânea garantida.
                </div>
            </div>

            <!-- CABEÇALHO -->
            <div class="vendor-header">
                <h1><i class="bi bi-rocket-takeoff"></i> Torne-se um Vendedor!</h1>
                <p class="lead mb-0">Ganhe dinheiro vendendo na maior plataforma crypto do Brasil</p>
                
                <div class="benefits-grid">
                    <div class="benefit-card">
                        <i class="bi bi-cash-coin display-6"></i>
                        <h6>Ganhos Ilimitados</h6>
                    </div>
                    <div class="benefit-card">
                        <i class="bi bi-shield-check display-6"></i>
                        <h6>100% Seguro</h6>
                    </div>
                    <div class="benefit-card">
                        <i class="bi bi-lightning display-6"></i>
                        <h6>Aprovação Instantânea</h6>
                    </div>
                    <div class="benefit-card">
                        <i class="bi bi-people display-6"></i>
                        <h6>Milhares de Clientes</h6>
                    </div>
                </div>
            </div>

            <div class="form-section">
                <!-- ALERTAS -->
                <?php if ($error): ?>
                    <div class="alert alert-danger alert-enhanced" style="border-left-color: #dc3545;">
                        <i class="bi bi-exclamation-triangle-fill"></i> 
                        <strong>ERRO:</strong> <?= htmlspecialchars($error) ?>
                    </div>
                <?php endif; ?>

                <?php if ($message): ?>
                    <div class="alert alert-success alert-enhanced" style="border-left-color: #28a745;">
                        <i class="bi bi-check-circle-fill"></i> <?= htmlspecialchars($message) ?>
                    </div>
                <?php endif; ?>

                <!-- STATUS ATUAL -->
                <div class="status-current">
                    <h5><i class="bi bi-person-badge"></i> Suas Informações:</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <strong>👤 Nome:</strong> <?= htmlspecialchars($user['name']) ?><br>
                            <strong>📧 Email:</strong> <?= htmlspecialchars($user['email']) ?>
                        </div>
                        <div class="col-md-6">
                            <strong>📅 Membro desde:</strong> <?= date('d/m/Y', strtotime($user['created_at'])) ?><br>
                            <strong>🏷️ Status atual:</strong> 
                            <span class="badge bg-light text-dark">
                                <?= $user['is_vendor'] ? '🏪 VENDEDOR' : '👤 CLIENTE' ?>
                            </span>
                        </div>
                    </div>
                </div>

                <!-- FORMULÁRIO OTIMIZADO -->
                <form method="POST" id="vendorForm" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <input type="hidden" name="virar_vendedor" value="1">
                    
                    <h4 class="text-center mb-4">
                        <i class="bi bi-clipboard-check"></i> Aceite os Termos para Continuar
                    </h4>

                    <!-- TERMOS SIMPLIFICADOS -->
                    <div class="terms-card">
                        <div class="form-check">
                            <input class="form-check-input custom-checkbox" 
                                   type="checkbox" 
                                   name="maior_idade" 
                                   value="1" 
                                   id="maior_idade" 
                                   required>
                            <label class="form-check-label fw-bold" for="maior_idade">
                                <i class="bi bi-person-check text-success"></i> 
                                Confirmo que sou <strong>maior de 18 anos</strong>
                            </label>
                        </div>
                        <small class="text-muted mt-2 d-block">
                            É obrigatório ser maior de idade para vender na plataforma
                        </small>
                    </div>

                    <div class="terms-card">
                        <div class="form-check">
                            <input class="form-check-input custom-checkbox" 
                                   type="checkbox" 
                                   name="dados_verdadeiros" 
                                   value="1" 
                                   id="dados_verdadeiros" 
                                   required>
                            <label class="form-check-label fw-bold" for="dados_verdadeiros">
                                <i class="bi bi-shield-check text-primary"></i> 
                                Declaro que as <strong>informações são verdadeiras</strong>
                            </label>
                        </div>
                        <small class="text-muted mt-2 d-block">
                            Informações falsas podem resultar em banimento permanente
                        </small>
                    </div>

                    <div class="terms-card">
                        <div class="form-check">
                            <input class="form-check-input custom-checkbox" 
                                   type="checkbox" 
                                   name="aceitar_termos" 
                                   value="1" 
                                   id="aceitar_termos" 
                                   required>
                            <label class="form-check-label fw-bold" for="aceitar_termos">
                                <i class="bi bi-file-text text-warning"></i> 
                                Aceito os <strong>termos de uso e responsabilidades</strong>
                            </label>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted">Incluindo:</small>
                            <ul class="small text-muted mt-1">
                                <li>📋 Fornecer descrições precisas dos produtos</li>
                                <li>🚚 Enviar produtos conforme anunciado</li>
                                <li>💰 Taxa da plataforma: 2.5% por venda</li>
                                <li>⚡ Manter comportamento ético e profissional</li>
                            </ul>
                        </div>
                    </div>

                    <!-- AVISO IMPORTANTE -->
                    <div class="alert alert-info alert-enhanced" style="border-left-color: #17a2b8;">
                        <h6><i class="bi bi-info-circle"></i> Processo Otimizado:</h6>
                        <p class="mb-0">
                            <strong>✅ Aprovação instantânea garantida!</strong><br>
                            Assim que aceitar os termos, você se tornará vendedor imediatamente e poderá cadastrar produtos.
                        </p>
                    </div>

                    <!-- BOTÃO DE SUBMISSÃO -->
                    <div class="text-center mt-4">
                        <button type="submit" class="btn btn-vendor pulse" id="submitBtn" disabled>
                            <i class="bi bi-rocket-takeoff"></i> 
                            🚀 QUERO ME TORNAR VENDEDOR AGORA! 🚀
                        </button>
                        
                        <div class="mt-3">
                            <a href="../dashboard.php" class="btn btn-outline-secondary me-2">
                                <i class="bi bi-arrow-left"></i> Voltar ao Dashboard
                            </a>
                            <a href="cadastrar_produto.php" class="btn btn-outline-success">
                                <i class="bi bi-plus-circle"></i> Cadastrar Produto (após aprovação)
                            </a>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const form = document.getElementById('vendorForm');
        const submitBtn = document.getElementById('submitBtn');
        const checkboxes = document.querySelectorAll('input[type="checkbox"]');
        
        // ✅ VERIFICAR SE TODOS OS CHECKBOXES ESTÃO MARCADOS
        function verificarCheckboxes() {
            let todosChecados = true;
            
            checkboxes.forEach(function(checkbox) {
                if (!checkbox.checked) {
                    todosChecados = false;
                }
                
                // Visual feedback
                const card = checkbox.closest('.terms-card');
                if (checkbox.checked) {
                    card.style.borderColor = '#28a745';
                    card.style.backgroundColor = '#f8fff9';
                } else {
                    card.style.borderColor = '#e9ecef';
                    card.style.backgroundColor = 'white';
                }
            });
            
            // Habilitar/desabilitar botão
            submitBtn.disabled = !todosChecados;
            
            if (todosChecados) {
                submitBtn.classList.add('pulse');
                submitBtn.innerHTML = '<i class="bi bi-rocket-takeoff"></i> 🚀 QUERO ME TORNAR VENDEDOR AGORA! 🚀';
            } else {
                submitBtn.classList.remove('pulse');
                submitBtn.innerHTML = '<i class="bi bi-x-circle"></i> Aceite todos os termos para continuar';
            }
        }
        
        // ✅ EVENT LISTENERS
        checkboxes.forEach(function(checkbox) {
            checkbox.addEventListener('change', verificarCheckboxes);
        });
        
        // ✅ VERIFICAÇÃO INICIAL
        verificarCheckboxes();
        
        // ✅ VALIDAÇÃO NO SUBMIT
        form.addEventListener('submit', function(e) {
            console.log('🚀 Formulário sendo enviado (sistema otimizado)...');
            
            // Verificar checkboxes
            let todosChecados = true;
            
            checkboxes.forEach(function(checkbox) {
                if (!checkbox.checked) {
                    todosChecados = false;
                }
            });
            
            if (!todosChecados) {
                e.preventDefault();
                alert('❌ Você deve aceitar TODOS os termos para continuar!');
                return false;
            }
            
            // Confirmação final otimizada
            if (!confirm('🚀 CONFIRMAÇÃO FINAL:\n\nDeseja realmente se tornar um VENDEDOR na ZeeMarket?\n\n✅ Aprovação será INSTANTÂNEA!\n✅ Poderá cadastrar produtos imediatamente!\n\nContinuar?')) {
                e.preventDefault();
                return false;
            }
            
            // Loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processando aprovação...';
            
            console.log('✅ Formulário validado - sistema otimizado');
            
            // Auto-reabilitar em caso de erro
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.disabled = false;
                    verificarCheckboxes();
                }
            }, 15000);
        });
        
        console.log('✅ Sistema de vendedor otimizado inicializado!');
        console.log('🎯 Arquitetura simplificada - apenas users.is_vendor');
    });
    </script>
</body>
</html>