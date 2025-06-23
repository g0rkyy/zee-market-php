<?php
/**
 * SISTEMA DE VENDEDOR - CORREÇÃO FINAL DUPLICATE ENTRY
 * ✅ VERIFICAÇÃO COMPLETA antes de inserir na tabela vendedores
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
    
    error_log("🔍 DEBUG INICIAL: user_id=$user_id, is_vendor=" . ($user['is_vendor'] ?? 'null'));
    
} catch (Exception $e) {
    die("❌ Erro no sistema: " . $e->getMessage());
}

// ✅ VERIFICAÇÃO COMPLETA DE STATUS DE VENDEDOR
$stmt = $conn->prepare("SELECT id FROM vendedores WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$vendor_exists = $stmt->get_result()->fetch_assoc();
$stmt->close();

error_log("🔍 VERIFICAÇÃO VENDEDOR - user_id: $user_id, is_vendor: " . ($user['is_vendor'] ?? 'null') . ", exists_in_vendedores: " . ($vendor_exists ? 'SIM' : 'NÃO'));

// ✅ SE JÁ É VENDEDOR OU JÁ EXISTE NA TABELA VENDEDORES
if ($user['is_vendor'] == 1 || $vendor_exists) {
    
    // Se is_vendor = 1 mas não existe na tabela vendedores, criar registro
    if ($user['is_vendor'] == 1 && !$vendor_exists) {
        error_log("🔧 SINCRONIZAÇÃO: Usuário é vendedor mas não existe na tabela vendedores - criando registro");
        
        try {
            $nome = $user['name'];
            $email = $user['email'];
            $senha_vazia = '';
            $btc_wallet_value = $user['btc_wallet'] ?? '';
            $carteira_value = $user['btc_wallet'] ?? '';
            $created_at = $user['created_at'];
            
            $stmt = $conn->prepare("INSERT INTO vendedores (id, nome, email, senha, btc_wallet, carteira, status, created_at, produtos_cadastrados, criptomoeda) VALUES (?, ?, ?, ?, ?, ?, 'ativo', ?, 0, 'BTC')");
            $stmt->bind_param("issssss", 
                $user_id, $nome, $email, $senha_vazia, $btc_wallet_value, $carteira_value, $created_at
            );
            $stmt->execute();
            $stmt->close();
            
            error_log("✅ SINCRONIZAÇÃO CONCLUÍDA - Registro de vendedor criado");
        } catch (Exception $e) {
            error_log("❌ ERRO NA SINCRONIZAÇÃO: " . $e->getMessage());
        }
    }
    
    // Se existe na tabela vendedores mas is_vendor = 0, atualizar user
    if ($vendor_exists && $user['is_vendor'] != 1) {
        error_log("🔧 SINCRONIZAÇÃO: Registro de vendedor existe mas is_vendor = 0 - atualizando user");
        
        try {
            $stmt = $conn->prepare("UPDATE users SET is_vendor = 1 WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->close();
            
            error_log("✅ SINCRONIZAÇÃO CONCLUÍDA - is_vendor atualizado para 1");
        } catch (Exception $e) {
            error_log("❌ ERRO NA SINCRONIZAÇÃO: " . $e->getMessage());
        }
    }
    
    $_SESSION['is_vendor'] = 1;
    header("Location: ../dashboard.php?sucesso=" . urlencode("✅ Você já é um vendedor autorizado!"));
    exit();
}

// ✅ PROCESSAR FORMULÁRIO DE VIRAR VENDEDOR
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['virar_vendedor'])) {
    
    error_log("🔥 RECEBIDO POST para virar vendedor - user_id: $user_id");
    
    // ✅ VERIFICAÇÃO DUPLA ANTES DE PROCESSAR
    $stmt = $conn->prepare("SELECT id FROM vendedores WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $already_vendor = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if ($already_vendor) {
        error_log("⚠️ TENTATIVA DE CRIAR VENDEDOR DUPLICADO - user_id: $user_id já existe na tabela");
        $_SESSION['is_vendor'] = 1;
        header("Location: ../dashboard.php?sucesso=" . urlencode("✅ Você já é um vendedor autorizado!"));
        exit();
    }
    
    // ✅ VALIDAR CHECKBOXES
    $termos_aceitos = isset($_POST['aceitar_termos']) && $_POST['aceitar_termos'] == '1';
    $maior_idade = isset($_POST['maior_idade']) && $_POST['maior_idade'] == '1';
    $dados_verdadeiros = isset($_POST['dados_verdadeiros']) && $_POST['dados_verdadeiros'] == '1';
    
    error_log("🔍 Checkboxes - Termos: " . ($termos_aceitos ? 'SIM' : 'NÃO') . 
              ", Idade: " . ($maior_idade ? 'SIM' : 'NÃO') . 
              ", Dados: " . ($dados_verdadeiros ? 'SIM' : 'NÃO'));
    
    if (!$termos_aceitos || !$maior_idade || !$dados_verdadeiros) {
        $error = "❌ Você deve aceitar TODOS os termos para se tornar vendedor!";
        error_log("❌ ERRO: Nem todos os termos foram aceitos");
    } else {
        
        try {
            error_log("🔄 INICIANDO PROCESSO DE CRIAÇÃO DE VENDEDOR - user_id: $user_id");
            
            // ✅ PASSO 1: VERIFICAÇÃO FINAL antes de qualquer alteração
            $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $current_user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            
            $stmt = $conn->prepare("SELECT id FROM vendedores WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $current_vendor = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            
            if ($current_user['is_vendor'] == 1 || $current_vendor) {
                error_log("⚠️ RACE CONDITION DETECTADA - usuário já é vendedor, abortando");
                $_SESSION['is_vendor'] = 1;
                header("Location: ../dashboard.php?sucesso=" . urlencode("✅ Você já é um vendedor autorizado!"));
                exit();
            }
            
            // ✅ PASSO 2: ATUALIZAR USUÁRIO PARA VENDEDOR
            error_log("🔄 STEP 1: Atualizando is_vendor=1 para user_id: $user_id");
            
            $stmt = $conn->prepare("UPDATE users SET is_vendor = 1, updated_at = NOW() WHERE id = ? AND is_vendor = 0");
            $stmt->bind_param("i", $user_id);
            $success = $stmt->execute();
            $affected_rows = $stmt->affected_rows;
            $stmt->close();
            
            error_log("✅ UPDATE users executado - Success: " . ($success ? 'SIM' : 'NÃO') . ", Affected rows: $affected_rows");
            
            if (!$success || $affected_rows == 0) {
                throw new Exception("Falha ao atualizar usuário para vendedor - possivelmente já é vendedor");
            }
            
            // ✅ PASSO 3: VERIFICAÇÃO TRIPLA antes de inserir na tabela vendedores
            $stmt = $conn->prepare("SELECT id FROM vendedores WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $triple_check = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            
            if ($triple_check) {
                error_log("⚠️ VENDEDOR JÁ EXISTE NA TABELA - abortando INSERT");
                $_SESSION['is_vendor'] = 1;
                header("Location: ../dashboard.php?sucesso=" . urlencode("✅ Você já é um vendedor autorizado!"));
                exit();
            }
            
            // ✅ PASSO 4: INSERIR NA TABELA VENDEDORES com proteção contra duplicate
            error_log("🔄 STEP 2: Inserindo na tabela vendedores - user_id: $user_id");
            
            $nome = $user['name'];
            $email = $user['email'];
            $senha_vazia = '';
            $btc_wallet_value = $user['btc_wallet'] ?? '';
            $carteira_value = $user['btc_wallet'] ?? '';
            
            // Usar INSERT IGNORE para evitar duplicate entry
            $stmt = $conn->prepare("INSERT IGNORE INTO vendedores (id, nome, email, senha, btc_wallet, carteira, status, created_at, produtos_cadastrados, criptomoeda) VALUES (?, ?, ?, ?, ?, ?, 'ativo', NOW(), 0, 'BTC')");
            $stmt->bind_param("isssss", 
                $user_id, $nome, $email, $senha_vazia, $btc_wallet_value, $carteira_value
            );
            
            $vendor_success = $stmt->execute();
            $vendor_affected = $stmt->affected_rows;
            $stmt->close();
            
            error_log("✅ INSERT IGNORE vendedores executado - Success: " . ($vendor_success ? 'SIM' : 'NÃO') . ", Affected rows: $vendor_affected");
            
            // ✅ PASSO 5: VERIFICAÇÃO FINAL
            $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $check_result = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            
            $stmt = $conn->prepare("SELECT id FROM vendedores WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $vendor_check = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            
            if ($check_result['is_vendor'] != 1 || !$vendor_check) {
                throw new Exception("Verificação final falhou - estado inconsistente");
            }
            
            error_log("✅ VERIFICAÇÃO FINAL OK - is_vendor: " . $check_result['is_vendor'] . ", vendedor_id: " . $vendor_check['id']);
            
            // ✅ LOG DE AUDITORIA (opcional)
            try {
                $details = json_encode([
                    'user_id' => $user_id, 
                    'name' => $user['name'], 
                    'email' => $user['email'],
                    'timestamp' => date('Y-m-d H:i:s'),
                    'vendor_created' => true,
                    'method' => 'duplicate_protected'
                ]);
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                
                $stmt = $conn->prepare("INSERT INTO admin_logs (user_id, action, details, ip_address, created_at) VALUES (?, 'became_vendor', ?, ?, NOW())");
                $stmt->bind_param("iss", $user_id, $details, $ip);
                $stmt->execute();
                $stmt->close();
            } catch (Exception $log_error) {
                error_log("⚠️ Erro no log de auditoria (não crítico): " . $log_error->getMessage());
            }
            
            // ✅ ATUALIZAR SESSÃO
            $_SESSION['is_vendor'] = 1;
            $_SESSION['user_type'] = 'vendor';
            
            session_write_close();
            session_start();
            $_SESSION['is_vendor'] = 1;
            
            error_log("🎉 SUCESSO TOTAL! Usuário $user_id agora é vendedor (protegido contra duplicates)");
            
            // ✅ REDIRECIONAR
            header("Location: ../dashboard.php?sucesso=" . urlencode("🎉 PARABÉNS! Você agora é um VENDEDOR autorizado! Pode cadastrar produtos."));
            exit();
            
        } catch (Exception $e) {
            $error_msg = $e->getMessage();
            error_log("❌ ERRO ao tornar vendedor user_id $user_id: $error_msg");
            
            // ✅ TENTAR REVERTER APENAS SE NECESSÁRIO
            if (strpos($error_msg, 'Duplicate entry') === false) {
                try {
                    $stmt = $conn->prepare("UPDATE users SET is_vendor = 0 WHERE id = ?");
                    $stmt->bind_param("i", $user_id);
                    $stmt->execute();
                    $stmt->close();
                    error_log("🔄 Reversão de is_vendor concluída");
                } catch (Exception $revert_error) {
                    error_log("⚠️ Erro na reversão: " . $revert_error->getMessage());
                }
            }
            
            $error = "❌ Erro interno do sistema. Contate o suporte. (Código: VND004) - " . $error_msg;
        }
    }
}

// ✅ FUNÇÃO AUXILIAR PARA VERIFICAR INTEGRIDADE
function verificarIntegridadeVendedor($conn, $user_id) {
    try {
        $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $user_data = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        $stmt = $conn->prepare("SELECT id FROM vendedores WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $vendor_data = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        return [
            'is_vendor_user' => $user_data['is_vendor'] ?? 0,
            'exists_vendor_table' => !empty($vendor_data),
            'synchronized' => ($user_data['is_vendor'] == 1) && !empty($vendor_data)
        ];
        
    } catch (Exception $e) {
        error_log("❌ Erro na verificação de integridade: " . $e->getMessage());
        return ['error' => $e->getMessage()];
    }
}

$integridade = verificarIntegridadeVendedor($conn, $user_id);
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
        .debug-info {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            font-family: monospace;
            font-size: 0.9rem;
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
        .duplicate-fix-notice {
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

                <!-- ✅ AVISO DE CORREÇÃO DUPLICATE -->
                <div class="duplicate-fix-notice">
                    <i class="bi bi-shield-check-fill"></i> 
                    <strong>Duplicate Entry Corrigido:</strong> Múltiplas verificações implementadas + INSERT IGNORE para evitar entradas duplicadas
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
                <!-- DEBUG INFO -->
                <?php if (isset($integridade) && !isset($integridade['error'])): ?>
                    <div class="debug-info">
                        <strong>🔍 Status de Integridade:</strong><br>
                        • Is Vendor (users): <?= $integridade['is_vendor_user'] ? '✅ SIM' : '❌ NÃO' ?><br>
                        • Existe na tabela vendedores: <?= $integridade['exists_vendor_table'] ? '✅ SIM' : '❌ NÃO' ?><br>
                        • Sincronizado: <?= $integridade['synchronized'] ? '✅ SIM' : '❌ NÃO' ?><br>
                        • <strong>Proteção:</strong> ✅ Múltiplas verificações + INSERT IGNORE
                    </div>
                <?php endif; ?>

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

                <!-- FORMULÁRIO PRINCIPAL -->
                <form method="POST" id="vendorForm" novalidate>
                    <input type="hidden" name="virar_vendedor" value="1">
                    
                    <h4 class="text-center mb-4">
                        <i class="bi bi-clipboard-check"></i> Aceite os Termos para Continuar
                    </h4>

                    <!-- TERMO 1 -->
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

                    <!-- TERMO 2 -->
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

                    <!-- TERMO 3 -->
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
                    <div class="alert alert-warning alert-enhanced" style="border-left-color: #ffc107;">
                        <h6><i class="bi bi-exclamation-triangle"></i> Importante:</h6>
                        <p class="mb-0">
                            Ao se tornar vendedor, você concorda em seguir todas as regras da plataforma. 
                            <strong>Violações podem resultar em suspensão da conta.</strong>
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
        
        // ✅ FUNÇÃO PARA VERIFICAR SE TODOS OS CHECKBOXES ESTÃO MARCADOS
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
        
        // ✅ ADICIONAR EVENT LISTENERS
        checkboxes.forEach(function(checkbox) {
            checkbox.addEventListener('change', verificarCheckboxes);
        });
        
        // ✅ VERIFICAÇÃO INICIAL
        verificarCheckboxes();
        
        // ✅ VALIDAÇÃO NO SUBMIT
        form.addEventListener('submit', function(e) {
            console.log('🚀 Formulário sendo enviado (duplicate entry protegido)...');
            
            // Verificar checkboxes novamente
            let todosChecados = true;
            const valores = {};
            
            checkboxes.forEach(function(checkbox) {
                valores[checkbox.name] = checkbox.checked;
                if (!checkbox.checked) {
                    todosChecados = false;
                }
            });
            
            if (!todosChecados) {
                e.preventDefault();
                alert('❌ Você deve aceitar TODOS os termos para continuar!');
                return false;
            }
            
            // Confirmação final
            if (!confirm('🚀 CONFIRMAÇÃO FINAL:\n\nDeseja realmente se tornar um VENDEDOR na ZeeMarket?\n\n✅ Sistema protegido contra entradas duplicadas.\n\nEsta ação é irreversível!')) {
                e.preventDefault();
                return false;
            }
            
            // Desabilitar botão e mostrar loading
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processando com proteção anti-duplicate...';
            
            console.log('✅ Formulário validado - proteção duplicate ativa');
            
            // Auto-reabilitar em caso de falha de rede
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.disabled = false;
                    verificarCheckboxes();
                }
            }, 15000);
        });
        
        console.log('✅ Sistema de vendedor inicializado - Proteção duplicate entry ativa!');
        console.log('🛡️ Proteções: Múltiplas verificações + INSERT IGNORE + Race condition detection');
    });
    </script>
</body>
</html>