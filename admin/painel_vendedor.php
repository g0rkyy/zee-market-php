<?php
/**
 * PAINEL DO VENDEDOR - SISTEMA DE GERENCIAMENTO
 * Versão fortificada com proteção CSRF completa
 * 
 * @author Blackcat Security Team
 * @version 5.0 - CSRF Protected & Ultra-Hardened
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ✅ INICIALIZAR SESSÃO SEGURA
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../includes/config.php';
require_once '../includes/functions.php';

// ✅ VERIFICAÇÃO RIGOROSA DE AUTENTICAÇÃO
if (!isset($_SESSION['vendedor_id']) || empty($_SESSION['vendedor_id'])) {
    error_log("🚨 ACESSO NÃO AUTORIZADO - painel_vendedor.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - Session: " . session_id());
    header("Location: ../vendedores.php?erro=" . urlencode("Acesso negado - faça login"));
    exit();
}

// ✅ GERAR TOKEN CSRF SE NÃO EXISTIR
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$vendedor_id = (int)$_SESSION['vendedor_id'];

// ✅ BUSCAR DADOS DO VENDEDOR COM PREPARED STATEMENT
try {
    $stmt = $conn->prepare("SELECT id, nome, email, btc_wallet, status, created_at FROM vendedores WHERE id = ?");
    if (!$stmt) {
        throw new Exception("Erro na preparação da query: " . $conn->error);
    }
    
    $stmt->bind_param("i", $vendedor_id);
    $stmt->execute();
    $vendedor = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$vendedor) {
        error_log("🚨 VENDEDOR NÃO ENCONTRADO - ID: $vendedor_id - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        header("Location: ../vendedores.php?erro=" . urlencode("Vendedor não encontrado"));
        exit();
    }
    
    // Verificar se vendedor está ativo
    if ($vendedor['status'] !== 'ativo') {
        error_log("🚨 VENDEDOR INATIVO TENTOU ACESSO - ID: $vendedor_id - Status: " . $vendedor['status']);
        header("Location: ../vendedores.php?erro=" . urlencode("Conta de vendedor inativa"));
        exit();
    }
    
} catch (Exception $e) {
    error_log("❌ ERRO AO BUSCAR VENDEDOR - ID: $vendedor_id - Erro: " . $e->getMessage());
    header("Location: ../vendedores.php?erro=" . urlencode("Erro interno do sistema"));
    exit();
}

// ✅ PROCESSAR FORMULÁRIOS COM PROTEÇÃO CSRF TOTAL
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 🛡️ VALIDAÇÃO CSRF OBRIGATÓRIA
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        // Log detalhado de tentativa CSRF
        error_log("🚨 CSRF ATTACK - painel_vendedor.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . 
                  " - Vendedor: $vendedor_id" .
                  " - User Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown') . 
                  " - Referer: " . ($_SERVER['HTTP_REFERER'] ?? 'unknown') .
                  " - Token Enviado: " . ($_POST['csrf_token'] ?? 'VAZIO') .
                  " - Action: " . (isset($_POST['pedido_id']) ? 'UPDATE_ORDER' : (isset($_POST['btc_wallet']) ? 'UPDATE_WALLET' : 'UNKNOWN')));
        
        $_SESSION['erro_csrf'] = "🛡️ ERRO DE SEGURANÇA: Token CSRF inválido. Operação bloqueada por segurança.";
        header("Location: painel_vendedor.php");
        exit();
    }
    
    // ✅ ATUALIZAÇÃO DE STATUS DO PEDIDO COM VALIDAÇÃO TOTAL
    if (isset($_POST['pedido_id'])) {
        $pedido_id = (int)$_POST['pedido_id'];
        $concluido = isset($_POST['concluido']) ? 1 : 0;
        
        // Validações de segurança
        if ($pedido_id <= 0) {
            $_SESSION['erro_pedido'] = "ID do pedido inválido";
            header("Location: painel_vendedor.php?tab=pedidos");
            exit();
        }
        
        try {
            // Verificar se o pedido pertence ao vendedor
            $stmt_check = $conn->prepare("SELECT id, concluido, pago FROM compras WHERE id = ? AND vendedor_id = ?");
            $stmt_check->bind_param("ii", $pedido_id, $vendedor_id);
            $stmt_check->execute();
            $pedido_existente = $stmt_check->get_result()->fetch_assoc();
            $stmt_check->close();
            
            if (!$pedido_existente) {
                error_log("🚨 TENTATIVA DE ALTERAÇÃO DE PEDIDO NÃO PRÓPRIO - Vendedor: $vendedor_id - Pedido: $pedido_id");
                $_SESSION['erro_pedido'] = "Pedido não encontrado ou não pertence a você";
                header("Location: painel_vendedor.php?tab=pedidos");
                exit();
            }
            
            // Não permitir marcar como entregue se não foi pago
            if ($concluido && !$pedido_existente['pago']) {
                $_SESSION['erro_pedido'] = "Não é possível marcar como entregue um pedido não pago";
                header("Location: painel_vendedor.php?tab=pedidos");
                exit();
            }
            
            // Atualizar status
            $stmt = $conn->prepare("UPDATE compras SET concluido = ?, updated_at = NOW() WHERE id = ? AND vendedor_id = ?");
            if (!$stmt) {
                throw new Exception("Erro na preparação da query: " . $conn->error);
            }
            
            $stmt->bind_param("iii", $concluido, $pedido_id, $vendedor_id);
            
            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) {
                    // Log de sucesso
                    error_log("✅ STATUS PEDIDO ATUALIZADO - Vendedor: $vendedor_id - Pedido: $pedido_id - Concluído: $concluido");
                    
                    $_SESSION['sucesso_pedido'] = $concluido ? "Pedido marcado como entregue" : "Pedido marcado como pendente";
                    
                    // Regenerar token CSRF
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                } else {
                    $_SESSION['erro_pedido'] = "Nenhuma alteração foi realizada";
                }
            } else {
                throw new Exception("Erro na execução: " . $stmt->error);
            }
            
            $stmt->close();
            
        } catch (Exception $e) {
            error_log("❌ ERRO AO ATUALIZAR PEDIDO - Vendedor: $vendedor_id - Pedido: $pedido_id - Erro: " . $e->getMessage());
            $_SESSION['erro_pedido'] = "Erro interno ao atualizar pedido";
        }
        
        header("Location: painel_vendedor.php?tab=pedidos");
        exit();
    }
    
    // ✅ ATUALIZAÇÃO DE CARTEIRA BITCOIN COM VALIDAÇÃO ULTRA-SEGURA
    if (isset($_POST['btc_wallet'])) {
        $nova_carteira = trim($_POST['btc_wallet'] ?? '');
        
        // Validações rigorosas
        if (empty($nova_carteira)) {
            $_SESSION['erro_carteira'] = "Endereço da carteira é obrigatório";
        } elseif (strlen($nova_carteira) > 100) {
            $_SESSION['erro_carteira'] = "Endereço da carteira muito longo";
        } else {
            
            // ✅ VALIDAÇÃO AVANÇADA DE ENDEREÇO BITCOIN
            $padroes_bitcoin = [
                '/^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/',        // Legacy P2PKH
                '/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/',        // Legacy P2SH
                '/^bc1[a-z0-9]{39,59}$/i',                  // Bech32 P2WPKH/P2WSH
                '/^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/',    // Testnet
                '/^tb1[a-z0-9]{39,59}$/i'                   // Testnet Bech32
            ];
            
            $endereco_valido = false;
            foreach ($padroes_bitcoin as $padrao) {
                if (preg_match($padrao, $nova_carteira)) {
                    $endereco_valido = true;
                    break;
                }
            }
            
            if (!$endereco_valido) {
                $_SESSION['erro_carteira'] = "Formato de endereço Bitcoin inválido";
            } else {
                
                // Verificar se não é um endereço blacklistado
                $enderecos_blacklist = [
                    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', // Genesis block
                    'bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6', // Exemplo suspeito
                ];
                
                if (in_array($nova_carteira, $enderecos_blacklist)) {
                    error_log("🚨 TENTATIVA DE USAR ENDEREÇO BLACKLISTADO - Vendedor: $vendedor_id - Endereço: $nova_carteira");
                    $_SESSION['erro_carteira'] = "Endereço não permitido por questões de segurança";
                } else {
                    try {
                        // Verificar se endereço não está sendo usado por outro vendedor
                        $stmt_check = $conn->prepare("SELECT id FROM vendedores WHERE btc_wallet = ? AND id != ?");
                        $stmt_check->bind_param("si", $nova_carteira, $vendedor_id);
                        $stmt_check->execute();
                        $endereco_existe = $stmt_check->get_result()->fetch_assoc();
                        $stmt_check->close();
                        
                        if ($endereco_existe) {
                            $_SESSION['erro_carteira'] = "Este endereço já está sendo usado por outro vendedor";
                        } else {
                            
                            // Atualizar carteira
                            $stmt = $conn->prepare("UPDATE vendedores SET btc_wallet = ?, updated_at = NOW() WHERE id = ?");
                            if (!$stmt) {
                                throw new Exception("Erro na preparação da query: " . $conn->error);
                            }
                            
                            $stmt->bind_param("si", $nova_carteira, $vendedor_id);
                            
                            if ($stmt->execute()) {
                                if ($stmt->affected_rows > 0) {
                                    // Atualizar dados na sessão
                                    $vendedor['btc_wallet'] = $nova_carteira;
                                    
                                    // Log de sucesso
                                    error_log("✅ CARTEIRA BTC ATUALIZADA - Vendedor: $vendedor_id - Novo endereço: " . substr($nova_carteira, 0, 10) . "...");
                                    
                                    $_SESSION['sucesso_carteira'] = "Carteira Bitcoin atualizada com sucesso";
                                    
                                    // Regenerar token CSRF
                                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                                } else {
                                    $_SESSION['info_carteira'] = "Nenhuma alteração foi necessária";
                                }
                            } else {
                                throw new Exception("Erro na execução: " . $stmt->error);
                            }
                            
                            $stmt->close();
                        }
                        
                    } catch (Exception $e) {
                        error_log("❌ ERRO AO ATUALIZAR CARTEIRA - Vendedor: $vendedor_id - Erro: " . $e->getMessage());
                        $_SESSION['erro_carteira'] = "Erro interno ao atualizar carteira";
                    }
                }
            }
        }
        
        header("Location: painel_vendedor.php");
        exit();
    }
}

// ✅ BUSCAR PRODUTOS DO VENDEDOR COM PREPARED STATEMENT
try {
    $stmt = $conn->prepare("SELECT * FROM produtos WHERE vendedor_id = ? ORDER BY data_cadastro DESC");
    if (!$stmt) {
        throw new Exception("Erro na preparação da query produtos: " . $conn->error);
    }
    
    $stmt->bind_param("i", $vendedor_id);
    $stmt->execute();
    $produtos = $stmt->get_result();
    $stmt->close();
    
} catch (Exception $e) {
    error_log("❌ ERRO AO BUSCAR PRODUTOS - Vendedor: $vendedor_id - Erro: " . $e->getMessage());
    $produtos = false;
}

// ✅ BUSCAR PEDIDOS COM STATUS DE PAGAMENTO
try {
    $stmt = $conn->prepare("SELECT 
        c.id, c.nome, c.endereco, c.btc_wallet_vendedor, c.valor_btc, 
        c.tx_hash, c.pago, c.concluido, c.data_compra,
        p.nome AS produto_nome
        FROM compras c
        JOIN produtos p ON c.produto_id = p.id
        WHERE c.vendedor_id = ?
        ORDER BY c.data_compra DESC");
        
    if (!$stmt) {
        throw new Exception("Erro na preparação da query pedidos: " . $conn->error);
    }
    
    $stmt->bind_param("i", $vendedor_id);
    $stmt->execute();
    $pedidos = $stmt->get_result();
    $stmt->close();
    
} catch (Exception $e) {
    error_log("❌ ERRO AO BUSCAR PEDIDOS - Vendedor: $vendedor_id - Erro: " . $e->getMessage());
    $pedidos = false;
}

// ✅ VALIDAR ABA ATIVA (PREVENÇÃO DE TAMPERING)
$abas_validas = ['produtos', 'pedidos'];
$active_tab = isset($_GET['tab']) && in_array($_GET['tab'], $abas_validas) ? $_GET['tab'] : 'produtos';
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="ZeeMarket - Painel do Vendedor Seguro">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <title>Painel do Vendedor - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #6f42c1;
            --secondary-color: #ffc107;
            --success-color: #28a745;
            --danger-color: #dc3545;
            --warning-color: #fd7e14;
            --info-color: #17a2b8;
        }
        
        .vendor-panel {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .vendor-header {
            background: linear-gradient(135deg, var(--primary-color), #4b2e83);
            color: white;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            position: relative;
            overflow: hidden;
        }
        
        .vendor-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--secondary-color), var(--success-color), var(--info-color));
        }
        
        .product-card {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            height: 100%;
            border: none;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .product-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 12px 24px rgba(0,0,0,0.15);
        }
        
        .order-row {
            transition: all 0.3s ease;
            border-left: 4px solid transparent;
        }
        
        .order-row:hover {
            background-color: #f8f9fa;
            border-left-color: var(--primary-color);
        }
        
        .status-badge {
            font-size: 0.85rem;
            padding: 6px 12px;
            border-radius: 25px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        
        .status-pending {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .status-paid {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .badge-bitcoin {
            background: linear-gradient(135deg, var(--secondary-color), #e0a800);
            color: #212529;
            font-weight: bold;
        }
        
        .security-badge {
            background: linear-gradient(45deg, var(--success-color), #20c997);
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: bold;
            animation: securityPulse 3s ease-in-out infinite;
        }
        
        @keyframes securityPulse {
            0%, 100% { box-shadow: 0 0 5px rgba(40, 167, 69, 0.5); }
            50% { box-shadow: 0 0 15px rgba(40, 167, 69, 0.8); }
        }
        
        .alert-enhanced {
            border: none;
            border-radius: 12px;
            border-left: 4px solid;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .nav-tabs .nav-link {
            border-radius: 12px 12px 0 0;
            border: none;
            padding: 12px 20px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .nav-tabs .nav-link.active {
            background: linear-gradient(135deg, var(--primary-color), #5a4088);
            color: white;
            border: none;
        }
        
        .nav-tabs .nav-link:hover:not(.active) {
            background-color: #f8f9fa;
            color: var(--primary-color);
        }
        
        .btn-enhanced {
            border-radius: 8px;
            font-weight: 600;
            padding: 8px 16px;
            transition: all 0.3s ease;
        }
        
        .btn-enhanced:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        .modal-content {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .modal-header {
            background: linear-gradient(135deg, var(--primary-color), #5a4088);
            color: white;
            border-radius: 15px 15px 0 0;
            border: none;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(111, 66, 193, 0.25);
        }
        
        .table-responsive {
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .loading-spinner {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 9999;
        }
    </style>
</head>
<body class="vendor-panel">
    <!-- Loading Spinner -->
    <div class="loading-spinner">
        <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">Carregando...</span>
        </div>
    </div>

    <div class="container py-4">
        <!-- ✅ CABEÇALHO SEGURO -->
        <div class="vendor-header p-4 mb-4">
            <div class="d-flex flex-column flex-md-row justify-content-between align-items-center">
                <div class="text-center text-md-start mb-3 mb-md-0">
                    <h2 class="mb-1">
                        <i class="bi bi-shield-check"></i> Painel do Vendedor 
                        <span class="security-badge">🛡️ CSRF PROTECTED</span>
                    </h2>
                    <p class="mb-0">Bem-vindo, <strong><?= htmlspecialchars($vendedor['nome'] ?? 'Vendedor', ENT_QUOTES, 'UTF-8') ?></strong></p>
                    <small class="opacity-75">
                        <i class="bi bi-calendar"></i> Membro desde: <?= htmlspecialchars(date('d/m/Y', strtotime($vendedor['created_at'] ?? 'now')), ENT_QUOTES, 'UTF-8') ?>
                    </small>
                </div>
                <div class="d-flex flex-wrap justify-content-center gap-2">
                    <a href="../index.php" class="btn btn-light btn-sm btn-enhanced">
                        <i class="bi bi-house"></i> Home
                    </a>
                    <button class="btn btn-info btn-sm btn-enhanced" data-bs-toggle="modal" data-bs-target="#walletModal">
                        <i class="bi bi-wallet2"></i> Carteira BTC
                    </button>
                    <a href="cadastrar_produto.php" class="btn btn-primary btn-sm btn-enhanced">
                        <i class="bi bi-plus-circle"></i> Novo
                    </a>
    
                    <a href="../logout.php" class="btn btn-danger btn-sm btn-enhanced" onclick="return confirm('Tem certeza que deseja sair?')">
                        <i class="bi bi-box-arrow-right"></i> Sair
                    </a>
                </div>
            </div>
        </div>

        <!-- ✅ ALERTAS SEGUROS -->
        <?php if (isset($_GET['sucesso'])): ?>
            <div class="alert alert-success alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle-fill"></i> <?= htmlspecialchars($_GET['sucesso'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['erro'])): ?>
            <div class="alert alert-danger alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i> <?= htmlspecialchars($_GET['erro'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($_SESSION['erro_csrf'])): ?>
            <div class="alert alert-danger alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-shield-exclamation"></i> <?= htmlspecialchars($_SESSION['erro_csrf'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['erro_csrf']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['sucesso_pedido'])): ?>
            <div class="alert alert-success alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle-fill"></i> <?= htmlspecialchars($_SESSION['sucesso_pedido'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['sucesso_pedido']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['erro_pedido'])): ?>
            <div class="alert alert-danger alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i> <?= htmlspecialchars($_SESSION['erro_pedido'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['erro_pedido']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['sucesso_carteira'])): ?>
            <div class="alert alert-success alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-wallet-fill"></i> <?= htmlspecialchars($_SESSION['sucesso_carteira'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['sucesso_carteira']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['erro_carteira'])): ?>
            <div class="alert alert-danger alert-enhanced alert-dismissible fade show" role="alert">
                <i class="bi bi-wallet-fill"></i> <?= htmlspecialchars($_SESSION['erro_carteira'], ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['erro_carteira']); ?>
        <?php endif; ?>

        <!-- ✅ NAVEGAÇÃO POR ABAS -->
        <ul class="nav nav-tabs mb-4" id="vendorTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link <?= $active_tab === 'produtos' ? 'active' : '' ?>" 
                        id="products-tab" data-bs-toggle="tab" data-bs-target="#products" 
                        type="button" role="tab">
                    <i class="bi bi-box-seam"></i> Meus Produtos
                    <?php if ($produtos): ?>
                        <span class="badge bg-light text-dark ms-1"><?= htmlspecialchars($produtos->num_rows, ENT_QUOTES, 'UTF-8') ?></span>
                    <?php endif; ?>
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link <?= $active_tab === 'pedidos' ? 'active' : '' ?>" 
                        id="orders-tab" data-bs-toggle="tab" data-bs-target="#orders" 
                        type="button" role="tab">
                    <i class="bi bi-receipt"></i> Pedidos
                    <?php if ($pedidos): ?>
                        <span class="badge bg-light text-dark ms-1"><?= htmlspecialchars($pedidos->num_rows, ENT_QUOTES, 'UTF-8') ?></span>
                    <?php endif; ?>
                </button>
            </li>
        </ul>

        <!-- ✅ CONTEÚDO DAS ABAS -->
        <div class="tab-content" id="vendorTabContent">
            
            <!-- ABA PRODUTOS -->
            <div class="tab-pane fade <?= $active_tab === 'produtos' ? 'show active' : '' ?>" 
                 id="products" role="tabpanel">
                 
                <?php if (!$produtos || $produtos->num_rows === 0): ?>
                    <div class="alert alert-info alert-enhanced">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-info-circle-fill me-2"></i>
                            <div>
                                <p class="mb-0">Você ainda não tem produtos cadastrados.</p>
                                <a href="cadastrar_produto.php" class="btn btn-sm btn-primary mt-2 btn-enhanced">
                                    <i class="bi bi-plus-circle"></i> Adicionar Primeiro Produto
                                </a>
                            </div>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
                        <?php while ($produto = $produtos->fetch_assoc()): ?>
                            <div class="col">
                                <div class="card product-card h-100">
                                    <img src="../assets/uploads/<?= htmlspecialchars($produto['imagem'] ?? 'default.jpg', ENT_QUOTES, 'UTF-8') ?>" 
                                         class="card-img-top" 
                                         alt="<?= htmlspecialchars($produto['nome'] ?? 'Produto', ENT_QUOTES, 'UTF-8') ?>"
                                         style="height: 200px; object-fit: cover;"
                                         loading="lazy"
                                         onerror="this.src='../assets/images/no-image.png'">
                                    <div class="card-body">
                                        <h5 class="card-title"><?= htmlspecialchars($produto['nome'] ?? 'Sem nome', ENT_QUOTES, 'UTF-8') ?></h5>
                                        <p class="card-text">
                                            <?= nl2br(htmlspecialchars(substr($produto['descricao'] ?? 'Sem descrição', 0, 100), ENT_QUOTES, 'UTF-8')) ?>
                                            <?= strlen($produto['descricao'] ?? '') > 100 ? '...' : '' ?>
                                        </p>
                                        <div class="d-flex flex-wrap gap-1 mb-2">
                                            <?php if (isset($produto['aceita_cripto'])): ?>
                                                <?php $criptos = explode(',', $produto['aceita_cripto']); ?>
                                                <?php foreach ($criptos as $crypto): ?>
                                                    <span class="badge badge-bitcoin"><?= htmlspecialchars(trim($crypto), ENT_QUOTES, 'UTF-8') ?></span>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <div class="card-footer bg-white">
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <span class="h5 text-success mb-0">R$ <?= htmlspecialchars(number_format($produto['preco'] ?? 0, 2, ',', '.'), ENT_QUOTES, 'UTF-8') ?></span>
                                            <span class="badge bg-primary">
                                                Estoque: <?= htmlspecialchars(isset($produto['estoque']) ? (int)$produto['estoque'] : 0, ENT_QUOTES, 'UTF-8') ?>
                                            </span>
                                        </div>
                                        <div class="row g-2">
                                            <div class="col-6">
                                                <small class="text-muted">
                                                    <i class="bi bi-currency-bitcoin"></i> 
                                                    <?= htmlspecialchars(number_format($produto['preco_btc'] ?? 0, 8), ENT_QUOTES, 'UTF-8') ?> BTC
                                                </small>
                                            </div>
                                            <div class="col-6">
                                                <small class="text-muted">
                                                    <i class="bi bi-currency-dollar"></i> 
                                                    <?= htmlspecialchars(number_format($produto['preco_eth'] ?? 0, 6), ENT_QUOTES, 'UTF-8') ?> ETH
                                                </small>
                                            </div>
                                        </div>
                                        <div class="d-grid gap-2 mt-3">
                                            <a href="editar_produto.php?id=<?= htmlspecialchars((int)$produto['id'], ENT_QUOTES, 'UTF-8') ?>" 
                                               class="btn btn-outline-primary btn-sm btn-enhanced">
                                                <i class="bi bi-pencil"></i> Editar Produto
                                            </a>
                                        </div>
                                        <div class="mt-2">
                                            <small class="text-muted">
                                                <i class="bi bi-calendar"></i> 
                                                Cadastrado em: <?= htmlspecialchars(date('d/m/Y', strtotime($produto['data_cadastro'] ?? 'now')), ENT_QUOTES, 'UTF-8') ?>
                                            </small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endwhile; ?>
                    </div>
                <?php endif; ?>
            </div>

            <!-- ABA PEDIDOS -->
            <div class="tab-pane fade <?= $active_tab === 'pedidos' ? 'show active' : '' ?>" 
                 id="orders" role="tabpanel">
                 
                <?php if (!$pedidos || $pedidos->num_rows === 0): ?>
                    <div class="alert alert-info alert-enhanced">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-info-circle-fill me-2"></i>
                            <p class="mb-0">Você ainda não tem pedidos recebidos.</p>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th><i class="bi bi-hash"></i> Pedido</th>
                                    <th><i class="bi bi-box"></i> Produto</th>
                                    <th><i class="bi bi-currency-bitcoin"></i> Valor (BTC)</th>
                                    <th><i class="bi bi-credit-card"></i> Pagamento</th>
                                    <th><i class="bi bi-truck"></i> Entrega</th>
                                    <th><i class="bi bi-gear"></i> Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($pedido = $pedidos->fetch_assoc()): ?>
                                    <tr class="order-row">
                                        <td>
                                            <strong>#<?= htmlspecialchars((int)$pedido['id'], ENT_QUOTES, 'UTF-8') ?></strong>
                                            <br>
                                            <small class="text-muted">
                                                <?= htmlspecialchars(date('d/m/Y H:i', strtotime($pedido['data_compra'] ?? 'now')), ENT_QUOTES, 'UTF-8') ?>
                                            </small>
                                        </td>
                                        <td>
                                            <strong><?= htmlspecialchars($pedido['produto_nome'] ?? 'Produto não encontrado', ENT_QUOTES, 'UTF-8') ?></strong>
                                            <br>
                                            <small class="text-muted">
                                                Cliente: <?= htmlspecialchars(substr($pedido['nome'] ?? 'Anônimo', 0, 20), ENT_QUOTES, 'UTF-8') ?>
                                                <?= strlen($pedido['nome'] ?? '') > 20 ? '...' : '' ?>
                                            </small>
                                        </td>
                                        <td>
                                            <span class="badge badge-bitcoin">
                                                <?= htmlspecialchars(number_format($pedido['valor_btc'] ?? 0, 8), ENT_QUOTES, 'UTF-8') ?> BTC
                                            </span>
                                        </td>
                                        <td>
                                            <?php if ($pedido['pago']): ?>
                                                <span class="status-badge status-paid">
                                                    <i class="bi bi-check-circle-fill"></i> Pago
                                                    <?php if ($pedido['tx_hash']): ?>
                                                        <a href="https://blockchain.com/btc/tx/<?= htmlspecialchars($pedido['tx_hash'], ENT_QUOTES, 'UTF-8') ?>" 
                                                           target="_blank" 
                                                           class="ms-1" 
                                                           title="Ver transação na blockchain"
                                                           rel="noopener noreferrer">
                                                            <i class="bi bi-link-45deg"></i>
                                                        </a>
                                                    <?php endif; ?>
                                                </span>
                                            <?php else: ?>
                                                <span class="status-badge status-pending">
                                                    <i class="bi bi-clock-history"></i> Aguardando
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <!-- ✅ FORMULÁRIO COM CSRF PROTECTION -->
                                            <form method="POST" class="d-flex align-items-center" onsubmit="return confirmarMudancaStatus(this)">
                                                <!-- 🛡️ TOKEN CSRF OBRIGATÓRIO -->
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                                                <input type="hidden" name="pedido_id" value="<?= htmlspecialchars((int)$pedido['id'], ENT_QUOTES, 'UTF-8') ?>">
                                                
                                                <div class="form-check form-switch">
                                                    <input class="form-check-input" 
                                                           type="checkbox" 
                                                           name="concluido" 
                                                           value="1" 
                                                           <?= $pedido['concluido'] ? 'checked' : '' ?>
                                                           <?= !$pedido['pago'] ? 'disabled title="Só pode marcar como entregue após pagamento"' : '' ?>
                                                           onchange="this.form.submit()">
                                                    <label class="form-check-label">
                                                        <?= $pedido['concluido'] ? 'Entregue' : 'Pendente' ?>
                                                    </label>
                                                </div>
                                            </form>
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary btn-enhanced" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#orderModal<?= htmlspecialchars((int)$pedido['id'], ENT_QUOTES, 'UTF-8') ?>">
                                                <i class="bi bi-eye"></i> Detalhes
                                            </button>
                                        </td>
                                    </tr>

                                    <!-- ✅ MODAL DE DETALHES SEGURO -->
                                    <div class="modal fade" id="orderModal<?= htmlspecialchars((int)$pedido['id'], ENT_QUOTES, 'UTF-8') ?>" tabindex="-1">
                                        <div class="modal-dialog modal-lg">
                                            <div class="modal-content">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">
                                                        <i class="bi bi-receipt"></i> Pedido #<?= htmlspecialchars((int)$pedido['id'], ENT_QUOTES, 'UTF-8') ?>
                                                    </h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="row">
                                                        <div class="col-md-6">
                                                            <h6><i class="bi bi-person-circle"></i> Informações do Comprador</h6>
                                                            <ul class="list-group list-group-flush mb-3">
                                                                <li class="list-group-item">
                                                                    <strong>Nome:</strong> <?= htmlspecialchars($pedido['nome'] ?? 'Não informado', ENT_QUOTES, 'UTF-8') ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Endereço:</strong> 
                                                                    <div class="mt-1">
                                                                        <?= nl2br(htmlspecialchars($pedido['endereco'] ?? 'Não informado', ENT_QUOTES, 'UTF-8')) ?>
                                                                    </div>
                                                                </li>
                                                                <?php if ($pedido['btc_wallet_vendedor']): ?>
                                                                <li class="list-group-item">
                                                                    <strong>Carteira BTC (Vendedor):</strong>
                                                                    <div class="mt-1">
                                                                        <code class="small"><?= htmlspecialchars($pedido['btc_wallet_vendedor'], ENT_QUOTES, 'UTF-8') ?></code>
                                                                    </div>
                                                                </li>
                                                                <?php endif; ?>
                                                            </ul>
                                                        </div>
                                                        <div class="col-md-6">
                                                            <h6><i class="bi bi-box-seam"></i> Informações do Pedido</h6>
                                                            <ul class="list-group list-group-flush">
                                                                <li class="list-group-item">
                                                                    <strong>Produto:</strong> <?= htmlspecialchars($pedido['produto_nome'] ?? 'Produto não encontrado', ENT_QUOTES, 'UTF-8') ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Valor:</strong> 
                                                                    <span class="badge badge-bitcoin">
                                                                        <?= htmlspecialchars(number_format($pedido['valor_btc'] ?? 0, 8), ENT_QUOTES, 'UTF-8') ?> BTC
                                                                    </span>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Data do Pedido:</strong> 
                                                                    <?= htmlspecialchars(date('d/m/Y H:i:s', strtotime($pedido['data_compra'] ?? 'now')), ENT_QUOTES, 'UTF-8') ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Status Pagamento:</strong>
                                                                    <?php if ($pedido['pago']): ?>
                                                                        <span class="badge bg-success">
                                                                            <i class="bi bi-check-circle"></i> Pago
                                                                        </span>
                                                                        <?php if ($pedido['tx_hash']): ?>
                                                                            <div class="mt-2">
                                                                                <strong>Hash da Transação:</strong><br>
                                                                                <code class="small"><?= htmlspecialchars($pedido['tx_hash'], ENT_QUOTES, 'UTF-8') ?></code>
                                                                                <a href="https://blockchain.com/btc/tx/<?= htmlspecialchars($pedido['tx_hash'], ENT_QUOTES, 'UTF-8') ?>" 
                                                                                   target="_blank" 
                                                                                   class="btn btn-sm btn-outline-primary ms-2"
                                                                                   rel="noopener noreferrer">
                                                                                    <i class="bi bi-link-45deg"></i> Ver na Blockchain
                                                                                </a>
                                                                            </div>
                                                                        <?php endif; ?>
                                                                    <?php else: ?>
                                                                        <span class="badge bg-warning text-dark">
                                                                            <i class="bi bi-clock-history"></i> Aguardando pagamento
                                                                        </span>
                                                                    <?php endif; ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Status Entrega:</strong>
                                                                    <span class="badge <?= $pedido['concluido'] ? 'bg-success' : 'bg-secondary' ?>">
                                                                        <i class="bi bi-<?= $pedido['concluido'] ? 'check-circle' : 'clock' ?>"></i>
                                                                        <?= $pedido['concluido'] ? 'Entregue' : 'Pendente' ?>
                                                                    </span>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary btn-enhanced" data-bs-dismiss="modal">
                                                        <i class="bi bi-x-circle"></i> Fechar
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endwhile; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- ✅ MODAL CARTEIRA BTC COM CSRF PROTECTION -->
    <div class="modal fade" id="walletModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-wallet2"></i> Configurar Carteira Bitcoin
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <!-- ✅ FORMULÁRIO COM CSRF PROTECTION -->
                <form method="POST" onsubmit="return validarCarteiraBTC(this)">
                    <!-- 🛡️ TOKEN CSRF OBRIGATÓRIO -->
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="btc_wallet" class="form-label fw-bold">
                                <i class="bi bi-currency-bitcoin"></i> Seu endereço Bitcoin:
                            </label>
                            <input type="text" 
                                   class="form-control" 
                                   id="btc_wallet" 
                                   name="btc_wallet" 
                                   value="<?= htmlspecialchars($vendedor['btc_wallet'] ?? '', ENT_QUOTES, 'UTF-8') ?>" 
                                   required
                                   maxlength="100"
                                   placeholder="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh">
                            <div class="form-text">
                                <small>
                                    <strong>Formatos aceitos:</strong><br>
                                    • Legacy (P2PKH): 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa<br>
                                    • Script (P2SH): 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy<br>
                                    • Bech32 (P2WPKH): bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
                                </small>
                            </div>
                        </div>
                        
                        <div class="alert alert-info">
                            <h6><i class="bi bi-info-circle"></i> Importante:</h6>
                            <ul class="mb-0 small">
                                <li>Este é o endereço onde você receberá os pagamentos em Bitcoin</li>
                                <li>Certifique-se de que você tem controle total sobre esta carteira</li>
                                <li>Nunca use endereços de exchanges ou carteiras de terceiros</li>
                                <li>O endereço será validado antes de ser salvo</li>
                            </ul>
                        </div>
                        
                        <div class="alert alert-warning">
                            <small>
                                <i class="bi bi-shield-exclamation"></i> 
                                <strong>Segurança:</strong> Este formulário é protegido contra ataques CSRF e todas as alterações são registradas.
                            </small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary btn-enhanced" data-bs-dismiss="modal">
                            <i class="bi bi-x-circle"></i> Cancelar
                        </button>
                        <button type="submit" class="btn btn-primary btn-enhanced">
                            <i class="bi bi-check-circle"></i> Salvar Carteira
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        
        // ✅ ATIVAR TOOLTIPS
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // ✅ AUTO-HIDE ALERTS APÓS 8 SEGUNDOS
        setTimeout(function() {
            document.querySelectorAll('.alert').forEach(function(alert) {
                if (alert.querySelector('.btn-close')) {
                    alert.style.transition = 'opacity 0.5s';
                    alert.style.opacity = '0';
                    setTimeout(() => {
                        if (alert.parentNode) {
                            alert.remove();
                        }
                    }, 500);
                }
            });
        }, 8000);
        
        // ✅ CONFIRMAÇÃO PARA MUDANÇA DE STATUS DE ENTREGA
        window.confirmarMudancaStatus = function(form) {
            const checkbox = form.querySelector('input[name="concluido"]');
            const pedidoId = form.querySelector('input[name="pedido_id"]').value;
            
            if (checkbox.checked) {
                return confirm(`Confirma que o pedido #${pedidoId} foi entregue?\n\nEsta ação será registrada e o cliente será notificado.`);
            } else {
                return confirm(`Confirma que quer marcar o pedido #${pedidoId} como pendente novamente?`);
            }
        };
        
        // ✅ VALIDAÇÃO DE CARTEIRA BITCOIN
        window.validarCarteiraBTC = function(form) {
            const carteira = form.querySelector('#btc_wallet').value.trim();
            
            if (!carteira) {
                alert('❌ Endereço da carteira é obrigatório');
                return false;
            }
            
            // Padrões de validação
            const padroes = [
                /^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/,        // Legacy P2PKH
                /^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/,        // Legacy P2SH
                /^bc1[a-z0-9]{39,59}$/i,                  // Bech32
                /^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/,    // Testnet
                /^tb1[a-z0-9]{39,59}$/i                   // Testnet Bech32
            ];
            
            let valido = false;
            for (let padrao of padroes) {
                if (padrao.test(carteira)) {
                    valido = true;
                    break;
                }
            }
            
            if (!valido) {
                alert('❌ Formato de endereço Bitcoin inválido!\n\nFormatos aceitos:\n• Legacy (1...)\n• Script (3...)\n• Bech32 (bc1...)');
                return false;
            }
            
            return confirm(`Confirma a atualização da carteira Bitcoin?\n\nNovo endereço: ${carteira.substring(0, 20)}...`);
        };
        
        // ✅ LOADING SPINNER PARA FORMULÁRIOS
        document.querySelectorAll('form').forEach(function(form) {
            form.addEventListener('submit', function() {
                const loadingSpinner = document.querySelector('.loading-spinner');
                if (loadingSpinner) {
                    loadingSpinner.style.display = 'block';
                }
                
                // Auto-hide após 10 segundos
                setTimeout(() => {
                    if (loadingSpinner) {
                        loadingSpinner.style.display = 'none';
                    }
                }, 10000);
            });
        });
        
        // ✅ NAVEGAÇÃO POR ABAS COM HISTÓRICO
        const tabButtons = document.querySelectorAll('#vendorTabs button[data-bs-toggle="tab"]');
        tabButtons.forEach(button => {
            button.addEventListener('shown.bs.tab', function (e) {
                const tabId = e.target.getAttribute('data-bs-target').replace('#', '');
                const url = new URL(window.location);
                url.searchParams.set('tab', tabId);
                window.history.replaceState(null, '', url);
            });
        });
        
        // ✅ MELHORAR UX DOS CHECKBOXES DE ENTREGA
        document.querySelectorAll('input[name="concluido"]').forEach(checkbox => {
            checkbox.addEventListener('change', function() {
                if (this.disabled) {
                    this.checked = false;
                    alert('⚠️ Só é possível marcar como entregue pedidos que já foram pagos.');
                    return;
                }
                
                const label = this.parentNode.querySelector('label');
                if (this.checked) {
                    label.innerHTML = '<i class="bi bi-check-circle text-success"></i> Entregue';
                    this.parentNode.parentNode.style.background = '#d4edda';
                } else {
                    label.innerHTML = '<i class="bi bi-clock text-warning"></i> Pendente';
                    this.parentNode.parentNode.style.background = '';
                }
            });
        });
        
        // ✅ LAZY LOADING PARA IMAGENS
        if ('IntersectionObserver' in window) {
            const imageObserver = new IntersectionObserver((entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        if (img.dataset.src) {
                            img.src = img.dataset.src;
                            img.removeAttribute('data-src');
                            observer.unobserve(img);
                        }
                    }
                });
            });
            
            document.querySelectorAll('img[data-src]').forEach(img => {
                imageObserver.observe(img);
            });
        }
        
        // ✅ PREVENÇÃO DE DUPLO CLIQUE
        document.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(button => {
            button.addEventListener('click', function() {
                const btn = this;
                setTimeout(() => {
                    btn.disabled = true;
                    setTimeout(() => btn.disabled = false, 3000);
                }, 100);
            });
        });
        
        console.log('✅ Painel do vendedor carregado com proteção CSRF e validações de segurança!');
    });
    
    // ✅ PREVENÇÃO DE SAÍDA ACIDENTAL
    let formChanged = false;
    document.querySelectorAll('form input, form textarea, form select').forEach(input => {
        input.addEventListener('change', () => formChanged = true);
    });
    
    window.addEventListener('beforeunload', function(e) {
        if (formChanged) {
            const message = 'Você tem alterações não salvas. Tem certeza que deseja sair?';
            e.returnValue = message;
            return message;
        }
    });
    </script>
</body>
</html>