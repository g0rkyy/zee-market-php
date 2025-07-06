<?php
/**
 * PAINEL DO VENDEDOR - SISTEMA CORRIGIDO
 * ✅ ARQUITETURA ATUALIZADA - USA APENAS users.is_vendor
 * ✅ TODAS AS REFERÊNCIAS À TABELA vendedores REMOVIDAS
 * ✅ SISTEMA DE AUTENTICAÇÃO CORRIGIDO
 * ✅ QUERIES ATUALIZADAS PARA NOVA ESTRUTURA
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../includes/config.php';
require_once '../includes/functions.php';

// ✅ VERIFICAÇÃO CORRIGIDA - USA user_id EM VEZ DE vendedor_id
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    error_log("🚨 ACESSO NÃO AUTORIZADO - painel_vendedor.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    header("Location: ../login.php?erro=" . urlencode("Acesso negado - faça login"));
    exit();
}

$user_id = (int)$_SESSION['user_id'];

// ✅ GERAR TOKEN CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ✅ BUSCAR DADOS DO USUÁRIO/VENDEDOR CORRIGIDO
try {
    $stmt = $conn->prepare("SELECT id, name, email, btc_wallet, is_vendor, created_at FROM users WHERE id = ?");
    if (!$stmt) {
        throw new Exception("Erro na preparação da query: " . $conn->error);
    }
    
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $user_data = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user_data) {
        error_log("🚨 USUÁRIO NÃO ENCONTRADO - ID: $user_id");
        header("Location: ../login.php?erro=" . urlencode("Usuário não encontrado"));
        exit();
    }
    
    // ✅ VERIFICAR SE É VENDEDOR
    if (!$user_data['is_vendor']) {
        error_log("🚨 USUÁRIO NÃO É VENDEDOR - ID: $user_id");
        header("Location: ../vendedores/isvendor.php?msg=" . urlencode("Você precisa ser vendedor para acessar este painel"));
        exit();
    }
    
} catch (Exception $e) {
    error_log("❌ ERRO AO BUSCAR USUÁRIO - ID: $user_id - Erro: " . $e->getMessage());
    header("Location: ../login.php?erro=" . urlencode("Erro interno do sistema"));
    exit();
}

// ✅ PROCESSAR FORMULÁRIOS COM CSRF PROTECTION
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 🛡️ VALIDAÇÃO CSRF
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("🚨 CSRF ATTACK - painel_vendedor.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - User: $user_id");
        $_SESSION['erro_csrf'] = "🛡️ ERRO DE SEGURANÇA: Token CSRF inválido.";
        header("Location: painel_vendedor.php");
        exit();
    }
    
    // ✅ ATUALIZAÇÃO DE STATUS DO PEDIDO CORRIGIDA
    if (isset($_POST['pedido_id'])) {
        $pedido_id = (int)$_POST['pedido_id'];
        $concluido = isset($_POST['concluido']) ? 1 : 0;
        
        if ($pedido_id <= 0) {
            $_SESSION['erro_pedido'] = "ID do pedido inválido";
            header("Location: painel_vendedor.php?tab=pedidos");
            exit();
        }
        
        try {
            // ✅ VERIFICAR SE O PEDIDO PERTENCE AO VENDEDOR (CORRIGIDO)
            $stmt_check = $conn->prepare("SELECT id, status FROM purchases WHERE id = ? AND vendedor_id = ?");
            $stmt_check->bind_param("ii", $pedido_id, $user_id);
            $stmt_check->execute();
            $pedido_existente = $stmt_check->get_result()->fetch_assoc();
            $stmt_check->close();
            
            if (!$pedido_existente) {
                error_log("🚨 TENTATIVA DE ALTERAÇÃO DE PEDIDO NÃO PRÓPRIO - User: $user_id - Pedido: $pedido_id");
                $_SESSION['erro_pedido'] = "Pedido não encontrado ou não pertence a você";
                header("Location: painel_vendedor.php?tab=pedidos");
                exit();
            }
            
            // Não permitir marcar como entregue se não foi pago
            if ($concluido && $pedido_existente['status'] !== 'paid') {
                $_SESSION['erro_pedido'] = "Só é possível marcar como entregue pedidos pagos";
                header("Location: painel_vendedor.php?tab=pedidos");
                exit();
            }
            
            // ✅ ATUALIZAR STATUS DO PEDIDO
            $new_status = $concluido ? 'shipped' : 'paid';
            $stmt = $conn->prepare("UPDATE purchases SET status = ?, updated_at = NOW() WHERE id = ? AND vendedor_id = ?");
            if (!$stmt) {
                throw new Exception("Erro na preparação da query: " . $conn->error);
            }
            
            $stmt->bind_param("sii", $new_status, $pedido_id, $user_id);
            
            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) {
                    error_log("✅ STATUS PEDIDO ATUALIZADO - User: $user_id - Pedido: $pedido_id - Status: $new_status");
                    $_SESSION['sucesso_pedido'] = $concluido ? "Pedido marcado como enviado" : "Status do pedido atualizado";
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                } else {
                    $_SESSION['erro_pedido'] = "Nenhuma alteração foi realizada";
                }
            } else {
                throw new Exception("Erro na execução: " . $stmt->error);
            }
            
            $stmt->close();
            
        } catch (Exception $e) {
            error_log("❌ ERRO AO ATUALIZAR PEDIDO - User: $user_id - Pedido: $pedido_id - Erro: " . $e->getMessage());
            $_SESSION['erro_pedido'] = "Erro interno ao atualizar pedido";
        }
        
        header("Location: painel_vendedor.php?tab=pedidos");
        exit();
    }
    
    // ✅ ATUALIZAÇÃO DE CARTEIRA BITCOIN CORRIGIDA
    if (isset($_POST['btc_wallet'])) {
        $nova_carteira = trim($_POST['btc_wallet'] ?? '');
        
        if (empty($nova_carteira)) {
            $_SESSION['erro_carteira'] = "Endereço da carteira é obrigatório";
        } elseif (strlen($nova_carteira) > 100) {
            $_SESSION['erro_carteira'] = "Endereço da carteira muito longo";
        } else {
            
            // ✅ VALIDAÇÃO DE ENDEREÇO BITCOIN
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
                try {
                    // Verificar se endereço não está sendo usado por outro vendedor
                    $stmt_check = $conn->prepare("SELECT id FROM users WHERE btc_wallet = ? AND id != ?");
                    $stmt_check->bind_param("si", $nova_carteira, $user_id);
                    $stmt_check->execute();
                    $endereco_existe = $stmt_check->get_result()->fetch_assoc();
                    $stmt_check->close();
                    
                    if ($endereco_existe) {
                        $_SESSION['erro_carteira'] = "Este endereço já está sendo usado por outro usuário";
                    } else {
                        
                        // ✅ ATUALIZAR CARTEIRA
                        $stmt = $conn->prepare("UPDATE users SET btc_wallet = ?, updated_at = NOW() WHERE id = ?");
                        if (!$stmt) {
                            throw new Exception("Erro na preparação da query: " . $conn->error);
                        }
                        
                        $stmt->bind_param("si", $nova_carteira, $user_id);
                        
                        if ($stmt->execute()) {
                            if ($stmt->affected_rows > 0) {
                                // Atualizar dados na variável local
                                $user_data['btc_wallet'] = $nova_carteira;
                                
                                error_log("✅ CARTEIRA BTC ATUALIZADA - User: $user_id - Novo endereço: " . substr($nova_carteira, 0, 10) . "...");
                                $_SESSION['sucesso_carteira'] = "Carteira Bitcoin atualizada com sucesso";
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
                    error_log("❌ ERRO AO ATUALIZAR CARTEIRA - User: $user_id - Erro: " . $e->getMessage());
                    $_SESSION['erro_carteira'] = "Erro interno ao atualizar carteira";
                }
            }
        }
        
        header("Location: painel_vendedor.php");
        exit();
    }
}

// ✅ BUSCAR PRODUTOS DO VENDEDOR CORRIGIDO
try {
    $stmt = $conn->prepare("SELECT * FROM produtos WHERE vendedor_id = ? ORDER BY data_cadastro DESC");
    if (!$stmt) {
        throw new Exception("Erro na preparação da query produtos: " . $conn->error);
    }
    
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $produtos = $stmt->get_result();
    $stmt->close();
    
} catch (Exception $e) {
    error_log("❌ ERRO AO BUSCAR PRODUTOS - User: $user_id - Erro: " . $e->getMessage());
    $produtos = false;
}

// ✅ BUSCAR PEDIDOS CORRIGIDO - USA purchases EM VEZ DE compras
try {
    $stmt = $conn->prepare("SELECT 
        p.id, p.nome, p.endereco, p.payment_address, p.valor_btc_total, 
        p.tx_hash, p.status, p.created_at,
        pr.nome AS produto_nome
        FROM purchases p
        JOIN produtos pr ON p.produto_id = pr.id
        WHERE p.vendedor_id = ?
        ORDER BY p.created_at DESC");
        
    if (!$stmt) {
        throw new Exception("Erro na preparação da query pedidos: " . $conn->error);
    }
    
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $pedidos = $stmt->get_result();
    $stmt->close();
    
} catch (Exception $e) {
    error_log("❌ ERRO AO BUSCAR PEDIDOS - User: $user_id - Erro: " . $e->getMessage());
    $pedidos = false;
}

// Validar aba ativa
$abas_validas = ['produtos', 'pedidos'];
$active_tab = isset($_GET['tab']) && in_array($_GET['tab'], $abas_validas) ? $_GET['tab'] : 'produtos';
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel do Vendedor - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #6f42c1;
            --secondary-color: #ffc107;
            --success-color: #28a745;
            --danger-color: #dc3545;
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
            background: linear-gradient(90deg, var(--secondary-color), var(--success-color));
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
        
        .fix-notice {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            border: 1px solid rgba(255,255,255,0.2);
        }
    </style>
</head>
<body class="vendor-panel">
    <div class="container py-4">
        <!-- ✅ AVISO DE CORREÇÃO -->
        <div class="fix-notice">
            <i class="bi bi-shield-check-fill"></i> 
            <strong>Sistema Corrigido:</strong> Painel atualizado para nova arquitetura. 
            Todas as referências à tabela 'vendedores' foram removidas.
        </div>

        <!-- ✅ CABEÇALHO CORRIGIDO -->
        <div class="vendor-header p-4 mb-4">
            <div class="d-flex flex-column flex-md-row justify-content-between align-items-center">
                <div class="text-center text-md-start mb-3 mb-md-0">
                    <h2 class="mb-1">
                        <i class="bi bi-shield-check"></i> Painel do Vendedor 
                        <span class="security-badge">🛡️ CSRF PROTECTED</span>
                    </h2>
                    <p class="mb-0">Bem-vindo, <strong><?= htmlspecialchars($user_data['name'] ?? 'Vendedor') ?></strong></p>
                    <small class="opacity-75">
                        <i class="bi bi-calendar"></i> Membro desde: <?= date('d/m/Y', strtotime($user_data['created_at'] ?? 'now')) ?>
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
                        <i class="bi bi-plus-circle"></i> Novo Produto
                    </a>
                    <a href="../logout.php" class="btn btn-danger btn-sm btn-enhanced" onclick="return confirm('Tem certeza que deseja sair?')">
                        <i class="bi bi-box-arrow-right"></i> Sair
                    </a>
                </div>
            </div>
        </div>

        <!-- ✅ ALERTAS SEGUROS -->
        <?php if (isset($_GET['sucesso'])): ?>
            <div class="alert alert-success alert-enhanced alert-dismissible fade show">
                <i class="bi bi-check-circle-fill"></i> <?= htmlspecialchars($_GET['sucesso']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['erro'])): ?>
            <div class="alert alert-danger alert-enhanced alert-dismissible fade show">
                <i class="bi bi-exclamation-triangle-fill"></i> <?= htmlspecialchars($_GET['erro']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php foreach (['erro_csrf', 'sucesso_pedido', 'erro_pedido', 'sucesso_carteira', 'erro_carteira'] as $session_key): ?>
            <?php if (isset($_SESSION[$session_key])): ?>
                <div class="alert alert-<?= strpos($session_key, 'erro') !== false ? 'danger' : 'success' ?> alert-enhanced alert-dismissible fade show">
                    <i class="bi bi-<?= strpos($session_key, 'erro') !== false ? 'exclamation-triangle' : 'check-circle' ?>-fill"></i> 
                    <?= htmlspecialchars($_SESSION[$session_key]) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                <?php unset($_SESSION[$session_key]); ?>
            <?php endif; ?>
        <?php endforeach; ?>

        <!-- ✅ NAVEGAÇÃO POR ABAS -->
        <ul class="nav nav-tabs mb-4">
            <li class="nav-item">
                <button class="nav-link <?= $active_tab === 'produtos' ? 'active' : '' ?>" 
                        onclick="switchTab('produtos')">
                    <i class="bi bi-box-seam"></i> Meus Produtos
                    <?php if ($produtos): ?>
                        <span class="badge bg-light text-dark ms-1"><?= $produtos->num_rows ?></span>
                    <?php endif; ?>
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link <?= $active_tab === 'pedidos' ? 'active' : '' ?>" 
                        onclick="switchTab('pedidos')">
                    <i class="bi bi-receipt"></i> Pedidos
                    <?php if ($pedidos): ?>
                        <span class="badge bg-light text-dark ms-1"><?= $pedidos->num_rows ?></span>
                    <?php endif; ?>
                </button>
            </li>
        </ul>

        <!-- ✅ CONTEÚDO DAS ABAS -->
        <div class="tab-content">
            
            <!-- ABA PRODUTOS -->
            <div class="tab-pane <?= $active_tab === 'produtos' ? 'show active' : '' ?>" id="produtos">
                 
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
                                    <img src="../assets/uploads/<?= htmlspecialchars($produto['imagem'] ?? 'default.jpg') ?>" 
                                         class="card-img-top" 
                                         alt="<?= htmlspecialchars($produto['nome'] ?? 'Produto') ?>"
                                         style="height: 200px; object-fit: cover;"
                                         loading="lazy"
                                         onerror="this.src='../assets/images/no-image.png'">
                                    <div class="card-body">
                                        <h5 class="card-title"><?= htmlspecialchars($produto['nome'] ?? 'Sem nome') ?></h5>
                                        <p class="card-text">
                                            <?= nl2br(htmlspecialchars(substr($produto['descricao'] ?? 'Sem descrição', 0, 100))) ?>
                                            <?= strlen($produto['descricao'] ?? '') > 100 ? '...' : '' ?>
                                        </p>
                                        <div class="d-flex flex-wrap gap-1 mb-2">
                                            <?php if (isset($produto['aceita_cripto'])): ?>
                                                <?php $criptos = explode(',', $produto['aceita_cripto']); ?>
                                                <?php foreach ($criptos as $crypto): ?>
                                                    <span class="badge bg-warning text-dark"><?= htmlspecialchars(trim($crypto)) ?></span>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <div class="card-footer bg-white">
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <span class="h5 text-success mb-0">R$ <?= number_format($produto['preco'] ?? 0, 2, ',', '.') ?></span>
                                        </div>
                                        <div class="row g-2">
                                            <div class="col-6">
                                                <small class="text-muted">
                                                    <i class="bi bi-currency-bitcoin"></i> 
                                                    <?= number_format($produto['preco_btc'] ?? 0, 8) ?> BTC
                                                </small>
                                            </div>
                                            <div class="col-6">
                                                <small class="text-muted">
                                                    <i class="bi bi-currency-dollar"></i> 
                                                    <?= number_format($produto['preco_eth'] ?? 0, 6) ?> ETH
                                                </small>
                                            </div>
                                        </div>
                                        <div class="d-grid gap-2 mt-3">
                                            <a href="editar_produto.php?id=<?= (int)$produto['id'] ?>" 
                                               class="btn btn-outline-primary btn-sm btn-enhanced">
                                                <i class="bi bi-pencil"></i> Editar Produto
                                            </a>
                                        </div>
                                        <div class="mt-2">
                                            <small class="text-muted">
                                                <i class="bi bi-calendar"></i> 
                                                Cadastrado em: <?= date('d/m/Y', strtotime($produto['data_cadastro'] ?? 'now')) ?>
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
            <div class="tab-pane <?= $active_tab === 'pedidos' ? 'show active' : '' ?>" id="pedidos">
                 
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
                                    <th><i class="bi bi-credit-card"></i> Status</th>
                                    <th><i class="bi bi-gear"></i> Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($pedido = $pedidos->fetch_assoc()): ?>
                                    <tr class="order-row">
                                        <td>
                                            <strong>#<?= (int)$pedido['id'] ?></strong>
                                            <br>
                                            <small class="text-muted">
                                                <?= date('d/m/Y H:i', strtotime($pedido['created_at'] ?? 'now')) ?>
                                            </small>
                                        </td>
                                        <td>
                                            <strong><?= htmlspecialchars($pedido['produto_nome'] ?? 'Produto não encontrado') ?></strong>
                                            <br>
                                            <small class="text-muted">
                                                Cliente: <?= htmlspecialchars(substr($pedido['nome'] ?? 'Anônimo', 0, 20)) ?>
                                                <?= strlen($pedido['nome'] ?? '') > 20 ? '...' : '' ?>
                                            </small>
                                        </td>
                                        <td>
                                            <span class="badge bg-warning text-dark">
                                                <?= number_format($pedido['valor_btc_total'] ?? 0, 8) ?> BTC
                                            </span>
                                        </td>
                                        <td>
                                            <?php
                                            $status = $pedido['status'] ?? 'pending';
                                            $status_classes = [
                                                'pending' => 'bg-secondary',
                                                'paid' => 'bg-success',
                                                'shipped' => 'bg-info',
                                                'completed' => 'bg-primary'
                                            ];
                                            $status_names = [
                                                'pending' => 'Pendente',
                                                'paid' => 'Pago',
                                                'shipped' => 'Enviado',
                                                'completed' => 'Concluído'
                                            ];
                                            ?>
                                            <span class="badge <?= $status_classes[$status] ?? 'bg-secondary' ?>">
                                                <?= $status_names[$status] ?? ucfirst($status) ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if ($status === 'paid'): ?>
                                                <!-- ✅ FORMULÁRIO COM CSRF PROTECTION -->
                                                <form method="POST" style="display: inline;" onsubmit="return confirm('Marcar como enviado?')">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                    <input type="hidden" name="pedido_id" value="<?= (int)$pedido['id'] ?>">
                                                    <input type="hidden" name="concluido" value="1">
                                                    <button type="submit" class="btn btn-sm btn-success btn-enhanced">
                                                        <i class="bi bi-truck"></i> Marcar como Enviado
                                                    </button>
                                                </form>
                                            <?php endif; ?>
                                            
                                            <button class="btn btn-sm btn-outline-primary btn-enhanced" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#orderModal<?= (int)$pedido['id'] ?>">
                                                <i class="bi bi-eye"></i> Detalhes
                                            </button>
                                        </td>
                                    </tr>

                                    <!-- ✅ MODAL DE DETALHES -->
                                    <div class="modal fade" id="orderModal<?= (int)$pedido['id'] ?>" tabindex="-1">
                                        <div class="modal-dialog modal-lg">
                                            <div class="modal-content">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">
                                                        <i class="bi bi-receipt"></i> Pedido #<?= (int)$pedido['id'] ?>
                                                    </h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="row">
                                                        <div class="col-md-6">
                                                            <h6><i class="bi bi-person-circle"></i> Informações do Comprador</h6>
                                                            <ul class="list-group list-group-flush mb-3">
                                                                <li class="list-group-item">
                                                                    <strong>Nome:</strong> <?= htmlspecialchars($pedido['nome'] ?? 'Não informado') ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Endereço:</strong> 
                                                                    <div class="mt-1">
                                                                        <?= nl2br(htmlspecialchars($pedido['endereco'] ?? 'Não informado')) ?>
                                                                    </div>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                        <div class="col-md-6">
                                                            <h6><i class="bi bi-box-seam"></i> Informações do Pedido</h6>
                                                            <ul class="list-group list-group-flush">
                                                                <li class="list-group-item">
                                                                    <strong>Produto:</strong> <?= htmlspecialchars($pedido['produto_nome'] ?? 'Produto não encontrado') ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Valor:</strong> 
                                                                    <span class="badge bg-warning text-dark">
                                                                        <?= number_format($pedido['valor_btc_total'] ?? 0, 8) ?> BTC
                                                                    </span>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Data do Pedido:</strong> 
                                                                    <?= date('d/m/Y H:i:s', strtotime($pedido['created_at'] ?? 'now')) ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Status:</strong>
                                                                    <span class="badge <?= $status_classes[$status] ?? 'bg-secondary' ?>">
                                                                        <?= $status_names[$status] ?? ucfirst($status) ?>
                                                                    </span>
                                                                </li>
                                                                <?php if ($pedido['tx_hash']): ?>
                                                                <li class="list-group-item">
                                                                    <strong>Hash da Transação:</strong><br>
                                                                    <code class="small"><?= htmlspecialchars($pedido['tx_hash']) ?></code>
                                                                    <a href="https://blockchain.com/btc/tx/<?= htmlspecialchars($pedido['tx_hash']) ?>" 
                                                                       target="_blank" 
                                                                       class="btn btn-sm btn-outline-primary ms-2"
                                                                       rel="noopener noreferrer">
                                                                        <i class="bi bi-link-45deg"></i> Ver na Blockchain
                                                                    </a>
                                                                </li>
                                                                <?php endif; ?>
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
                <form method="POST" onsubmit="return validarCarteiraBTC(this)">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="btc_wallet" class="form-label fw-bold">
                                <i class="bi bi-currency-bitcoin"></i> Seu endereço Bitcoin:
                            </label>
                            <input type="text" 
                                   class="form-control" 
                                   id="btc_wallet" 
                                   name="btc_wallet" 
                                   value="<?= htmlspecialchars($user_data['btc_wallet'] ?? '') ?>" 
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
                                <strong>Segurança:</strong> Este formulário é protegido contra ataques CSRF.
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        
        // ✅ FUNÇÃO PARA ALTERNAR ABAS
        window.switchTab = function(tabName) {
            // Esconder todas as abas
            document.querySelectorAll('.tab-pane').forEach(tab => {
                tab.classList.remove('show', 'active');
            });
            
            // Remover classe active dos botões
            document.querySelectorAll('.nav-link').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Mostrar aba selecionada
            document.getElementById(tabName).classList.add('show', 'active');
            event.target.classList.add('active');
            
            // Atualizar URL
            const url = new URL(window.location);
            url.searchParams.set('tab', tabName);
            window.history.replaceState(null, '', url);
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
        
        // ✅ AUTO-HIDE ALERTS
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
        
        console.log('✅ Painel do vendedor carregado com arquitetura corrigida!');
        console.log('🎯 Agora usa apenas users.is_vendor');
    });
    </script>
</body>
</html>