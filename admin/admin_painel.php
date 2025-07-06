<?php
/**
 * PAINEL ADMINISTRATIVO COMPLETO - VERSÃO CORRIGIDA
 * ✅ TODAS AS QUERIES ATUALIZADAS PARA NOVA ARQUITETURA
 * ✅ REMOVIDAS REFERÊNCIAS À TABELA vendedores
 * ✅ CORRIGIDAS INCONSISTÊNCIAS DE DADOS
 */

session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Verificar se é admin
if (!isset($_SESSION['user_id']) || !isAdmin($_SESSION['user_id'])) {
    die("Acesso negado!");
}

function isAdmin($userId) {
    global $conn;
    $stmt = $conn->prepare("SELECT is_admin FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result && $result['is_admin'] == 1;
}

// ✅ ESTATÍSTICAS CORRIGIDAS - USA APENAS TABELA users
$stmt = $conn->prepare("SELECT COUNT(*) FROM users");
$stmt->execute();
$total_users = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE is_vendor = 1");
$stmt->execute();
$total_vendors = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM produtos");
$stmt->execute();
$total_products = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM purchases");
$stmt->execute();
$total_orders = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM btc_transactions WHERE status = 'pending'");
$stmt->execute();
$pending_payments = $stmt->get_result()->fetch_row()[0];
$stmt->close();

// ✅ SALDOS TOTAIS DA PLATAFORMA
$stmt = $conn->prepare("SELECT COALESCE(SUM(btc_balance), 0) FROM users");
$stmt->execute();
$total_btc_balance = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stmt = $conn->prepare("SELECT COALESCE(SUM(eth_balance), 0) FROM users");
$stmt->execute();
$total_eth_balance = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM btc_transactions WHERE DATE(created_at) = CURDATE()");
$stmt->execute();
$recent_transactions = $stmt->get_result()->fetch_row()[0];
$stmt->close();

$stats = [
    'total_users' => $total_users,
    'total_vendors' => $total_vendors,
    'total_products' => $total_products,
    'total_orders' => $total_orders,
    'pending_payments' => $pending_payments,
    'total_btc_balance' => $total_btc_balance,
    'total_eth_balance' => $total_eth_balance,
    'recent_transactions' => $recent_transactions
];

// ✅ TRANSAÇÕES RECENTES CORRIGIDAS - JOIN COM users EM VEZ DE vendedores
$stmt = $conn->prepare("
    SELECT bt.*, u.name as username, u.email 
    FROM btc_transactions bt 
    JOIN users u ON bt.user_id = u.id 
    ORDER BY bt.created_at DESC 
    LIMIT 20
");
$stmt->execute();
$recent_txs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// ✅ USUÁRIOS SUSPEITOS CORRIGIDOS
$stmt = $conn->prepare("
    SELECT u.*, COUNT(bt.id) as tx_count, COALESCE(SUM(bt.amount), 0) as total_amount
    FROM users u 
    LEFT JOIN btc_transactions bt ON u.id = bt.user_id 
    WHERE bt.created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    GROUP BY u.id 
    HAVING tx_count > 10 OR total_amount > 1.0
    ORDER BY total_amount DESC
");
$stmt->execute();
$suspicious_users = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// Processar ações do admin
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'toggle_real_mode':
            $stmt = $conn->prepare("UPDATE system_config SET config_value = ? WHERE config_key = 'real_mode'");
            $newMode = ($_POST['real_mode'] === '1') ? '1' : '0';
            $stmt->bind_param("s", $newMode);
            $stmt->execute();
            $stmt->close();
            $message = $newMode ? "Modo real ATIVADO!" : "Modo simulado ativado";
            break;
            
        case 'manual_confirm':
            if (isset($_POST['tx_id'])) {
                $tx_id = (int)$_POST['tx_id'];
                $stmt = $conn->prepare("UPDATE btc_transactions SET status = 'confirmed' WHERE id = ?");
                
                if ($stmt === false) {
                    error_log("Admin Panel - Prepare failed for manual_confirm: " . $conn->error);
                    $message = "Erro ao preparar a confirmação.";
                    break;
                }
                
                $stmt->bind_param("i", $tx_id);
                
                if ($stmt->execute()) {
                    $message = "Transação ID: " . htmlspecialchars($tx_id) . " confirmada manualmente.";
                } else {
                    error_log("Admin Panel - Execute failed for manual_confirm: " . $stmt->error);
                    $message = "Falha ao confirmar a transação.";
                }
                
                $stmt->close();
            }
            break;
            
        case 'block_user':
            if (isset($_POST['user_id'])) {
                $user_id = (int)$_POST['user_id'];
                $stmt = $conn->prepare("UPDATE users SET is_blocked = 1 WHERE id = ?");
                
                if ($stmt === false) {
                    error_log('Admin Panel - Prepare failed for block_user: ' . $conn->error);
                    $message = 'Erro no sistema ao bloquear usuário.';
                    break;
                }
                
                $stmt->bind_param("i", $user_id);
                
                if ($stmt->execute()) {
                    $message = "Usuário ID: " . htmlspecialchars($user_id) . " bloqueado com sucesso.";
                } else {
                    error_log('Admin Panel - Execute failed for block_user: ' . $stmt->error);
                    $message = "Falha ao bloquear usuário.";
                }
                
                $stmt->close();
            }
            break;
    }
    
    if (isset($message)) {
        $_SESSION['admin_message'] = $message;
        header("Location: admin_painel.php");
        exit();
    }
}

// Verificar modo atual
$stmt = $conn->prepare("SELECT config_value FROM system_config WHERE config_key = 'real_mode'");
$stmt->execute();
$result = $stmt->get_result();
$real_mode_data = $result->fetch_row();
$real_mode = $real_mode_data ? $real_mode_data[0] : '0';
$stmt->close();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Painel Admin - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        body { background: #1a1a1a; color: #e0e0e0; }
        .card { background: #2d2d2d; border: 1px solid #444; }
        .stat-card { transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-5px); }
        .danger-zone { border: 2px solid #dc3545; background: rgba(220, 53, 69, 0.1); }
        .real-mode-active { background: linear-gradient(45deg, #28a745, #20c997); }
        .real-mode-inactive { background: linear-gradient(45deg, #ffc107, #fd7e14); }
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
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand">🛡️ Admin Panel - ZeeMarket</span>
            <a href="../dashboard.php" class="btn btn-outline-light">Voltar ao Dashboard</a>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <!-- ✅ AVISO DE CORREÇÃO -->
        <div class="fix-notice">
            <i class="bi bi-shield-check-fill"></i> 
            <strong>Sistema Corrigido:</strong> Todas as queries foram atualizadas para a nova arquitetura. 
            Tabela 'vendedores' removida, usando apenas 'users.is_vendor'.
        </div>

        <?php if (isset($_SESSION['admin_message'])): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <?= htmlspecialchars($_SESSION['admin_message']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['admin_message']); ?>
        <?php endif; ?>

        <!-- Controles do Sistema -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card danger-zone">
                    <div class="card-header">
                        <h4><i class="bi bi-gear"></i> Controles do Sistema</h4>
                    </div>
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-6">
                                <h5>Modo de Operação:</h5>
                                <div class="badge <?= $real_mode == '1' ? 'real-mode-active' : 'real-mode-inactive' ?> fs-6 p-3">
                                    <?= $real_mode == '1' ? '🔴 MODO REAL ATIVO' : '🟡 MODO SIMULADO' ?>
                                </div>
                                <p class="mt-2 text-muted">
                                    <?= $real_mode == '1' ? 'APIs blockchain reais ativas' : 'Transações simuladas para desenvolvimento' ?>
                                </p>
                            </div>
                            <div class="col-md-6">
                                <form method="POST" onsubmit="return confirm('Tem certeza? Isso afeta todo o sistema!')">
                                    <input type="hidden" name="action" value="toggle_real_mode">
                                    <input type="hidden" name="real_mode" value="<?= $real_mode == '1' ? '0' : '1' ?>">
                                    <button type="submit" class="btn <?= $real_mode == '1' ? 'btn-warning' : 'btn-success' ?> btn-lg">
                                        <?= $real_mode == '1' ? 'Desativar Modo Real' : 'Ativar Modo Real' ?>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Estatísticas Corrigidas -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card text-center">
                    <div class="card-body">
                        <i class="bi bi-people fs-1 text-primary"></i>
                        <h3><?= number_format($stats['total_users']) ?></h3>
                        <p>Usuários Totais</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card text-center">
                    <div class="card-body">
                        <i class="bi bi-shop fs-1 text-success"></i>
                        <h3><?= number_format($stats['total_vendors']) ?></h3>
                        <p>Vendedores Ativos</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card text-center">
                    <div class="card-body">
                        <i class="bi bi-currency-bitcoin fs-1 text-warning"></i>
                        <h3><?= number_format($stats['total_btc_balance'], 6) ?></h3>
                        <p>BTC na Plataforma</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card text-center">
                    <div class="card-body">
                        <i class="bi bi-exclamation-triangle fs-1 text-danger"></i>
                        <h3><?= number_format($stats['pending_payments']) ?></h3>
                        <p>Pagamentos Pendentes</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Transações Recentes -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h4><i class="bi bi-clock-history"></i> Transações Recentes</h4>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-dark table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Usuário</th>
                                        <th>Tipo</th>
                                        <th>Valor</th>
                                        <th>Status</th>
                                        <th>Data</th>
                                        <th>Ações</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($recent_txs as $tx): ?>
                                        <tr>
                                            <td><?= htmlspecialchars($tx['id']) ?></td>
                                            <td><?= htmlspecialchars($tx['username']) ?></td>
                                            <td>
                                                <span class="badge <?= $tx['type'] === 'deposit' ? 'bg-success' : 'bg-danger' ?>">
                                                    <?= ucfirst($tx['type']) ?>
                                                </span>
                                            </td>
                                            <td><?= number_format($tx['amount'], 8) ?> <?= htmlspecialchars($tx['crypto_type']) ?></td>
                                            <td>
                                                <span class="badge <?= $tx['status'] === 'confirmed' ? 'bg-success' : 'bg-warning' ?>">
                                                    <?= ucfirst($tx['status']) ?>
                                                </span>
                                            </td>
                                            <td><?= date('d/m/Y H:i', strtotime($tx['created_at'])) ?></td>
                                            <td>
                                                <?php if ($tx['status'] === 'pending'): ?>
                                                    <form method="POST" style="display: inline;">
                                                        <input type="hidden" name="action" value="manual_confirm">
                                                        <input type="hidden" name="tx_id" value="<?= $tx['id'] ?>">
                                                        <button type="submit" class="btn btn-sm btn-success" 
                                                                onclick="return confirm('Confirmar transação?')">
                                                            Confirmar
                                                        </button>
                                                    </form>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Usuários Suspeitos -->
        <?php if (!empty($suspicious_users)): ?>
            <div class="row">
                <div class="col-12">
                    <div class="card border-warning">
                        <div class="card-header bg-warning text-dark">
                            <h4><i class="bi bi-shield-exclamation"></i> Usuários Suspeitos (24h)</h4>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-dark table-striped">
                                    <thead>
                                        <tr>
                                            <th>Usuário</th>
                                            <th>Email</th>
                                            <th>Transações</th>
                                            <th>Volume Total</th>
                                            <th>Ações</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($suspicious_users as $user): ?>
                                            <tr>
                                                <td><?= htmlspecialchars($user['name']) ?></td>
                                                <td><?= htmlspecialchars($user['email']) ?></td>
                                                <td><span class="badge bg-danger"><?= $user['tx_count'] ?></span></td>
                                                <td><?= number_format($user['total_amount'], 6) ?> BTC</td>
                                                <td>
                                                    <form method="POST" style="display: inline;">
                                                        <input type="hidden" name="action" value="block_user">
                                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                        <button type="submit" class="btn btn-sm btn-danger" 
                                                                onclick="return confirm('Bloquear usuário?')">
                                                            Bloquear
                                                        </button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Ferramentas de Sistema -->
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="bi bi-tools"></i> Ferramentas</h5>
                    </div>
                    <div class="card-body">
                        <div class="d-grid gap-2">
                            <a href="../api/blockchain_integration.php?test=1" class="btn btn-info" target="_blank">
                                <i class="bi bi-link"></i> Testar APIs Blockchain
                            </a>
                            <a href="../btc/process_deposit.php" class="btn btn-warning">
                                <i class="bi bi-currency-bitcoin"></i> Processar Depósitos
                            </a>
                            <a href="../verificar_pagos.php" class="btn btn-success">
                                <i class="bi bi-check-circle"></i> Verificar Pagamentos
                            </a>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="bi bi-graph-up"></i> Relatórios</h5>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-6">
                                <h6>Hoje</h6>
                                <p class="text-success"><?= $stats['recent_transactions'] ?> transações</p>
                            </div>
                            <div class="col-6">
                                <h6>Total</h6>
                                <p class="text-info"><?= number_format($stats['total_orders']) ?> pedidos</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="../assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh a cada 30 segundos
        setTimeout(() => location.reload(), 30000);
        
        // Mostrar notificação de modo real
        <?php if ($real_mode == '1'): ?>
            console.warn('🔴 MODO REAL ATIVO - Transações reais sendo processadas!');
        <?php endif; ?>
        
        console.log('✅ Admin Panel corrigido e funcional');
    </script>
</body>
</html>