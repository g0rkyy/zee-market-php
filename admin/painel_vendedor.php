<?php
session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Verificação de autenticação
if (!isset($_SESSION['vendedor_id']) || empty($_SESSION['vendedor_id'])) {
    header("Location: ../vendedores.php?erro=Acesso negado");
    exit();
}

// Busca dados do vendedor
$vendedor = $conn->query("SELECT id, nome, email, btc_wallet FROM vendedores WHERE id = ".$_SESSION['vendedor_id'])->fetch_assoc();

if (!$vendedor) {
    header("Location: ../vendedores.php?erro=Vendedor não encontrado");
    exit();
}

// Busca produtos do vendedor
$produtos = $conn->query("SELECT * FROM produtos WHERE vendedor_id = ".$_SESSION['vendedor_id']." ORDER BY data_cadastro DESC");

// Busca pedidos com status de pagamento
$pedidos = $conn->query("SELECT 
    c.id, c.nome, c.endereco, c.btc_wallet_vendedor, c.valor_btc, 
    c.tx_hash, c.pago, c.concluido, c.data_compra,
    p.nome AS produto_nome
    FROM compras c
    JOIN produtos p ON c.produto_id = p.id
    WHERE c.vendedor_id = ".$_SESSION['vendedor_id']."
    ORDER BY c.data_compra DESC");

// Atualização de status
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['pedido_id'])) {
        $pedido_id = (int)$_POST['pedido_id'];
        $concluido = isset($_POST['concluido']) ? 1 : 0;
        $conn->query("UPDATE compras SET concluido = $concluido WHERE id = $pedido_id");
        
        // Mantém a aba pedidos ativa após atualização
        $_SESSION['active_tab'] = 'pedidos';
        header("Location: painel_vendedor.php?tab=pedidos");
        exit();
    }
    
    // Atualização da carteira BTC
    if (isset($_POST['btc_wallet'])) {
        $nova_carteira = $conn->real_escape_string(trim($_POST['btc_wallet']));
        if (!empty($nova_carteira)) {
            $conn->query("UPDATE vendedores SET btc_wallet = '$nova_carteira' WHERE id = ".$_SESSION['vendedor_id']);
            $vendedor['btc_wallet'] = $nova_carteira;
            $_SESSION['mensagem_sucesso'] = "Carteira BTC atualizada com sucesso!";
        }
    }
}

$active_tab = isset($_GET['tab']) && in_array($_GET['tab'], ['produtos', 'pedidos']) ? $_GET['tab'] : 'produtos';
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
        }
        
        .vendor-panel {
            background-color: #f8f9fa;
            min-height: 100vh;
        }
        
        .vendor-header {
            background: linear-gradient(135deg, var(--primary-color), #4b2e83);
            color: white;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        
        .product-card {
            transition: all 0.3s;
            height: 100%;
        }
        
        .product-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .order-row {
            transition: all 0.3s;
        }
        
        .order-row:hover {
            background-color: #f8f9fa;
        }
        
        .status-badge {
            font-size: 0.85rem;
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: 500;
        }
        
        .status-pending {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .status-paid {
            background-color: #d4edda;
            color: #155724;
        }
        
        .badge-bitcoin {
            background-color: var(--secondary-color);
            color: #212529;
        }
    </style>
</head>
<body class="vendor-panel">
    <div class="container py-4">
        <!-- Cabeçalho -->
        <div class="vendor-header p-4 mb-4">
            <div class="d-flex flex-column flex-md-row justify-content-between align-items-center">
                <div class="text-center text-md-start mb-3 mb-md-0">
                    <h2 class="mb-1"><i class="bi bi-person-badge"></i> Painel do Vendedor</h2>
                    <p class="mb-0">Bem-vindo, <strong><?= htmlspecialchars($vendedor['nome']) ?></strong></p>
                </div>
                <div class="d-flex flex-wrap justify-content-center gap-2">
                    <a href="../index.php" class="btn btn-light btn-sm">
                        <i class="bi bi-house"></i> Home
                    </a>
                    <button class="btn btn-info btn-sm" data-bs-toggle="modal" data-bs-target="#walletModal">
                        <i class="bi bi-wallet2"></i> Carteira BTC
                    </button>
                    <a href="cadastrar_produto.php" class="btn btn-primary btn-sm">
                        <i class="bi bi-plus-circle"></i> Novo Produto
                    </a>
                    <a href="../logout.php" class="btn btn-danger btn-sm">
                        <i class="bi bi-box-arrow-right"></i> Sair
                    </a>
                </div>
            </div>
        </div>

        <!-- Exibir mensagem de sucesso -->
        <?php if (isset($_SESSION['mensagem_sucesso'])): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle-fill"></i> <?= $_SESSION['mensagem_sucesso'] ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
            <?php unset($_SESSION['mensagem_sucesso']); ?>
        <?php endif; ?>

        <!-- Abas -->
        <ul class="nav nav-tabs mb-4" id="vendorTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link <?= $active_tab === 'produtos' ? 'active' : '' ?>" 
                        id="products-tab" data-bs-toggle="tab" data-bs-target="#products" 
                        type="button" role="tab">
                    <i class="bi bi-box-seam"></i> Meus Produtos
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link <?= $active_tab === 'pedidos' ? 'active' : '' ?>" 
                        id="orders-tab" data-bs-toggle="tab" data-bs-target="#orders" 
                        type="button" role="tab">
                    <i class="bi bi-receipt"></i> Pedidos
                    <span class="badge bg-secondary ms-1"><?= $pedidos->num_rows ?></span>
                </button>
            </li>
        </ul>

        <!-- Conteúdo das Abas -->
        <div class="tab-content" id="vendorTabContent">
            <!-- Aba Produtos -->
            <div class="tab-pane fade <?= $active_tab === 'produtos' ? 'show active' : '' ?>" 
                 id="products" role="tabpanel">
                <?php if ($produtos->num_rows === 0): ?>
                    <div class="alert alert-info">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-info-circle-fill me-2"></i>
                            <div>
                                <p class="mb-0">Você ainda não tem produtos cadastrados.</p>
                                <a href="cadastrar_produto.php" class="btn btn-sm btn-primary mt-2">
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
                                         alt="<?= htmlspecialchars($produto['nome']) ?>"
                                         style="height: 200px; object-fit: cover;">
                                    <div class="card-body">
                                        <h5 class="card-title"><?= htmlspecialchars($produto['nome']) ?></h5>
                                        <p class="card-text">
                                            <?= nl2br(htmlspecialchars(substr($produto['descricao'] ?? 'Sem descrição', 0, 100))) ?>
                                            <?= strlen($produto['descricao'] ?? '') > 100 ? '...' : '' ?>
                                        </p>
                                    </div>
                                    <div class="card-footer bg-white">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <span class="h5 text-success">R$ <?= number_format($produto['preco'], 2, ',', '.') ?></span>
                                            <span class="badge bg-primary">Estoque: <?= isset($produto['estoque']) ? $produto['estoque'] : 0 ?></span>
                                        </div>
                                        <div class="d-grid gap-2 mt-3">
                                            <a href="editar_produto.php?id=<?= $produto['id'] ?>" class="btn btn-outline-primary btn-sm">
                                                <i class="bi bi-pencil"></i> Editar
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endwhile; ?>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Aba Pedidos -->
            <div class="tab-pane fade <?= $active_tab === 'pedidos' ? 'show active' : '' ?>" 
                 id="orders" role="tabpanel">
                <?php if ($pedidos->num_rows === 0): ?>
                    <div class="alert alert-info">
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
                                    <th>Pedido #</th>
                                    <th>Produto</th>
                                    <th>Valor (BTC)</th>
                                    <th>Status Pagamento</th>
                                    <th>Entrega</th>
                                    <th>Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($pedido = $pedidos->fetch_assoc()): ?>
                                    <tr class="order-row">
                                        <td>#<?= $pedido['id'] ?></td>
                                        <td><?= htmlspecialchars($pedido['produto_nome']) ?></td>
                                        <td><?= number_format($pedido['valor_btc'], 8) ?></td>
                                        <td>
                                            <?php if ($pedido['pago']): ?>
                                                <span class="status-badge status-paid">
                                                    <i class="bi bi-check-circle-fill"></i> Pago
                                                    <?php if ($pedido['tx_hash']): ?>
                                                        <a href="https://blockchain.com/btc/tx/<?= $pedido['tx_hash'] ?>" 
                                                           target="_blank" class="ms-1" title="Ver transação">
                                                            <i class="bi bi-link-45deg"></i>
                                                        </a>
                                                    <?php endif; ?>
                                                </span>
                                            <?php else: ?>
                                                <span class="status-badge status-pending">
                                                    <i class="bi bi-clock-history"></i> Pendente
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <form method="POST" class="d-flex align-items-center">
                                                <input type="hidden" name="pedido_id" value="<?= $pedido['id'] ?>">
                                                <div class="form-check form-switch">
                                                    <input class="form-check-input" type="checkbox" 
                                                           name="concluido" value="1" 
                                                           <?= $pedido['concluido'] ? 'checked' : '' ?>
                                                           onchange="this.form.submit()">
                                                    <label class="form-check-label">
                                                        <?= $pedido['concluido'] ? 'Entregue' : 'Pendente' ?>
                                                    </label>
                                                </div>
                                            </form>
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#orderModal<?= $pedido['id'] ?>">
                                                <i class="bi bi-eye"></i> Detalhes
                                            </button>
                                        </td>
                                    </tr>

                                    <!-- Modal de Detalhes -->
                                    <div class="modal fade" id="orderModal<?= $pedido['id'] ?>" tabindex="-1">
                                        <div class="modal-dialog modal-lg">
                                            <div class="modal-content">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Pedido #<?= $pedido['id'] ?></h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="row">
                                                        <div class="col-md-6">
                                                            <h6><i class="bi bi-person"></i> Informações do Comprador</h6>
                                                            <ul class="list-group list-group-flush mb-3">
                                                                <li class="list-group-item">
                                                                    <strong>Nome:</strong> <?= htmlspecialchars($pedido['nome']) ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Endereço:</strong> <?= htmlspecialchars($pedido['endereco']) ?>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                        <div class="col-md-6">
                                                            <h6><i class="bi bi-box-seam"></i> Informações do Pedido</h6>
                                                            <ul class="list-group list-group-flush">
                                                                <li class="list-group-item">
                                                                    <strong>Produto:</strong> <?= htmlspecialchars($pedido['produto_nome']) ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Valor:</strong> <?= number_format($pedido['valor_btc'], 8) ?> BTC
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Status Pagamento:</strong>
                                                                    <?php if ($pedido['pago']): ?>
                                                                        <span class="badge bg-success">Pago</span>
                                                                        <?php if ($pedido['tx_hash']): ?>
                                                                            <a href="https://blockchain.com/btc/tx/<?= $pedido['tx_hash'] ?>" 
                                                                               target="_blank" class="ms-2">
                                                                                <i class="bi bi-link-45deg"></i> Ver transação
                                                                            </a>
                                                                        <?php endif; ?>
                                                                    <?php else: ?>
                                                                        <span class="badge bg-warning text-dark">Aguardando pagamento</span>
                                                                    <?php endif; ?>
                                                                </li>
                                                                <li class="list-group-item">
                                                                    <strong>Status Entrega:</strong>
                                                                    <span class="badge <?= $pedido['concluido'] ? 'bg-success' : 'bg-secondary' ?>">
                                                                        <?= $pedido['concluido'] ? 'Entregue' : 'Pendente' ?>
                                                                    </span>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
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

    <!-- Modal Carteira BTC -->
    <div class="modal fade" id="walletModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-wallet2"></i> Carteira Bitcoin</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="btc_wallet" class="form-label">Seu endereço Bitcoin:</label>
                            <input type="text" class="form-control" id="btc_wallet" name="btc_wallet" 
                                   value="<?= htmlspecialchars($vendedor['btc_wallet']) ?>" required>
                        </div>
                        <p class="text-muted">Este é o endereço onde você receberá os pagamentos em Bitcoin.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" class="btn btn-primary">Salvar Alterações</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Ativa tooltips
        document.addEventListener('DOMContentLoaded', function() {
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        });
    </script>
</body>
</html>