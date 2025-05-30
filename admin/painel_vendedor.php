<?php
session_start();
require_once '../includes/config.php'; // Já contém $conn MySQLi
require_once '../includes/functions.php';

// Verifica autenticação
if (!isset($_SESSION['vendedor_id'])) {
    header("Location: ../vendedores.php");
    exit();
}

// Busca dados do vendedor
$stmt = $conn->prepare("SELECT * FROM vendedores WHERE id = ?");
$stmt->bind_param("i", $_SESSION['vendedor_id']);
$stmt->execute();
$result = $stmt->get_result();
$vendedor = $result->fetch_assoc();

// Busca produtos do vendedor
$produtos = $conn->prepare("SELECT * FROM produtos WHERE vendedor_id = ?");
$produtos->bind_param("i", $_SESSION['vendedor_id']);
$produtos->execute();
$produtos_result = $produtos->get_result();

// Busca pedidos associados ao vendedor
$pedidos = $conn->prepare("SELECT c.id, c.nome, c.endereco, c.btc_wallet, p.nome AS produto_nome, c.concluido 
                           FROM compras c 
                           JOIN produtos p ON c.produto_id = p.id 
                           WHERE c.vendedor_id = ?");
$pedidos->bind_param("i", $_SESSION['vendedor_id']);
$pedidos->execute();
$pedidos_result = $pedidos->get_result();

// Atualiza o status do pedido
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pedido_id'])) {
    $pedido_id = (int)$_POST['pedido_id'];
    $concluido = isset($_POST['concluido']) ? 1 : 0;

    $update_stmt = $conn->prepare("UPDATE compras SET concluido = ? WHERE id = ?");
    $update_stmt->bind_param("ii", $concluido, $pedido_id);
    $update_stmt->execute();
    header("Location: painel_vendedor.php?tab=pedidos");
    exit();
}

// Define a aba ativa com base no parâmetro da URL
$active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'produtos';
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Painel do Vendedor - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <style>
        .card-img-top {
            height: 200px;
            object-fit: cover;
        }
        .nav-tabs .nav-link.active {
            background-color: #007bff;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1>Olá, <?= htmlspecialchars($vendedor['nome']) ?>!</h1>
            <a href="../index.php">Home</a>
            <div>
                <a href="cadastrar_produto.php" class="btn btn-primary">
                    <i class="bi bi-plus-circle"></i> Novo Produto
                </a>
                <a href="../logout.php" class="btn btn-danger">
                    <i class="bi bi-box-arrow-right"></i> Sair
                </a>
            </div>
        </div>

        <!-- Abas -->
        <ul class="nav nav-tabs mb-4">
            <li class="nav-item">
                <a class="nav-link <?= $active_tab === 'produtos' ? 'active' : '' ?>" href="?tab=produtos">Seus Produtos</a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?= $active_tab === 'pedidos' ? 'active' : '' ?>" href="?tab=pedidos">Pedidos</a>
            </li>
        </ul>

        <div class="tab-content">
            <!-- Aba Produtos -->
            <div class="tab-pane fade <?= $active_tab === 'produtos' ? 'show active' : '' ?>" id="produtos">
                <?php if ($produtos_result->num_rows === 0): ?>
                    <div class="alert alert-info">
                        Você ainda não tem produtos cadastrados. <a href="cadastrar_produto.php">Clique aqui</a> para adicionar.
                    </div>
                <?php else: ?>
                    <h2 class="mb-3">Seus Produtos</h2>
                    <div class="row">
                        <?php while ($produto = $produtos_result->fetch_assoc()): ?>
                            <div class="col-md-4 mb-4">
                                <div class="card h-100">
                                    <img src="../assets/uploads/<?= htmlspecialchars($produto['imagem'] ?? 'placeholder.jpg') ?>" 
                                         class="card-img-top" 
                                         alt="<?= htmlspecialchars($produto['nome']) ?>">
                                    <div class="card-body d-flex flex-column">
                                        <h5 class="card-title"><?= htmlspecialchars($produto['nome']) ?></h5>
                                        <p class="card-text flex-grow-1">
                                            <?= nl2br(htmlspecialchars($produto['descricao'] ?? 'Sem descrição')) ?>
                                        </p>
                                        <p class="fw-bold">R$ <?= number_format($produto['preco'], 2, ',', '.') ?></p>
                                        <div class="d-grid gap-2">
                                            <a href="editar_produto.php?id=<?= $produto['id'] ?>" class="btn btn-warning">
                                                <i class="bi bi-pencil-square"></i> Editar
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
            <div class="tab-pane fade <?= $active_tab === 'pedidos' ? 'show active' : '' ?>" id="pedidos">
                <?php if ($pedidos_result->num_rows === 0): ?>
                    <div class="alert alert-info">
                        Você ainda não tem pedidos associados aos seus produtos.
                    </div>
                <?php else: ?>
                    <h2 class="mb-3">Pedidos</h2>
                    <table class="table table-bordered">
                        <thead>
                            <tr>
                                <th>Produto</th>
                                <th>Nome do Comprador</th>
                                <th>Endereço</th>
                                <th>Carteira Bitcoin</th>
                                <th>Concluído</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($pedido = $pedidos_result->fetch_assoc()): ?>
                                <tr>
                                    <td><?= htmlspecialchars($pedido['produto_nome']) ?></td>
                                    <td><?= htmlspecialchars($pedido['nome']) ?></td>
                                    <td><?= htmlspecialchars($pedido['endereco']) ?></td>
                                    <td><?= htmlspecialchars($pedido['btc_wallet']) ?></td>
                                    <td>
                                        <form method="POST" action="">
                                            <input type="hidden" name="pedido_id" value="<?= $pedido['id'] ?>">
                                            <input type="checkbox" name="concluido" value="1" <?= $pedido['concluido'] ? 'checked' : '' ?> onchange="this.form.submit()">
                                        </form>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>