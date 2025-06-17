<?php
session_start();
require_once '../includes/config.php';

// Verifica autenticação
if (!isset($_SESSION['vendedor_id'])) {
    header("Location: ../vendedores.php");
    exit();
}

// Busca compras associadas ao vendedor
$vendedor_id = $_SESSION['vendedor_id'];
$stmt = $conn->prepare("SELECT c.id, c.nome, c.endereco, c.btc_wallet, p.nome AS produto_nome 
                        FROM compras c 
                        JOIN produtos p ON c.produto_id = p.id 
                        WHERE c.vendedor_id = ?");
$stmt->bind_param("i", $vendedor_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Painel do Vendedor</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h2>Painel do Vendedor</h2>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>Produto</th>
                    <th>Nome do Comprador</th>
                    <th>Endereço</th>
                    <th>Carteira Bitcoin</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($compra = $result->fetch_assoc()): ?>
                    <tr>
                        <td><?= htmlspecialchars($compra['produto_nome']) ?></td>
                        <td><?= htmlspecialchars($compra['nome']) ?></td>
                        <td><?= htmlspecialchars($compra['endereco']) ?></td>
                        <td><?= htmlspecialchars($compra['btc_wallet']) ?></td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>