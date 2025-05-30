<?php
require_once 'includes/config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $produto_id = (int)$_POST['produto_id'];
    $nome = trim($_POST['nome']);
    $endereco = trim($_POST['endereco']);
    $btc_wallet = trim($_POST['btc_wallet']);

    // Busca o vendedor associado ao produto
    $stmt = $conn->prepare("SELECT vendedor_id FROM produtos WHERE id = ?");
    $stmt->bind_param("i", $produto_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $produto = $result->fetch_assoc();
    $vendedor_id = $produto['vendedor_id'];

    // Validações básicas
    if (empty($nome) || empty($endereco) || empty($btc_wallet)) {
        die("Preencha todos os campos!");
    }

    // Salvar a compra no banco de dados
    $stmt = $conn->prepare("INSERT INTO compras (produto_id, vendedor_id, nome, endereco, btc_wallet) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("iisss", $produto_id, $vendedor_id, $nome, $endereco, $btc_wallet);

    if ($stmt->execute()) {
        echo "Compra realizada com sucesso!";
        // Redirecionar para uma página de confirmação (opcional)
        // header("Location: confirmacao.php");
        // exit();
    } else {
        echo "Erro ao processar a compra.";
    }
}
?>