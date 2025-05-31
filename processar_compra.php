<?php
require_once 'includes/config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $produto_id = (int)$_POST['produto_id'];
    $nome = trim($_POST['nome']);
    $endereco = trim($_POST['endereco']);
    $btc_wallet = trim($_POST['btc_wallet']);

    // Busca o produto e vendedor
    $stmt = $conn->prepare("SELECT p.*, v.id as vendedor_id 
                           FROM produtos p 
                           JOIN vendedores v ON p.vendedor_id = v.id 
                           WHERE p.id = ?");
    $stmt->bind_param("i", $produto_id);
    $stmt->execute();
    $produto = $stmt->get_result()->fetch_assoc();

    if (!$produto) die("Produto não encontrado!");

    // Configuração da taxa (3% para Wasabi)
    $wasabi_wallet = "bc1qaecjks06lyrfqzqm8dhn5c98ltd9zmlstg36f2"; // SEU ENDEREÇO
    $taxa_plataforma = $produto['preco_btc'] * 0.03;
    $valor_vendedor = $produto['preco_btc'] - $taxa_plataforma;

    // Insere a compra no banco
    $stmt = $conn->prepare("INSERT INTO compras 
                          (produto_id, vendedor_id, nome, endereco, btc_wallet, 
                           valor_btc, taxa_plataforma, wallet_plataforma) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("iisssdds", 
                     $produto_id, 
                     $produto['vendedor_id'], 
                     $nome, 
                     $endereco, 
                     $btc_wallet,
                     $produto['preco_btc'],
                     $taxa_plataforma,
                     $wasabi_wallet);

    if ($stmt->execute()) {
        header("Location: pagamento_btc.php?id=" . $conn->insert_id);
        exit();
    } else {
        die("Erro ao processar compra: " . $conn->error);
    }
}
?>