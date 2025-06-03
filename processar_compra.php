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

    // ========== CONFIGURAÇÃO DE TAXAS ========== //
    
    // Taxa da plataforma (2.5% ao invés de 3%)
    $taxa_percentual = 0.025; // 2.5%
    $platform_wallet = "bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m"; // SEU ENDEREÇO
    
    // Cálculos
    $valor_total_btc = $produto['preco_btc'];
    $taxa_plataforma = $valor_total_btc * $taxa_percentual;
    $valor_vendedor = $valor_total_btc - $taxa_plataforma;
    
    // Validação mínima
    if ($valor_vendedor <= 0) {
        die("Erro: valor do produto muito baixo para cobrir taxas!");
    }

    // ========== INSERIR COMPRA NO BANCO ========== //
    
    $stmt = $conn->prepare("INSERT INTO compras 
                          (produto_id, vendedor_id, nome, endereco, btc_wallet_comprador, 
                           valor_btc, taxa_plataforma, wallet_plataforma) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("iisssdds", 
                     $produto_id, 
                     $produto['vendedor_id'], 
                     $nome, 
                     $endereco, 
                     $btc_wallet,
                     $valor_total_btc,      // Valor total que o cliente paga
                     $taxa_plataforma,      // Taxa da plataforma (2.5%)
                     $platform_wallet       // Sua carteira
                    );

    if ($stmt->execute()) {
        $compra_id = $conn->insert_id;
        
        // Log da transação
        error_log("Nova compra #$compra_id - Total: $valor_total_btc BTC - Taxa: $taxa_plataforma BTC - Vendedor: $valor_vendedor BTC");
        
        // Redirecionar para pagamento
        header("Location: pagamento_btc.php?id=" . $compra_id);
        exit();
    } else {
        die("Erro ao processar compra: " . $conn->error);
    }
}
?>