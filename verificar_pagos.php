<?php
require_once 'includes/config.php';

// Simulação: marca compras antigas como pagas (para testes locais)
$conn->query("UPDATE compras SET pago = 1 
              WHERE pago = 0 AND data_compra < NOW() - INTERVAL 1 HOUR");

// Para produção real, substitua pelo código de verificação da blockchain
// usando API como BlockCypher ou Blockstream
?>

<!-- Interface simples para testes -->
<!DOCTYPE html>
<html>
<head>
    <title>Verificar Pagamentos</title>
</head>
<body>
    <h1>Compras pendentes:</h1>
    <?php
    $pendentes = $conn->query("SELECT * FROM compras WHERE pago = 0");
    while ($compra = $pendentes->fetch_assoc()): ?>
        <div style="border:1px solid #ccc; padding:10px; margin:10px;">
            <h3>Compra #<?= $compra['id'] ?></h3>
            <p>Valor: <?= $compra['valor_btc'] ?> BTC</p>
            <p>Carteira: <?= $compra['btc_wallet'] ?></p>
            <form method="post">
                <input type="hidden" name="id" value="<?= $compra['id'] ?>">
                <button type="submit" name="marcar_pago">Simular Pagamento</button>
            </form>
        </div>
    <?php endwhile;

    if (isset($_POST['marcar_pago'])) {
        $id = (int)$_POST['id'];
        $conn->query("UPDATE compras SET pago = 1 WHERE id = $id");
        header("Refresh:0");
    }
    ?>
</body>
</html>