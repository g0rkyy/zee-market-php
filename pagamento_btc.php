<?php
require_once 'includes/config.php';
$compra_id = (int)$_GET['id'];
$compra = $conn->query("SELECT c.*, p.nome as produto_nome 
                        FROM compras c
                        JOIN produtos p ON c.produto_id = p.id
                        WHERE c.id = $compra_id")->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Pagamento com Bitcoin</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <style>
        .qr-code { width: 200px; height: 200px; margin: 20px auto; }
        .crypto-details { background: #f8f9fa; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="card">
            <div class="card-header bg-warning">
                <h3 class="text-center">Pagamento - <?= htmlspecialchars($compra['produto_nome']) ?></h3>
            </div>
            <div class="card-body">
                <div class="crypto-details">
                    <h4>Total a pagar: <strong><?= number_format($compra['valor_btc'], 8) ?> BTC</strong></h4>
                    <p class="text-muted">(Taxa de 3% incluída: <?= number_format($compra['taxa_plataforma'], 8) ?> BTC)</p>
                    
                    <div class="text-center mt-3">
                        <div class="qr-code">
                            <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=bitcoin:<?= $compra['btc_wallet'] ?>?amount=<?= $compra['valor_btc'] ?>" 
                                 alt="QR Code para pagamento">
                        </div>
                        <p class="mt-2">Envie para:<br>
                        <code><?= htmlspecialchars($compra['btc_wallet']) ?></code></p>
                    </div>
                </div>

                <div class="alert alert-info mt-3">
                    <h5>Instruções:</h5>
                    <ol>
                        <li>Abra sua carteira Bitcoin (Wasabi, Electrum, etc.)</li>
                        <li>Digitalize o QR code ou copie o endereço manualmente</li>
                        <li>Envie <strong>exatamente <?= number_format($compra['valor_btc'], 8) ?> BTC</strong></li>
                        <li>A confirmação pode levar até 30 minutos</li>
                    </ol>
                </div>

                <div class="d-grid gap-2 mt