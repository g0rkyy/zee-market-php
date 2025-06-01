<?php
require_once 'includes/config.php';

// Função para verificar status individual (usada pelo AJAX)
if (isset($_GET['id'])) {
    $compra_id = (int)$_GET['id'];
    $compra = $conn->query("SELECT pago, tx_hash FROM compras WHERE id = $compra_id")->fetch_assoc();
    
    header('Content-Type: application/json');
    echo json_encode([
        'pago' => (bool)$compra['pago'],
        'tx_hash' => $compra['tx_hash'] ?? null
    ]);
    exit();
}

// Modo simulação (apenas para desenvolvimento)
if (isset($_POST['marcar_pago'])) {
    $id = (int)$_POST['id'];
    $conn->query("UPDATE compras SET pago = 1 WHERE id = $id");
    header("Refresh:0");
    exit();
}

// Simulação automática para testes
$conn->query("UPDATE compras SET pago = 1 
              WHERE pago = 0 AND data_compra < NOW() - INTERVAL 1 HOUR");
?>

<!DOCTYPE html>
<html>
<head>
    <title>Verificar Pagamentos</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <style>
        .compra-card {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .compra-id {
            font-size: 1.2rem;
            color: #2c3e50;
        }
        .wallet-address {
            font-family: monospace;
            background: #f8f9fa;
            padding: 5px;
            border-radius: 3px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <h1 class="mb-4">Verificação de Pagamentos</h1>
        
        <div class="alert alert-info mb-4">
            <h5><i class="fas fa-info-circle"></i> Modo Simulação</h5>
            <p class="mb-0">Em produção, integre com API blockchain como BlockCypher ou Blockstream</p>
        </div>

        <h2>Compras pendentes:</h2>
        <?php
        $pendentes = $conn->query("SELECT * FROM compras WHERE pago = 0 ORDER BY data_compra DESC");
        while ($compra = $pendentes->fetch_assoc()): ?>
            <div class="compra-card">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h3 class="compra-id">Compra #<?= $compra['id'] ?></h3>
                        <p><strong>Valor:</strong> <?= number_format($compra['valor_btc'], 8) ?> BTC</p>
                        <p><strong>Carteira:</strong> <span class="wallet-address"><?= htmlspecialchars($compra['btc_wallet_vendedor']) ?></span></p>
                        <p><strong>Data:</strong> <?= date('d/m/Y H:i', strtotime($compra['data_compra'])) ?></p>
                    </div>
                    <form method="post">
                        <input type="hidden" name="id" value="<?= $compra['id'] ?>">
                        <button type="submit" name="marcar_pago" class="btn btn-success">
                            <i class="fas fa-check"></i> Marcar como Pago
                        </button>
                    </form>
                </div>
            </div>
        <?php endwhile; ?>

        <?php if ($pendentes->num_rows === 0): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> Nenhuma compra pendente!
            </div>
        <?php endif; ?>
    </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
</body>
</html>