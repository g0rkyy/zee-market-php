<?php
require_once 'includes/config.php';
$id = (int)$_GET['id'];
$produto = $conn->query("SELECT * FROM produtos WHERE id=$id")->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Comprar Produto</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .container {
            max-width: 800px;
            margin-top: 50px;
        }
        .product-image {
            max-height: 300px;
            object-fit: cover;
            border-radius: 10px;
        }
        .crypto-options button {
            margin-right: 10px;
        }
        .crypto-price {
            font-size: 1.2rem;
            font-weight: bold;
            margin-top: 20px;
        }
        .purchase-form {
            margin-top: 30px;
            padding: 20px;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            background-color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header bg-warning text-white">
                <h2 class="text-center"><?= htmlspecialchars($produto['nome']) ?></h2>
            </div>
            <div class="card-body">
                <div class="text-center mb-4">
                    <img src="assets/uploads/<?= htmlspecialchars($produto['imagem']) ?>" 
                         alt="<?= htmlspecialchars($produto['nome']) ?>" 
                         class="product-image img-fluid">
                </div>
                <p class="text-muted"><?= nl2br(htmlspecialchars($produto['descricao'])) ?></p>
                <div class="crypto-options">
                    <h3>Pagamento com:</h3>
                    <?php if (strpos($produto['aceita_cripto'], 'BTC') !== false): ?>
                        <button class="btn btn-outline-warning crypto-btn" data-coin="BTC">
                            Bitcoin - <?= $produto['preco_btc'] ?> BTC
                        </button>
                    <?php endif; ?>
                </div>
                <div class="crypto-price text-center mt-4">
                    Preço: R$ <?= number_format($produto['preco'], 2, ',', '.') ?> 
                    (≈ <?= $produto['preco_btc'] ?> BTC)
                </div>
            </div>
        </div>

        <!-- Formulário de Compra -->
        <div class="purchase-form">
            <h3 class="text-center">Finalizar Compra</h3>
            <form method="POST" action="processar_compra.php">
                <input type="hidden" name="produto_id" value="<?= $produto['id'] ?>">
                <div class="mb-3">
                    <label for="nome" class="form-label">Nome Completo</label>
                    <input type="text" id="nome" name="nome" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="endereco" class="form-label">Endereço de Entrega</label>
                    <textarea id="endereco" name="endereco" class="form-control" rows="3" required></textarea>
                </div>
                <div class="mb-3">
                    <label for="btc_wallet" class="form-label">Carteira Bitcoin</label>
                    <input type="text" id="btc_wallet" name="btc_wallet" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-warning w-100">Comprar com Bitcoin</button>
            </form>
        </div>
    </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
</body>
</html>