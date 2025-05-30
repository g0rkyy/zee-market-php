<?php
require_once 'includes/config.php';
$id = (int)$_GET['id'];
$produto = $conn->query("SELECT * FROM produtos WHERE id=$id")->fetch_assoc();
?>

<div class="crypto-options">
    <h3>Pagamento com:</h3>
    <?php if (strpos($produto['aceita_cripto'], 'BTC') !== false): ?>
        <button class="btn btn-outline-warning crypto-btn" data-coin="BTC">
            Bitcoin - <?= $produto['preco_btc'] ?> BTC
        </button>
    <?php endif; ?>
    
    <?php if (strpos($produto['aceita_cripto'], 'ETH') !== false): ?>
        <button class="btn btn-outline-primary crypto-btn" data-coin="ETH">
            Ethereum - <?= $produto['preco_eth'] ?> ETH
        </button>
    <?php endif; ?>
</div>
<div class="crypto-price" 
     data-price="<?= $produto['preco'] ?>" 
     data-btc="<?= $produto['preco_btc'] ?>"
     data-eth="<?= $produto['preco_eth'] ?>">
     Preço: R$ <?= $produto['preco'] ?> 
     (≈ <?= $produto['preco_btc'] ?> BTC)
</div>

<script src="crypto_converter.js"></script>