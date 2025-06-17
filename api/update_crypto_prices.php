<?php
// Atualiza preços dos produtos automaticamente
require_once '../includes/config.php';

function updateCryptoPrices() {
    $rates = getCryptoRates();
    
    $stmt = $conn->prepare("UPDATE produtos SET 
        preco_btc = preco / ?,
        preco_eth = preco / ?
        WHERE preco > 0");
    $stmt->bind_param("dd", $rates['bitcoin']['usd'], $rates['ethereum']['usd']);
    $stmt->execute();
}

updateCryptoPrices();
?>