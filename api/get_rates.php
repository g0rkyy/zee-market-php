<?php
header('Content-Type: application/json');

// Simula delay de API real
sleep(1); 

// Dados fictícios (não conecta a APIs reais)
$fake_rates = [
    'BTC' => rand(45000, 50000),
    'ETH' => rand(2500, 3000),
    'XMR' => rand(150, 200)
];

// Adiciona variação diária fictícia
foreach ($fake_rates as &$rate) {
    $rate += rand(-500, 500);
}

echo json_encode([
    'success' => true,
    'rates' => $fake_rates,
    'timestamp' => time()
]);
?>