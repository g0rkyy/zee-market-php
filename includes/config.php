<?php
$host = "localhost";
$user = "root";
$pass = ""; 
$db = "zee_market"; // Verifique se este é o nome correto do banco

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error);
}
$blockchainConfig = [
    'api_key' => 'SUA_CHAVE_DE_API_AQUI', // Obtenha em blockchain.com/api
    'xpub' => 'SEU_XPUB_AQUI', // Sua Extended Public Key
    'secret' => hash('sha256', uniqid('zee_market_', true)), // Gera um segredo forte
    'callback_url' => 'https://' . $_SERVER['HTTP_HOST'] . '/btc/webhook.php',
    'min_confirmations' => 3 // Número de confirmações necessárias
];
?> 