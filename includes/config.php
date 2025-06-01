<?php
// Configurações do Banco de Dados
$host = "localhost";
$user = "root";
$pass = ""; 
$db = "zee_market";

// Conexão com MySQL
$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    error_log("Erro de conexão MySQL: " . $conn->connect_error);
    die("Falha na conexão com o banco de dados");
}

// Configuração de charset
$conn->set_charset("utf8mb4");

// Configurações Bitcoin
$blockchainConfig = [
    // BlockCypher API - Gratuita até 3 requests/segundo
    'blockcypher' => [
        'api_key' => 'YOUR_BLOCKCYPHER_API_KEY', // Opcional para rate limit maior
        'base_url' => 'https://api.blockcypher.com/v1/btc/main',
        'webhook_url' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/btc/webhook.php'
    ],
    
    // Blockstream API - Gratuita
    'blockstream' => [
        'base_url' => 'https://blockstream.info/api'
    ],
    
    // Configurações gerais
    'min_confirmations' => 1, // Mínimo de confirmações para considerar válido
    'dust_limit' => 0.00000546, // Limite mínimo de transação (546 satoshis)
    'fee_rate' => 10, // Taxa de rede em sat/byte
    'network' => 'mainnet', // mainnet ou testnet
    
    // Segurança
    'webhook_secret' => hash('sha256', 'zee_market_webhook_' . time()),
    'encryption_key' => hash('sha256', 'zee_market_encrypt_' . time())
];

// Configurações de Sessão Segura
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
ini_set('session.use_strict_mode', 1);

// Timezone
date_default_timezone_set('America/Sao_Paulo');

// Configurações de Log
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Função para criar diretório de logs se não existir
if (!file_exists(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0750, true);
}

// Constantes globais
define('SITE_URL', 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'));
define('BTC_PRECISION', 8);
define('SATOSHI_TO_BTC', 100000000);

// Função para converter satoshis para BTC
function satoshiToBtc($satoshis) {
    return number_format($satoshis / SATOSHI_TO_BTC, BTC_PRECISION, '.', '');
}

// Função para converter BTC para satoshis
function btcToSatoshi($btc) {
    return (int)($btc * SATOSHI_TO_BTC);
}

// Headers de segurança
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
?>