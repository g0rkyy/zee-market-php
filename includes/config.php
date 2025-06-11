<?php
// Configurações de Sessão Segura (DEVE vir ANTES do session_start())
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    
    // Configurações de sessão adicionais para segurança
    ini_set('session.entropy_length', 32);
    ini_set('session.hash_function', 'sha256');
    ini_set('session.cookie_lifetime', 0); // Expira quando o navegador fechar
    ini_set('session.gc_maxlifetime', 3600); // 1 hora
}

// Timezone (definir antes de qualquer operação de data)
date_default_timezone_set('America/Sao_Paulo');

// Configurações de Log
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Função para criar diretório de logs se não existir
if (!file_exists(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0750, true);
}
require_once __DIR__ . '/../vendor/autoload.php';

// Configurações do Banco de Dados
$host = "localhost";
$user = "root";
$pass = "123456"; 
$db = "zee_market";

// Conexão com MySQL
try {
    $conn = new mysqli($host, $user, $pass, $db);
    
    if ($conn->connect_error) {
        error_log("Erro de conexão MySQL: " . $conn->connect_error);
        throw new Exception("Falha na conexão com o banco de dados");
    }
    
    // Configuração de charset
    $conn->set_charset("utf8mb4");
    
    // Verificar se a conexão está funcionando
    $conn->query("SELECT 1");
    
} catch (Exception $e) {
    error_log("Erro crítico de banco: " . $e->getMessage());
    die("Sistema temporariamente indisponível. Tente novamente em alguns minutos.");
}

    // =============================================
// CONFIGURAÇÕES GERAIS DO SITE
// =============================================
define('SITE_NAME', 'Zee-Market');
define('SITE_URL', 'http://localhost'); // Futuramente, nosso endereço .onion
define('DEBUG_MODE', true);              // Mudar para false em produção

// CHAVE PÚBLICA MESTRA (XPUB) PARA CARTEIRA DE DEPÓSITOS BTC
define('MASTER_PUBLIC_KEY', 'zpub6nMVW3iQ5Sq3VNdjEhFcKYXiNZWW7RCiMydEyPMZ82PKnKaCursZUgCwtYQadRtjonR3Vg3uDn2ZuTGZpdNKcWyNPXtvK7P2oSdsaZXDAax'); // <-- COLE SUA XPUB REAL AQUI

// Configurações Bitcoin
$blockchainConfig = [
    // BlockCypher API - Gratuita até 3 requests/segundo
    'blockcypher' => [
        'api_key' => '1a406e8d527943418bd99f7afaf3d461', // Deixe vazio para usar sem token (limitado)
        'base_url' => 'https://api.blockcypher.com/v1/btc/main',
        'webhook_url' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/btc/webhook.php'
    ],
    
    // Blockstream API - Gratuita
    'blockstream' => [
        'base_url' => 'https://blockstream.info/api'
    ],
    
    // Etherscan API
    'etherscan' => [
    'api_key' => '6PA6CHCT9UGWQ2MWFE2UFM94UVFAFKQT8Z',
    'base_url' => 'https://api.etherscan.io/api'
],
    
    // CoinGecko API para cotações
    'coingecko' => [
        'base_url' => 'https://api.coingecko.com/api/v3'
    ],
    
    // Configurações gerais
    'min_confirmations' => 1, // Mínimo de confirmações para considerar válido
    'dust_limit' => 0.00000546, // Limite mínimo de transação (546 satoshis)
    'fee_rate' => 10, // Taxa de rede em sat/byte
    'network' => 'mainnet', // mainnet ou testnet
    
    // Limites de saque diário
    'daily_limits' => [
        'BTC' => 1.0,
        'ETH' => 10.0,
        'XMR' => 100.0
    ],
    
    // Taxas de saque
    'withdrawal_fees' => [
        'BTC' => 0.0001,
        'ETH' => 0.001,
        'XMR' => 0.01
    ],
    
    // Segurança
    'webhook_secret' => 'zee_market_webhook_2024_' . md5($_SERVER['HTTP_HOST'] ?? 'localhost'),
    'encryption_key' => 'zee_market_encrypt_2024_' . md5($_SERVER['HTTP_HOST'] ?? 'localhost')
];
$torConfig = [
    'proxy' => 'socks5://127.0.0.1:9050',
    'user_agent_rotation' => true,
    'circuit_renewal' => 300, // Renovar circuito a cada 5min
    'timeout' => 60,
    'ssl_verify' => false // Apenas para .onion
];

// Constantes globais
define('SITE_URL', (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'));
define('BTC_PRECISION', 8);
define('ETH_PRECISION', 6);
define('XMR_PRECISION', 6);
define('SATOSHI_TO_BTC', 100000000);
define('WEI_TO_ETH', 1000000000000000000);

// Função para converter satoshis para BTC
function satoshiToBtc($satoshis) {
    return number_format($satoshis / SATOSHI_TO_BTC, BTC_PRECISION, '.', '');
}

// Função para converter BTC para satoshis
function btcToSatoshi($btc) {
    return (int)($btc * SATOSHI_TO_BTC);
}

// Função para converter Wei para ETH
function weiToEth($wei) {
    return number_format($wei / WEI_TO_ETH, ETH_PRECISION, '.', '');
}

// Função para converter ETH para Wei
function ethToWei($eth) {
    return (int)($eth * WEI_TO_ETH);
}

// Função para formatar valores de criptomoeda
function formatCrypto($amount, $crypto) {
    $precision = [
        'BTC' => BTC_PRECISION,
        'ETH' => ETH_PRECISION,
        'XMR' => XMR_PRECISION
    ];
    
    $decimals = $precision[strtoupper($crypto)] ?? 8;
    return number_format($amount, $decimals, '.', '');
}

// Função para validar endereços de criptomoeda
function isValidCryptoAddress($address, $crypto) {
    $patterns = [
        'BTC' => '/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/',
        'ETH' => '/^0x[a-fA-F0-9]{40}$/',
        'XMR' => '/^4[0-9A-Za-z]{94}$/'
    ];
    
    return isset($patterns[strtoupper($crypto)]) ? 
           preg_match($patterns[strtoupper($crypto)], $address) : false;
}

// Função para gerar hash seguro
function generateSecureHash($data) {
    return hash('sha256', $data . $blockchainConfig['encryption_key'] . time());
}

// Função para criptografia simples
function encryptData($data, $key = null) {
    global $blockchainConfig;
    $key = $key ?: hash('sha256', $blockchainConfig['encryption_key']);
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

// Função para descriptografia
function decryptData($encryptedData, $key = null) {
    global $blockchainConfig;
    $key = $key ?: hash('sha256', $blockchainConfig['encryption_key']);
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
}

// Função para log de transações
function logTransaction($message, $level = 'INFO') {
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] [$level] $message" . PHP_EOL;
    file_put_contents(__DIR__ . '/logs/transactions.log', $logMessage, FILE_APPEND | LOCK_EX);
}

// Função para verificar se é requisição AJAX
function isAjaxRequest() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

// Função para resposta JSON
function jsonResponse($data, $httpCode = 200) {
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// Headers de segurança (apenas se não foram enviados ainda)
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // CSP para desenvolvimento (relaxado)
    if (strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false) {
        header("Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https:; img-src 'self' data: https:;");
    }
}

// Configuração de erro handling
set_error_handler(function($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    
    $errorType = '';
    switch ($severity) {
        case E_ERROR:
        case E_USER_ERROR:
            $errorType = 'ERROR';
            break;
        case E_WARNING:
        case E_USER_WARNING:
            $errorType = 'WARNING';
            break;
        case E_NOTICE:
        case E_USER_NOTICE:
            $errorType = 'NOTICE';
            break;
        default:
            $errorType = 'UNKNOWN';
    }
    
    $logMessage = "[$errorType] $message in $file on line $line";
    error_log($logMessage);
    
    return true;
});

// Função para sanitizar input
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Função para validar CSRF token
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// Função para gerar CSRF token
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Verificar se todas as tabelas necessárias existem
function checkDatabaseTables() {
    global $conn;
    
    $requiredTables = [
        'users',
        'btc_transactions',
        'btc_balance_history'
    ];
    
    foreach ($requiredTables as $table) {
        $result = $conn->query("SHOW TABLES LIKE '$table'");
        if ($result->num_rows === 0) {
            error_log("Tabela obrigatória '$table' não encontrada no banco de dados");
            return false;
        }
    }
    
    return true;
}

// Verificar tabelas na inicialização (apenas em desenvolvimento)
if (strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false) {
    try {
        checkDatabaseTables();
    } catch (Exception $e) {
        error_log("Erro ao verificar tabelas: " . $e->getMessage());
    }
}

// Configuração de rate limiting básico
$_SESSION['api_calls'] = $_SESSION['api_calls'] ?? [];
$_SESSION['last_api_call'] = $_SESSION['last_api_call'] ?? 0;

// Limpar calls antigos (mais de 1 minuto)
if (time() - ($_SESSION['last_api_call'] ?? 0) > 60) {
    $_SESSION['api_calls'] = [];
}
class TorNetwork {
    private static $userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
    ];

    public static function makeSecureRequest($url, $data = null) {
        global $torConfig;
        
        $ch = curl_init();
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_PROXY => $torConfig['proxy'],
            CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5_HOSTNAME,
            CURLOPT_TIMEOUT => $torConfig['timeout'],
            CURLOPT_SSL_VERIFYPEER => $torConfig['ssl_verify'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true
        ];

        // Rotação de User-Agent
        if ($torConfig['user_agent_rotation']) {
            $options[CURLOPT_USERAGENT] = self::getRandomUserAgent();
        }

        // Adicionar dados para POST se necessário
        if (!empty($data)) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = is_array($data) ? http_build_query($data) : $data;
        }

        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            error_log("TOR Request Failed: " . curl_error($ch));
            return false;
        }

        curl_close($ch);
        return $response;
    }

    private static function getRandomUserAgent() {
        return self::$userAgents[array_rand(self::$userAgents)];
    }
}
// =============================================
// CLASSE AdvancedCrypto (Adicionada no final)
// =============================================
class AdvancedCrypto {
    private static $pepper = 'ZEE_ULTRA_SECRET_2024_RANDOM_STRING';
    
    public static function encryptData($data, $userKey = null) {
        $key = hash('sha3-512', self::$pepper . ($userKey ?? random_bytes(32)));
        $iv = random_bytes(16);
        $tag = '';
        $encrypted = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
        return base64_encode($iv . $tag . $encrypted);
    }
    
    public static function decryptData($encryptedData, $userKey = null) {
        $key = hash('sha3-512', self::$pepper . ($userKey ?? ''));
        $data = base64_decode($encryptedData);
        $iv = substr($data, 0, 16);
        $tag = substr($data, 16, 16);
        $encrypted = substr($data, 32);
        return openssl_decrypt($encrypted, 'aes-256-gcm', $key, 0, $iv, $tag);
    }
    
    public static function generateSecureAddress() {
        // Implementação básica (apenas para exemplo)
        $prefix = 'bc1q';
        $randomBytes = bin2hex(random_bytes(16));
        return $prefix . substr($randomBytes, 0, 40); // Simula um endereço Bitcoin
    }
}
?>