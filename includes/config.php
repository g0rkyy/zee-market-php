<?php
/**
 * ARQUIVO DE CONFIGURAÇÃO CENTRAL - ZEE-MARKET
 * Responsabilidade: Apenas definições, constantes e conexão com BD.
 * @author Blackcat & Whitecat Security Team
 */

// --- HEADERS E POLÍTICAS DE SEGURANÇA ---
if (!headers_sent()) {
    $is_local = (strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false);
    
    // Política de Segurança de Conteúdo (CSP)
    $csp_script_src = "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com https://ajax.googleapis.com";
    $csp_style_src = "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com";
    $csp_font_src = "'self' https://fonts.gstatic.com https://cdn.jsdelivr.net";
    $csp_img_src = "'self' data: https: " . ($is_local ? "http:" : "");
    $csp_connect_src = "'self' https: " . ($is_local ? "http: ws: wss:" : "");

    $csp = "default-src 'self'; ";
    $csp .= "script-src {$csp_script_src}; ";
    $csp .= "style-src {$csp_style_src}; ";
    $csp .= "font-src {$csp_font_src}; ";
    $csp .= "img-src {$csp_img_src}; ";
    $csp .= "connect-src {$csp_connect_src}; ";
    $csp .= "media-src 'self' https: data:; ";
    $csp .= "object-src 'none'; ";
    $csp .= "frame-ancestors 'none';";
    
    header("Content-Security-Policy: " . $csp);
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    header("Referrer-Policy: no-referrer");
}

// --- CONFIGURAÇÕES DE SESSÃO SEGURA (ANTES DE session_start()) ---
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.entropy_length', 32);
    ini_set('session.hash_function', 'sha256');
    ini_set('session.cookie_lifetime', 0);
    ini_set('session.gc_maxlifetime', 3600);
}

$pagina_atual = basename($_SERVER['PHP_SELF']);
if ($pagina_atual !== 'gate.php' && $pagina_atual !== 'captcha.php') {
    if (!isset($_SESSION['captcha_verified']) || $_SESSION['captcha_verified'] !== true) {
        header('Location: gate.php');
        exit();
    }
}

// --- CONFIGURAÇÕES GERAIS ---
date_default_timezone_set('America/Sao_Paulo');
define('SITE_NAME', 'Zee-Market');
define('DEBUG_MODE', true); // Mudar para false em produção

// --- LOGS ---
ini_set('log_errors', 1);
$log_path = __DIR__ . '/logs';
if (!file_exists($log_path)) {
    mkdir($log_path, 0755, true);
}
ini_set('error_log', $log_path . '/php_errors.log');

// --- BANCO DE DADOS ---
// Carregar variáveis de ambiente se o vendor/autoload existir
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
    if (file_exists(__DIR__ . '/../.env')) {
        $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
        $dotenv->load();
    }
}

$host = $_ENV['DB_HOST'] ?? 'localhost';
$user = $_ENV['DB_USER'] ?? 'root'; // Padrão para dev
$pass = $_ENV['DB_PASS'] ?? '';
$db   = $_ENV['DB_NAME'] ?? 'zee_market';

$conn = null;
try {
    // Desabilitar report de erro do mysqli para tratar manualmente
    mysqli_report(MYSQLI_REPORT_OFF);
    
    $conn = new mysqli($host, $user, $pass, $db);
    
    if ($conn->connect_error) {
        throw new Exception("Falha na conexão com o banco de dados: " . $conn->connect_error);
    }
    
    $conn->set_charset("utf8mb4");
    
} catch (Exception $e) {
    error_log("Erro crítico de banco de dados: " . $e->getMessage());
    // Em um ambiente de produção, você pode querer mostrar uma página de erro mais amigável.
    die("Sistema temporariamente indisponível. Tente novamente mais tarde.");
}

// --- CONSTANTES DE CRIPTOMOEDAS ---
define('BTC_PRECISION', 8);
define('ETH_PRECISION', 8);
define('XMR_PRECISION', 12);
define('SATOSHI_TO_BTC', 100000000);
define('WEI_TO_ETH', 1000000000000000000);

// --- CHAVES E SEGREDOS ---
define('MASTER_PUBLIC_KEY', 'zpub6nMVW3iQ5Sq3VNdjEhFcKYXiNZWW7RCiMydEyPMZ82PKnKaCursZUgCwtYQadRtjonR3Vg3uDn2ZuTGZpdNKcWyNPXtvK7P2oSdsaZXDAax');
define('WEBHOOK_SECRET', 'zee_market_webhook_2024_' . hash('sha256', $_SERVER['HTTP_HOST'] ?? 'localhost'));
define('ENCRYPTION_PEPPER', 'ZEE_ULTRA_SECRET_2024_RANDOM_STRING_PEPPER' . hash('sha256', $_SERVER['HTTP_HOST'] ?? 'localhost'));

?>