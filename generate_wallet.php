<?php
/**
 * Gerador de Carteiras Seguro - ZeeMarket
 * @author Blackcat & Whitecat Security Team
 * @version 4.0 - Lógica Centralizada
 */

// Inicia a sessão e carrega os arquivos de base
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'includes/config.php';
require_once 'includes/functions.php';

// --- Validações de Segurança Iniciais ---

// Garante que o usuário está logado
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Aceita apenas requisições POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: dashboard.php");
    exit();
}

// Valida o token CSRF para prevenir ataques
if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
    error_log("🚨 CSRF ATTACK BLOCKED - generate_wallet.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - User ID: " . ($_SESSION['user_id'] ?? 'unknown'));
    $_SESSION['error_msg'] = 'Token de segurança inválido. Tente novamente.';
    header("Location: dashboard.php");
    exit();
}

// --- Lógica Principal ---

// Pega e valida a criptomoeda solicitada
$crypto = strtoupper(trim($_POST['crypto'] ?? ''));
$supportedCryptos = ['BTC', 'ETH', 'XMR'];

if (!in_array($crypto, $supportedCryptos)) {
    $_SESSION['error_msg'] = 'Criptomoeda não suportada.';
    header("Location: dashboard.php");
    exit();
}

$user_id = $_SESSION['user_id'];

try {
    // Tenta gerar e salvar o endereço da carteira
    $newAddress = generateAndSaveWalletAddress($user_id, $crypto);
    
    // Se tudo deu certo, define a mensagem de sucesso
    $_SESSION['success_msg'] = "Endereço $crypto gerado com sucesso!";

} catch (Exception $e) {
    // Se algo deu errado, captura o erro e define a mensagem de erro
    $_SESSION['error_msg'] = $e->getMessage();
    error_log("❌ ERRO AO GERAR ENDEREÇO $crypto - User ID: $user_id - Erro: " . $e->getMessage() . " - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

// Regenera o token CSRF para a próxima requisição
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Redireciona de volta para o dashboard para mostrar a mensagem
header("Location: dashboard.php");
exit();