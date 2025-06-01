<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';

if (!isset($_SESSION)) {
    session_start();
}

// Verifica CSRF
if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    $_SESSION['error_msg'] = 'Token CSRF inválido';
    header("Location: dashboard.php");
    exit();
}

verificarLogin();

// Validação do endereço
function isValidBTCAddress($address) {
    return preg_match('/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/', $address);
}

if (empty($_POST['btc_wallet']) || !isValidBTCAddress($_POST['btc_wallet'])) {
    $_SESSION['error_msg'] = 'Endereço Bitcoin inválido!';
    header("Location: dashboard.php");
    exit();
}

// Atualiza no banco de dados
$stmt = $conn->prepare("UPDATE users SET btc_wallet = ?, btc_deposit_address = NULL WHERE id = ?");
$stmt->bind_param("si", $_POST['btc_wallet'], $_SESSION['user_id']);

if ($stmt->execute()) {
    $_SESSION['success_msg'] = 'Carteira Bitcoin configurada com sucesso!';
    
    // Registra a mudança via trigger
    $conn->query("UPDATE users SET btc_wallet = btc_wallet WHERE id = " . $_SESSION['user_id']);
} else {
    $_SESSION['error_msg'] = 'Erro ao salvar carteira: ' . $stmt->error;
}

header("Location: dashboard.php");
exit();
?>