<?php
session_start();
require_once 'includes/config.php'; // Conexão com o banco
require_once 'vendor/autoload.php'; // GoogleAuthenticator

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$ga = new PHPGangsta_GoogleAuthenticator();
$secret = $ga->createSecret();
echo "Seu segredo: " . $secret;

// Verifica se 2FA já está ativo
$stmt = $pdo->prepare("SELECT two_factor_enabled FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['enable_2fa'])) {
    // Gera segredo e QR Code
    $secret = $ga->createSecret();
    $qrCodeUrl = $ga->getQRCodeGoogleUrl('ZeeMarket', $secret);

    // Salva no banco
    $stmt = $pdo->prepare("UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?");
    $stmt->execute([$secret, $user_id]);

    echo "<h3>2FA ativado!</h3>";
    echo "<p>Escaneie este QR Code com o Google Authenticator:</p>";
    echo "<img src='$qrCodeUrl'>";
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Painel do Usuário</title>
</head>
<body>
    <h2>Bem-vindo ao seu painel</h2>

    <?php if ($user['two_factor_enabled']): ?>
        <p><strong>2FA já está ativado!</strong></p>
    <?php else: ?>
        <form method="POST">
            <input type="submit" name="enable_2fa" value="Ativar 2FA">
        </form>
    <?php endif; ?>

    <p><a href="logout.php">Sair</a></p>
</body>
</html>
