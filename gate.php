<?php
// gate.php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'includes/config.php'; 

// Se o usuário já passou pelo captcha, ele não deveria estar aqui.
if (isset($_SESSION['captcha_verified']) && $_SESSION['captcha_verified'] === true) {
    header('Location: index.php');
    exit();
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['captcha_code']) && isset($_SESSION['captcha_text']) && strtolower($_POST['captcha_code']) === strtolower($_SESSION['captcha_text'])) {
        // Sucesso!
        $_SESSION['captcha_verified'] = true;
        unset($_SESSION['captcha_text']); // Limpa o captcha usado
        header('Location: index.php');
        exit();
    } else {
        $error = 'Código incorreto. Tente novamente.';
    }
}
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Verificação de Segurança - Zee Market</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { display: flex; align-items: center; justify-content: center; min-height: 100vh; background-color: #212529; }
        .captcha-box { background: #343a40; padding: 40px; border-radius: 15px; text-align: center; color: white; }
        .captcha-img { border: 2px solid #495057; border-radius: 10px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="captcha-box">
        <h2 class="mb-3">Verificação de Segurança</h2>
        <p class="text-muted">Por favor, digite os caracteres que você vê na imagem abaixo.</p>
        <img src="includes/captcha.php" alt="Código Captcha" class="captcha-img">
        <form method="POST">
            <div class="mb-3">
                <input type="text" name="captcha_code" class="form-control form-control-lg text-center" required autofocus>
            </div>
            <?php if ($error): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <button type="submit" class="btn btn-primary w-100">Entrar</button>
        </form>
    </div>
</body>
</html>
