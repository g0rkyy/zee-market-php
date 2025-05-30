<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'includes/functions.php';

// Se já estiver logado, redireciona
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

$erro = ""; // Inicializa a variável de erro

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $senha = trim($_POST['senha']);
    
    $resultado = login($email, $senha);
    
    if ($resultado === true) {
        header("Location: dashboard.php");
        exit();
    } else {
        $erro = "Email ou senha incorretos, ou email não cadastrado.";
    }
}
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="utf-8">
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="assets/css/signup.css">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <script src="/js/login.js" defer></script>
</head>
<body>
    <div id="menu">
        <a href="index.php">home</a>
        <a href="signup.php">registro</a>
        <a href="FAQ.html">faq</a>
    </div>
    <div id="loginContainer">
        <div class="container-login">
            <img src="assets/images/perfil.png" alt="Imagem de perfil">
            <h1>Login</h1>
            <form id="loginForm" method="post">
                <div>
                    <input class="form-control input-btn" type="text" name="email" id="user" placeholder="Email" required><br>
                    <input class="form-control input-btn" type="password" name="senha" id="password" placeholder="Digite sua senha" required><br>
                    
                    <div class="form-check text-start my-3">
                        <input type="checkbox" class="form-check-input" id="flexCheckDefault">
                        <label class="form-check-label" for="flexCheckDefault">Lembre-se de Mim</label>
                    </div>

                    <input class="submit btn btn-primary w-100" type="submit" value="Enviar">
                </div>
            </form>
            <!-- Exibe a mensagem de erro, se houver -->
            <?php if (!empty($erro)): ?>
                <div id="errorContainer" style="color: red; margin-top: 10px;">
                    <?= htmlspecialchars($erro) ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>