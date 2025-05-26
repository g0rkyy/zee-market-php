<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'includes/functions.php';

$erro = ''; // Inicializa a variável de erro

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome = trim($_POST['nome']);
    $email = trim($_POST['email']);
    $senha = trim($_POST['senha']);
    
    $resultado = cadastrarUsuario($nome, $email, $senha);
    
    if ($resultado === true) {
        header("Location: login.php?cadastro=sucesso");
        exit();
    } else {
        $erro = $resultado; // Armazena a mensagem de erro
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Registro</title>
    <link rel="stylesheet" type="text/css" href="assets/css/signup.css">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <style>
        .mensagem-erro {
            color: #dc3545; /* Vermelho do Bootstrap */
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }
    </style>
</head>
<body>
    <div id="menu">
        <a href="index.php">home</a>
        <a href="login.php">login</a>
        <a href="FAQ.html">faq</a>
    </div>
    <div id="signupContainer">
        <div id="registro-bloco">
            <img src="assets/images/perfil.png" alt="Imagem de perfil">
            <h1 id="titulo-registro">Registro</h1>
            
            <?php if (!empty($erro)): ?>
                <div class="alert alert-danger" role="alert">
                    <?php echo htmlspecialchars($erro); ?>
                </div>
            <?php endif; ?>
            
            <form id="registroForm" method="post">
                <div>
                    <input class="form-control input-btn" type="text" name="nome" id="floatingInput" placeholder="Nickname" required><br>
                    <input class="form-control input-btn" type="email" name="email" id="mail" placeholder="Digite seu email" required><br>
                    <input class="form-control input-btn" type="password" name="senha" id="password" placeholder="Digite sua senha" required minlength="8"><br>

                    <div class="form-check text-start my-3">
                        <input type="checkbox" class="form-check-input" id="flexCheckDefault">
                        <label class="form-check-label" for="flexCheckDefault">Lembre-se de Mim</label>
                    </div>

                    <input class="submit btn btn-primary w-100 btn-sub" type="submit" value="Enviar">
                </div>
            </form>
        </div>
    </div>
</body>
</html>