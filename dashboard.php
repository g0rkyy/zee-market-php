<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'includes/functions.php';
verificarLogin();
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="assets/css/user.css">
    <script src="/js/usuario.js" defer></script>
    <title>Página de Usuário</title>
</head>
<body>
    <div id="body">
    <div id="container-principal">
            <div id="button-container"> 
        <a href="logout.php" id="logoutBtn" class="btn btn-outline-danger w-45">Sair</a>
        <a href="index.php" id="homeBtn" class="btn btn-outline-primary w-45">Home</a>
        <a href="FAQ.html" id="faqBtn" class="btn btn-outline-secondary w-45">FAQ</a>
        <button class="btn btn-warning w-45" id="editBtn"> 
            <span class="bi bi-pencil-fill"></span> 
            <span>Editar</span>
        </button>
    
            </div>
        <div id="welcome-container">
            <img src="assets/images/perfil.png" alt="Imagem de perfil">
            <h1 id="usuarioNome">Bem-vindo, <?php echo htmlspecialchars($_SESSION['user_name']); ?></h1>
        </div>
        <!-- AREA DE INTERAÇÃO COM O USÚARIO -->
         <div id="user-interaction-container">
            <h2>Área de Interação</h2>
            <div id="user-interaction-content">
                <p>Conteúdo interativo para o usuário vai aqui.</p>
                <!-- Adicione mais conteúdo interativo conforme necessário -->
            </div>
         </div>
    </div>
        <div id="footer">
            <p>&copy; Desde 2025. Todos os direitos reservados[piada da zebrinha].</p>
        </div>
    </div>
</body>
</html>
