<?php 
error_reporting(E_ALL);
ini_set('display_errors', 1);
require 'includes/functions.php';
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="/css/usuario.css">
    <script src="/js/usuario.js" defer></script>
    <title>Página de Usuário</title>
</head>
<body>
    <div id="container-principal">
            <div id="button-container"> 
        <button id="logoutBtn" class="btn btn-outline-danger w-45">Sair</button>
        <button id="homeBtn" class="btn btn-outline-dark">Voltar para a página inicial</button>
            </div>
        <div id="welcome-container">
            <img src="images/perfil.png" alt="Imagem de perfil">
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

</body>
</html>
