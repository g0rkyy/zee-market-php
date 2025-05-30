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
    <style>
        #edit-container {
            display: none;
            margin-top: 20px;
            border: 1px solid #dee2e6;
            padding: 20px;
            border-radius: 10px;
            background-color: #f8f9fa;
        }
        #edit-container.active {
            display: block;
        }
    </style>
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
                <h1 id="usuarioNome">Bem-vindo, <?php echo htmlspecialchars($_SESSION['user_name'] ?? 'Usuário'); ?></h1>
            </div>

            <!-- Área de Edição -->
            <div id="edit-container">
                <h2>Editar Informações</h2>
                <form method="POST" action="editar_usuario.php">
                    <div class="mb-3">
                        <label for="nome" class="form-label">Nome</label>
                        <input type="text" id="nome" name="nome" class="form-control" value="<?php echo htmlspecialchars($_SESSION['user_name'] ?? ''); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">E-mail</label>
                        <input type="email" id="email" name="email" class="form-control" value="<?php echo htmlspecialchars($_SESSION['user_email'] ?? ''); ?>" required>
                    </div>
                    <button type="submit" class="btn btn-success">Salvar Alterações</button>
                </form>
            </div>

            <!-- Área de Interação com o Usuário -->
            <div id="user-interaction-container">
                <h2>Área de Interação</h2>
                <div id="user-interaction-content">
                    <p>Conteúdo interativo para o usuário vai aqui.</p>
                    <!-- Adicione mais conteúdo interativo conforme necessário -->
                </div>
            </div>

            <!-- Nova seção: Configurações -->
            <!-- Nova seção: Configurações -->
<div id="settings-container" class="mt-4">
    <h2>Configurações</h2>
    <ul class="list-group">
        <li class="list-group-item"><a href="alterar_senha.php">Alterar senha</a></li>
        <li class="list-group-item"><a href="gerenciar_notificacoes.php">Gerenciar notificações</a></li>
        <li class="list-group-item"><a href="excluir_conta.php">Excluir conta</a></li>
    </ul>
</div>
        </div>
        <div id="footer">
            <p>&copy; Desde 2025. Todos os direitos reservados[piada da zebrinha].</p>
        </div>
    </div>

    <script>
        // Função para alternar a exibição do formulário de edição
        document.getElementById('editBtn').addEventListener('click', function() {
            const editContainer = document.getElementById('edit-container');
            editContainer.classList.toggle('active');
        });
    </script>
</body>
</html>