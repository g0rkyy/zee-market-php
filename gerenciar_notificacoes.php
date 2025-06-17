<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';
verificarLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $notificacoes = isset($_POST['notificacoes']) ? 1 : 0;

    $stmt = $conn->prepare("UPDATE users SET notificacoes = ? WHERE id = ?");
    $stmt->bind_param("ii", $notificacoes, $_SESSION['user_id']);
    if ($stmt->execute()) {
        echo "Configuração de notificações atualizada!";
    } else {
        echo "Erro ao atualizar notificações.";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Gerenciar Notificações</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
</head>
<body>
    <div class="container mt-4">
        <h2>Gerenciar Notificações</h2>
        <form method="POST">
            <div class="form-check">
                <input type="checkbox" id="notificacoes" name="notificacoes" class="form-check-input" <?= $_SESSION['notificacoes'] ? 'checked' : '' ?>>
                <label for="notificacoes" class="form-check-label">Ativar notificações</label>
            </div>
            <button type="submit" class="btn btn-success mt-3">Salvar Configurações</button>
        </form>
    </div>
</body>
</html>