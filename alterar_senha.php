<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';
verificarLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nova_senha = trim($_POST['nova_senha']);
    $confirmar_senha = trim($_POST['confirmar_senha']);

    if ($nova_senha !== $confirmar_senha) {
        die("As senhas não coincidem.");
    }

    $senha_hash = password_hash($nova_senha, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
    $stmt->bind_param("si", $senha_hash, $_SESSION['user_id']);
    if ($stmt->execute()) {
        echo "Senha alterada com sucesso!";
    } else {
        echo "Erro ao alterar a senha.";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Alterar Senha</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
</head>
<body>
    <div class="container mt-4">
        <h2>Alterar Senha</h2>
        <form method="POST">
            <div class="mb-3">
                <label for="nova_senha" class="form-label">Nova Senha</label>
                <input type="password" id="nova_senha" name="nova_senha" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="confirmar_senha" class="form-label">Confirmar Senha</label>
                <input type="password" id="confirmar_senha" name="confirmar_senha" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-success">Alterar Senha</button>
        </form>
    </div>
</body>
</html>