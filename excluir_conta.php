<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';
verificarLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
    $stmt->bind_param("i", $_SESSION['user_id']);
    if ($stmt->execute()) {
        session_destroy();
        header("Location: index.php");
        exit();
    } else {
        echo "Erro ao excluir a conta.";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Excluir Conta</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
</head>
<body>
    <div class="container mt-4">
        <h2>Excluir Conta</h2>
        <form method="POST">
            <p>Tem certeza de que deseja excluir sua conta? Esta ação não pode ser desfeita.</p>
            <button type="submit" class="btn btn-danger">Excluir Conta</button>
        </form>
    </div>
</body>
</html>