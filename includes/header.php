<?php
// Verifica se a sessão não está ativa
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeeMarket</title>
    <link rel="icon" href="assets/images/capsule.png" type="image/x-icon">
    <!-- CSS -->
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" href="/assets/css/style.css">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="assets/bootstrap-icons/font/bootstrap-icons.css">
    <!-- CSS Personalizado -->
    <style>
        .navbar-brand img {
            height: 30px;
            margin-right: 10px;
        }
        body {
            background-color: #1a1a1a;
            color: #e0e0e0;
        }
    </style>
</head>
<body>
    <!-- Barra de Navegação -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="index.php">
                <img src="assets/icons2/zebra_branca.svg" alt="ZeeMarket">
                ZeeMarket
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="index.php">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="produtos.php">Produtos</a></li>
                    <li class="nav-item"><a class="nav-link" href="seguranca.php">Guia de Segurança</a></li>
                </ul>
                <?php if(isset($_SESSION['user_id'])): ?>
                    <span class="navbar-text me-3">
                        Olá, <?= htmlspecialchars($_SESSION['user_name']) ?>
                    </span>
                    <a href="/includes/logout_2.php" class="btn btn-outline-danger">Sair</a>
                <?php else: ?>
                    <a href="login.php" class="btn btn-outline-light me-2">Login</a>
                    <a href="signup.php" class="btn btn-warning">Cadastre-se</a>
                <?php endif; ?>
            </div>
        </div>
    </nav>
    <div class="container mt-4">