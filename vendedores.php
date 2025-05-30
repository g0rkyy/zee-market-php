<?php
session_start();
require_once 'includes/config.php'; // Arquivo com a conexão MySQLi ($conn)

// Redireciona se já estiver logado
if (isset($_SESSION['vendedor_id'])) {
    header("Location: admin/painel_vendedor.php");
    exit();
}

$erro = "";

// Processar Registro
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['registrar'])) {
    $nome = trim($_POST['nome']);
    $email = trim($_POST['email']);
    $senha = $_POST['senha'];

    // Validações básicas
    if (empty($nome) || empty($email) || empty($senha)) {
        $erro = "Preencha todos os campos!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = "E-mail inválido!";
    } else {
        // Verifica se e-mail já existe
        $stmt = $conn->prepare("SELECT id FROM vendedores WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $erro = "E-mail já cadastrado!";
        } else {
            // Cadastra novo vendedor
            $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO vendedores (nome, email, senha) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $nome, $email, $senha_hash);
            
            if ($stmt->execute()) {
                $_SESSION['vendedor_id'] = $conn->insert_id;
                header("Location: admin/painel_vendedor.php");
                exit();
            } else {
                $erro = "Erro ao cadastrar. Tente novamente.";
            }
        }
    }
}

// Processar Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email']);
    $senha = $_POST['senha'];

    $stmt = $conn->prepare("SELECT id, nome, senha FROM vendedores WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $vendedor = $result->fetch_assoc();

    if ($vendedor && password_verify($senha, $vendedor['senha'])) {
        $_SESSION['vendedor_id'] = $vendedor['id'];
        $_SESSION['vendedor_nome'] = $vendedor['nome'];
        header("Location: admin/painel_vendedor.php");
        exit();
    } else {
        $erro = "E-mail ou senha inválidos!";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Área do Vendedor - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 600px; margin-top: 50px; }
        .tab-content { background: white; padding: 20px; border: 1px solid #dee2e6; border-top: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">Área do Vendedor</h1>
        
        <!-- Abas (Registro/Login) -->
        <ul class="nav nav-tabs nav-justified" id="myTab" role="tablist">
            <li class="nav-item">
                <a class="nav-link active" id="registro-tab" data-bs-toggle="tab" href="#registro">Registrar</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="login-tab" data-bs-toggle="tab" href="#login">Login</a>
            </li>
        </ul>

        <!-- Conteúdo das Abas -->
        <div class="tab-content">
            <!-- Registro -->
            <div class="tab-pane fade show active" id="registro">
                <?php if (!empty($erro) && isset($_POST['registrar'])): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($erro) ?></div>
                <?php endif; ?>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Nome Completo</label>
                        <input type="text" name="nome" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">E-mail</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Senha (mínimo 6 caracteres)</label>
                        <input type="password" name="senha" class="form-control" minlength="6" required>
                    </div>
                    <button type="submit" name="registrar" class="btn btn-warning w-100">Criar Conta</button>
                </form>
            </div>

            <!-- Login -->
            <div class="tab-pane fade" id="login">
                <?php if (!empty($erro) && isset($_POST['login'])): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($erro) ?></div>
                <?php endif; ?>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">E-mail</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Senha</label>
                        <input type="password" name="senha" class="form-control" required>
                    </div>
                    <button type="submit" name="login" class="btn btn-success w-100">Entrar</button>
                </form>
            </div>
        </div>
    </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
</body>
</html>