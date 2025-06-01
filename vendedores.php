<?php
session_start();
require_once 'includes/config.php';

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
    $criptomoeda = $_POST['criptomoeda'];
    $carteira = trim($_POST['carteira']);

    // Validações
    if (empty($nome) || empty($email) || empty($senha) || empty($carteira)) {
        $erro = "Preencha todos os campos obrigatórios!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = "E-mail inválido!";
    } else {
        // Validação específica por criptomoeda
        if ($criptomoeda === 'BTC' && !preg_match('/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/', $carteira)) {
            $erro = "Carteira Bitcoin inválida!";
        } elseif ($criptomoeda === 'ETH' && !preg_match('/^0x[a-fA-F0-9]{40}$/', $carteira)) {
            $erro = "Carteira Ethereum inválida!";
        } else {
            // Verifica e-mail
            $stmt = $conn->prepare("SELECT id FROM vendedores WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $erro = "E-mail já cadastrado!";
            } else {
                // Cadastra vendedor
                $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO vendedores (nome, email, senha, criptomoeda, carteira) VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssss", $nome, $email, $senha_hash, $criptomoeda, $carteira);
                
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
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Área do Vendedor - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
        }
        
        body {
            background-color: #f5f7fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .container {
            max-width: 600px;
            margin-top: 50px;
        }
        
        .card-auth {
            border: none;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .card-body {
            padding: 30px;
            background: white;
        }
        
        .form-select {
            border-radius: 8px;
            padding: 12px 15px;
            border: 1px solid #ddd;
        }
        
        .form-control {
            border-radius: 8px;
            padding: 12px 15px;
            border: 1px solid #ddd;
        }
        
        .btn-primary {
            background-color: var(--secondary-color);
            border: none;
            padding: 12px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
            transform: translateY(-2px);
        }
        
        .crypto-selector {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .crypto-option {
            flex: 1;
            text-align: center;
            padding: 12px;
            border: 2px solid #eee;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .crypto-option:hover {
            border-color: var(--secondary-color);
        }
        
        .crypto-option.active {
            border-color: var(--secondary-color);
            background-color: #f8fafc;
        }
        
        .crypto-icon {
            font-size: 24px;
            margin-bottom: 8px;
            color: var(--primary-color);
        }
        
        .nav-tabs .nav-link {
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card card-auth">
            <div class="card-header">
                <h2><i class="fas fa-store-alt"></i> Área do Vendedor</h2>
            </div>
            
            <!-- Abas (Registro/Login) -->
            <ul class="nav nav-tabs nav-justified" id="myTab" role="tablist">
                <li class="nav-item">
                    <a class="nav-link active" id="registro-tab" data-bs-toggle="tab" href="#registro">Registrar</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="login-tab" data-bs-toggle="tab" href="#login">Login</a>
                </li>
            </ul>

            <div class="tab-content">
                <!-- Registro -->
                <div class="tab-pane fade show active" id="registro">
                    <?php if (!empty($erro) && isset($_POST['registrar'])): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($erro) ?></div>
                    <?php endif; ?>
                    
                    <form method="POST" class="card-body">
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
                        
                        <div class="mb-3">
                            <label class="form-label">Selecione sua Criptomoeda</label>
                            <div class="crypto-selector">
                                <div class="crypto-option active" data-value="BTC">
                                    <div class="crypto-icon"><i class="fab fa-bitcoin"></i></div>
                                    <div>Bitcoin</div>
                                </div>
                                <div class="crypto-option" data-value="ETH">
                                    <div class="crypto-icon"><i class="fab fa-ethereum"></i></div>
                                    <div>Ethereum</div>
                                </div>
                                <div class="crypto-option" data-value="WASABI">
                                    <div class="crypto-icon"><i class="fas fa-coins"></i></div>
                                    <div>Wasabi</div>
                                </div>
                            </div>
                            <input type="hidden" name="criptomoeda" id="criptomoeda" value="BTC" required>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Endereço da Carteira</label>
                            <input type="text" name="carteira" class="form-control" required>
                            <small class="text-muted" id="wallet-example">Exemplo: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</small>
                        </div>
                        
                        <button type="submit" name="registrar" class="btn btn-primary w-100">
                            <i class="fas fa-user-plus"></i> Criar Conta
                        </button>
                    </form>
                </div>

                <!-- Login -->
                <div class="tab-pane fade" id="login">
                    <?php if (!empty($erro) && isset($_POST['login'])): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($erro) ?></div>
                    <?php endif; ?>
                    
                    <form method="POST" class="card-body">
                        <div class="mb-3">
                            <label class="form-label">E-mail</label>
                            <input type="email" name="email" class="form-control" required>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Senha</label>
                            <input type="password" name="senha" class="form-control" required>
                        </div>
                        
                        <button type="submit" name="login" class="btn btn-primary w-100">
                            <i class="fas fa-sign-in-alt"></i> Entrar
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
    <script>
        // Seleção de criptomoeda
        document.querySelectorAll('.crypto-option').forEach(option => {
            option.addEventListener('click', function() {
                document.querySelectorAll('.crypto-option').forEach(opt => {
                    opt.classList.remove('active');
                });
                this.classList.add('active');
                document.getElementById('criptomoeda').value = this.dataset.value;
                
                // Atualiza exemplo de carteira
                const examples = {
                    'BTC': 'Ex: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                    'ETH': 'Ex: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
                    'WASABI': 'Ex: wasabi1qzy9fhmzzxd8...'
                };
                document.getElementById('wallet-example').textContent = examples[this.dataset.value];
            });
        });
    </script>
</body>
</html>