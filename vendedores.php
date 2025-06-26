<?php
/**
 * ÁREA DO VENDEDOR - REGISTRO E LOGIN
 * Design Deep Web com correções de erro - VERSÃO CORRIGIDA
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'includes/config.php';

// ✅ VERIFICAR SE JÁ ESTÁ LOGADO COMO VENDEDOR
if (isset($_SESSION['vendedor_id'])) {
    header("Location: admin/painel_vendedor.php");
    exit();
}

$erro = "";
$sucesso = "";

// ✅ CRIAR TABELA DE VENDEDORES SE NÃO EXISTIR (CORRIGIDA PARA COINCIDIR COM PAINEL)
    
    // ✅ VERIFICAR SE PRECISA ADICIONAR COLUNAS (PARA TABELAS EXISTENTES)
    $checkColumns = "DESCRIBE vendedores";
    $result = $conn->query($checkColumns);
    $columns = [];
    while ($row = $result->fetch_assoc()) {
        $columns[] = $row['Field'];
    }
    
    // Adicionar colunas que podem estar faltando
    if (!in_array('btc_wallet', $columns)) {
        $conn->query("ALTER TABLE users ADD COLUMN btc_wallet VARCHAR(255) DEFAULT NULL");
    }
    if (!in_array('status', $columns)) {
        $conn->query("ALTER TABLE users ADD COLUMN status ENUM('ativo', 'inativo', 'pendente') DEFAULT 'ativo'");
    }
    if (!in_array('created_at', $columns)) {
        $conn->query("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
    }
    if (!in_array('updated_at', $columns)) {
        $conn->query("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
    }
    
// ✅ PROCESSAR LOGIN
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email'] ?? '');
    $senha = $_POST['senha'] ?? '';
    
    if (empty($email) || empty($senha)) {
        $erro = "Preencha e-mail e senha!";
    } else {
        try {
            $stmt = $conn->prepare("SELECT id, senha, nome, status FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $vendedor = $result->fetch_assoc();
                
                // Verificar se vendedor está ativo
                if ($vendedor['status'] !== 'ativo') {
                    $erro = "Conta de vendedor está inativa. Entre em contato com o suporte.";
                } elseif (password_verify($senha, $vendedor['senha'])) {
                    $_SESSION['vendedor_id'] = $vendedor['id'];
                    $_SESSION['vendedor_nome'] = $vendedor['nome'];
                    $_SESSION['vendedor_email'] = $email;
                    
                    // Log de sucesso
                    error_log("✅ LOGIN VENDEDOR - ID: " . $vendedor['id'] . " - Email: " . $email);
                    
                    header("Location: admin/painel_vendedor.php");
                    exit();
                } else {
                    $erro = "Senha incorreta!";
                }
            } else {
                $erro = "E-mail não cadastrado!";
            }
            $stmt->close();
        } catch (Exception $e) {
            error_log("Erro no login: " . $e->getMessage());
            $erro = "Erro interno no login.";
        }
    }
}

// ✅ PROCESSAR REGISTRO (CORRIGIDO)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['registrar'])) {
    $nome = trim($_POST['nome'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $senha = $_POST['senha'] ?? '';
    $btc_wallet = trim($_POST['carteira'] ?? '');

    // Validações básicas
    if (empty($nome) || empty($email) || empty($senha) || empty($btc_wallet)) {
        $erro = "Preencha todos os campos obrigatórios!";
    } elseif (strlen($nome) < 2) {
        $erro = "Nome deve ter pelo menos 2 caracteres!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = "E-mail inválido!";
    } elseif (strlen($senha) < 6) {
        $erro = "Senha deve ter pelo menos 6 caracteres!";
    } else {
        // ✅ VALIDAÇÃO BÁSICA DE CARTEIRA BITCOIN
        if (strlen($btc_wallet) < 26 || strlen($btc_wallet) > 62) {
            $erro = "Carteira Bitcoin inválida! Deve ter entre 26 e 62 caracteres.";
        } else {
            try {
                // Verificar se e-mail já existe
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    $erro = "E-mail já cadastrado!";
                } else {
                    // Verificar se carteira já existe
                    $stmt_wallet = $conn->prepare("SELECT id FROM users WHERE btc_wallet = ?");
                    $stmt_wallet->bind_param("s", $btc_wallet);
                    $stmt_wallet->execute();
                    $result_wallet = $stmt_wallet->get_result();
                    
                    if ($result_wallet->num_rows > 0) {
                        $erro = "Esta carteira Bitcoin já está sendo usada por outro vendedor!";
                    } else {
                        // ✅ CADASTRAR VENDEDOR (CORRIGIDO)
                        $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
                        
                        $stmt_insert = $conn->prepare("INSERT INTO users (nome, email, senha, btc_wallet, status) VALUES (?, ?, ?, ?, 'ativo')");
                        $stmt_insert->bind_param("ssss", $nome, $email, $senha_hash, $btc_wallet);
                        
                        if ($stmt_insert->execute()) {
                            $vendedor_id = $conn->insert_id;
                            
                            // Log de sucesso
                            error_log("✅ NOVO VENDEDOR REGISTRADO - ID: $vendedor_id - Email: $email");
                            
                            // Auto-login após registro
                            $_SESSION['vendedor_id'] = $vendedor_id;
                            $_SESSION['vendedor_nome'] = $nome;
                            $_SESSION['vendedor_email'] = $email;
                            
                            header("Location: admin/painel_vendedor.php");
                            exit();
                            
                        } else {
                            $erro = "Erro ao cadastrar: " . $conn->error;
                        }
                        $stmt_insert->close();
                    }
                    $stmt_wallet->close();
                }
                $stmt->close();
            } catch (Exception $e) {
                error_log("Erro no registro: " . $e->getMessage());
                $erro = "Erro interno: " . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Área do Vendedor - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* DEEP WEB DARK THEME */
        :root {
            --bg-dark: #0a0a0a;
            --bg-darker: #151515;
            --bg-card: #1a1a1a;
            --border-dark: #333;
            --text-primary: #e0e0e0;
            --text-secondary: #999;
            --accent-green: #00ff88;
            --accent-red: #ff4444;
            --accent-blue: #4488ff;
            --accent-orange: #ffaa00;
        }
        
        body { 
            background: var(--bg-dark);
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 25% 25%, #001100 0%, transparent 50%),
                radial-gradient(circle at 75% 75%, #110000 0%, transparent 50%);
        }
        
        .container { 
            max-width: 600px; 
            margin-top: 50px; 
        }
        
        .card-auth { 
            background: var(--bg-card);
            border: 2px solid var(--border-dark);
            border-radius: 0;
            box-shadow: 0 0 20px rgba(0,255,136,0.1);
        }
        
        .card-header { 
            background: linear-gradient(45deg, #001a00, #001100);
            color: var(--accent-green);
            padding: 20px; 
            text-align: center;
            border-bottom: 2px solid var(--accent-green);
        }
        
        .card-header h2 {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            text-shadow: 0 0 10px var(--accent-green);
            letter-spacing: 2px;
        }
        
        .card-body { 
            padding: 30px; 
            background: var(--bg-card);
        }
        
        .nav-tabs {
            border-bottom: 2px solid var(--border-dark);
            background: var(--bg-darker);
        }
        
        .nav-tabs .nav-link {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-weight: bold;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .nav-tabs .nav-link:hover {
            color: var(--accent-green);
            background: rgba(0,255,136,0.1);
        }
        
        .nav-tabs .nav-link.active {
            color: var(--accent-green);
            background: var(--bg-card);
            border-bottom: 2px solid var(--accent-green);
        }
        
        .form-control, .form-select { 
            background: var(--bg-darker);
            border: 1px solid var(--border-dark);
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            border-radius: 0;
        }
        
        .form-control:focus, .form-select:focus { 
            background: var(--bg-darker);
            border-color: var(--accent-green);
            color: var(--text-primary);
            box-shadow: 0 0 10px rgba(0,255,136,0.3);
        }
        
        .form-control::placeholder {
            color: var(--text-secondary);
            font-style: italic;
        }
        
        .form-label {
            color: var(--accent-green);
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }
        
        .btn-primary { 
            background: linear-gradient(45deg, #004400, #008800);
            border: 2px solid var(--accent-green);
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: 'Courier New', monospace;
            border-radius: 0;
            transition: all 0.3s;
        }
        
        .btn-primary:hover { 
            background: linear-gradient(45deg, #008800, #00ff88);
            border-color: #00ff88;
            box-shadow: 0 0 20px rgba(0,255,136,0.5);
            transform: translateY(-2px);
        }
        
        .alert {
            border: none;
            border-radius: 0;
            font-family: 'Courier New', monospace;
            border-left: 4px solid;
        }
        
        .alert-danger {
            background: rgba(255,68,68,0.1);
            color: var(--accent-red);
            border-left-color: var(--accent-red);
        }
        
        .alert-success {
            background: rgba(0,255,136,0.1);
            color: var(--accent-green);
            border-left-color: var(--accent-green);
        }
        
        /* Terminal-like styling */
        .terminal-text {
            font-family: 'Courier New', monospace;
            color: var(--accent-green);
            text-shadow: 0 0 5px var(--accent-green);
        }
        
        .blink {
            animation: blink 1s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        
        /* Matrix-like background effect */
        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.05;
            pointer-events: none;
        }
        
        small.text-muted {
            color: var(--text-secondary) !important;
            font-family: 'Courier New', monospace;
            font-size: 0.8em;
        }
        
        /* Back button */
        .back-btn {
            position: fixed;
            top: 20px;
            left: 20px;
            background: var(--bg-card);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 10px 15px;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s;
        }
        
        .back-btn:hover {
            background: rgba(0,255,136,0.2);
            color: var(--accent-green);
            box-shadow: 0 0 10px rgba(0,255,136,0.3);
        }
    </style>
</head>
<body>
    <div class="matrix-bg">
        <pre class="terminal-text">
01001000 01100001 01100011 01101011 01100101 01110010
01010000 01100001 01110010 01100001 01100100 01101001
01000100 01100101 01100101 01110000 01010111 01100101
        </pre>
    </div>

    <a href="index.php" class="back-btn">
        <i class="fas fa-arrow-left"></i> VOLTAR
    </a>

    <div class="container">
        <div class="card card-auth">
            <div class="card-header">
                <h2><i class="fas fa-user-secret"></i> ÁREA DO VENDEDOR <span class="blink">_</span></h2>
                <small class="terminal-text">// Acesso Restrito - Vendedores Autorizados //</small>
            </div>
            
            <ul class="nav nav-tabs nav-justified" id="myTab" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="registro-tab" data-bs-toggle="tab" data-bs-target="#registro" type="button" role="tab">
                        [REGISTRAR]
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="login-tab" data-bs-toggle="tab" data-bs-target="#login" type="button" role="tab">
                        [LOGIN]
                    </button>
                </li>
            </ul>

            <div class="tab-content">
                <div class="tab-pane fade show active" id="registro" role="tabpanel" aria-labelledby="registro-tab">
                    <?php if (!empty($erro) && isset($_POST['registrar'])): ?>
                        <div class="alert alert-danger mx-3">
                            <i class="fas fa-exclamation-triangle"></i> <?= htmlspecialchars($erro, ENT_QUOTES, 'UTF-8') ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="POST" class="card-body">
                        <div class="mb-3">
                            <label class="form-label">Nome Completo</label>
                            <input type="text" name="nome" class="form-control" required 
                                   value="<?= htmlspecialchars($_POST['nome'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                   placeholder="Digite seu nome real">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">E-mail</label>
                            <input type="email" name="email" class="form-control" required 
                                   value="<?= htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                   placeholder="seu@email.com">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Senha (mínimo 6 caracteres)</label>
                            <input type="password" name="senha" class="form-control" minlength="6" required
                                   placeholder="Digite uma senha forte">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Endereço da Carteira Bitcoin</label>
                            <input type="text" name="carteira" class="form-control" required 
                                   value="<?= htmlspecialchars($_POST['carteira'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                   placeholder="Cole o endereço da sua carteira Bitcoin">
                            <small class="text-muted">
                                Exemplo: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
                            </small>
                        </div>
                        
                        <button type="submit" name="registrar" class="btn btn-primary w-100">
                            <i class="fas fa-user-plus"></i> CRIAR CONTA DE VENDEDOR
                        </button>
                    </form>
                </div>

                <div class="tab-pane fade" id="login" role="tabpanel" aria-labelledby="login-tab">
                    <?php if (!empty($erro) && isset($_POST['login'])): ?>
                        <div class="alert alert-danger mx-3">
                            <i class="fas fa-exclamation-triangle"></i> <?= htmlspecialchars($erro, ENT_QUOTES, 'UTF-8') ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="POST" class="card-body">
                        <div class="mb-3">
                            <label class="form-label">E-mail</label>
                            <input type="email" name="email" class="form-control" required 
                                   value="<?= htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                   placeholder="seu@email.com">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Senha</label>
                            <input type="password" name="senha" class="form-control" required
                                   placeholder="Digite sua senha">
                        </div>
                        
                        <button type="submit" name="login" class="btn btn-primary w-100">
                            <i class="fas fa-sign-in-alt"></i> ACESSAR PAINEL
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Info Box -->
        <div class="card card-auth mt-4">
            <div class="card-body text-center">
                <h5 class="terminal-text">[ STATUS DO SISTEMA ]</h5>
                <p class="text-muted">
                    <i class="fas fa-shield-alt text-success"></i> Criptografia: ATIVA<br>
                    <i class="fas fa-user-secret text-success"></i> Anonimato: MÁXIMO<br>
                    <i class="fas fa-lock text-success"></i> Segurança: MILITAR
                </p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Ativar a aba correta em caso de erro
            <?php if (!empty($erro)): ?>
                <?php if(isset($_POST['registrar'])): ?>
                    var tab = new bootstrap.Tab(document.getElementById('registro-tab'));
                    tab.show();
                <?php elseif(isset($_POST['login'])): ?>
                    var tab = new bootstrap.Tab(document.getElementById('login-tab'));
                    tab.show();
                <?php endif; ?>
            <?php endif; ?>
            
            // Efeito de digitação no terminal
            setTimeout(() => {
                console.log('%c[SISTEMA] Página carregada com sucesso', 'color: #00ff88; font-family: monospace;');
            }, 1000);
        });
    </script>
</body>
</html>