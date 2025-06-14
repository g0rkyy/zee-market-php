<?php
session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';
verificarLogin();

// Gera token CSRF se não existir
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$erro = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verifica CSRF
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Token CSRF inválido. Operação bloqueada por segurança.");
    }

    $senha_confirmacao = trim($_POST['senha_confirmacao']);
    $confirmacao_texto = trim($_POST['confirmacao_texto']);

    // Validações rigorosas para exclusão
    if (empty($senha_confirmacao)) {
        $erro = "Digite sua senha para confirmar a exclusão.";
    } elseif (strtoupper($confirmacao_texto) !== 'EXCLUIR') {
        $erro = "Digite 'EXCLUIR' para confirmar que deseja apagar sua conta.";
    } else {
        // Verifica senha do usuário
        $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if (!$user || !password_verify($senha_confirmacao, $user['password'])) {
            $erro = "Senha incorreta. Exclusão cancelada.";
        } else {
            // Inicia transação para exclusão segura
            $conn->begin_transaction();
            
            try {
                // Remove dados relacionados primeiro (se houver tabelas relacionadas)
                // Exemplo: comentários, pedidos, etc.
                $stmt = $conn->prepare("DELETE FROM feedback WHERE email = (SELECT email FROM users WHERE id = ?)");
                $stmt->bind_param("i", $_SESSION['user_id']);
                $stmt->execute();
                
                // Remove o usuário
                $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
                $stmt->bind_param("i", $_SESSION['user_id']);
                
                if ($stmt->execute()) {
                    $conn->commit();
                    
                    // Log da exclusão (opcional - para auditoria)
                    error_log("Conta excluída - User ID: " . $_SESSION['user_id'] . " - IP: " . $_SERVER['REMOTE_ADDR']);
                    
                    // Destrói sessão e redireciona
                    session_destroy();
                    header("Location: index.php?msg=conta_excluida");
                    exit();
                } else {
                    throw new Exception("Erro ao excluir conta");
                }
            } catch (Exception $e) {
                $conn->rollback();
                $erro = "Erro interno. Sua conta não foi excluída. Tente novamente.";
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
    <title>ZeeMarket - Excluir Conta</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <style>
        .danger-zone {
            border: 2px solid #dc3545;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            background-color: #f8f9fa;
        }
        .warning-text {
            color: #dc3545;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h3 class="mb-0">⚠️ Zona de Perigo - Excluir Conta</h3>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($erro)): ?>
                            <div class="alert alert-danger">
                                <?php echo htmlspecialchars($erro); ?>
                            </div>
                        <?php endif; ?>

                        <div class="danger-zone">
                            <h4 class="warning-text">⚠️ ATENÇÃO: Esta ação é irreversível!</h4>
                            <p><strong>Ao excluir sua conta:</strong></p>
                            <ul>
                                <li>Todos os seus dados serão <strong>permanentemente apagados</strong></li>
                                <li>Seu histórico de transações será <strong>perdido</strong></li>
                                <li>Não será possível <strong>recuperar</strong> esta conta</li>
                                <li>Você perderá acesso a todos os serviços do ZeeMarket</li>
                            </ul>
                        </div>

                        <form method="POST" onsubmit="return confirmarExclusao()">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            
                            <div class="mb-3">
                                <label for="senha_confirmacao" class="form-label">
                                    <strong>Digite sua senha para confirmar:</strong>
                                </label>
                                <input type="password" id="senha_confirmacao" name="senha_confirmacao" 
                                       class="form-control" required placeholder="Sua senha atual">
                            </div>
                            
                            <div class="mb-3">
                                <label for="confirmacao_texto" class="form-label">
                                    <strong>Digite "EXCLUIR" (em maiúsculas) para confirmar:</strong>
                                </label>
                                <input type="text" id="confirmacao_texto" name="confirmacao_texto" 
                                       class="form-control" required placeholder="Digite: EXCLUIR">
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-danger btn-lg">
                                    🗑️ EXCLUIR MINHA CONTA PERMANENTEMENTE
                                </button>
                                <a href="dashboard.php" class="btn btn-success">
                                    ↩️ Cancelar - Manter Minha Conta
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        function confirmarExclusao() {
            const confirmacao = document.getElementById('confirmacao_texto').value;
            
            if (confirmacao !== 'EXCLUIR') {
                alert('Você deve digitar "EXCLUIR" para confirmar a exclusão da conta.');
                return false;
            }
            
            return confirm(
                '🚨 ÚLTIMA CHANCE! 🚨\n\n' +
                'Você tem CERTEZA ABSOLUTA de que deseja excluir sua conta?\n\n' +
                '• Esta ação é IRREVERSÍVEL\n' +
                '• Todos os seus dados serão PERDIDOS\n' +
                '• Não há como desfazer esta operação\n\n' +
                'Clique OK apenas se tiver CERTEZA TOTAL.'
            );
        }
        
        // Validação em tempo real
        document.getElementById('confirmacao_texto').addEventListener('input', function() {
            const valor = this.value;
            const botao = document.querySelector('button[type="submit"]');
            
            if (valor === 'EXCLUIR') {
                botao.disabled = false;
                this.style.borderColor = '#28a745';
            } else {
                botao.disabled = true;
                this.style.borderColor = '#dc3545';
            }
        });
        
        // Inicia com botão desabilitado
        document.querySelector('button[type="submit"]').disabled = true;
    </script>
</body>
</html>