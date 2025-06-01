<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'includes/functions.php';
verificarLogin();

// Obter dados do usuário
$user_id = $_SESSION['user_id'];
$user_data = $conn->query("SELECT name, email, btc_balance, btc_wallet FROM users WHERE id = $user_id")->fetch_assoc();
$reputacao = getReputacao($user_id);

// Verificar depósitos pendentes
verificarDepositosPendentes($user_id);
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #6f42c1;
            --secondary-color: #ffc107;
            --success-color: #28a745;
            --btc-orange: #f7931a;
        }
        
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        #container-principal {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 2rem;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        
        #button-container {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }
        
        #button-container .btn {
            flex: 1 1 200px;
            padding: 0.5rem;
            border-radius: 8px;
            font-weight: 500;
        }
        
        #welcome-container {
            text-align: center;
            margin-bottom: 2.5rem;
        }
        
        #welcome-container img {
            width: 120px;
            height: 120px;
            object-fit: cover;
            border-radius: 50%;
            border: 4px solid var(--primary-color);
            margin-bottom: 1rem;
        }
        
        .card-section {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            border: 1px solid #eee;
        }
        
        .card-section h3 {
            color: var(--primary-color);
            margin-bottom: 1.2rem;
            font-weight: 600;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 0.5rem;
        }
        
        .btc-balance {
            font-size: 2rem;
            font-weight: 700;
            color: var(--btc-orange);
            margin: 1rem 0;
        }
        
        .btc-wallet {
            background: #f8f9fa;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-family: monospace;
            word-break: break-all;
            color: #555;
            border: 1px dashed #ddd;
        }
        
        .reputation-badge {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
            margin-left: 0.5rem;
        }
        
        .reputation-gold {
            background-color: #ffd700;
            color: #8a6d3b;
        }
        
        .reputation-silver {
            background-color: #c0c0c0;
            color: #333;
        }
        
        .reputation-bronze {
            background-color: #cd7f32;
            color: #fff;
        }
        
        .form-control {
            border-radius: 8px;
            padding: 0.75rem 1rem;
            border: 1px solid #ddd;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 500;
        }
        
        .btn-primary:hover {
            background-color: #5a32a3;
        }
        
        .btn-success {
            background-color: var(--success-color);
            border: none;
        }
        
        #edit-container {
            display: none;
            margin-top: 2rem;
        }
        
        #edit-container.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .transaction-history {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .transaction-item {
            padding: 0.75rem;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
        }
        
        .transaction-item:last-child {
            border-bottom: none;
        }
        
        .status-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status-pending {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .status-confirmed {
            background-color: #d4edda;
            color: #155724;
        }
    </style>
</head>
<body>
    <div id="container-principal">
        <!-- Mensagens de status -->
        <?php if(isset($_SESSION['success_msg'])): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <?= $_SESSION['success_msg'] ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['success_msg']); ?>
        <?php endif; ?>
        
        <?php if(isset($_SESSION['error_msg'])): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?= $_SESSION['error_msg'] ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['error_msg']); ?>
        <?php endif; ?>

        <div id="button-container">
            <a href="index.php" class="btn btn-outline-primary">
                <i class="bi bi-house-door"></i> Home
            </a>
            <a href="products.php" class="btn btn-outline-primary">
                <i class="bi bi-shop"></i> Produtos
            </a>
            <a href="orders.php" class="btn btn-outline-primary">
                <i class="bi bi-receipt"></i> Pedidos
            </a>
            <a href="logout.php" class="btn btn-outline-danger">
                <i class="bi bi-box-arrow-right"></i> Sair
            </a>
        </div>

        <div id="welcome-container">
            <img src="assets/images/perfil.png" alt="Foto de perfil">
            <h1>Olá, <?= htmlspecialchars($user_data['name']) ?> 
                <span class="reputation-badge reputation-<?= strtolower($reputacao['level']) ?>">
                    <?= $reputacao['icon'] ?> <?= $reputacao['level'] ?>
                </span>
            </h1>
            <p class="text-muted">Bem-vindo ao seu painel de controle</p>
        </div>

        <!-- Seção de Saldo Bitcoin -->
        <div class="card-section">
            <h3><i class="bi bi-currency-bitcoin"></i> Carteira Bitcoin</h3>
            
            <div class="btc-balance">
                <?= number_format($user_data['btc_balance'], 8) ?> BTC
            </div>
            
            <?php if(!empty($user_data['btc_wallet'])): ?>
                <p>Seu endereço:</p>
                <div class="btc-wallet mb-3">
                    <?= htmlspecialchars($user_data['btc_wallet']) ?>
                </div>
                
                <form method="POST" action="process_deposit.php" class="mb-4">
                    <div class="mb-3">
                        <label for="tx_hash" class="form-label">Registrar novo depósito</label>
                        <input type="text" class="form-control" id="tx_hash" name="tx_hash" 
                               placeholder="Cole o hash da transação Bitcoin" required>
                        <small class="text-muted">Envie BTC para seu endereço acima e cole o hash aqui</small>
                    </div>
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-check-circle"></i> Confirmar Depósito
                    </button>
                </form>
            <?php else: ?>
                <div class="alert alert-warning">
                    <h5><i class="bi bi-exclamation-triangle"></i> Carteira não configurada</h5>
                    <p>Para receber pagamentos em Bitcoin, configure seu endereço abaixo:</p>
                    
                    <form method="POST" action="setup_btc_wallet.php">
                        <div class="mb-3">
                            <label for="btc_wallet" class="form-label">Endereço Bitcoin</label>
                            <input type="text" class="form-control" id="btc_wallet" name="btc_wallet" 
                                   placeholder="Digite seu endereço BTC" required>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-wallet2"></i> Salvar Carteira
                        </button>
                    </form>
                </div>
            <?php endif; ?>
            
            <!-- Histórico de Transações (simplificado) -->
            <h4 class="mt-4"><i class="bi bi-clock-history"></i> Últimas transações</h4>
            <div class="transaction-history">
                <?php
                $transactions = $conn->query("SELECT * FROM btc_transactions 
                                            WHERE user_id = $user_id 
                                            ORDER BY created_at DESC 
                                            LIMIT 5");
                
                if ($transactions->num_rows > 0): ?>
                    <?php while($tx = $transactions->fetch_assoc()): ?>
                        <div class="transaction-item">
                            <div>
                                <strong><?= substr($tx['tx_hash'], 0, 12) ?>...</strong>
                                <div class="text-muted small">
                                    <?= date('d/m/Y H:i', strtotime($tx['created_at'])) ?>
                                </div>
                            </div>
                            <div class="text-end">
                                <div class="<?= $tx['amount'] > 0 ? 'text-success' : 'text-danger' ?>">
                                    <?= $tx['amount'] > 0 ? '+' : '' ?><?= number_format($tx['amount'], 8) ?> BTC
                                </div>
                                <span class="status-badge status-<?= $tx['status'] ?>">
                                    <?= $tx['status'] === 'confirmed' ? 'Confirmado' : 'Pendente' ?>
                                </span>
                            </div>
                        </div>
                    <?php endwhile; ?>
                <?php else: ?>
                    <p class="text-muted">Nenhuma transação registrada ainda.</p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Seção de Edição de Perfil -->
        <div class="card-section">
            <div class="d-flex justify-content-between align-items-center">
                <h3><i class="bi bi-person-gear"></i> Configurações do Perfil</h3>
                <button class="btn btn-sm btn-outline-primary" id="editBtn">
                    <i class="bi bi-pencil"></i> Editar
                </button>
            </div>
            
            <div id="edit-container">
                <form method="POST" action="editar_usuario.php" class="mt-3">
                    <div class="mb-3">
                        <label for="nome" class="form-label">Nome Completo</label>
                        <input type="text" class="form-control" id="nome" name="nome" 
                               value="<?= htmlspecialchars($user_data['name']) ?>" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">E-mail</label>
                        <input type="email" class="form-control" id="email" name="email" 
                               value="<?= htmlspecialchars($user_data['email']) ?>" required>
                    </div>
                    <button type="submit" class="btn btn-success">
                        <i class="bi bi-save"></i> Salvar Alterações
                    </button>
                </form>
            </div>
            
            <div class="mt-3">
                <a href="alterar_senha.php" class="btn btn-outline-secondary me-2">
                    <i class="bi bi-shield-lock"></i> Alterar Senha
                </a>
                <a href="configuracoes.php" class="btn btn-outline-secondary">
                    <i class="bi bi-gear"></i> Mais Configurações
                </a>
            </div>
        </div>

        <!-- Seção de Atividades Recentes -->
        <div class="card-section">
            <h3><i class="bi bi-activity"></i> Suas Atividades</h3>
            <p class="text-muted">Seu histórico de ações aparecerá aqui.</p>
            <!-- Conteúdo dinâmico pode ser adicionado aqui -->
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Toggle do formulário de edição
        document.getElementById('editBtn').addEventListener('click', function() {
            document.getElementById('edit-container').classList.toggle('active');
        });
        
        // Fechar alerts automaticamente após 5 segundos
        setTimeout(() => {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                new bootstrap.Alert(alert).close();
            });
        }, 5000);
    </script>
</body>
</html>