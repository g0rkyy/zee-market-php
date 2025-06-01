<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'includes/functions.php';
verificarLogin();

// Gerar token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$user_id = $_SESSION['user_id'];

// Query modificada para verificar apenas a carteira do usuário
$user_data = $conn->query("
    SELECT u.name, u.email, u.btc_balance, u.btc_wallet, u.btc_deposit_address
    FROM users u
    WHERE u.id = $user_id
")->fetch_assoc();

// Debug - Verifique os valores no log
error_log("User Data: " . print_r($user_data, true));

$reputacao = getReputacao($user_id);
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
            --primary-color: #8a63f2;
            --primary-hover: #6e4acf;
            --secondary-color: #ffc107;
            --success-color: #28a745;
            --btc-orange: #f7931a;
            --dark-bg: #121212;
            --dark-card: #1e1e1e;
            --dark-border: #333;
            --dark-text: #e0e0e0;
            --dark-muted: #a0a0a0;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--dark-text);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        #container-principal {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 2rem;
            background: var(--dark-card);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            border: 1px solid var(--dark-border);
        }
        
        #button-container {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }
        
        #button-container .btn {
            flex: 1 1 200px;
            padding: 0.75rem;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 1px solid var(--dark-border);
        }
        
        .btn-outline-primary {
            color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-outline-primary:hover {
            background-color: var(--primary-color);
            color: white;
        }
        
        .btn-outline-danger:hover {
            background-color: #dc3545;
            color: white;
        }
        
        #welcome-container {
            text-align: center;
            margin-bottom: 2.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--dark-border);
        }
        
        #welcome-container img {
            width: 120px;
            height: 120px;
            object-fit: cover;
            border-radius: 50%;
            border: 4px solid var(--primary-color);
            margin-bottom: 1rem;
            box-shadow: 0 4px 15px rgba(138, 99, 242, 0.3);
        }
        
        .card-section {
            background: var(--dark-card);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            border: 1px solid var(--dark-border);
            transition: transform 0.3s ease;
        }
        
        .card-section:hover {
            transform: translateY(-3px);
        }
        
        .card-section h3 {
            color: var(--primary-color);
            margin-bottom: 1.2rem;
            font-weight: 600;
            border-bottom: 2px solid var(--dark-border);
            padding-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .btc-balance {
            font-size: 2rem;
            font-weight: 700;
            color: var(--btc-orange);
            margin: 1rem 0;
            text-shadow: 0 2px 4px rgba(247, 147, 26, 0.3);
        }
        
        .btc-wallet {
            background: rgba(15, 15, 15, 0.5);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            color: var(--btc-orange);
            border: 1px dashed var(--dark-border);
            margin: 1rem 0;
        }
        
        .reputation-badge {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
            margin-left: 0.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        
        .reputation-gold {
            background: linear-gradient(135deg, #ffd700, #ffbf00);
            color: #8a6d3b;
        }
        
        .reputation-silver {
            background: linear-gradient(135deg, #c0c0c0, #a0a0a0);
            color: #333;
        }
        
        .reputation-bronze {
            background: linear-gradient(135deg, #cd7f32, #b87333);
            color: #fff;
        }
        
        .form-control {
            border-radius: 8px;
            padding: 0.75rem 1rem;
            border: 1px solid var(--dark-border);
            background-color: rgba(30, 30, 30, 0.8);
            color: var(--dark-text);
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(138, 99, 242, 0.25);
            background-color: rgba(40, 40, 40, 0.8);
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-primary:hover {
            background-color: var(--primary-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        .btn-success {
            background-color: var(--success-color);
            border: none;
        }
        
        #edit-container {
            display: none;
            margin-top: 2rem;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .transaction-history {
            max-height: 300px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--primary-color) var(--dark-card);
        }
        
        .transaction-history::-webkit-scrollbar {
            width: 6px;
        }
        
        .transaction-history::-webkit-scrollbar-track {
            background: var(--dark-card);
        }
        
        .transaction-history::-webkit-scrollbar-thumb {
            background-color: var(--primary-color);
            border-radius: 6px;
        }
        
        .transaction-item {
            padding: 0.75rem;
            border-bottom: 1px solid var(--dark-border);
            display: flex;
            justify-content: space-between;
            transition: background-color 0.2s ease;
        }
        
        .transaction-item:hover {
            background-color: rgba(255,255,255,0.05);
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
            background-color: rgba(255, 243, 205, 0.2);
            color: #ffc107;
            border: 1px solid #ffc107;
        }
        
        .status-confirmed {
            background-color: rgba(40, 167, 69, 0.2);
            color: #28a745;
            border: 1px solid #28a745;
        }
        
        .alert {
            border-radius: 8px;
            border: none;
        }
        
        .text-muted {
            color: var(--dark-muted) !important;
        }
        
        /* Efeitos de Neon para elementos importantes */
        .neon-effect {
            text-shadow: 0 0 5px rgba(138, 99, 242, 0.7),
                         0 0 10px rgba(138, 99, 242, 0.5),
                         0 0 15px rgba(138, 99, 242, 0.3);
        }
        
        /* Responsividade */
        @media (max-width: 768px) {
            #container-principal {
                margin: 1rem;
                padding: 1rem;
            }
            
            .btc-balance {
                font-size: 1.5rem;
            }
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
            <h1 class="neon-effect">Olá, <?= htmlspecialchars($user_data['name']) ?> 
                <span class="reputation-badge reputation-<?= strtolower(str_replace(' ', '-', $reputacao['level'])) ?>">
                    <?= $reputacao['icon'] ?> <?= $reputacao['level'] ?>
                    <?php if (isset($reputacao['rating']) && $reputacao['rating'] > 0): ?>
                        (<?= $reputacao['rating'] ?>)
                    <?php endif; ?>
                </span>
            </h1>
            <p class="text-muted">Bem-vindo ao seu painel de controle</p>
        </div>

        <!-- Seção de Saldo Bitcoin -->
        <div class="card-section">
            <h3><i class="bi bi-currency-bitcoin"></i> Carteira Bitcoin</h3>
            
            <div class="btc-balance neon-effect">
                <?= number_format($user_data['btc_balance'], 8) ?> BTC
            </div>
            
            <?php 
            // Verifica primeiro o endereço de depósito gerado automaticamente
            if(!empty($user_data['btc_deposit_address'])): ?>
                <p>Seu endereço de depósito:</p>
                <div class="btc-wallet">
                    <?= htmlspecialchars($user_data['btc_deposit_address']) ?>
                </div>
                
                <form method="POST" action="process_deposit.php" class="mb-4">
                    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
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
            
            <?php 
            // Se não tem endereço de depósito, verifica se tem carteira manual
            elseif(!empty($user_data['btc_wallet'])): ?>
                <p>Seu endereço Bitcoin:</p>
                <div class="btc-wallet">
                    <?= htmlspecialchars($user_data['btc_wallet']) ?>
                </div>
                
                <div class="alert alert-info mt-3">
                    <i class="bi bi-info-circle"></i> Você configurou manualmente este endereço. 
                    <a href="#" id="generateDepositBtn" class="alert-link">Clique aqui</a> para gerar um endereço de depósito automático.
                </div>
            
            <?php 
            // Se não tem nenhum dos dois, mostra o formulário de configuração
            else: ?>
                <div class="alert alert-warning">
                    <h5><i class="bi bi-exclamation-triangle"></i> Carteira não configurada</h5>
                    <p>Para receber pagamentos em Bitcoin, escolha uma das opções abaixo:</p>
                    
                    <div class="row mt-3">
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-body">
                                    <h5><i class="bi bi-magic"></i> Opção Automática</h5>
                                    <p>Gere um endereço seguro diretamente pela plataforma</p>
                                    <button id="generateAutoWallet" class="btn btn-primary">
                                        <i class="bi bi-lightning"></i> Gerar Endereço Automático
                                    </button>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-body">
                                    <h5><i class="bi bi-pencil"></i> Opção Manual</h5>
                                    <p>Use seu próprio endereço de carteira externa</p>
                                    <form method="POST" action="setup_btc_wallet.php" id="manualWalletForm">
                                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                                        <div class="mb-3">
                                            <input type="text" class="form-control" name="btc_wallet" 
                                                   placeholder="Digite seu endereço BTC" required>
                                        </div>
                                        <button type="submit" class="btn btn-outline-primary">
                                            <i class="bi bi-wallet2"></i> Usar Este Endereço
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

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
                    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
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
            this.innerHTML = this.innerHTML.includes('Cancelar') ? 
                '<i class="bi bi-pencil"></i> Editar' : 
                '<i class="bi bi-x-circle"></i> Cancelar';
        });
        
        // Fechar alerts automaticamente após 5 segundos
        
        
        // Novo código para gerar endereço automático
        document.getElementById('generateAutoWallet')?.addEventListener('click', function() {
            if(confirm('Deseja gerar um endereço Bitcoin automático e seguro?')) {
                fetch('generate_wallet.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'csrf_token=' + encodeURIComponent('<?= $_SESSION['csrf_token'] ?>')
                })
                .then(response => response.json())
                .then(data => {
                    if(data.success) {
                        location.reload();
                    } else {
                        alert('Erro: ' + (data.message || 'Falha ao gerar endereço'));
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Erro na comunicação com o servidor');
                });
            }
        });

        // Validação de endereço BTC no formulário manual
        document.getElementById('manualWalletForm')?.addEventListener('submit', function(e) {
            const input = this.querySelector('[name="btc_wallet"]');
            if(input && !isValidBTCAddress(input.value)) {
                e.preventDefault();
                alert('Endereço Bitcoin inválido!');
                input.focus();
            }
        });

        function isValidBTCAddress(address) {
            return /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/.test(address);
        }
    </script>
</body>
</html>