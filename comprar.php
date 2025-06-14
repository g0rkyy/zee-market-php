<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';

$id = (int)$_GET['id'];

// Buscar produto com dados do vendedor
$stmt = $conn->prepare("SELECT p.*, v.nome as vendedor_nome 
                       FROM produtos p 
                       JOIN vendedores v ON p.vendedor_id = v.id 
                       WHERE p.id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$produto = $stmt->get_result()->fetch_assoc();

if (!$produto) {
    die("Produto não encontrado!");
}

// Verificar se usuário está logado para mostrar saldo
$user_logged_in = isLoggedIn();
$user_balance = null;

if ($user_logged_in) {
    $stmt = $conn->prepare("SELECT btc_balance, eth_balance, xmr_balance FROM users WHERE id = ?");
    $stmt->bind_param("i", $_SESSION['user_id']);
    $stmt->execute();
    $user_balance = $stmt->get_result()->fetch_assoc();
}

// Obter cotação atual do Bitcoin
function getBitcoinRate($db_connection) {
    if (!$db_connection) {
        return 1; // Retorna 1 para evitar divisão por zero se a conexão for inválida
    }
    
    $stmt = $db_connection->prepare("SELECT btc_usd FROM crypto_rates ORDER BY created_at DESC LIMIT 1");
    if (!$stmt) return 1;

    $stmt->execute();
    $result = $stmt->get_result();
    $rate = $result->fetch_assoc();
    $stmt->close();
    
    // Retorna o valor encontrado ou 1 para evitar divisão por zero
    return $rate ? (float)$rate['btc_usd'] : 1; 
}

// Corrigido: removida a chamada duplicada e inconsistente
$btc_rate = getBitcoinRate($conn);
$preco_btc_atual = $produto['preco'] / $btc_rate;
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($produto['nome']) ?> - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-dark: #1a1a1a;
            --secondary-dark: #2d2d2d;
            --accent-orange: #f7931a;
            --success-green: #28a745;
            --text-light: #e0e0e0;
            --text-muted: rgb(255, 255, 255);
            --border-dark: #444;
        }
        
        body {
            background: linear-gradient(135deg, var(--primary-dark) 0%, #0d1421 100%);
            color: var(--text-light);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .container {
            max-width: 1000px;
            margin: 2rem auto;
            padding: 0 1rem;
        }
        
        .product-card, .wallet-card {
            background: var(--secondary-dark);
            border: 1px solid var(--border-dark);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            overflow: hidden;
            margin-bottom: 2rem;
        }
        
        .product-header {
            background: linear-gradient(135deg, var(--accent-orange) 0%, #e67e22 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .wallet-header {
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
            color: white;
            padding: 1.5rem;
            text-align: center;
        }
        
        .product-body, .wallet-body {
            padding: 2rem;
        }
        
        .product-image {
            width: 100%;
            max-height: 400px;
            object-fit: cover;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .price-section {
            background: linear-gradient(135deg, rgba(247, 147, 26, 0.1), rgba(230, 126, 34, 0.1));
            border: 1px solid rgba(247, 147, 26, 0.3);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
            text-align: center;
        }
        
        .price-section h3 {
            color: var(--accent-orange);
            margin-bottom: 1rem;
        }
        
        .btc-price {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-orange);
            margin: 0.5rem 0;
        }
        
        .usd-price {
            font-size: 1.2rem;
            color: var(--text-muted);
        }
        
        .purchase-form {
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-dark);
            border-radius: 12px;
            padding: 2rem;
            margin-top: 2rem;
        }
        
        .payment-method-selector {
            margin-bottom: 2rem;
        }
        
        .payment-option {
            display: flex;
            align-items: center;
            padding: 1rem;
            border: 2px solid var(--border-dark);
            border-radius: 10px;
            margin-bottom: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
            background: rgba(255,255,255,0.05);
        }
        
        .payment-option:hover {
            border-color: var(--accent-orange);
        }
        
        .payment-option.active {
            border-color: var(--accent-orange);
            background: rgba(247, 147, 26, 0.1);
        }
        
        .payment-option input[type="radio"] {
            margin-right: 1rem;
        }
        
        .payment-icon {
            font-size: 1.5rem;
            margin-right: 1rem;
            width: 40px;
            text-align: center;
        }
        
        .payment-details {
            flex: 1;
        }
        
        .payment-title {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .payment-description {
            font-size: 0.9rem;
            color: var(--text-muted);
        }
        
        .balance-info {
            text-align: right;
            color: var(--success-green);
            font-weight: 600;
        }
        
        .insufficient-balance {
            color: #dc3545 !important;
        }
        
        .wallet-balance {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        
        .crypto-info {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .crypto-icon {
            font-size: 1.2rem;
        }
        
        .crypto-icon.btc { color: var(--accent-orange); }
        .crypto-icon.eth { color: #627eea; }
        .crypto-icon.xmr { color: #ff6600; }
        
        .balance-amount {
            font-weight: 600;
        }
        
        .form-label {
            color: var(--text-light);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .form-control {
            background: var(--primary-dark);
            border: 1px solid var(--border-dark);
            color: var(--text-light);
            border-radius: 8px;
            padding: 0.75rem;
        }
        
        .form-control:focus {
            background: var(--primary-dark);
            border-color: var(--accent-orange);
            color: var(--text-light);
            box-shadow: 0 0 0 0.2rem rgba(247, 147, 26, 0.25);
        }
        
        .form-control::placeholder {
            color: var(--text-muted);
        }
        
        .btn-purchase {
            background: linear-gradient(135deg, var(--accent-orange), #e67e22);
            border: none;
            color: white;
            padding: 1rem 2rem;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 700;
            width: 100%;
            transition: all 0.3s ease;
            margin-top: 1rem;
        }
        
        .btn-purchase:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(247, 147, 26, 0.4);
            color: white;
        }
        
        .btn-purchase:disabled {
            background: #6c757d;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .back-btn {
            background: linear-gradient(135deg, var(--border-dark), var(--primary-dark));
            border: 1px solid var(--border-dark);
            color: var(--text-light);
            padding: 0.75rem 1.5rem;
            border-radius: 10px;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            margin-bottom: 2rem;
        }
        
        .back-btn:hover {
            color: var(--text-light);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        
        .vendor-info {
            background: rgba(40, 167, 69, 0.1);
            border: 1px solid rgba(40, 167, 69, 0.3);
            border-radius: 10px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .security-notice {
            background: rgba(23, 162, 184, 0.1);
            border: 1px solid rgba(23, 162, 184, 0.3);
            border-radius: 10px;
            padding: 1.5rem;
            margin: 2rem 0;
        }
        
        .security-notice h6 {
            color: #17a2b8;
            margin-bottom: 1rem;
        }
        
        .security-notice ul {
            margin: 0;
            padding-left: 1.5rem;
        }
        
        .security-notice li {
            margin: 0.5rem 0;
            line-height: 1.6;
        }
        
        .crypto-badge {
            background: var(--accent-orange);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }
        
        .wallet-actions {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .btn-wallet {
            flex: 1;
            padding: 0.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-dark);
            background: rgba(255,255,255,0.05);
            color: var(--text-light);
            text-decoration: none;
            text-align: center;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .btn-wallet:hover {
            color: var(--text-light);
            border-color: var(--accent-orange);
            background: rgba(247, 147, 26, 0.1);
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 1rem auto;
                padding: 0 0.5rem;
            }
            
            .product-body, .wallet-body {
                padding: 1rem;
            }
            
            .purchase-form {
                padding: 1rem;
            }
            
            .wallet-actions {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="index.php" class="back-btn">
            <i class="fas fa-arrow-left"></i> Voltar ao Catálogo
        </a>
        
        <!-- Bloco da Carteira (se logado) -->
        <?php if ($user_logged_in && $user_balance): ?>
        <div class="wallet-card">
            <div class="wallet-header">
                <h4><i class="fas fa-wallet"></i> Minha Carteira</h4>
            </div>
            <div class="wallet-body">
                <div class="wallet-balance">
                    <div class="crypto-info">
                        <i class="fas fa-bitcoin crypto-icon btc"></i>
                        <span>Bitcoin (BTC)</span>
                    </div>
                    <span class="balance-amount"><?= number_format($user_balance['btc_balance'], 8) ?> BTC</span>
                </div>
                
                <div class="wallet-balance">
                    <div class="crypto-info">
                        <i class="fab fa-ethereum crypto-icon eth"></i>
                        <span>Ethereum (ETH)</span>
                    </div>
                    <span class="balance-amount"><?= number_format($user_balance['eth_balance'], 6) ?> ETH</span>
                </div>
                
                <div class="wallet-balance">
                    <div class="crypto-info">
                        <i class="fas fa-coins crypto-icon xmr"></i>
                        <span>Monero (XMR)</span>
                    </div>
                    <span class="balance-amount"><?= number_format($user_balance['xmr_balance'], 6) ?> XMR</span>
                </div>
                
                <div class="wallet-actions">
                    <a href="dashboard.php" class="btn-wallet">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                    <a href="dashboard.php#deposits" class="btn-wallet">
                        <i class="fas fa-plus-circle"></i> Depositar
                    </a>
                    <a href="dashboard.php#withdrawals" class="btn-wallet">
                        <i class="fas fa-minus-circle"></i> Sacar
                    </a>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
        <div class="product-card">
            <div class="product-header">
                <h1><?= htmlspecialchars($produto['nome']) ?></h1>
                <p class="mb-0">
                    <i class="fas fa-store"></i> Vendido por: <?= htmlspecialchars($produto['vendedor_nome']) ?>
                    <span class="crypto-badge">
                        <i class="fab fa-bitcoin"></i> Bitcoin
                    </span>
                </p>
            </div>
            
            <div class="product-body">
                <!-- Imagem do Produto -->
                <?php if (!empty($produto['imagem'])): ?>
                <div class="text-center">
                    <img src="assets/uploads/<?= htmlspecialchars($produto['imagem']) ?>" 
                         alt="<?= htmlspecialchars($produto['nome']) ?>" 
                         class="product-image">
                </div>
                <?php endif; ?>
                
                <!-- Descrição -->
                <div class="mb-4">
                    <h5><i class="fas fa-info-circle"></i> Descrição do Produto</h5>
                    <p class="text-muted"><?= nl2br(htmlspecialchars($produto['descricao'] ?: 'Sem descrição disponível.')) ?></p>
                </div>
                
                <!-- Informações do Vendedor -->
                <div class="vendor-info">
                    <h6><i class="fas fa-user-tie"></i> Informações do Vendedor</h6>
                    <p class="mb-0">
                        <strong><?= htmlspecialchars($produto['vendedor_nome']) ?></strong><br>
                        <small class="text-muted">Membro desde <?= date('M/Y', strtotime($produto['data_cadastro'])) ?></small>
                    </p>
                </div>
                
                <!-- Preços -->
                <div class="price-section">
                    <h3><i class="fas fa-tags"></i> Preço</h3>
                    <div class="btc-price">
                        <?= number_format($preco_btc_atual, 8) ?> BTC
                    </div>
                    <div class="usd-price">
                        ≈ R$ <?= number_format($produto['preco'], 2, ',', '.') ?>
                    </div>
                    <small class="text-muted">
                        Taxa da plataforma: 2.5% • Cotação: $<?= number_format($btc_rate, 2) ?>
                    </small>
                </div>
            </div>
        </div>

        <!-- Formulário de Compra -->
        <div class="purchase-form">
            <h3 class="text-center mb-4">
                <i class="fas fa-shopping-cart"></i> Finalizar Compra
            </h3>
            
            <form method="POST" action="processar_compra.php" id="purchase-form">
                <input type="hidden" name="produto_id" value="<?= $produto['id'] ?>">
                
                <!-- Seletor de Método de Pagamento -->
                <?php if ($user_logged_in): ?>
                <div class="payment-method-selector">
                    <h5><i class="fas fa-credit-card"></i> Método de Pagamento</h5>
                    
                    <!-- Pagamento com Saldo -->
                    <div class="payment-option" data-method="balance">
                        <input type="radio" name="payment_method" value="balance" id="payment-balance">
                        <div class="payment-icon">
                            <i class="fas fa-wallet"></i>
                        </div>
                        <div class="payment-details">
                            <div class="payment-title">Pagar com Saldo da Carteira</div>
                            <div class="payment-description">Use seu saldo em Bitcoin</div>
                        </div>
                        <div class="balance-info <?= floatval($user_balance['btc_balance']) < $preco_btc_atual ? 'insufficient-balance' : '' ?>">
                            <?= number_format($user_balance['btc_balance'], 8) ?> BTC
                            <?php if (floatval($user_balance['btc_balance']) < $preco_btc_atual): ?>
                                <br><small>Saldo insuficiente</small>
                            <?php endif; ?>
                        </div>
                    </div>
                    
                    <!-- Pagamento Externo -->
                    <div class="payment-option active" data-method="external">
                        <input type="radio" name="payment_method" value="external" id="payment-external" checked>
                        <div class="payment-icon">
                            <i class="fas fa-bitcoin"></i>
                        </div>
                        <div class="payment-details">
                            <div class="payment-title">Pagar com Bitcoin Externo</div>
                            <div class="payment-description">Enviar Bitcoin de sua carteira externa</div>
                        </div>
                        <div class="balance-info">
                            <?= number_format($preco_btc_atual, 8) ?> BTC
                        </div>
                    </div>
                </div>
                <?php else: ?>
                    <input type="hidden" name="payment_method" value="external">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> 
                        <a href="login.php" style="color: #17a2b8;">Faça login</a> para usar saldo da carteira ou pague diretamente com Bitcoin.
                    </div>
                <?php endif; ?>
                
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label for="nome" class="form-label">
                            <i class="fas fa-user"></i> Nome de Usuário *
                        </label>
                        <input type="text" id="nome" name="nome" class="form-control" 
                               placeholder="Seu nickname" required maxlength="100"
                               value="<?= $user_logged_in ? htmlspecialchars($_SESSION['user_name'] ?? '') : '' ?>">
                    </div>
                    
                    <div class="col-md-6 mb-3" id="btc-wallet-field">
                        <label for="btc_wallet" class="form-label">
                            <i class="fab fa-bitcoin"></i> Sua Carteira Bitcoin *
                        </label>
                        <input type="text" id="btc_wallet" name="btc_wallet" class="form-control" 
                               placeholder="bc1... ou 1... ou 3..." 
                               pattern="^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$">
                        <small class="text-muted">Para recebimento do produto</small>
                    </div>
                </div>
                
                <div class="mb-3">
                    <label for="endereco" class="form-label">
                        <i class="fas fa-map-marker-alt"></i> Endereço de Entrega *
                    </label>
                    <textarea id="endereco" name="endereco" class="form-control" rows="3" 
                              placeholder="Endereço completo para entrega" required maxlength="500"></textarea>
                </div>
                
                <button type="submit" class="btn-purchase" id="purchase-btn">
                    <i class="fab fa-bitcoin"></i> <span id="purchase-text">Comprar com Bitcoin</span>
                    <div style="font-size: 0.9rem; margin-top: 0.25rem;" id="purchase-amount">
                        <?= number_format($preco_btc_atual, 8) ?> BTC
                    </div>
                </button>
            </form>
        </div>
        
        <!-- Aviso de Segurança -->
        <div class="security-notice">
            <h6><i class="fas fa-shield-alt"></i> Informações de Segurança</h6>
            <ul>
                <li><strong>Pagamento Bitcoin:</strong> Transações irreversíveis na blockchain</li>
                <li><strong>Taxa da plataforma:</strong> 2.5% já incluída no preço</li>
                <li><strong>Confirmação:</strong> 1-3 confirmações (10-30 minutos)</li>
                <li><strong>Suporte:</strong> Acompanhe sua compra pela página de pagamento</li>
                <?php if ($user_logged_in): ?>
                <li><strong>Saldo interno:</strong> Pagamento instantâneo com saldo da carteira</li>
                <?php endif; ?>
            </ul>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        const productPrice = <?= $preco_btc_atual ?>;
        const userBalance = <?= $user_logged_in ? floatval($user_balance['btc_balance']) : 0 ?>;
        const isLoggedIn = <?= $user_logged_in ? 'true' : 'false' ?>;
        
        // Seletor de método de pagamento
        document.querySelectorAll('.payment-option').forEach(option => {
            option.addEventListener('click', function() {
                // Remove active de todas as opções
                document.querySelectorAll('.payment-option').forEach(opt => {
                    opt.classList.remove('active');
                    opt.querySelector('input[type="radio"]').checked = false;
                });
                
                // Ativa a opção clicada
                this.classList.add('active');
                this.querySelector('input[type="radio"]').checked = true;
                
                updatePaymentMethod();
            });
        });
        
        function updatePaymentMethod() {
            const selectedMethod = document.querySelector('input[name="payment_method"]:checked').value;
            const btcWalletField = document.getElementById('btc-wallet-field');
            const btcWalletInput = document.getElementById('btc_wallet');
            const purchaseBtn = document.getElementById('purchase-btn');
            const purchaseText = document.getElementById('purchase-text');
            
            if (selectedMethod === 'balance') {
                // Pagamento com saldo
                btcWalletField.style.display = 'none';
                btcWalletInput.required = false;
                
                if (userBalance >= productPrice) {
                    purchaseBtn.disabled = false;
                    purchaseText.textContent = 'Comprar com Saldo';
                    purchaseBtn.style.background = 'linear-gradient(135deg, #28a745, #20c997)';
                } else {
                    purchaseBtn.disabled = true;
                    purchaseText.textContent = 'Saldo Insuficiente';
                    purchaseBtn.style.background = '#6c757d';
                }
            } else {
                // Pagamento externo
                btcWalletField.style.display = 'block';
                btcWalletInput.required = true;
                purchaseBtn.disabled = false;
                purchaseText.textContent = 'Comprar com Bitcoin';
                purchaseBtn.style.background = 'linear-gradient(135deg, #f7931a, #e67e22)';
            }
        }
        
        // Inicializar com método selecionado
        if (isLoggedIn) {
            updatePaymentMethod();
        }
        
        // Validação do formulário
        document.getElementById('purchase-form').addEventListener('submit', function(e) {
            const nome = document.getElementById('nome').value.trim();
            const endereco = document.getElementById('endereco').value.trim();
            const selectedMethod = document.querySelector('input[name="payment_method"]:checked').value;
            
            if (nome.length < 3) {
                e.preventDefault();
                alert('Nome deve ter pelo menos 3 caracteres.');
                return;
            }
            
            if (endereco.length < 10) {
                e.preventDefault();
                alert('Endereço deve ser mais detalhado.');
                return;
            }
            
            if (selectedMethod === 'external') {
                const wallet = document.getElementById('btc_wallet').value.trim();
                const walletRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/;
                if (!walletRegex.test(wallet)) {
                    e.preventDefault();
                    alert('Formato de carteira Bitcoin inválido.\nUse formato: bc1... ou 1... ou 3...');
                    return;
                }
            }
            
            // Confirmação final
            const paymentText = selectedMethod === 'balance' ? 'saldo da carteira' : 'Bitcoin externo';
            const confirmMessage = `Confirmar compra?\n\nProduto: <?= htmlspecialchars($produto['nome']) ?>\nValor: ${document.querySelector('#purchase-amount').textContent}\nPagamento: ${paymentText}\n\nO pagamento será processado imediatamente.`;
            
            if (!confirm(confirmMessage)) {
                e.preventDefault();
            }
        });
        
        // Validação em tempo real da carteira
        document.getElementById('btc_wallet').addEventListener('input', function(e) {
            const wallet = e.target.value.trim();
            const walletRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/;
            
            if (wallet.length > 10) {
                if (walletRegex.test(wallet)) {
                    e.target.style.borderColor = '#28a745';
                } else {
                    e.target.style.borderColor = '#dc3545';
                }
            } else {
                e.target.style.borderColor = '#444';
            }
        });
    </script>
</body>
</html>