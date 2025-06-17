<?php
/**
 * PÁGINA DE COMPRA - VERSÃO CORRIGIDA
 * ✅ Correção de erros 500 e melhorias de segurança
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ✅ INICIALIZAR SESSÃO SEGURA
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'includes/config.php';
require_once 'includes/functions.php';

// ✅ VALIDAÇÃO SEGURA DO ID DO PRODUTO
$id = 0;
if (isset($_GET['id'])) {
    $id_param = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
    if ($id_param !== false && $id_param > 0) {
        $id = $id_param;
    }
}

if ($id === 0) {
    error_log("❌ ID de produto inválido: " . ($_GET['id'] ?? 'null'));
    die("❌ ID de produto inválido!");
}

// ✅ VERIFICAR CONEXÃO COM BANCO
if (!$conn || $conn->connect_error) {
    error_log("❌ Erro de conexão com banco: " . ($conn->connect_error ?? 'Conexão nula'));
    die("❌ Erro de conexão com o banco de dados!");
}

// ✅ BUSCAR PRODUTO COM VERIFICAÇÃO ROBUSTA
$produto = null;
try {
    // Corrigir JOIN - usar LEFT JOIN para evitar problemas se vendedor não existir
    $stmt = $conn->prepare("
        SELECT p.*, 
               COALESCE(v.nome, u.name, 'Vendedor Anônimo') as vendedor_nome, 
               COALESCE(v.created_at, u.created_at, NOW()) as data_cadastro 
        FROM produtos p 
        LEFT JOIN vendedores v ON p.vendedor_id = v.id 
        LEFT JOIN users u ON p.vendedor_id = u.id 
        WHERE p.id = ?
    ");
    
    if (!$stmt) {
        throw new Exception("Erro ao preparar query: " . $conn->error);
    }
    
    $stmt->bind_param("i", $id);
    if (!$stmt->execute()) {
        throw new Exception("Erro ao executar query: " . $stmt->error);
    }
    
    $result = $stmt->get_result();
    $produto = $result->fetch_assoc();
    $stmt->close();
    
    if (!$produto) {
        error_log("❌ Produto não encontrado - ID: $id");
        die("❌ Produto não encontrado!");
    }
    
    error_log("✅ Produto encontrado - ID: $id - Nome: " . $produto['nome']);
    
} catch (Exception $e) {
    error_log("❌ Erro ao buscar produto ID $id: " . $e->getMessage());
    die("❌ Erro ao carregar produto: " . htmlspecialchars($e->getMessage()));
}

// ✅ VERIFICAR LOGIN COM TRATAMENTO DE ERRO
$user_logged_in = false;
$user_balance = null;

try {
    $user_logged_in = isLoggedIn();
    
    if ($user_logged_in && isset($_SESSION['user_id'])) {
        $user_id = (int)$_SESSION['user_id'];
        
        $stmt = $conn->prepare("SELECT btc_balance, eth_balance, xmr_balance FROM users WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param("i", $user_id);
            if ($stmt->execute()) {
                $user_balance = $stmt->get_result()->fetch_assoc();
            }
            $stmt->close();
        }
        
        // Garantir valores padrão se não encontrar saldos
        if (!$user_balance) {
            $user_balance = [
                'btc_balance' => 0,
                'eth_balance' => 0,
                'xmr_balance' => 0
            ];
        }
    }
} catch (Exception $e) {
    error_log("⚠️ Erro ao verificar login: " . $e->getMessage());
    $user_logged_in = false;
    $user_balance = null;
}

// ✅ FUNÇÃO PARA OBTER COTAÇÃO BITCOIN COM FALLBACK ROBUSTO
function getBitcoinRate($db_connection) {
    try {
        if (!$db_connection || $db_connection->connect_error) {
            error_log("⚠️ Conexão de banco inválida para cotação BTC - usando fallback");
            return 45000; // Fallback padrão
        }
        
        // Verificar se tabela crypto_rates existe
        $check_table = $db_connection->query("SHOW TABLES LIKE 'crypto_rates'");
        if (!$check_table || $check_table->num_rows === 0) {
            error_log("⚠️ Tabela crypto_rates não existe - usando fallback");
            return 45000;
        }
        
        $stmt = $db_connection->prepare("SELECT btc_usd FROM crypto_rates ORDER BY created_at DESC LIMIT 1");
        if (!$stmt) {
            error_log("⚠️ Erro ao preparar query de cotação - usando fallback");
            return 45000;
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $rate = $result->fetch_assoc();
        $stmt->close();
        
        if ($rate && isset($rate['btc_usd']) && $rate['btc_usd'] > 0) {
            return (float)$rate['btc_usd'];
        } else {
            error_log("⚠️ Cotação BTC não encontrada ou inválida - usando fallback");
            return 45000;
        }
        
    } catch (Exception $e) {
        error_log("⚠️ Erro ao obter cotação BTC: " . $e->getMessage() . " - usando fallback");
        return 45000; // Fallback em caso de erro
    }
}

// ✅ CALCULAR PREÇOS COM VALIDAÇÃO
$btc_rate = getBitcoinRate($conn);
$preco_brl = (float)($produto['preco'] ?? 0);
$preco_btc_atual = $preco_brl > 0 ? ($preco_brl / $btc_rate) : 0;

// ✅ SANITIZAR DADOS DO PRODUTO
$produto_safe = [
    'id' => (int)$produto['id'],
    'nome' => htmlspecialchars($produto['nome'] ?? 'Produto sem nome', ENT_QUOTES, 'UTF-8'),
    'descricao' => htmlspecialchars($produto['descricao'] ?? '', ENT_QUOTES, 'UTF-8'),
    'preco' => $preco_brl,
    'preco_btc' => $preco_btc_atual,
    'imagem' => htmlspecialchars($produto['imagem'] ?? '', ENT_QUOTES, 'UTF-8'),
    'vendedor_nome' => htmlspecialchars($produto['vendedor_nome'] ?? 'Vendedor Anônimo', ENT_QUOTES, 'UTF-8'),
    'data_cadastro' => $produto['data_cadastro'] ?? date('Y-m-d H:i:s')
];

// ✅ SANITIZAR DADOS DO USUÁRIO
$user_data_safe = [
    'logged_in' => $user_logged_in,
    'name' => $user_logged_in ? htmlspecialchars($_SESSION['user_name'] ?? '', ENT_QUOTES, 'UTF-8') : '',
    'btc_balance' => $user_balance ? (float)$user_balance['btc_balance'] : 0,
    'eth_balance' => $user_balance ? (float)$user_balance['eth_balance'] : 0,
    'xmr_balance' => $user_balance ? (float)$user_balance['xmr_balance'] : 0
];

error_log("✅ Página de compra carregada - Produto: {$produto_safe['nome']} - Preço BTC: {$preco_btc_atual}");
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Comprar <?= $produto_safe['nome'] ?> com Bitcoin - ZeeMarket">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <title><?= $produto_safe['nome'] ?> - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-dark: #1a1a1a;
            --secondary-dark: #2d2d2d;
            --accent-orange: #f7931a;
            --success-green: #28a745;
            --text-light: #e0e0e0;
            --text-muted: #b0b0b0;
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
        
        .error-notice {
            background: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.3);
            border-radius: 10px;
            padding: 1rem;
            margin: 1rem 0;
            color: #dc3545;
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
        
        <?php if ($user_data_safe['logged_in'] && $user_balance): ?>
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
                    <span class="balance-amount"><?= number_format($user_data_safe['btc_balance'], 8) ?> BTC</span>
                </div>
                
                <div class="wallet-balance">
                    <div class="crypto-info">
                        <i class="fab fa-ethereum crypto-icon eth"></i>
                        <span>Ethereum (ETH)</span>
                    </div>
                    <span class="balance-amount"><?= number_format($user_data_safe['eth_balance'], 6) ?> ETH</span>
                </div>
                
                <div class="wallet-balance">
                    <div class="crypto-info">
                        <i class="fas fa-coins crypto-icon xmr"></i>
                        <span>Monero (XMR)</span>
                    </div>
                    <span class="balance-amount"><?= number_format($user_data_safe['xmr_balance'], 6) ?> XMR</span>
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
                <h1><?= $produto_safe['nome'] ?></h1>
                <p class="mb-0">
                    <i class="fas fa-store"></i> Vendido por: <?= $produto_safe['vendedor_nome'] ?>
                    <span class="crypto-badge">
                        <i class="fab fa-bitcoin"></i> Bitcoin
                    </span>
                </p>
            </div>
            
            <div class="product-body">
                <?php if (!empty($produto_safe['imagem'])): ?>
                <div class="text-center">
                    <img src="assets/uploads/<?= $produto_safe['imagem'] ?>" 
                         alt="<?= $produto_safe['nome'] ?>" 
                         class="product-image"
                         onerror="this.src='assets/images/placeholder.jpg'; this.style.opacity='0.6';">
                </div>
                <?php endif; ?>
                
                <div class="mb-4">
                    <h5><i class="fas fa-info-circle"></i> Descrição do Produto</h5>
                    <p class="text-muted"><?= nl2br($produto_safe['descricao'] ?: 'Sem descrição disponível.') ?></p>
                </div>
                
                <div class="vendor-info">
                    <h6><i class="fas fa-user-tie"></i> Informações do Vendedor</h6>
                    <p class="mb-0">
                        <strong><?= $produto_safe['vendedor_nome'] ?></strong><br>
                        <small class="text-muted">Membro desde <?= date('M/Y', strtotime($produto_safe['data_cadastro'])) ?></small>
                    </p>
                </div>
                
                <div class="price-section">
                    <h3><i class="fas fa-tags"></i> Preço</h3>
                    <div class="btc-price">
                        <?= number_format($produto_safe['preco_btc'], 8) ?> BTC
                    </div>
                    <div class="usd-price">
                        ≈ R$ <?= number_format($produto_safe['preco'], 2, ',', '.') ?>
                    </div>
                    <small class="text-muted">
                        Taxa da plataforma: 2.5% • Cotação: $<?= number_format($btc_rate, 2) ?>
                    </small>
                </div>
            </div>
        </div>

        <div class="purchase-form">
            <h3 class="text-center mb-4">
                <i class="fas fa-shopping-cart"></i> Finalizar Compra
            </h3>
            
            <form method="POST" action="processar_compra.php" id="purchase-form">
                <input type="hidden" name="produto_id" value="<?= $produto_safe['id'] ?>">
                
                <?php if ($user_data_safe['logged_in']): ?>
                <div class="payment-method-selector">
                    <h5><i class="fas fa-credit-card"></i> Método de Pagamento</h5>
                    
                    <div class="payment-option" data-method="balance">
                        <input type="radio" name="payment_method" value="balance" id="payment-balance">
                        <div class="payment-icon">
                            <i class="fas fa-wallet"></i>
                        </div>
                        <div class="payment-details">
                            <div class="payment-title">Pagar com Saldo da Carteira</div>
                            <div class="payment-description">Use seu saldo em Bitcoin</div>
                        </div>
                        <div class="balance-info <?= $user_data_safe['btc_balance'] < $produto_safe['preco_btc'] ? 'insufficient-balance' : '' ?>">
                            <?= number_format($user_data_safe['btc_balance'], 8) ?> BTC
                            <?php if ($user_data_safe['btc_balance'] < $produto_safe['preco_btc']): ?>
                                <br><small>Saldo insuficiente</small>
                            <?php endif; ?>
                        </div>
                    </div>
                    
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
                            <?= number_format($produto_safe['preco_btc'], 8) ?> BTC
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
                               value="<?= $user_data_safe['name'] ?>">
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
                        <?= number_format($produto_safe['preco_btc'], 8) ?> BTC
                    </div>
                </button>
            </form>
        </div>
        
        <div class="security-notice">
            <h6><i class="fas fa-shield-alt"></i> Informações de Segurança</h6>
            <ul>
                <li><strong>Pagamento Bitcoin:</strong> Transações irreversíveis na blockchain</li>
                <li><strong>Taxa da plataforma:</strong> 2.5% já incluída no preço</li>
                <li><strong>Confirmação:</strong> 1-3 confirmações (10-30 minutos)</li>
                <li><strong>Suporte:</strong> Acompanhe sua compra pela página de pagamento</li>
                <?php if ($user_data_safe['logged_in']): ?>
                <li><strong>Saldo interno:</strong> Pagamento instantâneo com saldo da carteira</li>
                <?php endif; ?>
            </ul>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // ✅ DADOS SEGUROS DO PHP PARA JAVASCRIPT
        const productData = {
            id: <?= json_encode($produto_safe['id'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
            name: <?= json_encode($produto_safe['nome'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
            price_btc: <?= json_encode($produto_safe['preco_btc'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
            price_brl: <?= json_encode($produto_safe['preco'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>
        };
        
        const userData = {
            logged_in: <?= $user_data_safe['logged_in'] ? 'true' : 'false' ?>,
            btc_balance: <?= json_encode($user_data_safe['btc_balance'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
            name: <?= json_encode($user_data_safe['name'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>
        };
        
        // ✅ SELETOR DE MÉTODO DE PAGAMENTO
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
        
        // ✅ ATUALIZAR MÉTODO DE PAGAMENTO
        function updatePaymentMethod() {
            const selectedMethod = document.querySelector('input[name="payment_method"]:checked')?.value || 'external';
            const btcWalletField = document.getElementById('btc-wallet-field');
            const btcWalletInput = document.getElementById('btc_wallet');
            const purchaseBtn = document.getElementById('purchase-btn');
            const purchaseText = document.getElementById('purchase-text');
            
            if (selectedMethod === 'balance' && userData.logged_in) {
                // Pagamento com saldo
                btcWalletField.style.display = 'none';
                btcWalletInput.required = false;
                
                if (userData.btc_balance >= productData.price_btc) {
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
        
        // ✅ INICIALIZAR COM MÉTODO SELECIONADO
        document.addEventListener('DOMContentLoaded', function() {
            if (userData.logged_in) {
                updatePaymentMethod();
            }
            
            console.log('✅ Página de compra carregada:', productData.name);
        });
        
        // ✅ VALIDAÇÃO DO FORMULÁRIO
        document.getElementById('purchase-form').addEventListener('submit', function(e) {
            const nome = document.getElementById('nome').value.trim();
            const endereco = document.getElementById('endereco').value.trim();
            const selectedMethod = document.querySelector('input[name="payment_method"]:checked')?.value || 'external';
            
            let errors = [];
            
            // Validações básicas
            if (nome.length < 3) {
                errors.push('Nome deve ter pelo menos 3 caracteres');
            }
            
            if (endereco.length < 10) {
                errors.push('Endereço deve ser mais detalhado (mínimo 10 caracteres)');
            }
            
            // Validação de carteira para pagamento externo
            if (selectedMethod === 'external') {
                const wallet = document.getElementById('btc_wallet').value.trim();
                const walletRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/;
                
                if (!wallet) {
                    errors.push('Carteira Bitcoin é obrigatória para pagamento externo');
                } else if (!walletRegex.test(wallet)) {
                    errors.push('Formato de carteira Bitcoin inválido');
                }
            }
            
            // Mostrar erros se houver
            if (errors.length > 0) {
                e.preventDefault();
                alert('❌ Erros encontrados:\n\n' + errors.join('\n'));
                return false;
            }
            
            // Confirmação final
            const paymentText = selectedMethod === 'balance' ? 'saldo da carteira' : 'Bitcoin externo';
            const confirmMessage = `🛒 Confirmar compra?\n\nProduto: ${productData.name}\nValor: ${document.querySelector('#purchase-amount').textContent.trim()}\nPagamento: ${paymentText}\n\n⚠️ O pagamento será processado imediatamente e é irreversível.\n\nDeseja continuar?`;
            
            if (!confirm(confirmMessage)) {
                e.preventDefault();
                return false;
            }
            
            // Mostrar loading
            const submitBtn = e.target.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processando compra...';
            
            console.log('✅ Compra sendo processada:', productData.name, selectedMethod);
        });
        
        // ✅ VALIDAÇÃO EM TEMPO REAL DA CARTEIRA
        document.getElementById('btc_wallet').addEventListener('input', function(e) {
            const wallet = e.target.value.trim();
            const walletRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/;
            
            if (wallet.length > 10) {
                if (walletRegex.test(wallet)) {
                    e.target.style.borderColor = '#28a745';
                    e.target.style.boxShadow = '0 0 0 0.2rem rgba(40, 167, 69, 0.25)';
                } else {
                    e.target.style.borderColor = '#dc3545';
                    e.target.style.boxShadow = '0 0 0 0.2rem rgba(220, 53, 69, 0.25)';
                }
            } else {
                e.target.style.borderColor = '#444';
                e.target.style.boxShadow = 'none';
            }
        });
        
        // ✅ PROTEÇÃO CONTRA MANIPULAÇÃO DE DADOS
        setInterval(() => {
            const priceElement = document.getElementById('purchase-amount');
            const expectedPrice = parseFloat(productData.price_btc).toFixed(8) + ' BTC';
            
            if (priceElement && priceElement.textContent.trim() !== expectedPrice) {
                console.warn('⚠️ Tentativa de manipulação de preço detectada');
                priceElement.textContent = expectedPrice;
            }
        }, 1000);
        
        // ✅ LOG DE SEGURANÇA
        console.log('🛡️ Página de compra segura carregada');
        console.log('✅ Produto:', productData.name);
        console.log('💰 Preço:', productData.price_btc, 'BTC');
        console.log('👤 Usuário logado:', userData.logged_in);
    </script>
</body>
</html>