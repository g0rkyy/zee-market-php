<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'includes/config.php';
require_once 'includes/functions.php';

// Verificar se ID da compra foi fornecido
if (!isset($_GET['id'])) {
    header("Location: index.php");
    exit();
}

$compra_id = (int)$_GET['id'];

try {
    // Buscar dados completos da compra
    $stmt = $conn->prepare("SELECT 
            c.id, c.valor_btc, c.taxa_plataforma, c.pago, c.tx_hash, c.data_compra,
            c.nome, c.endereco, c.btc_wallet_comprador, c.valor_recebido, c.confirmations,
            p.nome as produto_nome, p.preco, p.imagem, p.descricao,
            v.nome as vendedor_nome, v.email as vendedor_email
        FROM compras c
        JOIN produtos p ON c.produto_id = p.id
        JOIN vendedores v ON c.vendedor_id = v.id
        WHERE c.id = ? AND c.pago = 1");
    $stmt->bind_param("i", $compra_id);
    $stmt->execute();
    $compra = $stmt->get_result()->fetch_assoc();

    if (!$compra) {
        throw new Exception("Compra não encontrada ou pagamento não confirmado!");
    }

    // Buscar saldo atual do usuário se estiver logado
    $user_balance = null;
    if (isLoggedIn()) {
        $stmt = $conn->prepare("SELECT btc_balance, eth_balance, xmr_balance FROM users WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $user_balance = $stmt->get_result()->fetch_assoc();
    }

    // CORREÇÃO: Buscar cotação atual com prepared statement
    $rate_stmt = $conn->prepare("SELECT btc_usd FROM crypto_rates ORDER BY created_at DESC LIMIT 1");
    $rate_stmt->execute();
    $rate_result = $rate_stmt->get_result();
    $rate = $rate_result->fetch_assoc();
    $btc_rate = $rate ? floatval($rate['btc_usd']) : 100000.00;
    $rate_stmt->close();

} catch (Exception $e) {
    error_log("Erro na confirmação: " . $e->getMessage());
    die("Erro ao carregar dados da compra: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compra Confirmada - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-dark: #1a1a1a;
            --secondary-dark: #2d2d2d;
            --success-green: #28a745;
            --text-light: #e0e0e0;
            --text-muted: #a0a0a0;
            --border-dark: #444;
            --accent-orange: #f7931a;
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
        
        .success-card {
            background: var(--secondary-dark);
            border: 1px solid var(--border-dark);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            overflow: hidden;
            margin-bottom: 2rem;
        }
        
        .success-header {
            background: linear-gradient(135deg, var(--success-green) 0%, #20c997 100%);
            color: white;
            padding: 2rem;
            text-align: center;
            position: relative;
        }
        
        .success-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
            animation: checkmark 0.6s ease-in-out;
        }
        
        @keyframes checkmark {
            0% {
                transform: scale(0);
                opacity: 0;
            }
            50% {
                transform: scale(1.2);
                opacity: 1;
            }
            100% {
                transform: scale(1);
                opacity: 1;
            }
        }
        
        .success-body {
            padding: 2rem;
        }
        
        .order-details {
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1.5rem 0;
        }
        
        .detail-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border-dark);
        }
        
        .detail-row:last-child {
            border-bottom: none;
        }
        
        .detail-label {
            font-weight: 600;
            color: var(--text-muted);
        }
        
        .detail-value {
            font-weight: 700;
            color: var(--text-light);
        }
        
        .product-info {
            display: flex;
            align-items: center;
            gap: 1rem;
            background: rgba(255,255,255,0.05);
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
        }
        
        .product-image {
            width: 80px;
            height: 80px;
            object-fit: cover;
            border-radius: 8px;
        }
        
        .product-details h6 {
            margin: 0;
            font-size: 1.1rem;
        }
        
        .wallet-summary {
            background: linear-gradient(135deg, rgba(40, 167, 69, 0.1), rgba(32, 201, 151, 0.1));
            border: 1px solid rgba(40, 167, 69, 0.3);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
        }
        
        .wallet-summary h5 {
            color: var(--success-green);
            margin-bottom: 1rem;
        }
        
        .balance-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 0.5rem 0;
        }
        
        .crypto-icon {
            margin-right: 0.5rem;
            font-size: 1.1rem;
        }
        
        .crypto-icon.btc { color: #f7931a; }
        .crypto-icon.eth { color: #627eea; }
        .crypto-icon.xmr { color: #ff6600; }
        
        .action-buttons {
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: 10px;
            font-weight: 600;
            text-decoration: none;
            border: none;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6c757d, #495057);
            color: white;
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success-green), #20c997);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
            color: white;
        }
        
        .timeline {
            margin: 2rem 0;
        }
        
        .timeline-item {
            display: flex;
            align-items: center;
            margin: 1rem 0;
            padding: 1rem;
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
        }
        
        .timeline-icon {
            width: 40px;
            height: 40px;
            background: var(--success-green);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            color: white;
        }
        
        .timeline-content h6 {
            margin: 0;
            color: var(--success-green);
        }
        
        .timeline-content p {
            margin: 0;
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .confetti {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 1000;
        }
        
        .tx-hash {
            background: var(--primary-dark);
            padding: 0.5rem;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            word-break: break-all;
            margin-top: 0.5rem;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 1rem auto;
                padding: 0 0.5rem;
            }
            
            .success-body {
                padding: 1rem;
            }
            
            .action-buttons {
                flex-direction: column;
            }
            
            .detail-row {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <!-- Confetti Animation -->
    <div class="confetti" id="confetti"></div>
    
    <div class="container">
        <div class="success-card">
            <div class="success-header">
                <div class="success-icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                <h1>Compra Realizada com Sucesso!</h1>
                <p class="mb-0">Pagamento processado e confirmado na blockchain</p>
            </div>
            
            <div class="success-body">
                <!-- Informações do Produto -->
                <?php if (!empty($compra['imagem'])): ?>
                <div class="product-info">
                    <img src="assets/uploads/<?= htmlspecialchars($compra['imagem']) ?>" 
                         alt="Produto" class="product-image">
                    <div class="product-details">
                        <h6><?= htmlspecialchars($compra['produto_nome']) ?></h6>
                        <p class="text-muted mb-1">Vendedor: <?= htmlspecialchars($compra['vendedor_nome']) ?></p>
                        <p class="text-success mb-0">
                            <strong><?= number_format($compra['valor_btc'], 8) ?> BTC</strong>
                            <small>(≈ R$ <?= number_format($compra['preco'], 2, ',', '.') ?>)</small>
                        </p>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- Detalhes do Pedido -->
                <div class="order-details">
                    <h5><i class="fas fa-receipt"></i> Detalhes do Pedido</h5>
                    
                    <div class="detail-row">
                        <span class="detail-label">Número do Pedido:</span>
                        <span class="detail-value">#<?= $compra['id'] ?></span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Data da Compra:</span>
                        <span class="detail-value"><?= date('d/m/Y H:i', strtotime($compra['data_compra'])) ?></span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Valor Pago:</span>
                        <span class="detail-value"><?= number_format($compra['valor_btc'], 8) ?> BTC</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Taxa da Plataforma:</span>
                        <span class="detail-value"><?= number_format($compra['taxa_plataforma'], 8) ?> BTC</span>
                    </div>
                    
                    <?php if (!empty($compra['tx_hash'])): ?>
                    <div class="detail-row">
                        <span class="detail-label">Hash da Transação:</span>
                        <span class="detail-value">
                            <div class="tx-hash"><?= htmlspecialchars($compra['tx_hash']) ?></div>
                            <?php if (strpos($compra['tx_hash'], 'internal_') === false): ?>
                            <a href="https://blockstream.info/tx/<?= htmlspecialchars($compra['tx_hash']) ?>" 
                               target="_blank" class="btn btn-sm btn-outline-light mt-2">
                                <i class="fas fa-external-link-alt"></i> Ver na Blockchain
                            </a>
                            <?php endif; ?>
                        </span>
                    </div>
                    <?php endif; ?>
                    
                    <div class="detail-row">
                        <span class="detail-label">Entrega para:</span>
                        <span class="detail-value"><?= htmlspecialchars($compra['nome']) ?></span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Endereço:</span>
                        <span class="detail-value"><?= htmlspecialchars($compra['endereco']) ?></span>
                    </div>
                    
                    <?php if ($compra['confirmations'] > 0): ?>
                    <div class="detail-row">
                        <span class="detail-label">Confirmações:</span>
                        <span class="detail-value">
                            <span class="badge bg-success"><?= $compra['confirmations'] ?> confirmações</span>
                        </span>
                    </div>
                    <?php endif; ?>
                </div>
                
                <!-- Timeline do Processo -->
                <div class="timeline">
                    <h5><i class="fas fa-tasks"></i> Status do Pedido</h5>
                    
                    <div class="timeline-item">
                        <div class="timeline-icon">
                            <i class="fas fa-check"></i>
                        </div>
                        <div class="timeline-content">
                            <h6>Pagamento Confirmado</h6>
                            <p>Transação processada e confirmada com sucesso</p>
                        </div>
                    </div>
                    
                    <div class="timeline-item">
                        <div class="timeline-icon">
                            <i class="fas fa-bell"></i>
                        </div>
                        <div class="timeline-content">
                            <h6>Vendedor Notificado</h6>
                            <p>O vendedor foi informado sobre sua compra</p>
                        </div>
                    </div>
                    
                    <div class="timeline-item">
                        <div class="timeline-icon">
                            <i class="fas fa-truck"></i>
                        </div>
                        <div class="timeline-content">
                            <h6>Preparando Envio</h6>
                            <p>O vendedor está preparando seu pedido para envio</p>
                        </div>
                    </div>
                </div>
                
                <!-- Resumo da Carteira (se logado) -->
                <?php if ($user_balance): ?>
                <div class="wallet-summary">
                    <h5><i class="fas fa-wallet"></i> Saldo Atual da Carteira</h5>
                    
                    <div class="balance-item">
                        <div>
                            <i class="fas fa-bitcoin crypto-icon btc"></i>
                            Bitcoin (BTC)
                        </div>
                        <span class="detail-value"><?= number_format($user_balance['btc_balance'], 8) ?> BTC</span>
                    </div>
                    
                    <div class="balance-item">
                        <div>
                            <i class="fab fa-ethereum crypto-icon eth"></i>
                            Ethereum (ETH)
                        </div>
                        <span class="detail-value"><?= number_format($user_balance['eth_balance'], 6) ?> ETH</span>
                    </div>
                    
                    <div class="balance-item">
                        <div>
                            <i class="fas fa-coins crypto-icon xmr"></i>
                            Monero (XMR)
                        </div>
                        <span class="detail-value"><?= number_format($user_balance['xmr_balance'], 6) ?> XMR</span>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- Botões de Ação -->
                <div class="action-buttons">
                    <?php if (isLoggedIn()): ?>
                    <a href="dashboard.php" class="btn btn-primary">
                        <i class="fas fa-tachometer-alt"></i> Meu Dashboard
                    </a>
                    <?php endif; ?>
                    <a href="index.php" class="btn btn-secondary">
                        <i class="fas fa-shopping-bag"></i> Continuar Comprando
                    </a>
                    <button class="btn btn-success" onclick="compartilharCompra()">
                        <i class="fas fa-share-alt"></i> Compartilhar
                    </button>
                    <button class="btn btn-outline-light" onclick="imprimirComprovante()">
                        <i class="fas fa-print"></i> Imprimir Comprovante
                    </button>
                </div>
                
                <!-- Informações Adicionais -->
                <div class="mt-4 p-3" style="background: rgba(23, 162, 184, 0.1); border-radius: 10px; border: 1px solid rgba(23, 162, 184, 0.3);">
                    <h6 style="color: #17a2b8;"><i class="fas fa-info-circle"></i> Próximos Passos</h6>
                    <ul style="margin: 0; padding-left: 1.5rem;">
                        <li>O vendedor foi notificado sobre sua compra automaticamente</li>
                        <li>Você receberá atualizações sobre o status da entrega</li>
                        <li>Guarde este número do pedido: <strong>#<?= $compra['id'] ?></strong></li>
                        <li>Em caso de dúvidas, entre em contato pelo suporte</li>
                        <li>Avalie sua experiência após receber o produto</li>
                    </ul>
                </div>

                <!-- Informações de Contato -->
                <div class="mt-3 p-3" style="background: rgba(40, 167, 69, 0.1); border-radius: 10px; border: 1px solid rgba(40, 167, 69, 0.3);">
                    <h6 style="color: var(--success-green);"><i class="fas fa-headset"></i> Suporte</h6>
                    <p class="mb-0">
                        <strong>Email:</strong> z33m4rketofficial@pronton.me<br>
                        <strong>Pedido:</strong> #<?= $compra['id'] ?><br>
                        <small class="text-muted">Inclua sempre o número do pedido ao entrar em contato</small>
                    </p>
                </div>
            </div>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // Animação de confetti
        function createConfetti() {
            const confettiContainer = document.getElementById('confetti');
            const colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#f0932b', '#eb4d4b', '#6ab04c'];
            
            for (let i = 0; i < 100; i++) {
                const confettiPiece = document.createElement('div');
                confettiPiece.style.position = 'absolute';
                confettiPiece.style.width = '10px';
                confettiPiece.style.height = '10px';
                confettiPiece.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
                confettiPiece.style.left = Math.random() * 100 + '%';
                confettiPiece.style.top = '-10px';
                confettiPiece.style.borderRadius = '50%';
                confettiPiece.style.pointerEvents = 'none';
                confettiPiece.style.animation = `fall ${Math.random() * 2 + 3}s linear forwards`;
                confettiContainer.appendChild(confettiPiece);
                
                setTimeout(() => {
                    confettiPiece.remove();
                }, 5000);
            }
        }
        
        // CSS da animação de queda
        const style = document.createElement('style');
        style.textContent = `
            @keyframes fall {
                0% {
                    transform: translateY(-100vh) rotate(0deg);
                    opacity: 1;
                }
                100% {
                    transform: translateY(100vh) rotate(360deg);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
        
        // Iniciar confetti ao carregar
        window.addEventListener('load', () => {
            setTimeout(createConfetti, 500);
        });
        
        // Função para compartilhar compra
        function compartilharCompra() {
            if (navigator.share) {
                navigator.share({
                    title: 'Compra realizada no ZeeMarket!',
                    text: `Acabei de comprar <?= htmlspecialchars($compra['produto_nome']) ?> no ZeeMarket! Pedido #<?= $compra['id'] ?>`,
                    url: window.location.href
                });
            } else {
                // Fallback para navegadores que não suportam Web Share API
                const text = `Acabei de comprar <?= htmlspecialchars($compra['produto_nome']) ?> no ZeeMarket! Pedido #<?= $compra['id'] ?>`;
                navigator.clipboard.writeText(text + ' - ' + window.location.href)
                    .then(() => alert('Link copiado para a área de transferência!'))
                    .catch(() => alert('Não foi possível copiar o link'));
            }
        }
        
        // Função para imprimir comprovante
        function imprimirComprovante() {
            window.print();
        }
        
        // Adicionar estilo de impressão
        const printStyle = document.createElement('style');
        printStyle.textContent = `
            @media print {
                body * {
                    visibility: hidden;
                }
                .success-card, .success-card * {
                    visibility: visible;
                }
                .success-card {
                    position: absolute;
                    left: 0;
                    top: 0;
                    width: 100%;
                }
                .confetti {
                    display: none;
                }
                .action-buttons {
                    display: none;
                }
            }
        `;
        document.head.appendChild(printStyle);
        
        // Auto-refresh das confirmações (se for transação real)
        <?php if (!empty($compra['tx_hash']) && strpos($compra['tx_hash'], 'internal_') === false): ?>
        function atualizarConfirmacoes() {
            fetch(`verificar_pagamento.php?id=<?= $compra_id ?>`)
                .then(response => response.json())
                .then(data => {
                    if (data.confirmations && data.confirmations > <?= $compra['confirmations'] ?>) {
                        location.reload(); // Recarregar se houver novas confirmações
                    }
                })
                .catch(console.error);
        }
        
        // Verificar confirmações a cada 2 minutos
        setInterval(atualizarConfirmacoes, 120000);
        <?php endif; ?>
        
        console.log('🎉 Compra confirmada com sucesso!');
        console.log('Pedido #<?= $compra['id'] ?> - <?= htmlspecialchars($compra['produto_nome']) ?>');
    </script>
</body>
</html>