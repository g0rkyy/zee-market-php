<?php
require_once 'includes/config.php';

$compra_id = (int)$_GET['id'];

// Busca os dados da compra + carteira da plataforma
$compra = $conn->query("SELECT 
        c.id, c.valor_btc, c.taxa_plataforma, c.wallet_plataforma, c.pago, c.tx_hash, c.confirmations,
        p.nome as produto_nome, p.preco, p.imagem,
        v.nome as vendedor_nome
    FROM compras c
    JOIN produtos p ON c.produto_id = p.id
    JOIN vendedores v ON c.vendedor_id = v.id
    WHERE c.id = $compra_id")->fetch_assoc();

// Verifica se a compra existe
if (!$compra) {
    die("Compra não encontrada!");
}

// Define valores
$valor_total_btc = floatval($compra['valor_btc']);
$taxa_plataforma = floatval($compra['taxa_plataforma']);
$valor_vendedor = $valor_total_btc - $taxa_plataforma;
$wallet_pagamento = $compra['wallet_plataforma']; // Carteira da plataforma

// Formata os valores
$valor_btc_formatado = number_format($valor_total_btc, 8);
$taxa_formatada = number_format($taxa_plataforma, 8);
$vendedor_formatado = number_format($valor_vendedor, 8);

// Status da compra
$status_pago = (bool)$compra['pago'];
$confirmacoes = (int)$compra['confirmations'];
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pagamento Bitcoin - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-dark: #1a1a1a;
            --secondary-dark: #2d2d2d;
            --accent-orange: #f7931a;
            --success-green: #28a745;
            --warning-yellow: #ffc107;
            --text-light: #e0e0e0;
            --text-muted: #a0a0a0;
            --border-dark: #444;
        }
        
        body {
            background: linear-gradient(135deg, var(--primary-dark) 0%, #0d1421 100%);
            color: var(--text-light);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .payment-container {
            max-width: 900px;
            margin: 2rem auto;
            padding: 0 1rem;
        }
        
        .payment-card {
            background: var(--secondary-dark);
            border: 1px solid var(--border-dark);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            overflow: hidden;
        }
        
        .payment-header {
            background: linear-gradient(135deg, var(--accent-orange) 0%, #e67e22 100%);
            color: white;
            padding: 2rem;
            text-align: center;
            position: relative;
        }
        
        .payment-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="50" cy="50" r="1" fill="rgba(255,255,255,0.1)"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>');
            opacity: 0.3;
        }
        
        .payment-header h1 {
            position: relative;
            z-index: 1;
            margin: 0;
            font-size: 2rem;
            font-weight: 700;
        }
        
        .payment-header .product-info {
            position: relative;
            z-index: 1;
            margin-top: 1rem;
            opacity: 0.9;
        }
        
        .payment-body {
            padding: 2rem;
        }
        
        .crypto-amount {
            text-align: center;
            margin-bottom: 2rem;
            padding: 1.5rem;
            background: linear-gradient(135deg, rgba(247, 147, 26, 0.1), rgba(230, 126, 34, 0.1));
            border-radius: 12px;
            border: 1px solid rgba(247, 147, 26, 0.3);
        }
        
        .crypto-amount h2 {
            color: var(--accent-orange);
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .breakdown {
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 1rem;
            margin: 1rem 0;
            border: 1px solid var(--border-dark);
        }
        
        .breakdown-item {
            display: flex;
            justify-content: space-between;
            margin: 0.5rem 0;
            padding: 0.5rem 0;
        }
        
        .breakdown-item:not(:last-child) {
            border-bottom: 1px solid var(--border-dark);
        }
        
        .breakdown-total {
            font-weight: 700;
            font-size: 1.1rem;
            color: var(--accent-orange);
        }
        
        .qr-section {
            text-align: center;
            margin: 2rem 0;
        }
        
        .qr-code-container {
            background: white;
            padding: 1rem;
            border-radius: 15px;
            display: inline-block;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            margin-bottom: 1rem;
        }
        
        .wallet-address {
            background: var(--primary-dark);
            border: 1px solid var(--border-dark);
            border-radius: 10px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            word-break: break-all;
            margin: 1rem 0;
            position: relative;
        }
        
        .copy-btn {
            background: var(--accent-orange);
            border: none;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-top: 0.5rem;
        }
        
        .copy-btn:hover {
            background: #e67e22;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(247, 147, 26, 0.3);
        }
        
        .status-section {
            margin: 2rem 0;
        }
        
        .status-paid {
            background: linear-gradient(135deg, rgba(40, 167, 69, 0.2), rgba(25, 135, 84, 0.2));
            border: 1px solid var(--success-green);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }
        
        .status-pending {
            background: linear-gradient(135deg, rgba(255, 193, 7, 0.2), rgba(255, 149, 5, 0.2));
            border: 1px solid var(--warning-yellow);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }
        
        .status-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .refresh-btn {
            background: linear-gradient(135deg, #6c757d, #495057);
            border: none;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 10px;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-top: 1rem;
        }
        
        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(108, 117, 125, 0.3);
        }
        
        .instructions {
            background: rgba(23, 162, 184, 0.1);
            border: 1px solid rgba(23, 162, 184, 0.3);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
        }
        
        .instructions h5 {
            color: #17a2b8;
            margin-bottom: 1rem;
        }
        
        .instructions ol {
            margin: 0;
            padding-left: 1.5rem;
        }
        
        .instructions li {
            margin: 0.5rem 0;
            line-height: 1.6;
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
        
        .product-mini {
            display: flex;
            align-items: center;
            gap: 1rem;
            background: rgba(255,255,255,0.05);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        
        .product-mini img {
            width: 60px;
            height: 60px;
            object-fit: cover;
            border-radius: 8px;
        }
        
        .tx-hash {
            background: var(--primary-dark);
            padding: 0.5rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            margin-top: 0.5rem;
            word-break: break-all;
        }
        
        @media (max-width: 768px) {
            .payment-container {
                margin: 1rem auto;
                padding: 0 0.5rem;
            }
            
            .payment-body {
                padding: 1rem;
            }
            
            .crypto-amount h2 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="payment-container">
        <a href="index.php" class="back-btn">
            <i class="fas fa-arrow-left"></i> Voltar às Compras
        </a>
        
        <div class="payment-card">
            <div class="payment-header">
                <h1><i class="fab fa-bitcoin"></i> Pagamento Bitcoin</h1>
                <div class="product-info">
                    <h4><?= htmlspecialchars($compra['produto_nome']) ?></h4>
                    <p>Pedido #<?= $compra_id ?> • Vendedor: <?= htmlspecialchars($compra['vendedor_nome']) ?></p>
                </div>
            </div>
            
            <div class="payment-body">
                <!-- Informações do Produto -->
                <?php if (!empty($compra['imagem'])): ?>
                <div class="product-mini">
                    <img src="assets/uploads/<?= htmlspecialchars($compra['imagem']) ?>" alt="Produto">
                    <div>
                        <h6><?= htmlspecialchars($compra['produto_nome']) ?></h6>
                        <small class="text-muted">R$ <?= number_format($compra['preco'], 2, ',', '.') ?></small>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- Valor a Pagar -->
                <div class="crypto-amount">
                    <h5>Total a Pagar:</h5>
                    <h2><?= $valor_btc_formatado ?> BTC</h2>
                    <p class="mb-0">≈ R$ <?= number_format($compra['preco'], 2, ',', '.') ?></p>
                </div>
                
                <!-- Breakdown dos Valores -->
                <div class="breakdown">
                    <h6><i class="fas fa-calculator"></i> Detalhamento:</h6>
                    <div class="breakdown-item">
                        <span>Produto:</span>
                        <span><?= $vendedor_formatado ?> BTC</span>
                    </div>
                    <div class="breakdown-item">
                        <span>Taxa Plataforma (2.5%):</span>
                        <span><?= $taxa_formatada ?> BTC</span>
                    </div>
                    <div class="breakdown-item breakdown-total">
                        <span>Total:</span>
                        <span><?= $valor_btc_formatado ?> BTC</span>
                    </div>
                </div>
                
                <!-- Status do Pagamento -->
                <div class="status-section">
                    <?php if ($status_pago): ?>
                        <div class="status-paid">
                            <div class="status-icon text-success">
                                <i class="fas fa-check-circle"></i>
                            </div>
                            <h4>Pagamento Confirmado!</h4>
                            <p>Seu pagamento foi processado com sucesso.</p>
                            <?php if (!empty($compra['tx_hash'])): ?>
                                <div class="tx-hash">
                                    <strong>Hash da Transação:</strong><br>
                                    <?= htmlspecialchars($compra['tx_hash']) ?>
                                </div>
                            <?php endif; ?>
                            <?php if ($confirmacoes > 0): ?>
                                <p class="mt-2"><strong>Confirmações:</strong> <?= $confirmacoes ?></p>
                            <?php endif; ?>
                        </div>
                    <?php else: ?>
                        <div class="status-pending">
                            <div class="status-icon text-warning">
                                <i class="fas fa-clock"></i>
                            </div>
                            <h4>Aguardando Pagamento</h4>
                            <p>Envie <strong><?= $valor_btc_formatado ?> BTC</strong> para o endereço abaixo.</p>
                            
                            <!-- QR Code e Endereço -->
                            <div class="qr-section">
                                <div class="qr-code-container">
                                    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=bitcoin:<?= urlencode($wallet_pagamento) ?>?amount=<?= $valor_total_btc ?>" 
                                         alt="QR Code Bitcoin" style="width: 200px; height: 200px;">
                                </div>
                                
                                <h6><i class="fas fa-wallet"></i> Endereço de Pagamento:</h6>
                                <div class="wallet-address" id="wallet-address">
                                    <?= htmlspecialchars($wallet_pagamento) ?>
                                </div>
                                <button class="copy-btn" onclick="copyToClipboard()">
                                    <i class="fas fa-copy"></i> Copiar Endereço
                                </button>
                            </div>
                            
                            <button class="refresh-btn" onclick="verificarStatus()">
                                <i class="fas fa-sync-alt"></i> Verificar Pagamento
                            </button>
                        </div>
                    <?php endif; ?>
                </div>
                
                <!-- Instruções -->
                <div class="instructions">
                    <h5><i class="fas fa-info-circle"></i> Como Pagar:</h5>
                    <ol>
                        <li>Abra sua carteira Bitcoin (Electrum, Blockchain, etc.)</li>
                        <li>Escaneie o QR Code ou copie o endereço acima</li>
                        <li>Envie <strong>exatamente</strong> <?= $valor_btc_formatado ?> BTC</li>
                        <li>Aguarde 1-3 confirmações na blockchain (~10-30 min)</li>
                        <li>O pagamento será processado automaticamente</li>
                    </ol>
                </div>
            </div>
        </div>
    </div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // Função para copiar endereço
        function copyToClipboard() {
            const walletAddress = document.getElementById('wallet-address').textContent.trim();
            navigator.clipboard.writeText(walletAddress)
                .then(() => {
                    const btn = document.querySelector('.copy-btn');
                    const originalHTML = btn.innerHTML;
                    btn.innerHTML = '<i class="fas fa-check"></i> Copiado!';
                    btn.style.background = '#28a745';
                    setTimeout(() => {
                        btn.innerHTML = originalHTML;
                        btn.style.background = '#f7931a';
                    }, 2000);
                })
                .catch(err => {
                    console.error('Erro ao copiar:', err);
                    alert('Erro ao copiar. Copie manualmente o endereço.');
                });
        }
        
        // Verificar status do pagamento via AJAX
        function verificarStatus() {
            const btn = document.querySelector('.refresh-btn');
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verificando...';
            btn.disabled = true;
            
            fetch(`verificar_pagamento.php?id=<?= $compra_id ?>`)
                .then(response => response.json())
                .then(data => {
                    if (data.pago) {
                        // Recarregar a página para mostrar status atualizado
                        window.location.reload();
                    } else {
                        // Restaurar botão
                        setTimeout(() => {
                            btn.innerHTML = originalHTML;
                            btn.disabled = false;
                        }, 1000);
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    setTimeout(() => {
                        btn.innerHTML = originalHTML;
                        btn.disabled = false;
                    }, 1000);
                });
        }
        
        // Auto-verificar a cada 30 segundos se o pagamento ainda está pendente
        <?php if (!$status_pago): ?>
        setInterval(verificarStatus, 30000);
        <?php endif; ?>
        
        // Mostrar tempo desde o pedido
        const timeElement = document.createElement('small');
        timeElement.className = 'text-muted d-block mt-2';
        timeElement.textContent = 'Pedido criado em: <?= date("d/m/Y H:i", strtotime($compra["data_compra"] ?? "now")) ?>';
        document.querySelector('.product-info').appendChild(timeElement);
    </script>
</body>
</html>