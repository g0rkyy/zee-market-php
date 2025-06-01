<?php
require_once 'includes/config.php';

$compra_id = (int)$_GET['id'];

// Busca os dados da compra + carteira do vendedor
$compra = $conn->query("SELECT 
        c.id, c.valor_btc, c.btc_wallet_vendedor, c.pago, c.tx_hash,
        p.nome as produto_nome, p.preco,
        v.btc_wallet as vendedor_wallet
    FROM compras c
    JOIN produtos p ON c.produto_id = p.id
    JOIN vendedores v ON p.vendedor_id = v.id
    WHERE c.id = $compra_id")->fetch_assoc();

// Verifica se a compra existe
if (!$compra) {
    die("Compra não encontrada!");
}

// Modo de simulação (apenas para desenvolvimento)
if (isset($_GET['simular_pagamento'])) {
    $conn->query("UPDATE compras SET pago = 1 WHERE id = $compra_id");
    $compra['pago'] = 1;
}

// Define valores
$valor_btc = $compra['valor_btc'] ?? 0;
$preco_produto = $compra['preco'] ?? 0;
$wallet_vendedor = $compra['vendedor_wallet'] ?? $compra['btc_wallet_vendedor'] ?? '';

// Formata os valores
$valor_btc_formatado = number_format($valor_btc, 8);
$valor_total_formatado = number_format($preco_produto, 2, ',', '.');

// Tempo de confirmação
$tempo_confirmacao = date('H:i', strtotime('+30 minutes'));
$data_atual = date('d/m/Y H:i');
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pagamento com Bitcoin - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #f7931a;
            --success-color: #28a745;
        }
        
        .payment-card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .payment-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }
        
        .qr-code-box {
            width: 220px;
            height: 220px;
            background: white;
            padding: 15px;
            border-radius: 10px;
            margin: 0 auto;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .wallet-address {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            word-break: break-all;
        }
        
        .status-badge {
            padding: 10px 15px;
            border-radius: 8px;
            font-weight: bold;
        }
        
        .status-pago {
            background: #d4edda;
            color: #155724;
        }
        
        .status-pendente {
            background: #fff3cd;
            color: #856404;
        }
        
        .btn-outline-bitcoin {
            color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .btn-outline-bitcoin:hover {
            background: var(--secondary-color);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="payment-card card">
            <div class="payment-header card-header">
                <h3 class="text-center"><i class="fab fa-bitcoin"></i> Pagamento em Bitcoin</h3>
                <h4 class="text-center"><?= htmlspecialchars($compra['produto_nome']) ?></h4>
                <p class="text-center mb-0">Transação #<?= $compra_id ?></p>
            </div>
            
            <div class="card-body">
                <div class="text-center mb-4">
                    <h5>Total a pagar:</h5>
                    <h2 class="text-success"><?= $valor_btc_formatado ?> BTC</h2>
                    <p class="text-muted">≈ R$ <?= $valor_total_formatado ?></p>
                </div>
                
                <div class="text-center mb-4">
                    <div class="qr-code-box mb-3">
                        <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=bitcoin:<?= urlencode($wallet_vendedor) ?>?amount=<?= $valor_btc ?>" 
                             alt="QR Code para pagamento" class="img-fluid">
                    </div>
                    
                    <div class="mb-3">
                        <h6><i class="fas fa-wallet"></i> Enviar para:</h6>
                        <div class="wallet-address mb-2" id="wallet-address">
                            <?= htmlspecialchars($wallet_vendedor) ?>
                        </div>
                        <button class="btn btn-sm btn-outline-bitcoin" onclick="copyToClipboard()">
                            <i class="fas fa-copy"></i> Copiar Endereço
                        </button>
                    </div>
                </div>
                
                <!-- Área de status dinâmica -->
                <div id="status-area">
                    <?php if($compra['pago']): ?>
                        <div class="alert alert-success">
                            <h5><i class="fas fa-check-circle"></i> Pagamento Confirmado!</h5>
                            <p class="mb-1">Seu pagamento foi confirmado com sucesso.</p>
                            <?php if(!empty($compra['tx_hash'])): ?>
                                <p class="mb-0">
                                    Transação: <code><?= htmlspecialchars($compra['tx_hash']) ?></code>
                                </p>
                            <?php endif; ?>
                        </div>
                    <?php else: ?>
                        <div class="alert alert-warning">
                            <h5><i class="fas fa-clock"></i> Aguardando Pagamento</h5>
                            <p class="mb-2">Envie <strong><?= $valor_btc_formatado ?> BTC</strong> para o endereço acima.</p>
                            
                            <div class="d-flex justify-content-between mt-3">
                                <!-- Botão de simulação (remover em produção) -->
                                <button id="simular-pagamento" class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-bolt"></i> Simular Pagamento
                                </button>
                                
                                <button id="atualizar-status" class="btn btn-sm btn-secondary">
                                    <i class="fas fa-sync-alt"></i> Atualizar Status
                                </button>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
                
                <div class="alert alert-info mt-4">
                    <h5><i class="fas fa-info-circle"></i> Instruções:</h5>
                    <ol class="mb-0">
                        <li>Abra sua carteira Bitcoin</li>
                        <li>Digitalize o QR code ou copie o endereço</li>
                        <li>Envie o valor exato de <?= $valor_btc_formatado ?> BTC</li>
                        <li>Aguarde a confirmação (1-3 confirmações)</li>
                    </ol>
                </div>
            </div>
        </div>
    </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
    <script>
        // Função para copiar endereço
        function copyToClipboard() {
            const walletAddress = document.getElementById('wallet-address').textContent;
            navigator.clipboard.writeText(walletAddress)
                .then(() => {
                    const btn = document.querySelector('[onclick="copyToClipboard()"]');
                    btn.innerHTML = '<i class="fas fa-check"></i> Copiado!';
                    setTimeout(() => {
                        btn.innerHTML = '<i class="fas fa-copy"></i> Copiar Endereço';
                    }, 2000);
                });
        }
        
        // Verificar status do pagamento via AJAX
        function verificarStatus() {
            fetch(`verificar_pagamento.php?id=<?= $compra_id ?>`)
                .then(response => response.json())
                .then(data => {
                    if(data.pago) {
                        document.getElementById('status-area').innerHTML = `
                            <div class="alert alert-success">
                                <h5><i class="fas fa-check-circle"></i> Pagamento Confirmado!</h5>
                                <p class="mb-1">Seu pagamento foi confirmado com sucesso.</p>
                                ${data.tx_hash ? `<p class="mb-0">Transação: <code>${data.tx_hash}</code></p>` : ''}
                            </div>
                        `;
                    }
                });
        }
        
        // Event Listeners
        document.getElementById('atualizar-status')?.addEventListener('click', verificarStatus);
        document.getElementById('simular-pagamento')?.addEventListener('click', () => {
            window.location.href = window.location.href + '&simular_pagamento=1';
        });
        
        // Verificar a cada 30 segundos
        setInterval(verificarStatus, 30000);
    </script>
</body>
</html>