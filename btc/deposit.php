<?php
require_once '../includes/config.php';
require_once '../includes/blockchain_real.php';
require_once '../includes/functions.php';

// Verificar se usuário está logado
if (!isLoggedIn()) {
    header('Location: ../login.php');
    exit;
}

// Inicializar blockchain
$blockchain = new ZeeMarketBlockchain($conn);

// Rate limiting
//try {
//    checkRateLimit($_SESSION['user_id'], 'deposit', 10); // 10 tentativas por hora
//} catch (Exception $e) {
//    die("Muitas tentativas. Tente novamente em alguns minutos.");
//}

// Buscar dados do usuário
$stmt = $conn->prepare("SELECT id, btc_deposit_address, eth_deposit_address FROM users WHERE id = ?");
$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();

// Gerar/recuperar endereços de depósito
if (empty($user['btc_deposit_address'])) {
    try {
        $btc_result = $blockchain->generateBitcoinAddress($_SESSION['user_id']);
        if (!$btc_result['success']) {
            throw new Exception("Erro ao gerar endereço Bitcoin");
        }
        $btc_address = $btc_result['address'];
    } catch (Exception $e) {
        error_log("Erro na geração BTC: " . $e->getMessage());
        $btc_address = null;
    }
} else {
    $btc_address = $user['btc_deposit_address'];
}

if (empty($user['eth_deposit_address'])) {
    try {
        $eth_result = $blockchain->generateEthereumAddress($_SESSION['user_id']);
        if (!$eth_result['success']) {
            throw new Exception("Erro ao gerar endereço Ethereum");
        }
        $eth_address = $eth_result['address'];
    } catch (Exception $e) {
        error_log("Erro na geração ETH: " . $e->getMessage());
        $eth_address = null;
    }
} else {
    $eth_address = $user['eth_deposit_address'];
}

// Buscar histórico de depósitos
$stmt = $conn->prepare("
    SELECT * FROM (
        SELECT 'BTC' as crypto, amount, status, created_at, tx_hash 
        FROM btc_transactions 
        WHERE user_id = ? AND type = 'deposit'
        UNION ALL
        SELECT 'ETH' as crypto, amount, status, created_at, tx_hash 
        FROM eth_transactions 
        WHERE user_id = ? AND type = 'deposit'
    ) as deposits 
    ORDER BY created_at DESC 
    LIMIT 10
");
$stmt->bind_param("ii", $_SESSION['user_id'], $_SESSION['user_id']);
$stmt->execute();
$deposits = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Depósito - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: #1a1a1a;
            color: #e0e0e0;
        }
        .deposit-card {
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .crypto-address {
            background: #1a1a1a;
            padding: 10px;
            border-radius: 5px;
            word-break: break-all;
            font-family: monospace;
        }
        .deposit-history {
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 10px;
            padding: 20px;
        }
        .status-pending { color: #ffc107; }
        .status-confirmed { color: #28a745; }
        .status-failed { color: #dc3545; }
        .qr-code {
            background: white;
            padding: 10px;
            border-radius: 5px;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h2><i class="fas fa-download"></i> Depósito de Criptomoedas</h2>
        
        <!-- Bitcoin Deposit -->
        <div class="deposit-card">
            <h4><i class="fab fa-bitcoin"></i> Depósito Bitcoin</h4>
            <?php if ($btc_address): ?>
                <div class="alert alert-info">
                    <strong>Seu endereço Bitcoin para depósito:</strong>
                    <div class="crypto-address mt-2">
                        <?= htmlspecialchars($btc_address) ?>
                    </div>
                </div>
                <div class="text-center mb-3">
                    <div class="qr-code">
                        <img src="https://chart.googleapis.com/chart?chs=150x150&cht=qr&chl=bitcoin:<?= $btc_address ?>" 
                             alt="Bitcoin QR Code">
                    </div>
                </div>
            <?php else: ?>
                <div class="alert alert-danger">
                    Erro ao gerar endereço Bitcoin. Por favor, tente novamente mais tarde.
                </div>
            <?php endif; ?>
        </div>

        <!-- Ethereum Deposit -->
        <div class="deposit-card">
            <h4><i class="fab fa-ethereum"></i> Depósito Ethereum</h4>
            <?php if ($eth_address): ?>
                <div class="alert alert-info">
                    <strong>Seu endereço Ethereum para depósito:</strong>
                    <div class="crypto-address mt-2">
                        <?= htmlspecialchars($eth_address) ?>
                    </div>
                </div>
                <div class="text-center mb-3">
                    <div class="qr-code">
                        <img src="https://chart.googleapis.com/chart?chs=150x150&cht=qr&chl=ethereum:<?= $eth_address ?>" 
                             alt="Ethereum QR Code">
                    </div>
                </div>
            <?php else: ?>
                <div class="alert alert-danger">
                    Erro ao gerar endereço Ethereum. Por favor, tente novamente mais tarde.
                </div>
            <?php endif; ?>
        </div>

        <!-- Deposit History -->
        <div class="deposit-history">
            <h4><i class="fas fa-history"></i> Histórico de Depósitos</h4>
            <?php if ($deposits): ?>
                <div class="table-responsive">
                    <table class="table table-dark">
                        <thead>
                            <tr>
                                <th>Cripto</th>
                                <th>Quantidade</th>
                                <th>Status</th>
                                <th>Data</th>
                                <th>TX Hash</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($deposits as $deposit): ?>
                                <tr>
                                    <td>
                                        <i class="fab fa-<?= strtolower($deposit['crypto']) ?>"></i>
                                        <?= $deposit['crypto'] ?>
                                    </td>
                                    <td><?= number_format($deposit['amount'], 8) ?></td>
                                    <td>
                                        <span class="status-<?= $deposit['status'] ?>">
                                            <?= ucfirst($deposit['status']) ?>
                                        </span>
                                    </td>
                                    <td><?= date('d/m/Y H:i', strtotime($deposit['created_at'])) ?></td>
                                    <td>
                                        <a href="https://blockchain.info/tx/<?= $deposit['tx_hash'] ?>" 
                                           target="_blank" 
                                           class="text-info">
                                            <?= substr($deposit['tx_hash'], 0, 8) ?>...
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div class="alert alert-info">
                    Nenhum depósito encontrado.
                </div>
            <?php endif; ?>
        </div>

        <!-- Security Notice -->
        <div class="alert alert-warning mt-4">
            <h5><i class="fas fa-shield-alt"></i> Informações Importantes:</h5>
            <ul>
                <li>Envie apenas BTC para endereço Bitcoin e ETH para endereço Ethereum</li>
                <li>Depósitos são creditados após 3 confirmações na blockchain</li>
                <li>Guarde o TX Hash de suas transações</li>
                <li>Em caso de problemas, contate o suporte com o TX Hash</li>
            </ul>
        </div>
    </div>

    <script src="../assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // Atualizar status dos depósitos a cada 60 segundos
        setInterval(() => {
            fetch('../api/check_deposits.php')
            .then(response => response.json())
            .then(data => {
                if (data.updated) {
                    location.reload();
                }
            });
        }, 60000);
    </script>
</body>
</html>