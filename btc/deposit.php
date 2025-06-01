<?php
require_once '../includes/config.php';
require_once '../includes/btc_functions.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit;
}

$user = getUserById($_SESSION['user_id']);
$btcAddress = generateDepositAddress($user['id']);

// Atualiza o endereço de depósito do usuário se necessário
if (empty($user['btc_deposit_address'])) {
    updateUserDepositAddress($user['id'], $btcAddress);
    $user['btc_deposit_address'] = $btcAddress;
}

// Busca transações pendentes
$pendingTransactions = getPendingDeposits($user['id']);
?>

<h2>Depositar Bitcoin</h2>
<div class="card">
    <div class="card-body">
        <p>Envie Bitcoin para o endereço abaixo:</p>
        <div class="input-group mb-3">
            <input type="text" class="form-control" id="btcAddress" value="<?= htmlspecialchars($btcAddress) ?>" readonly>
            <button class="btn btn-outline-secondary" onclick="copyAddress()">Copiar</button>
        </div>
        
        <div class="text-center mb-3">
            <div id="qrcode"></div>
            <small class="text-muted">Escaneie este QR code com sua carteira</small>
        </div>
        
        <div class="alert alert-info">
            <strong>Atenção:</strong> 
            <ul>
                <li>Depósitos podem levar de 10 a 30 minutos para serem confirmados</li>
                <li>Envie apenas Bitcoin (BTC) para este endereço</li>
                <li>Depósitos mínimos: 0.0001 BTC</li>
            </ul>
        </div>
        
        <?php if (!empty($pendingTransactions)): ?>
        <h4>Depósitos Pendentes</h4>
        <table class="table">
            <thead>
                <tr>
                    <th>Tx Hash</th>
                    <th>Valor</th>
                    <th>Confirmações</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($pendingTransactions as $tx): ?>
                <tr>
                    <td><?= substr($tx['tx_hash'], 0, 10) ?>...</td>
                    <td><?= $tx['amount'] ?> BTC</td>
                    <td><?= $tx['confirmations'] ?>/3</td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<script>
function copyAddress() {
    const copyText = document.getElementById("btcAddress");
    copyText.select();
    copyText.setSelectionRange(0, 99999);
    document.execCommand("copy");
    alert("Endereço copiado: " + copyText.value);
}

// Gerar QR Code
new QRCode(document.getElementById("qrcode"), "bitcoin:<?= $btcAddress ?>");
</script>
<script src="../assets/js/qrcode.min.js"></script>