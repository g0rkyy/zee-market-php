<?php
// Verificar pagamentos reais via blockchain
require_once '../includes/btc_functions.php';

// Execute a cada 5 minutos via cron
$processed = checkAllPendingDeposits();
echo "Processadas: $processed transações";
?>