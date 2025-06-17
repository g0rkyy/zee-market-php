<?php
// Dashboard para monitorar transações em tempo real
header('Content-Type: application/json');

$stats = [
    'pending_deposits' => getPendingDepositsCount(),
    'daily_volume' => getDailyVolume(),
    'active_users' => getActiveUsers()
];

echo json_encode($stats);
?>