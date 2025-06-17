<?php
/**
 * API para verificar status do sistema
 * Local: admin/get_system_status.php
 */

require_once '../includes/config.php';

header('Content-Type: application/json');

try {
    // Verificar modo real
    $real_mode = $conn->query("
        SELECT config_value FROM system_config 
        WHERE config_key = 'real_mode'
    ")->fetch_row()[0] ?? '0';
    
    // Estatísticas rápidas
    $stats = [
        'real_mode' => ($real_mode == '1'),
        'total_users' => $conn->query("SELECT COUNT(*) FROM users")->fetch_row()[0],
        'pending_transactions' => $conn->query("SELECT COUNT(*) FROM btc_transactions WHERE status = 'pending'")->fetch_row()[0],
        'last_transaction' => $conn->query("SELECT MAX(created_at) FROM btc_transactions")->fetch_row()[0],
        'server_time' => date('Y-m-d H:i:s'),
        'php_version' => PHP_VERSION,
        'database_size' => getDatabaseSize()
    ];
    
    echo json_encode($stats);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

function getDatabaseSize() {
    global $conn;
    
    try {
        $result = $conn->query("
            SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS 'DB Size in MB'
            FROM information_schema.tables 
            WHERE table_schema = 'zee_market'
        ");
        
        return $result->fetch_row()[0] ?? 0;
    } catch (Exception $e) {
        return 0;
    }
}
?>