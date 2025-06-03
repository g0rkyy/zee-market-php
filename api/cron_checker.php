<?php
/**
 * SISTEMA DE VERIFICAÇÃO AUTOMÁTICA (substitui cron)
 * Local: api/cron_checker.php
 * Acesse: /api/cron_checker.php para executar manualmente
 */

require_once '../includes/config.php';
require_once '../includes/btc_functions.php';

// Headers para AJAX
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// Log de execução
function logExecution($message) {
    $logFile = '../logs/cron_' . date('Y-m-d') . '.log';
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($logFile, "[$timestamp] $message\n", FILE_APPEND | LOCK_EX);
}

try {
    $startTime = microtime(true);
    $results = [];
    
    logExecution("Iniciando verificação automática");
    
    // 1. Verificar depósitos pendentes
    $depositsChecked = checkAllPendingDeposits();
    $results['deposits_checked'] = $depositsChecked;
    logExecution("Verificados $depositsChecked depósitos");
    
    // 2. Atualizar cotações de criptomoedas
    $rates = updateCryptoPrices();
    $results['rates_updated'] = $rates;
    logExecution("Cotações atualizadas");
    
    // 3. Limpar transações antigas (mais de 30 dias)
    $cleaned = cleanOldTransactions();
    $results['cleaned_transactions'] = $cleaned;
    logExecution("$cleaned transações antigas limpas");
    
    // 4. Verificar transações suspeitas
    $suspicious = detectSuspiciousActivity();
    $results['suspicious_detected'] = count($suspicious);
    logExecution(count($suspicious) . " atividades suspeitas detectadas");
    
    // 5. Backup automático (semanal)
    if (date('w') == 0) { // Domingo
        $backup = createBackup();
        $results['backup_created'] = $backup;
        logExecution("Backup criado: " . ($backup ? 'sucesso' : 'falha'));
    }
    
    $executionTime = round((microtime(true) - $startTime) * 1000, 2);
    $results['execution_time_ms'] = $executionTime;
    $results['timestamp'] = date('Y-m-d H:i:s');
    $results['status'] = 'success';
    
    logExecution("Verificação concluída em {$executionTime}ms");
    
    echo json_encode($results, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    $error = "Erro na verificação: " . $e->getMessage();
    logExecution($error);
    
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'error' => $e->getMessage(),
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Atualizar preços de criptomoedas
 */
function updateCryptoPrices() {
    global $conn;
    
    try {
        $rates = getCryptoRates();
        
        if ($rates) {
            // Atualizar preços dos produtos
            $stmt = $conn->prepare("
                UPDATE produtos SET 
                    preco_btc = preco / ?,
                    preco_eth = preco / ?
                WHERE preco > 0
            ");
            $stmt->bind_param("dd", 
                $rates['bitcoin']['usd'], 
                $rates['ethereum']['usd']
            );
            $stmt->execute();
            
            // Salvar cotações históricas
            $stmt = $conn->prepare("
                INSERT INTO crypto_rates (btc_usd, eth_usd, xmr_usd, created_at) 
                VALUES (?, ?, ?, NOW())
            ");
            $stmt->bind_param("ddd", 
                $rates['bitcoin']['usd'],
                $rates['ethereum']['usd'],
                $rates['monero']['usd']
            );
            $stmt->execute();
            
            return true;
        }
        
        return false;
        
    } catch (Exception $e) {
        error_log("Erro ao atualizar preços: " . $e->getMessage());
        return false;
    }
}

/**
 * Limpar transações antigas
 */
function cleanOldTransactions() {
    global $conn;
    
    try {
        // Limpar transações rejeitadas há mais de 30 dias
        $result = $conn->query("
            DELETE FROM btc_transactions 
            WHERE status = 'rejected' 
            AND created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        
        return $conn->affected_rows;
        
    } catch (Exception $e) {
        error_log("Erro ao limpar transações: " . $e->getMessage());
        return 0;
    }
}

/**
 * Detectar atividade suspeita
 */
function detectSuspiciousActivity() {
    global $conn;
    
    try {
        $suspicious = [];
        
        // Usuários com muitas transações em 1 hora
        $stmt = $conn->query("
            SELECT user_id, COUNT(*) as tx_count, SUM(amount) as total_amount
            FROM btc_transactions 
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY user_id 
            HAVING tx_count > 20 OR total_amount > 10.0
        ");
        
        while ($row = $stmt->fetch_assoc()) {
            $suspicious[] = [
                'type' => 'high_frequency',
                'user_id' => $row['user_id'],
                'details' => $row
            ];
        }
        
        // Transações com valores muito altos
        $stmt = $conn->query("
            SELECT * FROM btc_transactions 
            WHERE amount > 5.0 
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");
        
        while ($row = $stmt->fetch_assoc()) {
            $suspicious[] = [
                'type' => 'high_value',
                'user_id' => $row['user_id'],
                'details' => $row
            ];
        }
        
        // Salvar alertas no banco
        foreach ($suspicious as $alert) {
            $stmt = $conn->prepare("
                INSERT INTO security_alerts (type, user_id, details, created_at) 
                VALUES (?, ?, ?, NOW())
            ");
            $details = json_encode($alert['details']);
            $stmt->bind_param("sis", $alert['type'], $alert['user_id'], $details);
            $stmt->execute();
        }
        
        return $suspicious;
        
    } catch (Exception $e) {
        error_log("Erro ao detectar atividade suspeita: " . $e->getMessage());
        return [];
    }
}

/**
 * Criar backup do banco
 */
function createBackup() {
    try {
        $backupDir = '../backups';
        if (!file_exists($backupDir)) {
            mkdir($backupDir, 0755, true);
        }
        
        $filename = $backupDir . '/backup_' . date('Y-m-d_H-i-s') . '.sql';
        
        // Comando mysqldump (adapte conforme seu sistema)
        $command = "mysqldump -h localhost -u root zee_market > $filename";
        
        exec($command, $output, $returnVar);
        
        if ($returnVar === 0 && file_exists($filename)) {
            // Manter apenas os últimos 10 backups
            $backups = glob($backupDir . '/backup_*.sql');
            if (count($backups) > 10) {
                sort($backups);
                for ($i = 0; $i < count($backups) - 10; $i++) {
                    unlink($backups[$i]);
                }
            }
            
            return true;
        }
        
        return false;
        
    } catch (Exception $e) {
        error_log("Erro no backup: " . $e->getMessage());
        return false;
    }
}

// Executar automaticamente via JavaScript se acessado pelo navegador
if (!isset($_GET['api'])) {
    echo '<script>
        fetch(window.location.href + "?api=1")
        .then(response => response.json())
        .then(data => {
            console.log("Verificação automática:", data);
            document.body.innerHTML = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
        });
    </script>';
}
?>