<?php
class FraudDetectionEngine {
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
    }
    
    public function analyzeWithdrawal($userId, $amount, $crypto, $toAddress) {
        $riskScore = 0;
        $alerts = [];
        
        // 1. Verificar padrões suspeitos
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as recent_withdrawals,
                   SUM(amount) as total_amount
            FROM withdrawal_requests 
            WHERE user_id = ? 
            AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            AND status != 'failed'
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $recent = $stmt->get_result()->fetch_assoc();
        
        if ($recent['recent_withdrawals'] > 5) {
            $riskScore += 30;
            $alerts[] = 'Múltiplos saques em 24h';
        }
        
        // 2. Verificar endereço novo
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as address_usage 
            FROM withdrawal_requests 
            WHERE to_address = ? AND status = 'completed'
        ");
        $stmt->bind_param("s", $toAddress);
        $stmt->execute();
        $addressUsage = $stmt->get_result()->fetch_assoc()['address_usage'];
        
        if ($addressUsage === 0) {
            $riskScore += 20;
            $alerts[] = 'Endereço nunca usado';
        }
        
        // 3. Verificar valor em relação ao histórico
        $stmt = $this->conn->prepare("
            SELECT AVG(amount) as avg_amount 
            FROM withdrawal_requests 
            WHERE user_id = ? AND status = 'completed'
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $avgAmount = $stmt->get_result()->fetch_assoc()['avg_amount'] ?? 0;
        
        if ($avgAmount > 0 && $amount > ($avgAmount * 5)) {
            $riskScore += 25;
            $alerts[] = 'Valor muito acima da média';
        }
        
        // 4. Verificar IP e User-Agent
        $currentIP = $_SERVER['REMOTE_ADDR'] ?? '';
        $stmt = $this->conn->prepare("
            SELECT DISTINCT ip_address 
            FROM user_sessions 
            WHERE user_id = ? 
            AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $recentIPs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        $ipKnown = false;
        foreach ($recentIPs as $ip) {
            if ($ip['ip_address'] === $currentIP) {
                $ipKnown = true;
                break;
            }
        }
        
        if (!$ipKnown) {
            $riskScore += 40;
            $alerts[] = 'IP desconhecido';
        }
        
        // 5. DECISÃO BASEADA NO SCORE
        if ($riskScore >= 70) {
            throw new Exception("Transação bloqueada: Alto risco de fraude. Alerts: " . implode(', ', $alerts));
        } elseif ($riskScore >= 40) {
            // Requerer aprovação manual
            $this->requireManualApproval($userId, $riskScore, $alerts);
        }
        
        return ['risk_score' => $riskScore, 'alerts' => $alerts];
    }
    
    private function requireManualApproval($userId, $riskScore, $alerts) {
        // Implementar lógica para requerer aprovação manual
        // Pode ser um registro no banco de dados ou notificação
    }
}