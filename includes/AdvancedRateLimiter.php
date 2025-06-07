<?php
class AdvancedRateLimiter {
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
    }
    
    public function checkLimits($userId, $action, $limits) {
        // Verificar limites por hora
        $hourly = $this->getCount($userId, $action, '1 HOUR');
        if ($hourly >= $limits['per_hour']) {
            throw new Exception("Limite horário excedido para esta ação");
        }
        
        // Verificar limites diários
        $daily = $this->getCount($userId, $action, '1 DAY');
        if ($daily >= $limits['per_day']) {
            throw new Exception("Limite diário excedido para esta ação");
        }
        
        // Verificar limites semanais
        $weekly = $this->getCount($userId, $action, '1 WEEK');
        if ($weekly >= $limits['per_week']) {
            throw new Exception("Limite semanal excedido para esta ação");
        }
    }
    
    public function incrementFailedAttempts($userId, $action) {
        $stmt = $this->conn->prepare("
            INSERT INTO rate_limiting_logs 
            (user_id, action, result, ip_address, created_at) 
            VALUES (?, ?, 'failed', ?, NOW())
        ");
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt->bind_param("iss", $userId, $action, $ip);
        $stmt->execute();
    }
    
    private function getCount($userId, $action, $interval) {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as count 
            FROM rate_limiting_logs 
            WHERE user_id = ? 
            AND action = ?
            AND created_at > DATE_SUB(NOW(), INTERVAL $interval)
        ");
        $stmt->bind_param("is", $userId, $action);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        return $result['count'] ?? 0;
    }
}