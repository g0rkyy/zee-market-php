<?php
class SecurityLogger {
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
    }
    
    public function logAttempt($userId, $action, $details) {
        $this->log($userId, $action, 'attempt', $details);
    }
    
    public function logSuccess($userId, $action, $details) {
        $this->log($userId, $action, 'success', $details);
    }
    
    public function logError($userId, $action, $details) {
        $this->log($userId, $action, 'error', $details);
    }
    
    private function log($userId, $action, $level, $details) {
        $stmt = $this->conn->prepare("
            INSERT INTO security_logs 
            (user_id, action, level, details, ip_address, user_agent, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $detailsJson = json_encode($details);
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $stmt->bind_param("isssss", 
            $userId, $action, $level, $detailsJson, $ipAddress, $userAgent
        );
        $stmt->execute();
        
        // Log crítico também em arquivo
        if ($level === 'error') {
            error_log("SECURITY_LOG: User:$userId Action:$action Level:$level Details:$detailsJson");
        }
    }
}