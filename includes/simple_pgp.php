<?php
/**
 * SISTEMA PGP SIMPLES QUE FUNCIONA
 * Salve como: includes/simple_pgp.php
 */

class SimplePGP {
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->createTable();
    }
    
    private function createTable() {
        $sql = "CREATE TABLE IF NOT EXISTS site_pgp_keys (
            id INT AUTO_INCREMENT PRIMARY KEY,
            site_name VARCHAR(50) NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            private_key_encrypted TEXT NOT NULL,
            passphrase VARCHAR(255) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        $this->conn->query($sql);
    }
    
    /**
     * Verificar se chaves existem
     */
    public function keysExist() {
        try {
            $stmt = $this->conn->prepare("SELECT COUNT(*) FROM site_pgp_keys WHERE site_name = 'zeemarket'");
            $stmt->execute();
            return $stmt->get_result()->fetch_row()[0] > 0;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Obter chave pública
     */
    public function getPublicKey() {
        if (!$this->keysExist()) {
            return null;
        }
        
        try {
            $stmt = $this->conn->prepare("SELECT public_key FROM site_pgp_keys WHERE site_name = 'zeemarket'");
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            return $result['public_key'] ?? null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    /**
     * Descriptografar mensagem
     */
    public function decryptMessage($encryptedMessage) {
        try {
            if (!$this->keysExist()) {
                throw new Exception("Chaves PGP não configuradas");
            }
            
            // Buscar chaves do banco
            $stmt = $this->conn->prepare("SELECT private_key_encrypted, passphrase FROM site_pgp_keys WHERE site_name = 'zeemarket'");
            $stmt->execute();
            $keys = $stmt->get_result()->fetch_assoc();
            
            if (!$keys) {
                throw new Exception("Chaves não encontradas no banco");
            }
            
            // Criar ambiente temporário
            $tempDir = sys_get_temp_dir() . '/decrypt_' . uniqid();
            mkdir($tempDir, 0700, true);
            $oldHome = getenv('GNUPGHOME');
            putenv("GNUPGHOME=" . $tempDir);
            
            // Importar chave privada
            $privateKeyFile = $tempDir . '/private.asc';
            file_put_contents($privateKeyFile, $keys['private_key_encrypted']);
            
            $importCmd = "gpg --batch --import '" . $privateKeyFile . "' 2>&1";
            $importResult = shell_exec($importCmd);
            
            // Salvar mensagem criptografada
            $messageFile = $tempDir . '/message.asc';
            file_put_contents($messageFile, $encryptedMessage);
            
            // Descriptografar (chave sem senha)
            $decryptCmd = "gpg --batch --yes --decrypt '" . $messageFile . "' 2>/dev/null";
            $decryptedMessage = shell_exec($decryptCmd);
            
            // Limpar
            shell_exec("rm -rf '" . $tempDir . "'");
            if ($oldHome) {
                putenv("GNUPGHOME=" . $oldHome);
            }
            
            if (empty($decryptedMessage)) {
                throw new Exception("Falha na descriptografia");
            }
            
            return [
                'success' => true,
                'message' => trim($decryptedMessage)
            ];
            
        } catch (Exception $e) {
            // Limpar em caso de erro
            if (isset($tempDir) && is_dir($tempDir)) {
                shell_exec("rm -rf '" . $tempDir . "'");
            }
            
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Salvar mensagem descriptografada
     */
    public function saveMessage($userId, $encryptedContent, $decryptedContent, $type = 'contact') {
        // Criar tabela se não existir
        $this->conn->query("CREATE TABLE IF NOT EXISTS user_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            message_type VARCHAR(20) DEFAULT 'contact',
            encrypted_content LONGTEXT NOT NULL,
            decrypted_content LONGTEXT NOT NULL,
            sender_ip VARCHAR(45),
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user (user_id)
        )");
        
        $senderIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt = $this->conn->prepare("
            INSERT INTO user_messages (user_id, message_type, encrypted_content, decrypted_content, sender_ip) 
            VALUES (?, ?, ?, ?, ?)
        ");
        $stmt->bind_param("issss", $userId, $type, $encryptedContent, $decryptedContent, $senderIP);
        
        if ($stmt->execute()) {
            return [
                'success' => true,
                'message_id' => $this->conn->insert_id
            ];
        } else {
            return [
                'success' => false,
                'error' => $stmt->error
            ];
        }
    }
}

// Inicializar automaticamente
try {
    $simplePGP = new SimplePGP($conn);
} catch (Exception $e) {
    error_log("Erro ao inicializar SimplePGP: " . $e->getMessage());
    $simplePGP = null;
}
?>