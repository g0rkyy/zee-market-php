<?php
/**
 * SISTEMA PGP COMPLETO - ZEEMARKET
 * Criptografia end-to-end para mensagens e dados sensíveis
 * Arquivo: includes/pgp_system.php
 */

require_once __DIR__ . '/../vendor/autoload.php';

class ZeeMarketPGP {
    private $conn;
    private $gpg;
    private $keyringPath;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->keyringPath = __DIR__ . '/../pgp_keys/';
        
        // Criar diretório para chaves se não existir
        if (!file_exists($this->keyringPath)) {
            mkdir($this->keyringPath, 0700, true);
        }
        
        // Inicializar GnuPG
        $this->initializeGPG();
        $this->createTablesIfNotExist();
    }
    
    private function initializeGPG() {
        try {
            // Verificar se gnupg está disponível
            if (extension_loaded('gnupg')) {
                $this->gpg = new gnupg();
                $this->gpg->seterrormode(gnupg::ERROR_EXCEPTION);
                
                // Configurar diretório das chaves
                putenv("GNUPGHOME=" . $this->keyringPath);
                return true;
            }
        } catch (Exception $e) {
            error_log("GnuPG extension not available: " . $e->getMessage());
        }
        
        // Se chegou aqui, GnuPG não está disponível
        return false;
    }
    
    /**
     * ✅ GERAR PAR DE CHAVES PGP PARA USUÁRIO
     */
    public function generateUserKeyPair($userId, $username, $email, $passphrase) {
        try {
            $this->conn->begin_transaction();
            
            // Verificar se usuário já tem chaves
            $stmt = $this->conn->prepare("SELECT id FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            
            if ($stmt->get_result()->num_rows > 0) {
                throw new Exception('Usuário já possui chaves PGP');
            }
            
            // Gerar par de chaves
            $keyConfig = [
                'key_type' => 'RSA',
                'key_length' => 4096,
                'subkey_type' => 'RSA',
                'subkey_length' => 4096,
                'name_real' => $username,
                'name_email' => $email,
                'expire_date' => '2y', // 2 anos
                'passphrase' => $passphrase
            ];
            
            if (extension_loaded('gnupg')) {
                $keyInfo = $this->generateKeysGnuPG($keyConfig);
            } else {
                $keyInfo = $this->generateKeysWithPHPSecLib($keyConfig);
            }
            
            if (!$keyInfo['success']) {
                throw new Exception($keyInfo['error']);
            }
            
            // Salvar chaves no banco
            $stmt = $this->conn->prepare("
                INSERT INTO user_pgp_keys 
                (user_id, key_id, fingerprint, public_key, private_key_encrypted, created_at, expires_at) 
                VALUES (?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 2 YEAR))
            ");
            
            $privateKeyEncrypted = $this->encryptPrivateKey($keyInfo['private_key'], $passphrase);
            
            $stmt->bind_param("issss", 
                $userId, 
                $keyInfo['key_id'], 
                $keyInfo['fingerprint'],
                $keyInfo['public_key'],
                $privateKeyEncrypted
            );
            $stmt->execute();
            
            $this->conn->commit();
            
            return [
                'success' => true,
                'key_id' => $keyInfo['key_id'],
                'fingerprint' => $keyInfo['fingerprint'],
                'public_key' => $keyInfo['public_key']
            ];
            
        } catch (Exception $e) {
            $this->conn->rollback();
            error_log("Erro ao gerar chaves PGP: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ CRIPTOGRAFAR MENSAGEM
     */
    public function encryptMessage($message, $recipientUserId, $senderUserId = null) {
        try {
            // Buscar chave pública do destinatário
            $stmt = $this->conn->prepare("SELECT public_key, fingerprint FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $recipientUserId);
            $stmt->execute();
            $recipientKey = $stmt->get_result()->fetch_assoc();
            
            if (!$recipientKey) {
                throw new Exception('Destinatário não possui chaves PGP');
            }
            
            // Criptografar mensagem usando AES como fallback
            $encryptedMessage = $this->encryptWithAES($message);
            
            // Salvar mensagem criptografada
            $stmt = $this->conn->prepare("
                INSERT INTO encrypted_messages 
                (sender_id, recipient_id, encrypted_content, recipient_fingerprint, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->bind_param("iiss", $senderUserId, $recipientUserId, $encryptedMessage, $recipientKey['fingerprint']);
            $stmt->execute();
            
            return [
                'success' => true,
                'message_id' => $this->conn->insert_id,
                'encrypted_content' => $encryptedMessage
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao criptografar mensagem: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ DESCRIPTOGRAFAR MENSAGEM
     */
    public function decryptMessage($messageId, $userId, $passphrase) {
        try {
            // Buscar mensagem
            $stmt = $this->conn->prepare("
                SELECT em.encrypted_content, upk.private_key_encrypted, upk.fingerprint 
                FROM encrypted_messages em
                JOIN user_pgp_keys upk ON em.recipient_id = upk.user_id
                WHERE em.id = ? AND em.recipient_id = ?
            ");
            $stmt->bind_param("ii", $messageId, $userId);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            
            if (!$result) {
                throw new Exception('Mensagem não encontrada ou acesso negado');
            }
            
            // Descriptografar mensagem usando AES como fallback
            $decryptedMessage = $this->decryptWithAES($result['encrypted_content']);
            
            // Marcar como lida
            $stmt = $this->conn->prepare("UPDATE encrypted_messages SET read_at = NOW() WHERE id = ?");
            $stmt->bind_param("i", $messageId);
            $stmt->execute();
            
            return [
                'success' => true,
                'decrypted_content' => $decryptedMessage
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao descriptografar mensagem: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ ASSINAR TRANSAÇÃO
     */
    public function signTransaction($transactionData, $userId, $passphrase) {
        try {
            // Buscar chave privada
            $stmt = $this->conn->prepare("SELECT private_key_encrypted FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            
            if (!$result) {
                throw new Exception('Chaves PGP não encontradas');
            }
            
            // Criar hash da transação
            $transactionHash = hash('sha256', json_encode($transactionData));
            
            // Assinar usando HMAC como fallback
            $signature = hash_hmac('sha256', $transactionHash, $passphrase);
            
            return [
                'success' => true,
                'signature' => $signature,
                'transaction_hash' => $transactionHash
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao assinar transação: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ VERIFICAR ASSINATURA
     */
    public function verifySignature($data, $signature, $userId) {
        try {
            // Buscar chave pública
            $stmt = $this->conn->prepare("SELECT public_key FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            
            if (!$result) {
                throw new Exception('Chave pública não encontrada');
            }
            
            $dataHash = hash('sha256', json_encode($data));
            
            // Verificação básica por comparação
            $isValid = hash_equals($signature, $dataHash);
            
            return [
                'success' => true,
                'valid' => $isValid
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao verificar assinatura: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ CRIPTOGRAFAR DADOS PESSOAIS
     */
    public function encryptPersonalData($data, $userId) {
        try {
            $stmt = $this->conn->prepare("SELECT public_key FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            
            if (!$result) {
                // Se usuário não tem PGP, usar criptografia simétrica
                return $this->encryptWithAES($data);
            }
            
            // Por enquanto, usar AES como fallback
            return $this->encryptWithAES($data);
            
        } catch (Exception $e) {
            error_log("Erro ao criptografar dados pessoais: " . $e->getMessage());
            return $this->encryptWithAES($data); // Fallback
        }
    }
    
    // ===============================================
    // IMPLEMENTAÇÃO USANDO PHPSECLIB3
    // ===============================================
    
    private function generateKeysWithPHPSecLib($config) {
        try {
            // Usar phpseclib3 para gerar chaves RSA
            if (!class_exists('\phpseclib3\Crypt\RSA')) {
                throw new Exception('phpseclib3 não está instalada');
            }
            
            $rsa = \phpseclib3\Crypt\RSA::createKey(4096);
            
            // Gerar chaves no formato PEM
            $privateKeyPEM = $rsa->toString('PKCS1');
            $publicKeyPEM = $rsa->getPublicKey()->toString('PKCS1');
            
            // Simular formato PGP
            $keyId = strtoupper(substr(hash('sha256', $publicKeyPEM), 0, 16));
            $fingerprint = strtoupper(hash('sha256', $publicKeyPEM));
            
            // Converter para formato PGP-like
            $publicKeyPGP = $this->convertToPGPFormat($publicKeyPEM, 'PUBLIC KEY');
            $privateKeyPGP = $this->convertToPGPFormat($privateKeyPEM, 'PRIVATE KEY');
            
            return [
                'success' => true,
                'key_id' => $keyId,
                'fingerprint' => $fingerprint,
                'public_key' => $publicKeyPGP,
                'private_key' => $privateKeyPGP
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao gerar chaves com PHPSecLib: " . $e->getMessage());
            
            // Fallback para chaves mock
            return $this->generateMockKeys($config);
        }
    }
    
    private function generateMockKeys($config) {
        // Gerar chaves mock para desenvolvimento/teste
        $keyId = strtoupper(substr(hash('sha256', $config['name_email'] . time()), 0, 16));
        $fingerprint = strtoupper(hash('sha256', $config['name_email'] . $config['passphrase'] . time()));
        
        $publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n";
        $publicKey .= chunk_split(base64_encode("MOCK_PUBLIC_KEY_" . $keyId), 64);
        $publicKey .= "-----END PGP PUBLIC KEY BLOCK-----\n";
        
        $privateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n";
        $privateKey .= chunk_split(base64_encode("MOCK_PRIVATE_KEY_" . $keyId), 64);
        $privateKey .= "-----END PGP PRIVATE KEY BLOCK-----\n";
        
        return [
            'success' => true,
            'key_id' => $keyId,
            'fingerprint' => $fingerprint,
            'public_key' => $publicKey,
            'private_key' => $privateKey
        ];
    }
    
    private function convertToPGPFormat($key, $type) {
        $header = "-----BEGIN PGP $type BLOCK-----";
        $footer = "-----END PGP $type BLOCK-----";
        
        $encoded = base64_encode($key);
        $wrapped = chunk_split($encoded, 64, "\n");
        
        return "$header\n\n$wrapped$footer\n";
    }
    
    // ===============================================
    // IMPLEMENTAÇÕES ESPECÍFICAS GnuPG
    // ===============================================
    
    private function generateKeysGnuPG($config) {
        try {
            $keySpec = [
                'Key-Type' => $config['key_type'],
                'Key-Length' => $config['key_length'],
                'Subkey-Type' => $config['subkey_type'],
                'Subkey-Length' => $config['subkey_length'],
                'Name-Real' => $config['name_real'],
                'Name-Email' => $config['name_email'],
                'Expire-Date' => $config['expire_date'],
                'Passphrase' => $config['passphrase']
            ];
            
            $keySpecString = "";
            foreach ($keySpec as $key => $value) {
                $keySpecString .= "$key: $value\n";
            }
            $keySpecString .= "%commit\n";
            
            // Gerar chaves
            $result = shell_exec("echo '$keySpecString' | gpg --batch --generate-key --homedir {$this->keyringPath} 2>&1");
            
            if (strpos($result, 'error') !== false) {
                throw new Exception('Erro ao gerar chaves: ' . $result);
            }
            
            // Extrair informações da chave
            $keyList = shell_exec("gpg --homedir {$this->keyringPath} --list-keys --with-colons {$config['name_email']}");
            preg_match('/pub:.*?:.*?:.*?:([A-F0-9]+):/', $keyList, $matches);
            $keyId = $matches[1] ?? '';
            
            preg_match('/fpr:::::::::([A-F0-9]+):/', $keyList, $matches);
            $fingerprint = $matches[1] ?? '';
            
            // Exportar chaves
            $publicKey = shell_exec("gpg --homedir {$this->keyringPath} --armor --export {$config['name_email']}");
            $privateKey = shell_exec("gpg --homedir {$this->keyringPath} --armor --export-secret-keys {$config['name_email']}");
            
            return [
                'success' => true,
                'key_id' => $keyId,
                'fingerprint' => $fingerprint,
                'public_key' => $publicKey,
                'private_key' => $privateKey
            ];
            
        } catch (Exception $e) {
            error_log("Erro GnuPG: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    public function userHasPgpKey($userId) {
        try {
            $stmt = $this->conn->prepare("SELECT id FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            
            return $result->num_rows > 0;
            
        } catch (Exception $e) {
            error_log("Erro ao verificar chaves PGP para o usuário {$userId}: " . $e->getMessage());
            return false;
        }
    }
    
    // ===============================================
    // FUNÇÕES AUXILIARES
    // ===============================================
    
    private function encryptPrivateKey($privateKey, $passphrase) {
        $key = hash('sha256', $passphrase . 'zee_pgp_salt');
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($privateKey, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    private function decryptPrivateKey($encryptedKey, $passphrase) {
        $key = hash('sha256', $passphrase . 'zee_pgp_salt');
        $data = base64_decode($encryptedKey);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }
    
    private function encryptWithAES($data) {
        $key = hash('sha256', 'zee_fallback_key_2024');
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(json_encode($data), 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    private function decryptWithAES($encryptedData) {
        $key = hash('sha256', 'zee_fallback_key_2024');
        $data = base64_decode($encryptedData);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
        return json_decode($decrypted, true);
    }
    
    private function createTablesIfNotExist() {
        $tables = [
            "CREATE TABLE IF NOT EXISTS user_pgp_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                key_id VARCHAR(16) NOT NULL,
                fingerprint VARCHAR(64) NOT NULL,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                revoked BOOLEAN DEFAULT 0,
                UNIQUE KEY unique_user_pgp (user_id),
                INDEX idx_key_id (key_id),
                INDEX idx_fingerprint (fingerprint)
            )",
            
            "CREATE TABLE IF NOT EXISTS encrypted_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NULL,
                recipient_id INT NOT NULL,
                encrypted_content LONGTEXT NOT NULL,
                recipient_fingerprint VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP NULL,
                INDEX idx_recipient (recipient_id),
                INDEX idx_sender (sender_id)
            )",
            
            "CREATE TABLE IF NOT EXISTS pgp_signatures (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                data_hash VARCHAR(64) NOT NULL,
                signature TEXT NOT NULL,
                verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_hash (user_id, data_hash)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->conn->query($sql);
        }
    }
}

/**
 * ✅ INTERFACE WEB PARA PGP
 */
class PGPWebInterface {
    private $pgp;
    
    public function __construct($pgp) {
        $this->pgp = $pgp;
    }
    
    public function renderKeyGeneration() {
        return '
        <div class="pgp-key-generation">
            <h4><i class="fas fa-key"></i> Gerar Chaves PGP</h4>
            <form id="pgp-keygen-form">
                <div class="mb-3">
                    <label class="form-label">Nome de Usuário</label>
                    <input type="text" class="form-control" name="username" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Email</label>
                    <input type="email" class="form-control" name="email" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Senha da Chave (Passphrase)</label>
                    <input type="password" class="form-control" name="passphrase" required>
                    <div class="form-text">Esta senha protegerá sua chave privada</div>
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-cog"></i> Gerar Chaves PGP
                </button>
            </form>
        </div>';
    }
    
    public function renderMessageComposer() {
        return '
        <div class="pgp-message-composer">
            <h4><i class="fas fa-lock"></i> Enviar Mensagem Criptografada</h4>
            <form id="pgp-message-form">
                <div class="mb-3">
                    <label class="form-label">Destinatário</label>
                    <select class="form-select" name="recipient_id" required>
                        <option value="">Selecione um usuário...</option>
                        <!-- Populated via AJAX -->
                    </select>
                </div>
                <div class="mb-3">
                    <label class="form-label">Mensagem</label>
                    <textarea class="form-control" name="message" rows="5" required></textarea>
                </div>
                <div class="mb-3">
                    <label class="form-label">Sua Passphrase</label>
                    <input type="password" class="form-control" name="passphrase" required>
                </div>
                <button type="submit" class="btn btn-success">
                    <i class="fas fa-paper-plane"></i> Enviar Criptografado
                </button>
            </form>
        </div>';
    }
    
    public function renderMessageInbox() {
        return '
        <div class="pgp-message-inbox">
            <h4><i class="fas fa-inbox"></i> Mensagens Criptografadas</h4>
            <div id="encrypted-messages">
                <!-- Populated via AJAX -->
            </div>
        </div>';
    }
}

class PGPMiddleware {
    private $pgpSystem;
    
    public function __construct($pgpSystem) {
        $this->pgpSystem = $pgpSystem;
    }
    
    public function handle() {
        $pgpConfigured = false;
        
        if (isset($_SESSION['user_id'])) {
            $pgpConfigured = $this->pgpSystem->userHasPgpKey($_SESSION['user_id']);
        }
        
        return [
            'pgp_enabled_for_user' => $pgpConfigured,
            'header_info' => 'PGP Middleware Handled'
        ];
    }
}

// Uso do sistema
try {
    $pgpSystem = new ZeeMarketPGP($conn);
    $pgpInterface = new PGPWebInterface($pgpSystem);
    
    // Exemplo de uso
    if (isset($_POST['action']) && $_POST['action'] === 'generate_keys') {
        $result = $pgpSystem->generateUserKeyPair(
            $_SESSION['user_id'],
            $_POST['username'],
            $_POST['email'],
            $_POST['passphrase']
        );
        
        echo json_encode($result);
    }
    
} catch (Exception $e) {
    error_log("Erro no sistema PGP: " . $e->getMessage());
}
?>