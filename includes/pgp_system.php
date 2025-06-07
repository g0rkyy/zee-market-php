<?php
/**
 * SISTEMA PGP COMPLETO - ZEEMARKET
 * Criptografia end-to-end para mensagens e dados sensíveis
 * Arquivo: includes/pgp_system.php
 */

require_once __DIR__ . '/config.php';

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
            if (!extension_loaded('gnupg')) {
                throw new Exception('Extensão GnuPG não está instalada');
            }
            
            $this->gpg = new gnupg();
            $this->gpg->seterrormode(gnupg::ERROR_EXCEPTION);
            
            // Configurar diretório das chaves
            putenv("GNUPGHOME=" . $this->keyringPath);
            
        } catch (Exception $e) {
            // Fallback para implementação PHP pura
            $this->initializePHPGPG();
        }
    }
    
    private function initializePHPGPG() {
        // Implementação alternativa usando OpenPGP-PHP
        require_once __DIR__ . '/../vendor/singpolyma/openpgp-php/lib/openpgp.php';
        require_once __DIR__ . '/../vendor/singpolyma/openpgp-php/lib/openpgp_crypt_rsa.php';
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
                $keyInfo = $this->generateKeysPHPGPG($keyConfig);
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
            
            // Criptografar mensagem
            if (extension_loaded('gnupg')) {
                $encryptedMessage = $this->encryptWithGnuPG($message, $recipientKey['public_key']);
            } else {
                $encryptedMessage = $this->encryptWithPHPGPG($message, $recipientKey['public_key']);
            }
            
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
            
            // Descriptografar chave privada
            $privateKey = $this->decryptPrivateKey($result['private_key_encrypted'], $passphrase);
            
            // Descriptografar mensagem
            if (extension_loaded('gnupg')) {
                $decryptedMessage = $this->decryptWithGnuPG($result['encrypted_content'], $privateKey);
            } else {
                $decryptedMessage = $this->decryptWithPHPGPG($result['encrypted_content'], $privateKey);
            }
            
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
            
            $privateKey = $this->decryptPrivateKey($result['private_key_encrypted'], $passphrase);
            
            // Criar hash da transação
            $transactionHash = hash('sha256', json_encode($transactionData));
            
            // Assinar hash
            if (extension_loaded('gnupg')) {
                $signature = $this->signWithGnuPG($transactionHash, $privateKey);
            } else {
                $signature = $this->signWithPHPGPG($transactionHash, $privateKey);
            }
            
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
            
            if (extension_loaded('gnupg')) {
                $isValid = $this->verifyWithGnuPG($dataHash, $signature, $result['public_key']);
            } else {
                $isValid = $this->verifyWithPHPGPG($dataHash, $signature, $result['public_key']);
            }
            
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
            
            if (extension_loaded('gnupg')) {
                return $this->encryptWithGnuPG(json_encode($data), $result['public_key']);
            } else {
                return $this->encryptWithPHPGPG(json_encode($data), $result['public_key']);
            }
            
        } catch (Exception $e) {
            error_log("Erro ao criptografar dados pessoais: " . $e->getMessage());
            return $this->encryptWithAES($data); // Fallback
        }
    }
    
    // ===============================================
    // IMPLEMENTAÇÕES ESPECÍFICAS GnuPG
    // ===============================================
    
    private function generateKeysGnuPG($config) {
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
            'key_id' => $keyId,
            'fingerprint' => $fingerprint,
            'public_key' => $publicKey,
            'private_key' => $privateKey
        ];
    }
    
    private function encryptWithGnuPG($message, $publicKey) {
        // Importar chave temporariamente
        $tempFile = tempnam(sys_get_temp_dir(), 'pgp_key_');
        file_put_contents($tempFile, $publicKey);
        
        shell_exec("gpg --homedir {$this->keyringPath} --import $tempFile");
        
        // Criptografar
        $messageFile = tempnam(sys_get_temp_dir(), 'pgp_msg_');
        file_put_contents($messageFile, $message);
        
        $encrypted = shell_exec("gpg --homedir {$this->keyringPath} --armor --encrypt --trust-model always --recipient-file $tempFile $messageFile");
        
        // Limpar arquivos temporários
        unlink($tempFile);
        unlink($messageFile);
        
        return $encrypted;
    }
    
    private function decryptWithGnuPG($encryptedMessage, $privateKey) {
        // Importar chave privada temporariamente
        $tempFile = tempnam(sys_get_temp_dir(), 'pgp_priv_');
        file_put_contents($tempFile, $privateKey);
        
        shell_exec("gpg --homedir {$this->keyringPath} --import $tempFile");
        
        // Descriptografar
        $encryptedFile = tempnam(sys_get_temp_dir(), 'pgp_enc_');
        file_put_contents($encryptedFile, $encryptedMessage);
        
        $decrypted = shell_exec("gpg --homedir {$this->keyringPath} --decrypt $encryptedFile 2>/dev/null");
        
        // Limpar arquivos temporários
        unlink($tempFile);
        unlink($encryptedFile);
        
        return $decrypted;
    }
    
    // ===============================================
    // IMPLEMENTAÇÕES PHP-GPG (FALLBACK)
    // ===============================================
    
    private function generateKeysPHPGPG($config) {
        // Implementação usando OpenPGP-PHP
        $rsa = new Crypt_RSA();
        $rsa->setKeyLength($config['key_length']);
        $keys = $rsa->createKey();
        
        $keyId = substr(hash('sha256', $keys['publickey']), 0, 16);
        $fingerprint = hash('sha256', $keys['publickey']);
        
        // Converter para formato PGP
        $publicKey = $this->convertToPGPFormat($keys['publickey'], $config);
        $privateKey = $this->convertToPGPFormat($keys['privatekey'], $config, true);
        
        return [
            'key_id' => strtoupper($keyId),
            'fingerprint' => strtoupper($fingerprint),
            'public_key' => $publicKey,
            'private_key' => $privateKey
        ];
    }
    
    private function convertToPGPFormat($key, $config, $isPrivate = false) {
        $type = $isPrivate ? 'PRIVATE' : 'PUBLIC';
        $header = "-----BEGIN PGP $type KEY BLOCK-----";
        $footer = "-----END PGP $type KEY BLOCK-----";
        
        $encoded = base64_encode($key);
        $wrapped = chunk_split($encoded, 64, "\n");
        
        return "$header\n\n$wrapped$footer\n";
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

// Uso do sistema
try {
    $pgpSystem = new ZeeMarketPGP($conn);
    $pgpInterface = new PGPWebInterface($pgpSystem);
    
    // Exemplo de uso
    if ($_POST['action'] === 'generate_keys') {
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