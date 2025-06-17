<?php
/**
 * 🔥 SISTEMA PGP REAL PARA DARKWEB - ZeeMarket
 * Uma chave pública do site, usuários criptografam mensagens para nós
 */

class DarkwebPGP {
    private $conn;
    private $sitePublicKey;
    private $sitePrivateKey;
    private $sitePassphrase;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->sitePassphrase = 'ZeeMarket_Master_Key_2024!@#$';
        $this->loadOrCreateSiteKeys();
    }
    
    /**
     * ✅ GERAR CHAVES DO SITE (APENAS UMA VEZ)
     */
    public function generateSiteKeys() {
        try {
            error_log("🔑 Gerando chaves MASTER do site...");
            
            // Criar diretório temporário
            $tempDir = sys_get_temp_dir() . '/zeemarket_master_' . uniqid();
            mkdir($tempDir, 0700, true);
            putenv("GNUPGHOME=" . $tempDir);
            
            // Script de geração de chave
            $keyGenScript = "
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA  
Subkey-Length: 4096
Name-Real: ZeeMarket Master
Name-Email: admin@zeemarket.onion
Expire-Date: 0
Passphrase: {$this->sitePassphrase}
%commit
";
            
            $scriptFile = $tempDir . '/keygen.txt';
            file_put_contents($scriptFile, $keyGenScript);
            
            // Gerar chave
            $output = shell_exec("gpg --homedir '$tempDir' --batch --generate-key '$scriptFile' 2>&1");
            
            if (strpos($output, 'gpg: key') === false) {
                throw new Exception("Falha na geração: " . $output);
            }
            
            // Exportar chave pública
            $publicKey = shell_exec("gpg --homedir '$tempDir' --armor --export 'admin@zeemarket.onion' 2>/dev/null");
            
            // Exportar chave privada
            $privateKey = shell_exec("gpg --homedir '$tempDir' --armor --export-secret-keys 'admin@zeemarket.onion' 2>/dev/null");
            
            // Limpar
            shell_exec("rm -rf '$tempDir'");
            
            if (empty($publicKey) || empty($privateKey)) {
                throw new Exception("Chaves vazias após exportação");
            }
            
            // Salvar no banco
            $this->saveSiteKeys($publicKey, $privateKey);
            
            error_log("✅ Chaves master do site geradas com sucesso!");
            
            return [
                'success' => true,
                'public_key' => $publicKey,
                'message' => 'Chaves master do site criadas!'
            ];
            
        } catch (Exception $e) {
            error_log("❌ Erro ao gerar chaves master: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ SALVAR CHAVES DO SITE NO BANCO
     */
    private function saveSiteKeys($publicKey, $privateKey) {
        // Criptografar chave privada antes de salvar
        $encryptedPrivateKey = $this->encryptPrivateKey($privateKey);
        
        // Deletar chaves antigas se existirem
        $this->conn->query("DELETE FROM site_pgp_keys WHERE site_name = 'zeemarket'");
        
        // Inserir novas chaves
        $stmt = $this->conn->prepare("
            INSERT INTO site_pgp_keys (site_name, public_key, private_key_encrypted, created_at) 
            VALUES ('zeemarket', ?, ?, NOW())
        ");
        $stmt->bind_param("ss", $publicKey, $encryptedPrivateKey);
        $stmt->execute();
        
        $this->sitePublicKey = $publicKey;
        $this->sitePrivateKey = $privateKey;
    }
    
    /**
     * ✅ CARREGAR CHAVES DO SITE
     */
    private function loadOrCreateSiteKeys() {
        $stmt = $this->conn->prepare("SELECT public_key, private_key_encrypted FROM site_pgp_keys WHERE site_name = 'zeemarket'");
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if ($result) {
            $this->sitePublicKey = $result['public_key'];
            $this->sitePrivateKey = $this->decryptPrivateKey($result['private_key_encrypted']);
            error_log("✅ Chaves do site carregadas do banco");
        } else {
            error_log("⚠️ Chaves do site não encontradas - precisam ser geradas");
        }
    }
    
    /**
     * ✅ OBTER CHAVE PÚBLICA DO SITE (PARA EXIBIR NO FRONTEND)
     */
    public function getSitePublicKey() {
        return $this->sitePublicKey;
    }
    
    /**
     * ✅ DESCRIPTOGRAFAR MENSAGEM ENVIADA PELOS USUÁRIOS
     */
    public function decryptUserMessage($encryptedMessage) {
        try {
            if (empty($this->sitePrivateKey)) {
                throw new Exception('Chave privada do site não disponível');
            }
            
            // Criar diretório temporário
            $tempDir = sys_get_temp_dir() . '/decrypt_' . uniqid();
            mkdir($tempDir, 0700, true);
            putenv("GNUPGHOME=" . $tempDir);
            
            // Importar chave privada
            $keyFile = $tempDir . '/private.asc';
            file_put_contents($keyFile, $this->sitePrivateKey);
            
            $importOutput = shell_exec("gpg --homedir '$tempDir' --batch --import '$keyFile' 2>&1");
            
            if (strpos($importOutput, 'imported') === false) {
                throw new Exception("Falha ao importar chave privada: " . $importOutput);
            }
            
            // Descriptografar mensagem
            $messageFile = $tempDir . '/encrypted.txt';
            file_put_contents($messageFile, $encryptedMessage);
            
            $decryptOutput = shell_exec("echo '{$this->sitePassphrase}' | gpg --homedir '$tempDir' --batch --yes --passphrase-fd 0 --decrypt '$messageFile' 2>/dev/null");
            
            // Limpar
            shell_exec("rm -rf '$tempDir'");
            
            if (empty($decryptOutput)) {
                throw new Exception('Falha na descriptografia - mensagem pode estar corrompida');
            }
            
            return [
                'success' => true,
                'decrypted_message' => trim($decryptOutput)
            ];
            
        } catch (Exception $e) {
            error_log("❌ Erro ao descriptografar: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ SALVAR MENSAGEM DESCRIPTOGRAFADA
     */
    public function saveUserMessage($userId, $encryptedMessage, $decryptedMessage, $type = 'contact') {
        try {
            $stmt = $this->conn->prepare("
                INSERT INTO user_messages (user_id, message_type, encrypted_content, decrypted_content, received_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->bind_param("isss", $userId, $type, $encryptedMessage, $decryptedMessage);
            $stmt->execute();
            
            return ['success' => true, 'message_id' => $this->conn->insert_id];
            
        } catch (Exception $e) {
            error_log("❌ Erro ao salvar mensagem: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ VERIFICAR SE CHAVES DO SITE EXISTEM
     */
    public function siteKeysExist() {
        return !empty($this->sitePublicKey) && !empty($this->sitePrivateKey);
    }
    
    /**
     * ✅ CRIAR TABELAS NECESSÁRIAS
     */
    public function createTables() {
        $tables = [
            "CREATE TABLE IF NOT EXISTS site_pgp_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                site_name VARCHAR(50) NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            
            "CREATE TABLE IF NOT EXISTS user_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                message_type VARCHAR(20) DEFAULT 'contact',
                encrypted_content LONGTEXT NOT NULL,
                decrypted_content LONGTEXT NOT NULL,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed BOOLEAN DEFAULT 0,
                INDEX idx_user (user_id),
                INDEX idx_type (message_type)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->conn->query($sql);
        }
    }
    
    // ===============================================
    // FUNÇÕES AUXILIARES
    // ===============================================
    
    private function encryptPrivateKey($privateKey) {
        $key = hash('sha256', $this->sitePassphrase . 'zee_encrypt_salt');
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($privateKey, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    private function decryptPrivateKey($encryptedKey) {
        $key = hash('sha256', $this->sitePassphrase . 'zee_encrypt_salt');
        $data = base64_decode($encryptedKey);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }
}

/**
 * ✅ INTERFACE DARKWEB PARA PGP
 */
class DarkwebPGPInterface {
    private $pgp;
    
    public function __construct($pgp) {
        $this->pgp = $pgp;
    }
    
    /**
     * ✅ EXIBIR CHAVE PÚBLICA DO SITE
     */
    public function renderPublicKeyDisplay() {
        $publicKey = $this->pgp->getSitePublicKey();
        
        if (empty($publicKey)) {
            return '<div class="alert alert-warning">⚠️ Chaves do site não configuradas ainda</div>';
        }
        
        return '
        <div class="pgp-public-key-display">
            <h4><i class="fas fa-key"></i> Nossa Chave Pública PGP</h4>
            <p class="text-muted">Use esta chave para criptografar suas mensagens antes de enviá-las</p>
            
            <div class="mb-3">
                <label class="form-label">Chave Pública ZeeMarket:</label>
                <textarea class="form-control font-monospace" rows="15" readonly>' . htmlspecialchars($publicKey) . '</textarea>
                <button class="btn btn-sm btn-outline-primary mt-2" onclick="copyPublicKey()">
                    <i class="fas fa-copy"></i> Copiar Chave
                </button>
            </div>
            
            <div class="alert alert-info">
                <h6><i class="fas fa-info-circle"></i> Como usar:</h6>
                <ol>
                    <li>Copie nossa chave pública acima</li>
                    <li>Use um software PGP (GPG, Kleopatra, etc.) em seu computador</li>
                    <li>Importe nossa chave pública</li>
                    <li>Criptografe sua mensagem com nossa chave</li>
                    <li>Cole o resultado criptografado no formulário abaixo</li>
                </ol>
            </div>
        </div>
        
        <script>
        function copyPublicKey() {
            const textarea = document.querySelector("textarea");
            textarea.select();
            document.execCommand("copy");
            alert("Chave pública copiada!");
        }
        </script>';
    }
    
    /**
     * ✅ FORMULÁRIO PARA RECEBER MENSAGENS CRIPTOGRAFADAS
     */
    public function renderEncryptedMessageForm() {
        return '
        <div class="encrypted-message-form">
            <h4><i class="fas fa-lock"></i> Enviar Mensagem Criptografada</h4>
            
            <form method="POST" action="process_encrypted_message.php">
                <div class="mb-3">
                    <label class="form-label">Sua mensagem criptografada:</label>
                    <textarea name="encrypted_message" class="form-control font-monospace" rows="10" 
                              placeholder="Cole aqui sua mensagem criptografada com nossa chave pública..." required></textarea>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">Tipo de mensagem:</label>
                    <select name="message_type" class="form-select">
                        <option value="contact">Contato Geral</option>
                        <option value="support">Suporte Técnico</option>
                        <option value="complaint">Reclamação</option>
                        <option value="order_issue">Problema com Pedido</option>
                    </select>
                </div>
                
                <button type="submit" class="btn btn-success">
                    <i class="fas fa-paper-plane"></i> Enviar Mensagem Segura
                </button>
            </form>
        </div>';
    }
}

// ===============================================
// INICIALIZAÇÃO E USO
// ===============================================

try {
    // Inicializar sistema PGP
    $darkwebPGP = new DarkwebPGP($conn);
    $darkwebPGP->createTables();
    
    // Verificar se precisa gerar chaves
    if (!$darkwebPGP->siteKeysExist()) {
        error_log("⚠️ Chaves do site precisam ser geradas!");
        // Descomente a linha abaixo para gerar chaves automaticamente:
        // $darkwebPGP->generateSiteKeys();
    }
    
    // Interface
    $pgpInterface = new DarkwebPGPInterface($darkwebPGP);
    
} catch (Exception $e) {
    error_log("❌ Erro no sistema PGP Darkweb: " . $e->getMessage());
}
?>