<?php
/**
 * SISTEMA DE AUTENTICAÇÃO DE DOIS FATORES - ZEEMARKET
 * Implementação completa de 2FA para máxima segurança
 * Arquivo: includes/two_factor_auth.php
 */

require_once __DIR__ . '/config.php';

class TwoFactorAuth {
    private $conn;
    private $secretLength = 32;
    private $windowSize = 2; // ±2 períodos (60 segundos cada)
    private $algorithm = 'sha1';
    
    public function __construct() {
        global $conn;
        $this->conn = $conn;
        $this->createTablesIfNotExist();
    }
    
    /**
     * ✅ GERAR SECRET E QR CODE PARA USUÁRIO
     */
    public function generateUserSecret($userId, $username) {
        try {
            // Verificar se já tem 2FA configurado
            if ($this->isUserTwoFAEnabled($userId)) {
                throw new Exception("2FA já está configurado para este usuário");
            }
            
            // Gerar secret aleatório
            $secret = $this->generateRandomSecret();
            
            // Salvar secret temporário (só ativará após primeira verificação)
            $stmt = $this->conn->prepare("
                INSERT INTO user_2fa 
                (user_id, secret_key, is_active, created_at) 
                VALUES (?, ?, 0, NOW())
                ON DUPLICATE KEY UPDATE 
                secret_key = VALUES(secret_key), 
                is_active = 0, 
                updated_at = NOW()
            ");
            $stmt->bind_param("is", $userId, $secret);
            $stmt->execute();
            
            // Gerar dados para QR Code
            $issuer = 'ZeeMarket';
            $label = $issuer . ':' . $username;
            $qrData = $this->generateQRCodeData($label, $secret, $issuer);
            
            // Gerar URL do QR Code
            $qrCodeUrl = $this->generateQRCodeUrl($qrData);
            
            return [
                'success' => true,
                'secret' => $secret,
                'qr_code_url' => $qrCodeUrl,
                'qr_data' => $qrData,
                'backup_codes' => $this->generateBackupCodes($userId),
                'manual_entry_key' => $this->formatSecretForManualEntry($secret)
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao gerar 2FA: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ VERIFICAR CÓDIGO 2FA
     */
    public function verifyCode($userId, $code, $window = null) {
        try {
            if (empty($code)) {
                return false;
            }
            
            // Verificar se é código de backup
            if ($this->isBackupCode($code)) {
                return $this->verifyBackupCode($userId, $code);
            }
            
            // Obter secret do usuário
            $secret = $this->getUserSecret($userId);
            if (!$secret) {
                return false;
            }
            
            // Verificar código TOTP
            $window = $window ?? $this->windowSize;
            $currentTime = time();
            
            for ($i = -$window; $i <= $window; $i++) {
                $timeSlice = floor($currentTime / 30) + $i;
                $expectedCode = $this->generateTOTP($secret, $timeSlice);
                
                if (hash_equals($expectedCode, $code)) {
                    // Verificar replay attack
                    if (!$this->isCodeAlreadyUsed($userId, $code, $timeSlice)) {
                        $this->markCodeAsUsed($userId, $code, $timeSlice);
                        $this->logSuccessfulVerification($userId);
                        return true;
                    }
                }
            }
            
            $this->logFailedVerification($userId, $code);
            return false;
            
        } catch (Exception $e) {
            error_log("Erro na verificação 2FA: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * ✅ ATIVAR 2FA APÓS PRIMEIRA VERIFICAÇÃO
     */
    public function activateTwoFA($userId, $verificationCode) {
        try {
            // Verificar código primeiro
            if (!$this->verifyCode($userId, $verificationCode)) {
                throw new Exception("Código de verificação inválido");
            }
            
            // Ativar 2FA
            $stmt = $this->conn->prepare("
                UPDATE user_2fa 
                SET is_active = 1, activated_at = NOW(), updated_at = NOW() 
                WHERE user_id = ?
            ");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            
            if ($stmt->affected_rows === 0) {
                throw new Exception("Falha ao ativar 2FA");
            }
            
            // Log de ativação
            $this->logTwoFAActivation($userId);
            
            return [
                'success' => true,
                'message' => '2FA ativado com sucesso!',
                'backup_codes' => $this->getUserBackupCodes($userId)
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ DESATIVAR 2FA
     */
    public function deactivateTwoFA($userId, $verificationCode, $password) {
        try {
            // Verificar senha atual
            if (!$this->verifyUserPassword($userId, $password)) {
                throw new Exception("Senha atual incorreta");
            }
            
            // Verificar código 2FA
            if (!$this->verifyCode($userId, $verificationCode)) {
                throw new Exception("Código 2FA inválido");
            }
            
            // Desativar 2FA
            $stmt = $this->conn->prepare("
                UPDATE user_2fa 
                SET is_active = 0, deactivated_at = NOW(), updated_at = NOW() 
                WHERE user_id = ?
            ");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            
            // Invalidar todos os códigos de backup
            $this->invalidateAllBackupCodes($userId);
            
            // Log de desativação
            $this->logTwoFADeactivation($userId);
            
            return [
                'success' => true,
                'message' => '2FA desativado com sucesso'
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ GERAR CÓDIGOS DE BACKUP
     */
    private function generateBackupCodes($userId) {
        $codes = [];
        
        // Invalidar códigos antigos
        $this->invalidateAllBackupCodes($userId);
        
        // Gerar 8 códigos novos
        for ($i = 0; $i < 8; $i++) {
            $code = $this->generateSecureBackupCode();
            $codes[] = $code;
            
            // Salvar no banco (hasheado)
            $hashedCode = password_hash($code, PASSWORD_DEFAULT);
            $stmt = $this->conn->prepare("
                INSERT INTO user_backup_codes 
                (user_id, code_hash, created_at) 
                VALUES (?, ?, NOW())
            ");
            $stmt->bind_param("is", $userId, $hashedCode);
            $stmt->execute();
        }
        
        return $codes;
    }
    
    /**
     * ✅ VERIFICAR CÓDIGO DE BACKUP
     */
    private function verifyBackupCode($userId, $code) {
        $stmt = $this->conn->prepare("
            SELECT id, code_hash 
            FROM user_backup_codes 
            WHERE user_id = ? AND used_at IS NULL
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $backupCodes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        foreach ($backupCodes as $backupCode) {
            if (password_verify($code, $backupCode['code_hash'])) {
                // Marcar como usado
                $stmt = $this->conn->prepare("
                    UPDATE user_backup_codes 
                    SET used_at = NOW() 
                    WHERE id = ?
                ");
                $stmt->bind_param("i", $backupCode['id']);
                $stmt->execute();
                
                $this->logBackupCodeUsed($userId, $backupCode['id']);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * ✅ VERIFICAR SE USUÁRIO TEM 2FA ATIVO
     */
    public function isUserTwoFAEnabled($userId) {
        $stmt = $this->conn->prepare("
            SELECT is_active 
            FROM user_2fa 
            WHERE user_id = ? AND is_active = 1
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return $result ? (bool)$result['is_active'] : false;
    }
    
    /**
     * ✅ OBTER SECRET DO USUÁRIO
     */
    private function getUserSecret($userId) {
        $stmt = $this->conn->prepare("
            SELECT secret_key 
            FROM user_2fa 
            WHERE user_id = ? AND is_active = 1
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return $result ? $result['secret_key'] : null;
    }
    
    /**
     * ✅ GERAR SECRET ALEATÓRIO
     */
    private function generateRandomSecret() {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32
        $secret = '';
        
        for ($i = 0; $i < $this->secretLength; $i++) {
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        return $secret;
    }
    
    /**
     * ✅ GERAR TOTP
     */
    private function generateTOTP($secret, $timeSlice = null) {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }
        
        // Converter secret de Base32 para binário
        $binarySecret = $this->base32Decode($secret);
        
        // Converter time slice para 8 bytes big-endian
        $timeBytes = pack('N*', 0) . pack('N*', $timeSlice);
        
        // Gerar HMAC
        $hash = hash_hmac($this->algorithm, $timeBytes, $binarySecret, true);
        
        // Extrair código de 6 dígitos
        $offset = ord($hash[19]) & 0xf;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;
        
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
    
    /**
     * ✅ DECODIFICAR BASE32
     */
    private function base32Decode($input) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0, $j = strlen($input); $i < $j; $i++) {
            $v <<= 5;
            $v += strpos($alphabet, $input[$i]);
            $vbits += 5;
            
            while ($vbits >= 8) {
                $vbits -= 8;
                $output .= chr($v >> $vbits);
                $v &= ((1 << $vbits) - 1);
            }
        }
        
        return $output;
    }
    
    /**
     * ✅ GERAR DADOS PARA QR CODE
     */
    private function generateQRCodeData($label, $secret, $issuer) {
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=6&period=30',
            urlencode($label),
            $secret,
            urlencode($issuer),
            strtoupper($this->algorithm)
        );
    }
    
    /**
     * ✅ GERAR URL DO QR CODE
     */
    private function generateQRCodeUrl($data) {
        return 'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=' . urlencode($data);
    }
    
    /**
     * ✅ FORMATAR SECRET PARA ENTRADA MANUAL
     */
    private function formatSecretForManualEntry($secret) {
        return chunk_split($secret, 4, ' ');
    }
    
    /**
     * ✅ GERAR CÓDIGO DE BACKUP SEGURO
     */
    private function generateSecureBackupCode() {
        // Gerar código de 8 dígitos
        return str_pad(random_int(10000000, 99999999), 8, '0', STR_PAD_LEFT);
    }
    
    /**
     * ✅ VERIFICAR SE É CÓDIGO DE BACKUP
     */
    private function isBackupCode($code) {
        return preg_match('/^\d{8}$/', $code);
    }
    
    /**
     * ✅ VERIFICAR SE CÓDIGO JÁ FOI USADO (ANTI-REPLAY)
     */
    private function isCodeAlreadyUsed($userId, $code, $timeSlice) {
        $stmt = $this->conn->prepare("
            SELECT id 
            FROM used_totp_codes 
            WHERE user_id = ? AND code_hash = ? AND time_slice = ?
        ");
        $codeHash = hash('sha256', $code);
        $stmt->bind_param("isi", $userId, $codeHash, $timeSlice);
        $stmt->execute();
        
        return $stmt->get_result()->num_rows > 0;
    }
    
    /**
     * ✅ MARCAR CÓDIGO COMO USADO
     */
    private function markCodeAsUsed($userId, $code, $timeSlice) {
        $stmt = $this->conn->prepare("
            INSERT INTO used_totp_codes 
            (user_id, code_hash, time_slice, used_at) 
            VALUES (?, ?, ?, NOW())
        ");
        $codeHash = hash('sha256', $code);
        $stmt->bind_param("isi", $userId, $codeHash, $timeSlice);
        $stmt->execute();
        
        // Limpar códigos antigos (mais de 2 horas)
        $this->cleanupOldUsedCodes();
    }
    
    /**
     * ✅ LIMPEZA DE CÓDIGOS ANTIGOS
     */
    private function cleanupOldUsedCodes() {
        $this->conn->query("
            DELETE FROM used_totp_codes 
            WHERE used_at < DATE_SUB(NOW(), INTERVAL 2 HOUR)
        ");
    }
    
    /**
     * ✅ VERIFICAR SENHA DO USUÁRIO
     */
    private function verifyUserPassword($userId, $password) {
        $stmt = $this->conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return $result ? password_verify($password, $result['password']) : false;
    }
    
    /**
     * ✅ INVALIDAR TODOS OS CÓDIGOS DE BACKUP
     */
    private function invalidateAllBackupCodes($userId) {
        $stmt = $this->conn->prepare("
            UPDATE user_backup_codes 
            SET used_at = NOW() 
            WHERE user_id = ? AND used_at IS NULL
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
    }
    
    /**
     * ✅ OBTER CÓDIGOS DE BACKUP DO USUÁRIO
     */
    private function getUserBackupCodes($userId) {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as remaining_codes 
            FROM user_backup_codes 
            WHERE user_id = ? AND used_at IS NULL
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return [
            'remaining_codes' => $result['remaining_codes'],
            'total_codes' => 8
        ];
    }
    
    /**
     * ✅ LOGS DE SEGURANÇA
     */
    private function logSuccessfulVerification($userId) {
        $this->logTwoFAEvent($userId, 'verification_success');
    }
    
    private function logFailedVerification($userId, $code) {
        $this->logTwoFAEvent($userId, 'verification_failed', ['attempted_code' => substr($code, 0, 2) . '****']);
    }
    
    private function logTwoFAActivation($userId) {
        $this->logTwoFAEvent($userId, 'activation');
    }
    
    private function logTwoFADeactivation($userId) {
        $this->logTwoFAEvent($userId, 'deactivation');
    }
    
    private function logBackupCodeUsed($userId, $codeId) {
        $this->logTwoFAEvent($userId, 'backup_code_used', ['code_id' => $codeId]);
    }
    
    private function logTwoFAEvent($userId, $event, $details = []) {
        $stmt = $this->conn->prepare("
            INSERT INTO two_fa_logs 
            (user_id, event_type, details, ip_address, user_agent, created_at) 
            VALUES (?, ?, ?, ?, ?, NOW())
        ");
        
        $detailsJson = json_encode($details);
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $stmt->bind_param("issss", $userId, $event, $detailsJson, $ip, $userAgent);
        $stmt->execute();
    }
    
    /**
     * ✅ CRIAR TABELAS NECESSÁRIAS
     */
    private function createTablesIfNotExist() {
        $tables = [
            "CREATE TABLE IF NOT EXISTS user_2fa (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                secret_key VARCHAR(64) NOT NULL,
                is_active BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activated_at TIMESTAMP NULL,
                deactivated_at TIMESTAMP NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_user_active (user_id, is_active)
            )",
            
            "CREATE TABLE IF NOT EXISTS user_backup_codes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                code_hash VARCHAR(255) NOT NULL,
                used_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_unused (user_id, used_at)
            )",
            
            "CREATE TABLE IF NOT EXISTS used_totp_codes (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                code_hash VARCHAR(64) NOT NULL,
                time_slice BIGINT NOT NULL,
                used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_time (user_id, time_slice),
                INDEX idx_cleanup (used_at)
            )",
            
            "CREATE TABLE IF NOT EXISTS two_fa_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                details JSON,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_event (user_id, event_type),
                INDEX idx_created (created_at)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->conn->query($sql);
        }
    }
}

/**
 * ✅ INTERFACE WEB PARA 2FA
 */
class TwoFAWebInterface {
    private $twoFA;
    
    public function __construct($twoFA) {
        $this->twoFA = $twoFA;
    }
    
    /**
     * ✅ RENDERIZAR CONFIGURAÇÃO 2FA
     */
    public function renderSetupPage($userId, $username) {
        $isEnabled = $this->twoFA->isUserTwoFAEnabled($userId);
        
        if ($isEnabled) {
            return $this->renderManagementPage($userId);
        } else {
            return $this->renderActivationPage($userId, $username);
        }
    }
    
    private function renderActivationPage($userId, $username) {
        $setupData = $this->twoFA->generateUserSecret($userId, $username);
        
        if (!$setupData['success']) {
            return '<div class="alert alert-danger">Erro: ' . $setupData['error'] . '</div>';
        }
        
        return '
        <div class="two-fa-setup">
            <h4><i class="fas fa-shield-alt"></i> Configurar Autenticação de Dois Fatores</h4>
            
            <div class="row">
                <div class="col-md-6">
                    <h5>1. Escaneie o QR Code</h5>
                    <div class="text-center mb-3">
                        <img src="' . $setupData['qr_code_url'] . '" alt="QR Code 2FA" class="img-fluid">
                    </div>
                    
                    <h5>2. Ou digite manualmente:</h5>
                    <div class="form-control mb-3" style="font-family: monospace;">
                        ' . $setupData['manual_entry_key'] . '
                    </div>
                </div>
                
                <div class="col-md-6">
                    <h5>3. Digite o código do seu app:</h5>
                    <form id="activate-2fa-form">
                        <div class="mb-3">
                            <input type="text" class="form-control text-center" 
                                   id="verification-code" name="code" 
                                   placeholder="000000" maxlength="6" required>
                        </div>
                        <button type="submit" class="btn btn-success w-100">
                            <i class="fas fa-check"></i> Ativar 2FA
                        </button>
                    </form>
                    
                    <div class="mt-4">
                        <h5>Apps Recomendados:</h5>
                        <ul class="list-unstyled">
                            <li><i class="fab fa-google"></i> Google Authenticator</li>
                            <li><i class="fas fa-key"></i> Authy</li>
                            <li><i class="fas fa-mobile-alt"></i> Microsoft Authenticator</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="alert alert-warning mt-4">
                <h6><i class="fas fa-exclamation-triangle"></i> Códigos de Backup</h6>
                <p>Após ativar o 2FA, você receberá códigos de backup. <strong>Guarde-os em local seguro!</strong></p>
                <div class="backup-codes" style="display: none;">
                    ' . implode(' | ', $setupData['backup_codes']) . '
                </div>
            </div>
        </div>
        
        <script>
        document.getElementById("activate-2fa-form").addEventListener("submit", function(e) {
            e.preventDefault();
            const code = document.getElementById("verification-code").value;
            
            fetch("activate_2fa.php", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({code: code})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("2FA ativado com sucesso!");
                    document.querySelector(".backup-codes").style.display = "block";
                    location.reload();
                } else {
                    alert("Erro: " + data.error);
                }
            });
        });
        </script>';
    }
    
    private function renderManagementPage($userId) {
        return '
        <div class="two-fa-management">
            <h4><i class="fas fa-shield-alt text-success"></i> 2FA Ativado</h4>
            
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> 
                Sua conta está protegida com autenticação de dois fatores.
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <h5>Gerar novos códigos de backup</h5>
                    <p class="text-muted">Se você perdeu seus códigos de backup</p>
                    <button class="btn btn-warning" onclick="generateNewBackupCodes()">
                        <i class="fas fa-sync"></i> Gerar Novos Códigos
                    </button>
                </div>
                
                <div class="col-md-6">
                    <h5>Desativar 2FA</h5>
                    <p class="text-muted">Remover proteção de dois fatores</p>
                    <button class="btn btn-danger" onclick="showDeactivateForm()">
                        <i class="fas fa-times"></i> Desativar 2FA
                    </button>
                </div>
            </div>
            
            <div id="deactivate-form" style="display: none;" class="mt-4">
                <div class="card border-danger">
                    <div class="card-body">
                        <h5 class="text-danger">Desativar 2FA</h5>
                        <form id="deactivate-2fa-form">
                            <div class="mb-3">
                                <label>Senha atual:</label>
                                <input type="password" class="form-control" name="password" required>
                            </div>
                            <div class="mb-3">
                                <label>Código 2FA:</label>
                                <input type="text" class="form-control" name="code" maxlength="6" required>
                            </div>
                            <button type="submit" class="btn btn-danger">Confirmar Desativação</button>
                            <button type="button" class="btn btn-secondary" onclick="hideDeactivateForm()">Cancelar</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        function showDeactivateForm() {
            document.getElementById("deactivate-form").style.display = "block";
        }
        
        function hideDeactivateForm() {
            document.getElementById("deactivate-form").style.display = "none";
        }
        
        function generateNewBackupCodes() {
            if (confirm("Isso invalidará todos os códigos de backup atuais. Continuar?")) {
                fetch("generate_backup_codes.php", {method: "POST"})
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert("Novos códigos gerados: " + data.codes.join(", "));
                    }
                });
            }
        }
        </script>';
    }
}

// Inicialização
try {
    $twoFA = new TwoFactorAuth();
    $interface = new TwoFAWebInterface($twoFA);
    
    // Exemplo de uso em login
    if ($_POST['action'] === 'verify_2fa') {
        $result = $twoFA->verifyCode($_SESSION['user_id'], $_POST['code']);
        echo json_encode(['success' => $result]);
    }
    
} catch (Exception $e) {
    error_log("Erro no sistema 2FA: " . $e->getMessage());
}
?>