<?php
// functions.php - VERSÃO LIMPA SEM PGP ANTIGO

// Iniciar sessão apenas se não estiver ativa
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'config.php';

// ====== FUNÇÕES DE AUTENTICAÇÃO ====== //
function login($email, $senha) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT id, name, password, is_vendor, btc_balance, eth_balance, xmr_balance FROM users WHERE email = ?");
    if (!$stmt) {
        error_log("Erro na preparação da consulta de login: " . $conn->error);
        return "Erro interno do servidor";
    }
    
    $stmt->bind_param("s", $email);
    if (!$stmt->execute()) {
        error_log("Erro ao executar consulta de login: " . $stmt->error);
        return "Erro interno do servidor";
    }
    
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($senha, $user['password'])) {
            // Regenerar ID da sessão para segurança
            session_regenerate_id(true);
            
            // Definir variáveis de sessão
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_name'] = $user['name'];
            $_SESSION['is_vendor'] = $user['is_vendor'];
            $_SESSION['btc_balance'] = $user['btc_balance'] ?? 0;
            $_SESSION['eth_balance'] = $user['eth_balance'] ?? 0;
            $_SESSION['xmr_balance'] = $user['xmr_balance'] ?? 0;
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            
            error_log("Login bem-sucedido para usuário ID: " . $user['id']);
            return true;
        } else {
            error_log("Tentativa de login com senha incorreta para email: " . $email);
        }
    } else {
        error_log("Tentativa de login com email não encontrado: " . $email);
    }
    
    return "Email ou senha incorretos!";
}

// ====== FUNÇÃO DE LOGOUT ====== //
function logout() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (isset($_SESSION['user_id'])) {
        error_log("Logout do usuário ID: " . $_SESSION['user_id']);
    }
    
    $_SESSION = array();
    
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    session_destroy();
    header("Location: login.php");
    exit();
}

// ====== FUNÇÃO PARA VERIFICAR SE ESTÁ LOGADO ====== //
function isLoggedIn() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    return isset($_SESSION['user_id']) && 
           isset($_SESSION['logged_in']) && 
           $_SESSION['logged_in'] === true;
}

// ====== FUNÇÕES DE REPUTAÇÃO ====== //
function getReputacao($user_id) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT COUNT(*) FROM produtos WHERE vendedor_id = ?");
        if (!$stmt) {
            error_log("Erro ao preparar consulta de reputação: " . $conn->error);
            return ["level" => "Novato", "icon" => "☆"];
        }
        
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $isVendedor = $stmt->get_result()->fetch_row()[0] > 0;

        if (!$isVendedor) {
            return ["level" => "Novato", "icon" => "☆"];
        }

        $stmt = $conn->prepare("SELECT AVG(rating) FROM feedback WHERE id IN (
            SELECT feedback_id FROM compras WHERE vendedor_id = ?
        )");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $avg = $stmt->get_result()->fetch_row()[0];
        $avg = $avg ? round($avg, 1) : 0;

        if ($avg >= 4.5) return ["level" => "Ouro", "icon" => "★★★★", "rating" => $avg];
        elseif ($avg >= 3.5) return ["level" => "Prata", "icon" => "★★★☆", "rating" => $avg];
        elseif ($avg > 0) return ["level" => "Bronze", "icon" => "★★☆☆", "rating" => $avg];
        return ["level" => "Sem avaliações", "icon" => "☆", "rating" => 0];
        
    } catch (Exception $e) {
        error_log("Erro ao obter reputação: " . $e->getMessage());
        return ["level" => "Erro", "icon" => "☆"];
    }
}

// ====== FUNÇÕES DE BITCOIN ====== //
function verificarDepositosPendentes($user_id) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT * FROM btc_transactions 
                              WHERE user_id = ? AND status = 'pending' 
                              AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    } catch (Exception $e) {
        error_log("Erro ao verificar depósitos pendentes: " . $e->getMessage());
        return [];
    }
}

function atualizarSaldoBTC($user_id, $amount) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?");
        $stmt->bind_param("di", $amount, $user_id);
        
        if ($stmt->execute()) {
            $_SESSION['btc_balance'] = ($_SESSION['btc_balance'] ?? 0) + $amount;
            return true;
        }
        
        return false;
    } catch (Exception $e) {
        error_log("Erro ao atualizar saldo BTC: " . $e->getMessage());
        return false;
    }
}


function isVendedor($user_id) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        return ($result['is_vendor'] ?? 0) == 1;
    } catch (Exception $e) {
        error_log("Erro ao verificar se é vendedor: " . $e->getMessage());
        return false;
    }
}

function redirecionarSeNaoVendedor() {
    verificarLogin();
    if (!isVendedor($_SESSION['user_id'])) {
        header("Location: acesso_negado.php");
        exit();
    }
}

function getUserWalletInfo($userId) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT 
            btc_wallet, btc_deposit_address, eth_deposit_address, xmr_deposit_address,
            btc_balance, eth_balance, xmr_balance
            FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    } catch (Exception $e) {
        error_log("Erro ao obter informações da carteira: " . $e->getMessage());
        return [];
    }
}

function updateSessionBalances($userId) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT btc_balance, eth_balance, xmr_balance FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if ($result) {
            $_SESSION['btc_balance'] = $result['btc_balance'] ?? 0;
            $_SESSION['eth_balance'] = $result['eth_balance'] ?? 0;
            $_SESSION['xmr_balance'] = $result['xmr_balance'] ?? 0;
        }
    } catch (Exception $e) {
        error_log("Erro ao atualizar saldos na sessão: " . $e->getMessage());
    }
}

function debugSession() {
    if (!isset($_SESSION)) {
        error_log("DEBUG: Sessão não iniciada");
        return;
    }
    
    $sessionData = [
        'session_id' => session_id(),
        'user_id' => $_SESSION['user_id'] ?? 'não definido',
        'logged_in' => $_SESSION['logged_in'] ?? 'não definido',
        'login_time' => $_SESSION['login_time'] ?? 'não definido'
    ];
    
    error_log("DEBUG Session: " . json_encode($sessionData));
}

function checkLoginAttempts($email) {
    $max_attempts = 5;
    $lockout_time = 300;
    
    $attempts = 0;
    $last_attempt = 0;
    
    if ($attempts >= $max_attempts && (time() - $last_attempt < $lockout_time)) {
        return false;
    }
    
    return true;
}

function emailExists($email) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    
    return $stmt->num_rows > 0;
}



// ====== FUNÇÕES TOR ====== //

function getRealIP() {
    $headers = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];
    
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, 
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function checkTorConnection() {
    try {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $ip = getRealIP();
        
        $torScore = 0;
        $indicators = [];
        
        if (strpos($userAgent, 'Firefox') !== false && 
            !strpos($userAgent, 'Chrome') && 
            !strpos($userAgent, 'Safari')) {
            $torScore += 25;
            $indicators[] = 'Firefox-only user agent';
        }
        
        if ($acceptLanguage === 'en-US,en;q=0.5' || $acceptLanguage === 'en-us,en;q=0.5') {
            $torScore += 30;
            $indicators[] = 'Default Tor language settings';
        }
        
        if (empty($_SERVER['HTTP_CACHE_CONTROL']) && 
            empty($_SERVER['HTTP_PRAGMA'])) {
            $torScore += 15;
            $indicators[] = 'Missing cache headers';
        }
        
        if (isKnownTorExitNode($ip)) {
            $torScore += 40;
            $indicators[] = 'Known Tor exit node';
        }
        
        if (empty($_SERVER['HTTP_DNT'])) {
            $torScore += 10;
            $indicators[] = 'No DNT header';
        }
        
        return [
            'connected' => $torScore >= 50,
            'confidence' => min($torScore, 100),
            'indicators' => $indicators,
            'user_agent' => $userAgent,
            'ip' => $ip
        ];
        
    } catch (Exception $e) {
        error_log("Erro ao verificar conexão Tor: " . $e->getMessage());
        return [
            'connected' => false,
            'confidence' => 0,
            'indicators' => [],
            'error' => $e->getMessage()
        ];
    }
}

function isKnownTorExitNode($ip) {
    $knownExitNodes = [
        '199.87.154.255',
        '185.220.101.0',
        '185.220.100.0',
        '192.42.116.0',
        '23.129.64.0'
    ];
    
    foreach ($knownExitNodes as $exitNode) {
        if (strpos($ip, substr($exitNode, 0, -1)) === 0) {
            return true;
        }
    }
    
    return false;
}

function logActivity($userId, $action, $details = []) {
    global $conn;
    
    try {
        $torDetection = checkTorConnection();
        
        $logData = array_merge($details, [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'ip' => getRealIP(),
            'tor_detected' => $torDetection['connected'],
            'tor_confidence' => $torDetection['confidence'],
            'timestamp' => time()
        ]);
        
        $stmt = $conn->prepare("
            INSERT INTO user_access_logs 
            (user_id, ip_address, user_agent, is_tor, tor_confidence, page_accessed, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $stmt->bind_param("ississ", 
            $userId,
            $logData['ip'],
            $logData['user_agent'],
            $logData['tor_detected'],
            $logData['tor_confidence'],
            $action
        );
        $stmt->execute();
        
        if (in_array($action, ['login', 'withdrawal', 'purchase', 'encrypted_message'])) {
            error_log("SECURITY LOG: User $userId performed $action - " . json_encode($logData));
        }
        
    } catch (Exception $e) {
        error_log("Erro ao registrar atividade: " . $e->getMessage());
    }
}

function generateAndSaveWalletAddress($userId, $crypto) {
    global $conn;

    $conn->begin_transaction();

    try {
        // 1. Verificar se o usuário já possui um endereço para essa moeda
        $addressField = strtolower($crypto) . '_deposit_address';
        $stmt = $conn->prepare("SELECT $addressField FROM users WHERE id = ? FOR UPDATE");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!empty($result[$addressField])) {
            throw new Exception("Você já possui um endereço $crypto configurado.");
        }

        // 2. Gerar um novo endereço
        $newAddress = generateCryptoAddress($crypto, $userId);
        if (!$newAddress) {
            throw new Exception("Falha crítica ao tentar gerar o endereço $crypto.");
        }

        // 3. Validar o formato do endereço gerado (segurança extra)
        if (!isValidCryptoAddress($newAddress, $crypto)) {
            throw new Exception("O endereço $crypto gerado é inválido. Contate o suporte.");
        }

        // 4. Salvar o novo endereço no banco de dados
        $stmt = $conn->prepare("UPDATE users SET $addressField = ?, updated_at = NOW() WHERE id = ?");
        $stmt->bind_param("si", $newAddress, $userId);
        
        if (!$stmt->execute() || $stmt->affected_rows === 0) {
            throw new Exception("Não foi possível salvar o novo endereço no banco de dados.");
        }
        $stmt->close();
        
        // 5. Se tudo correu bem, confirma a transação
        $conn->commit();
        
        error_log("✅ ENDEREÇO $crypto GERADO - User ID: $userId - Endereço: " . substr($newAddress, 0, 10) . "...");
        
        return $newAddress;

    } catch (Exception $e) {
        // Se qualquer passo falhar, desfaz tudo
        $conn->rollback();
        // Lança a exceção novamente para ser capturada pelo script principal
        throw $e;
    }
}


/**
 * Roteador: chama a função de geração correta com base na cripto.
 */
function generateCryptoAddress($crypto, $userId) {
    switch (strtoupper($crypto)) {
        case 'BTC':
            return generateBitcoinAddress($userId);
        case 'ETH':
            return generateEthereumAddress($userId);
        case 'XMR':
            return generateMoneroAddress($userId);
        default:
            return false;
    }
}

/**
 * Validador: chama a função de validação correta.
 */
function isValidCryptoAddress($address, $crypto) {
    switch (strtoupper($crypto)) {
        case 'BTC':
            return isValidBitcoinAddress($address);
        case 'ETH':
            return isValidEthereumAddress($address);
        case 'XMR':
            return isValidMoneroAddress($address);
        default:
            return false;
    }
}

// --- Funções Específicas de Geração e Validação ---

function generateBitcoinAddress($userId) {
    $seed = hash('sha256', 'zee_btc_v4_' . $userId . microtime() . random_bytes(32));
    // Simula um endereço Bech32 (bc1)
    return 'bc1q' . substr(strtolower(preg_replace('/[01io]/', '', $seed)), 0, 38);
}

function generateEthereumAddress($userId) {
    $seed = hash('sha256', 'zee_eth_v4_' . $userId . microtime() . random_bytes(32));
    return '0x' . substr($seed, 0, 40);
}

function generateMoneroAddress($userId) {
    $seed = hash('sha256', 'zee_xmr_v4_' . $userId . microtime() . random_bytes(64));
    return '4' . substr(preg_replace('/[^a-zA-Z0-9]/', '', $seed), 0, 94);
}

function isValidBitcoinAddress($address) {
    return preg_match('/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,61}$/', $address) === 1;
}

function isValidEthereumAddress($address) {
    return preg_match('/^0x[a-fA-F0-9]{40}$/', $address) === 1;
}

function isValidMoneroAddress($address) {
    // Corrigido: a validação deve estar dentro da função.
    if (strlen($address) !== 95 || !str_starts_with($address, '4')) {
        return false;
    }
    return ctype_alnum(substr($address, 1)); // Verifica se o resto é alfanumérico
}


function getSecurityLevel() {
    if (!isLoggedIn()) {
        return 'none';
    }
    
    $level = 'basic';
    
    if (isset($_SESSION['is_tor']) && $_SESSION['is_tor']) {
        $level = 'medium';
    }
    
    return $level;
}

function generateSecureCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    if (time() - ($_SESSION['csrf_token_time'] ?? 0) > 1800) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    return $_SESSION['csrf_token'];
}

function validateSecureCSRFToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    
    if (time() - ($_SESSION['csrf_token_time'] ?? 0) > 7200) {
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

function createLoginAttemptsTable() {
    global $conn;
    
    $sql = "CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        identifier VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45),
        email VARCHAR(255),
        success BOOLEAN DEFAULT FALSE,
        reason VARCHAR(100),
        attempt_time INT NOT NULL,
        user_agent TEXT,
        INDEX idx_identifier_time (identifier, attempt_time),
        INDEX idx_email_time (email, attempt_time)
    ) ENGINE=InnoDB";
    
    try {
        $conn->query($sql);
        error_log("Tabela login_attempts criada com sucesso");
    } catch (Exception $e) {
        error_log("Erro ao criar tabela login_attempts: " . $e->getMessage());
    }
}

function checkRateLimitAdvanced($identifier, $max_attempts = 5, $time_window = 900) {
    global $conn;
    
    try {
        // Verificar se a tabela existe, se não, criar
        $table_check = $conn->query("SHOW TABLES LIKE 'login_attempts'");
        if ($table_check->num_rows == 0) {
            createLoginAttemptsTable();
        }
        
        // Limpar tentativas antigas
        $cleanup_time = time() - $time_window;
        $stmt = $conn->prepare("DELETE FROM login_attempts WHERE attempt_time < ? AND identifier = ?");
        if ($stmt) {
            $stmt->bind_param("is", $cleanup_time, $identifier);
            $stmt->execute();
            $stmt->close();
        }
        
        // Contar tentativas recentes
        $stmt = $conn->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE identifier = ? AND attempt_time > ?");
        if ($stmt) {
            $stmt->bind_param("si", $identifier, $cleanup_time);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            
            return (int)$result['attempts'] < $max_attempts;
        }
        
        return true;
        
    } catch (Exception $e) {
        error_log("Erro no rate limiting: " . $e->getMessage());
        return true; // Em caso de erro, não bloquear
    }
}



function detectSuspiciousActivity($email) {
    global $conn;
    
    try {
        // Verificar se a tabela existe
        $table_check = $conn->query("SHOW TABLES LIKE 'login_attempts'");
        if ($table_check->num_rows == 0) {
            return ['suspicious' => false, 'reason' => ''];
        }
        
        // Verificar múltiplos IPs para mesmo email em pouco tempo
        $stmt = $conn->prepare("
            SELECT COUNT(DISTINCT ip_address) as ip_count 
            FROM login_attempts 
            WHERE email = ? AND attempt_time > ? AND success = 0
        ");
        $recent_time = time() - 3600; // Última hora
        $stmt->bind_param("si", $email, $recent_time);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        // Se mais de 3 IPs diferentes tentaram o mesmo email, é suspeito
        if ((int)$result['ip_count'] > 3) {
            return ['suspicious' => true, 'reason' => 'multiple_ips'];
        }
        
        return ['suspicious' => false, 'reason' => ''];
        
    } catch (Exception $e) {
        error_log("Erro na detecção de atividade suspeita: " . $e->getMessage());
        return ['suspicious' => false, 'reason' => ''];
    }
}

// ====== SISTEMA DE AUTENTICAÇÃO APRIMORADA ====== //

function loginSecure($email, $senha) {
    global $conn;
    
    try {
        // ✅ Buscar usuário com campos de segurança
        $stmt = $conn->prepare("SELECT id, name, email, password, failed_login_attempts, last_failed_login, account_locked_until FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        if ($user) {
            // ✅ Verificar se conta está bloqueada
            if (!empty($user['account_locked_until']) && time() < $user['account_locked_until']) {
                $unlock_time = date('H:i', $user['account_locked_until']);
                return "Conta bloqueada até {$unlock_time} devido a múltiplas tentativas falhadas.";
            }
            
            // ✅ Verificar senha
            if (password_verify($senha, $user['password'])) {
                // Login bem-sucedido
                
                // ✅ Resetar contador de tentativas falhadas
                $stmt = $conn->prepare("UPDATE users SET failed_login_attempts = 0, last_failed_login = NULL, account_locked_until = NULL WHERE id = ?");
                $stmt->bind_param("i", $user['id']);
                $stmt->execute();
                $stmt->close();
                
                // ✅ Configurar sessão segura
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int)$user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['user_email'] = $email;
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
                $_SESSION['logged_in'] = true;
                
                // ✅ Detectar TOR
                $torDetection = checkTorConnection();
                $_SESSION['is_tor'] = $torDetection['connected'];
                $_SESSION['tor_confidence'] = $torDetection['confidence'];
                
                // ✅ Atualizar último login
                $stmt = $conn->prepare("UPDATE users SET last_login = ?, last_ip = ? WHERE id = ?");
                $current_time = time();
                $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $stmt->bind_param("isi", $current_time, $client_ip, $user['id']);
                $stmt->execute();
                $stmt->close();
                
                return true;
                
            } else {
                // ✅ Incrementar contador de tentativas falhadas
                $failed_attempts = (int)$user['failed_login_attempts'] + 1;
                $lock_until = null;
                
                // Bloquear conta após 10 tentativas falhadas
                if ($failed_attempts >= 10) {
                    $lock_until = time() + 3600; // Bloquear por 1 hora
                    $error_message = "Conta bloqueada por 1 hora devido a múltiplas tentativas falhadas.";
                } else {
                    $remaining = 10 - $failed_attempts;
                    $error_message = "Email ou senha incorretos. Restam {$remaining} tentativas.";
                }
                
                $stmt = $conn->prepare("UPDATE users SET failed_login_attempts = ?, last_failed_login = ?, account_locked_until = ? WHERE id = ?");
                $current_time = time();
                $stmt->bind_param("isii", $failed_attempts, $current_time, $lock_until, $user['id']);
                $stmt->execute();
                $stmt->close();
                
                return $error_message;
            }
        } else {
            // ✅ Usuário não encontrado - manter tempo consistente
            $dummy_hash = '$2y$12$' . str_repeat('a', 53);
            password_verify($senha, $dummy_hash);
            
            return "Email ou senha incorretos.";
        }
        
    } catch (Exception $e) {
        error_log("Erro crítico no login seguro: " . $e->getMessage());
        return "Erro interno do sistema. Tente novamente em alguns minutos.";
    }
}

// ====== SISTEMA DE CADASTRO SEGURO ====== //

function cadastrarUsuarioSeguro($nome, $email, $senha) {
    global $conn;
    
    try {
        // ✅ Verificar se email já existe
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $existing_user = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        if ($existing_user) {
            return "Email já está em uso!";
        }
        
        // ✅ Criar hash seguro da senha
        $password_hash = password_hash($senha, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,       // 4 iterações
            'threads' => 3          // 3 threads
        ]);
        
        // ✅ Inserir usuário (SEM created_at - vai usar DEFAULT CURRENT_TIMESTAMP)
        $stmt = $conn->prepare("INSERT INTO users (name, email, password, last_ip, failed_login_attempts) VALUES (?, ?, ?, ?, 0)");
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt->bind_param("ssss", $nome, $email, $password_hash, $client_ip);
        
        if ($stmt->execute()) {
            $user_id = $conn->insert_id;
            $stmt->close();
            error_log("Novo usuário cadastrado com segurança: " . $email . " (ID: $user_id)");
            return true;
        } else {
            $error_msg = $conn->error;
            $stmt->close();
            error_log("Erro ao criar usuário seguro: " . $error_msg);
            return "Erro ao criar conta. Tente novamente.";
        }
        
    } catch (Exception $e) {
        error_log("Erro no cadastro seguro: " . $e->getMessage());
        return "Erro interno do sistema. Tente novamente em alguns minutos.";
    }
}
// ====== FUNÇÕES DE FINGERPRINTING ====== //

function getClientFingerprint() {
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    return hash('sha256', $client_ip . '|' . $user_agent);
}

function getSecureClientInfo() {
    return [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'fingerprint' => getClientFingerprint(),
        'tor_detected' => checkTorConnection()['connected']
    ];
}

// ====== SISTEMA DE VALIDAÇÃO APRIMORADA ====== //

function validateEmailSecure($email) {
    if (empty($email)) {
        return false;
    }
    
    if (strlen($email) > 255) {
        return false;
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    
    // Verificar domínios suspeitos básicos
    $suspicious_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com'];
    $domain = substr(strrchr($email, "@"), 1);
    
    if (in_array($domain, $suspicious_domains)) {
        return false;
    }
    
    return true;
}

function validatePasswordStrength($password) {
    if (strlen($password) < 8 || strlen($password) > 255) {
        return ['valid' => false, 'message' => 'Senha deve ter entre 8 e 255 caracteres'];
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        return ['valid' => false, 'message' => 'Senha deve conter pelo menos uma letra minúscula'];
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        return ['valid' => false, 'message' => 'Senha deve conter pelo menos uma letra maiúscula'];
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        return ['valid' => false, 'message' => 'Senha deve conter pelo menos um número'];
    }
    
    return ['valid' => true, 'message' => 'Senha válida'];
}

function validateNameSecure($name) {
    if (empty($name)) {
        return false;
    }
    
    if (strlen($name) < 2 || strlen($name) > 100) {
        return false;
    }
    
    // Apenas letras, espaços e alguns caracteres especiais
    if (!preg_match('/^[A-Za-zÀ-ÿ\s\-\'\.]+$/', $name)) {
        return false;
    }
    
    return true;
}

// ====== FUNÇÕES DE TIMING ATTACK PROTECTION ====== //

function secureTimingDelay($min_time = 0.5) {
    static $start_time;
    
    if ($start_time === null) {
        $start_time = microtime(true);
    }
    
    $elapsed_time = microtime(true) - $start_time;
    
    if ($elapsed_time < $min_time) {
        usleep(($min_time - $elapsed_time) * 1000000);
    }
    
    $start_time = null; // Reset para próxima chamada
}

// ====== FUNÇÕES DE AUDITORIA E LOG ====== //

function logSecurityEvent($event_type, $details = []) {
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
        'details' => $details
    ];
    
    error_log("SECURITY_EVENT: " . json_encode($log_data));
}

// ====== VERIFICAÇÃO DE TABELAS DO SISTEMA ====== //

function ensureSecurityTablesExist() {
    global $conn;
    
    // Criar tabela login_attempts se não existir
    $table_check = $conn->query("SHOW TABLES LIKE 'login_attempts'");
    if ($table_check->num_rows == 0) {
        createLoginAttemptsTable();
    }
    
    // Verificar se users tem campos de segurança
    $columns_check = $conn->query("SHOW COLUMNS FROM users LIKE 'failed_login_attempts'");
    if ($columns_check->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN failed_login_attempts INT DEFAULT 0");
        $conn->query("ALTER TABLE users ADD COLUMN last_failed_login INT DEFAULT NULL");
        $conn->query("ALTER TABLE users ADD COLUMN account_locked_until INT DEFAULT NULL");
        $conn->query("ALTER TABLE users ADD COLUMN last_login INT DEFAULT NULL");
        $conn->query("ALTER TABLE users ADD COLUMN last_ip VARCHAR(45) DEFAULT NULL");
        error_log("Campos de segurança adicionados à tabela users");
    }
}

// ====== VERIFICAÇÃO DE SESSÃO APRIMORADA ====== //

function verificarLoginSeguro() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        logSecurityEvent('unauthorized_access', ['page' => $_SERVER['REQUEST_URI'] ?? 'unknown']);
        
        $_SESSION = array();
        session_destroy();
        header("Location: login.php");
        exit();
    }
    
    // Verificar timeout de sessão
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 3600) {
        logSecurityEvent('session_timeout', ['user_id' => $_SESSION['user_id']]);
        logout();
    }
    
    // Verificar consistência de IP (opcional - pode causar problemas com proxies)
    if (isset($_SESSION['ip_address']) && 
        $_SESSION['ip_address'] !== ($_SERVER['REMOTE_ADDR'] ?? 'unknown')) {
        // Log but don't logout (users may have dynamic IPs)
        logSecurityEvent('ip_change', [
            'user_id' => $_SESSION['user_id'],
            'old_ip' => $_SESSION['ip_address'],
            'new_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
    }
    
    $_SESSION['last_activity'] = time();
}

// ====== FUNÇÃO PARA REGISTRAR TENTATIVAS DE LOGIN ====== //

function recordLoginAttempt($identifier, $email, $success, $reason) {
    global $conn;
    
    try {
        // Verificar se a tabela existe
        $table_check = $conn->query("SHOW TABLES LIKE 'login_attempts'");
        if ($table_check->num_rows == 0) {
            createLoginAttemptsTable();
        }
        
        // Inserir tentativa de login
        $stmt = $conn->prepare("INSERT INTO login_attempts (identifier, ip_address, email, success, reason, attempt_time, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)");
        
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255);
        $attempt_time = time();
        $success_int = $success ? 1 : 0;
        
        $stmt->bind_param("sssisss", $identifier, $ip_address, $email, $success_int, $reason, $attempt_time, $user_agent);
        
        if ($stmt->execute()) {
            $stmt->close();
            return true;
        } else {
            error_log("Erro ao registrar tentativa de login: " . $stmt->error);
            $stmt->close();
            return false;
        }
        
    } catch (Exception $e) {
        error_log("Erro na função recordLoginAttempt: " . $e->getMessage());
        return false;
    }
}

// ====== FUNÇÃO DE CADASTRO SIMPLES (FALLBACK) ====== //

function cadastrarUsuario($nome, $email, $senha) {
    global $conn;
    
    try {
        // Verificar se email já existe
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $existing_user = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        if ($existing_user) {
            return "Email já está em uso!";
        }
        
        // Criar hash da senha
        $password_hash = password_hash($senha, PASSWORD_DEFAULT);
        
        // Inserir usuário
        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $nome, $email, $password_hash);
        
        if ($stmt->execute()) {
            $stmt->close();
            error_log("Novo usuário cadastrado: " . $email);
            return true;
        } else {
            $stmt->close();
            error_log("Erro ao cadastrar usuário: " . $conn->error);
            return "Erro ao cadastrar usuário";
        }
        
    } catch (Exception $e) {
        error_log("Erro no cadastro: " . $e->getMessage());
        return "Erro interno do sistema. Tente novamente em alguns minutos.";
    }
}

?>