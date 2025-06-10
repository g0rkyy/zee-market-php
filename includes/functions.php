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

// ====== FUNÇÃO DE VERIFICAÇÃO DE LOGIN ====== //
function verificarLogin() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        error_log("Usuário não logado - redirecionando para login");
        
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
    
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 3600) {
        error_log("Sessão expirada para usuário ID: " . $_SESSION['user_id']);
        logout();
    }
    
    $_SESSION['login_time'] = time();
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

// ====== FUNÇÕES DE USUÁRIO ====== //
function cadastrarUsuario($nome, $email, $senha) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        if (!$stmt) {
            error_log("Erro na preparação da consulta de verificação: " . $conn->error);
            return "Erro interno do servidor";
        }
        
        $stmt->bind_param("s", $email);
        if (!$stmt->execute()) {
            error_log("Erro ao verificar e-mail: " . $stmt->error);
            return "Erro interno do servidor";
        }
        
        if ($stmt->get_result()->num_rows > 0) {
            return "E-mail já cadastrado!";
        }

        $senhaHash = password_hash($senha, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (name, email, password, btc_balance, eth_balance, xmr_balance, created_at) VALUES (?, ?, ?, 0, 0, 0, NOW())");
        if (!$stmt) {
            error_log("Erro na preparação do cadastro: " . $conn->error);
            return "Erro interno do servidor";
        }
        
        $stmt->bind_param("sss", $nome, $email, $senhaHash);
        
        if ($stmt->execute()) {
            error_log("Novo usuário cadastrado: " . $email);
            return true;
        } else {
            error_log("Erro ao cadastrar usuário: " . $stmt->error);
            return "Erro ao cadastrar usuário";
        }
    } catch (Exception $e) {
        error_log("Erro no cadastro: " . $e->getMessage());
        return "Erro interno do servidor";
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

function checkRateLimit($userId, $action, $maxAttempts, $timeWindow = 3600) {
    global $conn;
    
    $stmt = $conn->prepare("
        SELECT COUNT(*) as attempts 
        FROM rate_limits 
        WHERE user_id = ? AND action = ? 
        AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
    ");
    $stmt->bind_param("isi", $userId, $action, $timeWindow);
    $stmt->execute();
    
    $result = $stmt->get_result()->fetch_assoc();
    
    if ($result['attempts'] >= $maxAttempts) {
        throw new Exception("Rate limit excedido para $action");
    }
    
    $stmt = $conn->prepare("
        INSERT INTO rate_limits (user_id, action, created_at) 
        VALUES (?, ?, NOW())
    ");
    $stmt->bind_param("is", $userId, $action);
    $stmt->execute();
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
?>