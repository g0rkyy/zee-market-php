<?php
// functions.php - VERSÃO CORRIGIDA SEM LOOP DE REDIRECIONAMENTO

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

// ====== FUNÇÃO DE VERIFICAÇÃO DE LOGIN CORRIGIDA ====== //
function verificarLogin() {
    // Verificar se a sessão está ativa
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // Verificar se o usuário está logado
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        // Log para debug
        error_log("Usuário não logado - redirecionando para login");
        
        // Limpar sessão
        $_SESSION = array();
        
        // Destruir cookie de sessão se existir
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        // Destruir sessão
        session_destroy();
        
        // Redirecionar para login
        header("Location: login.php");
        exit();
    }
    
    // Verificar timeout de sessão (1 hora)
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 3600) {
        error_log("Sessão expirada para usuário ID: " . $_SESSION['user_id']);
        logout();
    }
    
    // Atualizar timestamp da sessão
    $_SESSION['login_time'] = time();
}

// ====== FUNÇÃO DE LOGOUT CORRIGIDA ====== //
function logout() {
    // Verificar se a sessão está ativa
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // Log para debug
    if (isset($_SESSION['user_id'])) {
        error_log("Logout do usuário ID: " . $_SESSION['user_id']);
    }
    
    // Limpar todas as variáveis de sessão
    $_SESSION = array();
    
    // Destruir cookie de sessão se existir
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Destruir a sessão
    session_destroy();
    
    // Redirecionar para login
    header("Location: login.php");
    exit();
}

// ====== FUNÇÃO PARA VERIFICAR SE ESTÁ LOGADO SEM REDIRECIONAR ====== //
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
        // Verifica se é vendedor (tem produtos cadastrados)
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

        // Para vendedores, calcula a reputação baseada nos feedbacks
        $stmt = $conn->prepare("SELECT AVG(rating) FROM feedback WHERE id IN (
            SELECT feedback_id FROM compras WHERE vendedor_id = ?
        )");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $avg = $stmt->get_result()->fetch_row()[0];
        $avg = $avg ? round($avg, 1) : 0;

        // Níveis de reputação
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
        // Verificar se email já existe
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

        // Cadastrar novo usuário
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

/**
 * Verifica se o usuário tem um endereço de depósito configurado
 * @param int $userId ID do usuário
 * @return array Retorna todos os endereços relacionados ao usuário
 */
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

/**
 * Atualizar saldos na sessão
 */
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

/**
 * Função para debug de sessão
 */
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
    $lockout_time = 300; // 5 minutos em segundos
    
    // Implemente a lógica para contar tentativas no seu banco de dados
    // Exemplo simplificado:
    $attempts = 0; // Substitua por consulta real ao banco
    $last_attempt = 0; // Substitua por consulta real ao banco
    
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
// Implementar função checkRateLimit em functions.php
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
    
    // Registrar tentativa
    $stmt = $conn->prepare("
        INSERT INTO rate_limits (user_id, action, created_at) 
        VALUES (?, ?, NOW())
    ");
    $stmt->bind_param("is", $userId, $action);
    $stmt->execute();
}
function loginWithPGP($email, $password, $pgpVerification) {
    global $conn;
    
    try {
        // Login normal primeiro
        $loginResult = login($email, $password);
        
        if ($loginResult !== true) {
            return $loginResult;
        }
        
        // Se chegou aqui, login normal foi bem-sucedido
        // Verificar se PGP foi validado
        if (!$pgpVerification['valid']) {
            // Fazer logout em caso de falha PGP
            logout();
            return "Assinatura PGP inválida";
        }
        
        // Marcar autenticação PGP na sessão
        $_SESSION['pgp_authenticated'] = true;
        $_SESSION['pgp_auth_time'] = time();
        $_SESSION['security_level'] = 'high';
        $_SESSION['auth_method'] = 'pgp';
        
        return true;
        
    } catch (Exception $e) {
        error_log("Erro no login PGP: " . $e->getMessage());
        return "Erro interno no login PGP";
    }
}

/**
 * ✅ VERIFICAR ASSINATURA PGP SIMPLES
 */
function verifyPGPSignature($message, $email) {
    global $conn;
    
    try {
        // Buscar chave PGP do usuário
        $stmt = $conn->prepare("
            SELECT upk.public_key, upk.fingerprint, u.id 
            FROM user_pgp_keys upk 
            JOIN users u ON upk.user_id = u.id 
            WHERE u.email = ? AND upk.revoked = 0
        ");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        if (!$result) {
            return [
                'valid' => false,
                'error' => 'Usuário não possui chaves PGP configuradas'
            ];
        }
        
        // Verificação simples (em produção, usar gnupg real)
        if (empty($message) || strlen($message) < 10) {
            return [
                'valid' => false,
                'error' => 'Mensagem PGP muito curta'
            ];
        }
        
        // Verificar se contém elementos básicos de uma assinatura PGP
        if (strpos($message, '-----BEGIN') === false || 
            strpos($message, '-----END') === false) {
            return [
                'valid' => false,
                'error' => 'Formato de assinatura PGP inválido'
            ];
        }
        
        // Por agora, aceitar qualquer assinatura válida em formato
        // Em produção: implementar verificação real com gnupg
        return [
            'valid' => true,
            'fingerprint' => $result['fingerprint'],
            'user_id' => $result['id']
        ];
        
    } catch (Exception $e) {
        error_log("Erro na verificação PGP: " . $e->getMessage());
        return [
            'valid' => false,
            'error' => 'Erro interno na verificação PGP'
        ];
    }
}

/**
 * ✅ VERIFICAR SE USUÁRIO TEM CHAVES PGP
 */
function userHasPGPKeys($userId) {
    global $conn;
    
    try {
        $stmt = $conn->prepare("SELECT id FROM user_pgp_keys WHERE user_id = ? AND revoked = 0");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        
        return $stmt->get_result()->num_rows > 0;
    } catch (Exception $e) {
        error_log("Erro ao verificar chaves PGP: " . $e->getMessage());
        return false;
    }
}

// ====== FUNÇÕES TOR ====== //

/**
 * ✅ OBTER IP REAL (FUNCIONA COM TOR)
 */
function getRealIP() {
    $headers = [
        'HTTP_CF_CONNECTING_IP',     // Cloudflare
        'HTTP_CLIENT_IP',            // Proxy
        'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
        'HTTP_X_FORWARDED',          // Proxy
        'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
        'HTTP_FORWARDED_FOR',        // Proxy
        'HTTP_FORWARDED',            // Proxy
        'REMOTE_ADDR'                // Standard
    ];
    
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            
            // Validar IP
            if (filter_var($ip, FILTER_VALIDATE_IP, 
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * ✅ VERIFICAR SE CONEXÃO É TOR
 */
function checkTorConnection() {
    try {
        // Verificar indicadores de Tor Browser
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $acceptEncoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
        $ip = getRealIP();
        
        $torScore = 0;
        $indicators = [];
        
        // 1. Verificar User-Agent típico do Tor Browser
        if (strpos($userAgent, 'Firefox') !== false && 
            !strpos($userAgent, 'Chrome') && 
            !strpos($userAgent, 'Safari')) {
            $torScore += 25;
            $indicators[] = 'Firefox-only user agent';
        }
        
        // 2. Verificar configurações de linguagem padrão do Tor
        if ($acceptLanguage === 'en-US,en;q=0.5' || $acceptLanguage === 'en-us,en;q=0.5') {
            $torScore += 30;
            $indicators[] = 'Default Tor language settings';
        }
        
        // 3. Verificar headers ausentes (Tor remove alguns)
        if (empty($_SERVER['HTTP_CACHE_CONTROL']) && 
            empty($_SERVER['HTTP_PRAGMA'])) {
            $torScore += 15;
            $indicators[] = 'Missing cache headers';
        }
        
        // 4. Verificar se vem de exit node conhecido (simulado)
        if (isKnownTorExitNode($ip)) {
            $torScore += 40;
            $indicators[] = 'Known Tor exit node';
        }
        
        // 5. Verificar outras características
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

/**
 * ✅ VERIFICAR SE IP É EXIT NODE TOR (SIMULADO)
 */
function isKnownTorExitNode($ip) {
    // Lista simplificada de exit nodes conhecidos (em produção, usar API real)
    $knownExitNodes = [
        '199.87.154.255',
        '185.220.101.0',
        '185.220.100.0',
        '192.42.116.0',
        '23.129.64.0'
    ];
    
    // Verificar se o IP está na lista ou subnet
    foreach ($knownExitNodes as $exitNode) {
        if (strpos($ip, substr($exitNode, 0, -1)) === 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * ✅ LOG DE ATIVIDADE COM SUPORTE PGP/TOR
 */
function logActivity($userId, $action, $details = []) {
    global $conn;
    
    try {
        // Detectar Tor
        $torDetection = checkTorConnection();
        
        // Preparar dados do log
        $logData = array_merge($details, [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'ip' => getRealIP(),
            'tor_detected' => $torDetection['connected'],
            'tor_confidence' => $torDetection['confidence'],
            'pgp_auth' => isset($_SESSION['pgp_authenticated']) ? $_SESSION['pgp_authenticated'] : false,
            'security_level' => $_SESSION['security_level'] ?? 'standard',
            'timestamp' => time()
        ]);
        
        // Salvar no banco
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
        
        // Log adicional para ações importantes
        if (in_array($action, ['login_pgp', 'login_tor', 'withdrawal', 'purchase'])) {
            error_log("SECURITY LOG: User $userId performed $action - " . json_encode($logData));
        }
        
    } catch (Exception $e) {
        error_log("Erro ao registrar atividade: " . $e->getMessage());
    }
}

/**
 * ✅ VERIFICAR NÍVEL DE SEGURANÇA DA SESSÃO
 */
function getSecurityLevel() {
    if (!isLoggedIn()) {
        return 'none';
    }
    
    $level = 'basic';
    
    // Verificar se está usando Tor
    if (isset($_SESSION['is_tor']) && $_SESSION['is_tor']) {
        $level = 'medium';
    }
    
    // Verificar se está usando PGP
    if (isset($_SESSION['pgp_authenticated']) && $_SESSION['pgp_authenticated']) {
        $level = 'high';
    }
    
    // Verificar se está usando ambos
    if (isset($_SESSION['is_tor']) && $_SESSION['is_tor'] && 
        isset($_SESSION['pgp_authenticated']) && $_SESSION['pgp_authenticated']) {
        $level = 'maximum';
    }
    
    return $level;
}

/**
 * ✅ GERAR TOKEN CSRF SEGURO
 */
function generateSecureCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    // Renovar token a cada 30 minutos
    if (time() - ($_SESSION['csrf_token_time'] ?? 0) > 1800) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * ✅ VALIDAR TOKEN CSRF SEGURO
 */
function validateSecureCSRFToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    
    // Verificar se token não expirou (2 horas)
    if (time() - ($_SESSION['csrf_token_time'] ?? 0) > 7200) {
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * ✅ REQUIRER NÍVEL MÍNIMO DE SEGURANÇA
 */
function requireSecurityLevel($minLevel) {
    $levels = ['none' => 0, 'basic' => 1, 'medium' => 2, 'high' => 3, 'maximum' => 4];
    $currentLevel = getSecurityLevel();
    
    if ($levels[$currentLevel] < $levels[$minLevel]) {
        $_SESSION['required_security_level'] = $minLevel;
        header("Location: security_upgrade.php");
        exit();
    }
}

/**
 * ✅ OBTER ESTATÍSTICAS DE SEGURANÇA DO USUÁRIO
 */
function getUserSecurityStats($userId) {
    global $conn;
    
    try {
        // Contar logins com Tor
        $stmt = $conn->prepare("
            SELECT 
                COUNT(*) as total_logins,
                SUM(CASE WHEN is_tor = 1 THEN 1 ELSE 0 END) as tor_logins,
                SUM(CASE WHEN pgp_used = 1 THEN 1 ELSE 0 END) as pgp_logins
            FROM login_logs 
            WHERE user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stats = $stmt->get_result()->fetch_assoc();
        
        // Verificar se tem chaves PGP
        $hasPGP = userHasPGPKeys($userId);
        
        return [
            'total_logins' => $stats['total_logins'] ?? 0,
            'tor_usage_percent' => $stats['total_logins'] > 0 ? 
                round(($stats['tor_logins'] / $stats['total_logins']) * 100, 1) : 0,
            'pgp_usage_percent' => $stats['total_logins'] > 0 ? 
                round(($stats['pgp_logins'] / $stats['total_logins']) * 100, 1) : 0,
            'has_pgp_keys' => $hasPGP,
            'security_score' => calculateSecurityScore($stats, $hasPGP)
        ];
        
    } catch (Exception $e) {
        error_log("Erro ao obter estatísticas de segurança: " . $e->getMessage());
        return [
            'total_logins' => 0,
            'tor_usage_percent' => 0,
            'pgp_usage_percent' => 0,
            'has_pgp_keys' => false,
            'security_score' => 0
        ];
    }
}

/**
 * ✅ CALCULAR SCORE DE SEGURANÇA
 */
function calculateSecurityScore($stats, $hasPGP) {
    $score = 0;
    
    // Base score por ter feito login
    if ($stats['total_logins'] > 0) {
        $score += 20;
    }
    
    // Score por uso do Tor
    $torPercent = $stats['tor_logins'] / max($stats['total_logins'], 1) * 100;
    $score += min($torPercent * 0.4, 40); // Máximo 40 pontos
    
    // Score por uso do PGP
    $pgpPercent = $stats['pgp_logins'] / max($stats['total_logins'], 1) * 100;
    $score += min($pgpPercent * 0.3, 30); // Máximo 30 pontos
    
    // Score por ter chaves PGP configuradas
    if ($hasPGP) {
        $score += 10;
    }
    
    return min(round($score), 100);
}
?>