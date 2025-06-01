<?php
// functions.php
if (!isset($_SESSION)) {
    session_start();
}

require_once 'config.php';

// ====== FUNÇÕES DE AUTENTICAÇÃO ====== //
function login($email, $senha) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT id, name, password, is_vendor, btc_balance FROM users WHERE email = ?");
    if (!$stmt) {
        return "Erro na preparação da consulta: " . $conn->error;
    }
    
    $stmt->bind_param("s", $email);
    if (!$stmt->execute()) {
        return "Erro ao executar a consulta: " . $stmt->error;
    }
    
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($senha, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_name'] = $user['name'];
            $_SESSION['is_vendor'] = $user['is_vendor'];
            $_SESSION['btc_balance'] = $user['btc_balance'];
            return true;
        }
    }
    return "Credenciais inválidas!";
}

// ====== FUNÇÕES DE REPUTAÇÃO ====== //
function getReputacao($user_id) {
    global $conn;
    
    // Verifica se é vendedor (tem produtos cadastrados)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM produtos WHERE vendedor_id = ?");
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
    if ($avg >= 4.5) return ["level" => "Ouro", "icon" => "★☆☆☆", "rating" => $avg];
    elseif ($avg >= 3.5) return ["level" => "Prata", "icon" => "★★☆☆", "rating" => $avg];
    elseif ($avg > 0) return ["level" => "Bronze", "icon" => "★★★☆", "rating" => $avg];
    return ["level" => "Sem avaliações", "icon" => "☆", "rating" => 0];
}

// ====== FUNÇÕES DE BITCOIN ====== //
function verificarDepositosPendentes($user_id) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT * FROM btc_transactions 
                          WHERE user_id = ? AND status = 'pending' 
                          AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    
    return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
}

function atualizarSaldoBTC($user_id, $amount) {
    global $conn;
    
    $stmt = $conn->prepare("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?");
    $stmt->bind_param("di", $amount, $user_id);
    
    if ($stmt->execute()) {
        $_SESSION['btc_balance'] += $amount;
        return true;
    }
    
    return false;
}

// ====== FUNÇÕES DE USUÁRIO ====== //
function cadastrarUsuario($nome, $email, $senha) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    if (!$stmt) {
        return "Erro na preparação da consulta: " . $conn->error;
    }
    
    $stmt->bind_param("s", $email);
    if (!$stmt->execute()) {
        return "Erro ao verificar e-mail: " . $stmt->error;
    }
    
    if ($stmt->get_result()->num_rows > 0) {
        return "E-mail já cadastrado!";
    }

    $senhaHash = password_hash($senha, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    if (!$stmt) {
        return "Erro na preparação do cadastro: " . $conn->error;
    }
    
    $stmt->bind_param("sss", $nome, $email, $senhaHash);
    return $stmt->execute() ? true : "Erro ao cadastrar: " . $stmt->error;
}

function verificarLogin() {
    if (!isset($_SESSION['user_id'])) {
        header("Location: login.php");
        exit();
    }
}

function logout() {
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    header("Location: login.php");
    exit();
}

function isVendedor($user_id) {
    global $conn;
    $stmt = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result['is_vendor'] == 1;
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
    
    $stmt = $conn->prepare("SELECT 
        btc_wallet, btc_deposit_address,
        (SELECT btc_wallet FROM vendedores WHERE id = ?) AS vendor_wallet
        FROM users WHERE id = ?");
    $stmt->bind_param("ii", $userId, $userId);
    $stmt->execute();
    
    $result = $stmt->get_result();
    return $result->fetch_assoc();
}
?>