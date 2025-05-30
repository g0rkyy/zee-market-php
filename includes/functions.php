<?php
// functions.php
if (!isset($_SESSION)) {
    session_start(); // Inicia a sessão se ainda não estiver iniciada
}

require_once 'config.php';

// Função de login
function login($email, $senha) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ?");
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
            return true;
        }
    }
    return "Credenciais inválidas!";
}

// Função de cadastro
function cadastrarUsuario($nome, $email, $senha) {
    global $conn;
    
    // Verifica se email já existe
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

    // Cadastra novo usuário
    $senhaHash = password_hash($senha, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    if (!$stmt) {
        return "Erro na preparação do cadastro: " . $conn->error;
    }
    
    $stmt->bind_param("sss", $nome, $email, $senhaHash);
    return $stmt->execute() ? true : "Erro ao cadastrar: " . $stmt->error;
}

// Verificação de login
function verificarLogin() {
    if (!isset($_SESSION['user_id'])) {
        header("Location: login.php");
        exit();
    }
}

// Logout
function logout() {
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    header("Location: login.php");
    exit();
}
function getReputacao($user_id) {
    global $conn;
    $stmt = $conn->prepare("SELECT AVG(rating) FROM feedback WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $avg = $stmt->get_result()->fetch_row()[0];
    
    // Níveis de reputação
    if ($avg >= 4.5) return ["level" => "Ouro", "icon" => "★☆☆☆"];
    elseif ($avg >= 3.5) return ["level" => "Prata", "icon" => "★★☆☆"];
    else return ["level" => "Bronze", "icon" => "★★★☆"];
}

if (!isset($_SESSION)) {
    session_start();
}

require_once 'config.php';

// ====== FUNÇÕES DE AUTENTICAÇÃO (ANTIGO auth.php) ====== //
function verificarAutenticacao() {
    if (!isset($_SESSION['user_id'])) {
        header("Location: login.php");
        exit();
    }
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
    verificarAutenticacao();
    if (!isVendedor($_SESSION['user_id'])) {
        header("Location: acesso_negado.php");
        exit();
    }
}

// ====== FUNÇÕES EXISTENTES (LOGIN/CADASTRO) ====== //
// ... (mantenha as funções login(), cadastrarUsuario(), etc. que já estão) ...
?>
