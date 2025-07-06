<?php
/**
 * ÁREA DO VENDEDOR - REGISTRO E LOGIN
 * Design Deep Web com correções de erro - VERSÃO CORRIGIDA PARA O BANCO DE DADOS ATUAL
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'includes/config.php';

// VERIFICAR SE JÁ ESTÁ LOGADO COMO VENDEDOR
if (isset($_SESSION['vendedor_id'])) {
    header("Location: admin/painel_vendedor.php");
    exit();
}

$erro = "";
$sucesso = "";

// PROCESSAR LOGIN (CORRIGIDO)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email'] ?? '');
    $senha = $_POST['senha'] ?? '';
    
    if (empty($email) || empty($senha)) {
        $erro = "Preencha e-mail e senha!";
    } else {
        try {
            // CORRIGIDO: Selecionando as colunas corretas (name, password, tipo)
            $stmt = $conn->prepare("SELECT id, password, name, tipo FROM users WHERE email = ?");
            
            if ($stmt === false) {
                 $erro = "Erro ao preparar a consulta: " . $conn->error;
            } else {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows === 1) {
                    $vendedor = $result->fetch_assoc();
                    
                    // CORRIGIDO: Verificar se o 'tipo' do usuário é 'vendedor'
                    if ($vendedor['tipo'] !== 'vendedor') {
                        $erro = "Esta conta não é uma conta de vendedor.";
                    // CORRIGIDO: Usar a coluna 'password' para verificação
                    } elseif (password_verify($senha, $vendedor['password'])) {
                        $_SESSION['vendedor_id'] = $vendedor['id'];
                        // CORRIGIDO: Usar a coluna 'name'
                        $_SESSION['vendedor_nome'] = $vendedor['name'];
                        $_SESSION['vendedor_email'] = $email;
                        
                        error_log("LOGIN VENDEDOR - ID: " . $vendedor['id'] . " - Email: " . $email);
                        
                        header("Location: admin/painel_vendedor.php");
                        exit();
                    } else {
                        $erro = "Senha incorreta!";
                    }
                } else {
                    $erro = "E-mail não cadastrado!";
                }
                $stmt->close();
            }
        } catch (Exception $e) {
            error_log("Erro no login: " . $e->getMessage());
            $erro = "Erro interno no login.";
        }
    }
}

// PROCESSAR REGISTRO (CORRIGIDO)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['registrar'])) {
    // CORRIGIDO: Campo 'nome' agora é 'name' e 'carteira' é 'btc_wallet'
    $nome = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $senha = $_POST['senha'] ?? '';
    $btc_wallet = trim($_POST['btc_wallet'] ?? '');

    // Validações básicas
    if (empty($nome) || empty($email) || empty($senha) || empty($btc_wallet)) {
        $erro = "Preencha todos os campos obrigatórios!";
    } elseif (strlen($nome) < 2) {
        $erro = "Nome deve ter pelo menos 2 caracteres!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = "E-mail inválido!";
    } elseif (strlen($senha) < 6) {
        $erro = "Senha deve ter pelo menos 6 caracteres!";
    } else {
        if (strlen($btc_wallet) < 26 || strlen($btc_wallet) > 62) {
            $erro = "Carteira Bitcoin inválida! Deve ter entre 26 e 62 caracteres.";
        } else {
            try {
                // Verificar se e-mail já existe
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    $erro = "E-mail já cadastrado!";
                } else {
                    // Verificar se carteira já existe
                    $stmt_wallet = $conn->prepare("SELECT id FROM users WHERE btc_wallet = ?");
                    $stmt_wallet->bind_param("s", $btc_wallet);
                    $stmt_wallet->execute();
                    $result_wallet = $stmt_wallet->get_result();
                    
                    if ($result_wallet->num_rows > 0) {
                        $erro = "Esta carteira Bitcoin já está sendo usada por outro vendedor!";
                    } else {
                        // CORRIGIDO: Inserindo nas colunas corretas (name, password, tipo, is_vendor)
                        $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
                        
                        // CORRIGIDO: Query de inserção atualizada para a nova estrutura da tabela
                        $stmt_insert = $conn->prepare("INSERT INTO users (name, email, password, btc_wallet, tipo, is_vendor) VALUES (?, ?, ?, ?, 'vendedor', 1)");
                        $stmt_insert->bind_param("ssss", $nome, $email, $senha_hash, $btc_wallet);
                        
                        if ($stmt_insert->execute()) {
                            $vendedor_id = $conn->insert_id;
                            
                            error_log("NOVO VENDEDOR REGISTRADO - ID: $vendedor_id - Email: $email");
                            
                            // Auto-login após registro
                            $_SESSION['vendedor_id'] = $vendedor_id;
                            $_SESSION['vendedor_nome'] = $nome;
                            $_SESSION['vendedor_email'] = $email;
                            
                            header("Location: admin/painel_vendedor.php");
                            exit();
                            
                        } else {
                            $erro = "Erro ao cadastrar: " . $conn->error;
                        }
                        $stmt_insert->close();
                    }
                    $stmt_wallet->close();
                }
                $stmt->close();
            } catch (Exception $e) {
                error_log("Erro no registro: " . $e->getMessage());
                $erro = "Erro interno: " . $e->getMessage();
            }
        }
    }
}
?>