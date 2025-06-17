<?php
/**
 * @author Blackcat Security Team
 * @version 2.0 - CSRF Protected
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ✅ INICIALIZAR SESSÃO
if (!isset($_SESSION)) {
    session_start();
}

require_once 'includes/config.php';
require_once 'includes/functions.php';

// ✅ VERIFICAR LOGIN OBRIGATÓRIO
verificarLogin();

// ✅ GERAR TOKEN CSRF SE NÃO EXISTIR
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ✅ VALIDAÇÃO CSRF ROBUSTA PARA REQUESTS POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificação CSRF obrigatória
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        // Log de tentativa de ataque CSRF
        error_log("🚨 CSRF ATTACK - setup_btc_wallet.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - User ID: " . ($_SESSION['user_id'] ?? 'unknown') . " - User Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
        
        $_SESSION['error_msg'] = '🛡️ ERRO DE SEGURANÇA: Token CSRF inválido. Operação bloqueada por segurança.';
        header("Location: dashboard.php");
        exit();
    }

    // ✅ FUNÇÃO DE VALIDAÇÃO MELHORADA DE ENDEREÇO BTC
    function isValidBTCAddress($address) {
        // Remove espaços em branco
        $address = trim($address);
        
        // Verifica se não está vazio
        if (empty($address)) {
            return false;
        }
        
        // Padrões para diferentes tipos de endereços Bitcoin
        $patterns = [
            // Legacy addresses (P2PKH) - começam com 1
            '/^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/',
            // Script addresses (P2SH) - começam com 3  
            '/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/',
            // Bech32 addresses (P2WPKH/P2WSH) - começam com bc1
            '/^bc1[a-z0-9]{39,59}$/',
            // Testnet addresses - começam com m, n, 2, tb1
            '/^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/',
            '/^tb1[a-z0-9]{39,59}$/'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $address)) {
                return true;
            }
        }
        
        return false;
    }

    // ✅ SANITIZAÇÃO E VALIDAÇÃO DO INPUT
    $btc_wallet = trim($_POST['btc_wallet'] ?? '');
    
    // Remover caracteres invisíveis e normalizações
    $btc_wallet = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '', $btc_wallet);
    
    if (empty($btc_wallet)) {
        $_SESSION['error_msg'] = '❌ Endereço Bitcoin é obrigatório!';
        header("Location: dashboard.php");
        exit();
    }

    if (!isValidBTCAddress($btc_wallet)) {
        error_log("Endereço BTC inválido fornecido - User ID: " . $_SESSION['user_id'] . " - Endereço: " . $btc_wallet);
        $_SESSION['error_msg'] = '❌ Endereço Bitcoin inválido! Verifique o formato do endereço.';
        header("Location: dashboard.php");
        exit();
    }

    // ✅ VALIDAÇÃO ADICIONAL DE SEGURANÇA
    if (strlen($btc_wallet) > 100) {
        $_SESSION['error_msg'] = '❌ Endereço Bitcoin muito longo!';
        header("Location: dashboard.php");
        exit();
    }

    // ✅ VERIFICAR SE NÃO É UM ENDEREÇO MALICIOSO CONHECIDO
    $blacklisted_addresses = [
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', // Genesis block address (Satoshi)
        'bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6', // Exemplo de endereço suspeito
        '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', // Silk Road address
        '1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF', // FBI seized address
    ];
    
    if (in_array($btc_wallet, $blacklisted_addresses)) {
        error_log("🚨 TENTATIVA DE USAR ENDEREÇO BLACKLISTADO - User ID: " . $_SESSION['user_id'] . " - Endereço: " . $btc_wallet . " - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $_SESSION['error_msg'] = '🚫 Endereço Bitcoin não permitido por questões de segurança.';
        header("Location: dashboard.php");
        exit();
    }

    // ✅ VERIFICAR SE O USUÁRIO NÃO ESTÁ TENTANDO USAR O MESMO ENDEREÇO
    try {
        $stmt_check = $conn->prepare("SELECT btc_wallet FROM users WHERE id = ?");
        $stmt_check->bind_param("i", $_SESSION['user_id']);
        $stmt_check->execute();
        $current_wallet = $stmt_check->get_result()->fetch_assoc();
        $stmt_check->close();
        
        if ($current_wallet && $current_wallet['btc_wallet'] === $btc_wallet) {
            $_SESSION['error_msg'] = 'ℹ️ Este endereço Bitcoin já está configurado em sua conta.';
            header("Location: dashboard.php");
            exit();
        }
    } catch (Exception $e) {
        error_log("Erro ao verificar carteira atual - User ID: " . $_SESSION['user_id'] . " - Erro: " . $e->getMessage());
    }

    try {
        // ✅ INICIAR TRANSAÇÃO PARA OPERAÇÃO ATÔMICA
        $conn->begin_transaction();
        
        // ✅ USAR PREPARED STATEMENTS PARA SEGURANÇA MÁXIMA
        $stmt = $conn->prepare("UPDATE users SET btc_wallet = ?, btc_deposit_address = NULL, updated_at = NOW() WHERE id = ?");
        
        if (!$stmt) {
            throw new Exception("Erro na preparação da query: " . $conn->error);
        }
        
        $stmt->bind_param("si", $btc_wallet, $_SESSION['user_id']);
        
        if ($stmt->execute()) {
            // ✅ VERIFICAR SE REALMENTE ATUALIZOU
            if ($stmt->affected_rows > 0) {
                // ✅ LOG DE SUCESSO PARA AUDITORIA
                error_log("✅ CARTEIRA BTC ATUALIZADA - User ID: " . $_SESSION['user_id'] . " - Novo endereço: " . substr($btc_wallet, 0, 10) . "... - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                
                // ✅ COMMIT DA TRANSAÇÃO
                $conn->commit();
                
                $_SESSION['success_msg'] = '✅ Carteira Bitcoin configurada com sucesso! Endereço: ' . substr($btc_wallet, 0, 15) . '...';
                
                // ✅ REGENERAR TOKEN CSRF APÓS OPERAÇÃO CRÍTICA (SECURITY BEST PRACTICE)
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                
            } else {
                throw new Exception("Nenhuma linha foi atualizada - possível erro de permissão");
            }
        } else {
            throw new Exception("Erro na execução da query: " . $stmt->error);
        }
        
        $stmt->close();
        
    } catch (Exception $e) {
        // ✅ ROLLBACK EM CASO DE ERRO
        if ($conn->inTransaction) {
            $conn->rollback();
        }
        
        // ✅ LOG DE ERRO DETALHADO PARA DEBUGGING
        error_log("❌ ERRO AO CONFIGURAR CARTEIRA BTC - User ID: " . $_SESSION['user_id'] . " - Erro: " . $e->getMessage() . " - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        
        $_SESSION['error_msg'] = '❌ Erro interno ao salvar carteira. Tente novamente em alguns instantes.';
    }

    // ✅ REDIRECIONAMENTO SEGURO COM PREVENÇÃO DE HEADER INJECTION
    header("Location: dashboard.php", true, 302);
    exit();
}

// ✅ SE NÃO FOR POST, REDIRECIONAR PARA DASHBOARD
// Este arquivo deve ser acessado apenas via POST do formulário
$_SESSION['error_msg'] = '⚠️ Acesso direto não permitido. Use o formulário no dashboard.';
header("Location: dashboard.php", true, 302);
exit();
