<?php
// Zee-Market - Sistema de Saque Seguro (Modelo Semi-Manual)
// Versão 2.0 - Hardened

session_start();

// Inclui nossos arquivos de configuração e funções essenciais.
require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/SecurityLogger.php';

// Redireciona para o login se o usuário não estiver autenticado. A segurança começa aqui.
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$securityLogger = new SecurityLogger();

// Apenas processa se o método for POST, para evitar acessos diretos ao script.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Validamos e sanitizamos as entradas do usuário. Nunca confie nos dados recebidos.
    $amount_str = $_POST['amount'] ?? '0';
    $address = trim($_POST['address'] ?? '');

    // Converte o valor para um formato numérico padronizado.
    $amount = (float) str_replace(',', '.', $amount_str);

    // Validação rigorosa dos dados de entrada.
    if ($amount <= 0) {
        header("Location: dashboard.php?error=" . urlencode("Valor de saque inválido."));
        exit();
    }

    if (empty($address) || strlen($address) > 255) { // Validação básica de endereço. Idealmente, usaríamos uma regex mais completa.
        header("Location: dashboard.php?error=" . urlencode("Endereço de destino inválido."));
        exit();
    }

    // =================================================================================
    // INÍCIO DA ZONA CRÍTICA - TRANSAÇÃO COM O BANCO DE DADOS
    // Usamos uma transação para garantir que as operações sejam atômicas (ou tudo funciona, ou nada é alterado).
    // =================================================================================

    $mysqli->begin_transaction();

    try {
        // Passo 1: Obter o saldo do usuário com um bloqueio de escrita (FOR UPDATE).
        // Isso impede que o usuário faça duas solicitações de saque ao mesmo tempo (condição de corrida),
        // gastando o mesmo saldo duas vezes.
        $stmt_get_balance = $mysqli->prepare("SELECT btc_balance FROM users WHERE id = ? FOR UPDATE");
        $stmt_get_balance->bind_param("i", $user_id);
        $stmt_get_balance->execute();
        $result = $stmt_get_balance->get_result();
        $user = $result->fetch_assoc();
        
        if (!$user) {
            throw new Exception("Usuário não encontrado.");
        }

        $current_balance = (float) $user['btc_balance'];

        // Passo 2: Verificar se o saldo é suficiente.
        if ($current_balance < $amount) {
            header("Location: dashboard.php?error=" . urlencode("Saldo insuficiente para completar o saque."));
            $mysqli->rollback(); // Reverte a transação mesmo que nada tenha sido alterado. Boa prática.
            exit();
        }

        // Passo 3: Debitar o valor do saldo INTERNO do usuário.
        $new_balance = $current_balance - $amount;
        $stmt_update_balance = $mysqli->prepare("UPDATE users SET btc_balance = ? WHERE id = ?");
        $stmt_update_balance->bind_param("di", $new_balance, $user_id);
        $stmt_update_balance->execute();

        // Passo 4: Inserir o registro do pedido de saque na nossa nova tabela 'pedidos_saque'.
        // O status 'pendente' sinaliza para nós (administradores) que esta solicitação precisa ser processada manualmente.
        $stmt_insert_request = $mysqli->prepare("INSERT INTO pedidos_saque (user_id, valor_btc, endereco_destino, status) VALUES (?, ?, ?, 'pendente')");
        $stmt_insert_request->bind_param("ids", $user_id, $amount, $address);
        $stmt_insert_request->execute();
        
        // Passo 5: Se todas as operações no banco de dados foram bem-sucedidas, nós confirmamos as alterações.
        $mysqli->commit();

        // Logamos o evento de segurança para nosso controle.
        $securityLogger->logSecurityEvent('Pedido de Saque Criado', $user_id, 'INFO', $_SERVER['REMOTE_ADDR']);

        // Redireciona o usuário com uma mensagem de sucesso.
        header("Location: dashboard.php?success=" . urlencode("Seu pedido de saque foi recebido e está sendo processado. Os fundos serão enviados em breve."));
        exit();

    } catch (Exception $e) {
        // Em caso de QUALQUER erro durante o processo, revertemos TODAS as alterações no banco de dados.
        $mysqli->rollback();

        // Logamos o erro para investigação posterior.
        $securityLogger->logSecurityEvent('Falha Crítica no Pedido de Saque', $user_id, 'CRITICAL', $_SERVER['REMOTE_ADDR'], $e->getMessage());

        // Informa o usuário sobre o erro.
        header("Location: dashboard.php?error=" . urlencode("Ocorreu um erro inesperado ao processar sua solicitação. Por favor, tente novamente mais tarde."));
        exit();
    }

} else {
    // Se alguém tentar acessar o script diretamente via GET, redireciona.
    header("Location: dashboard.php");
    exit();
}

// =================================================================================
// FIM DO SCRIPT
// Observe que toda a lógica perigosa de chamar APIs de blockchain,
// manusear chaves privadas ou assinar transações foi COMPLETAMENTE REMOVIDA.
// A responsabilidade do servidor agora é apenas gerenciar o banco de dados de forma segura.
// =================================================================================
?>