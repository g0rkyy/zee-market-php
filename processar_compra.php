<?php
/**
 * PROCESSADOR DE COMPRAS - VERSÃO RECALIBRADA
 * ✅ SINCRONIZADO COM NOVA ARQUITETURA DA BASE DE DADOS
 * ✅ purchases TABLE (NÃO MAIS compras)
 * ✅ users TABLE (NÃO MAIS vendedores)
 */

require_once 'includes/config.php';
require_once 'includes/functions.php';

// Função para obter configurações do sistema
function getSystemConfig($key, $default = null) {
    global $conn;
    $stmt = $conn->prepare("SELECT config_value FROM system_config WHERE config_key = ?");
    $stmt->bind_param("s", $key);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result ? $result['config_value'] : $default;
}

// Função para obter cotação atual do Bitcoin
function getBitcoinPrice() {
    global $conn;
    
    // Tentar buscar cotação mais recente (últimos 5 minutos)
    $stmt = $conn->query("SELECT btc_usd FROM crypto_rates WHERE created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE) ORDER BY created_at DESC LIMIT 1");
    $rate = $stmt->fetch_assoc();
    
    if ($rate) {
        return floatval($rate['btc_usd']);
    }
    
    // Se não tem cotação recente, usar padrão ou buscar online
    return 100000.00; // Valor padrão em caso de erro
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ========== VALIDAÇÃO E OBTENÇÃO DOS DADOS ========== //
    
    $produto_id = (int)$_POST['produto_id'];
    $nome_comprador = trim($_POST['nome']);
    $endereco_comprador = trim($_POST['endereco']);
    $payment_method = $_POST['payment_method'] ?? 'external';
    $btc_wallet_comprador = trim($_POST['btc_wallet'] ?? '');

    // Validações básicas
    if (empty($nome_comprador) || empty($endereco_comprador)) {
        die("Erro: Nome e endereço são obrigatórios!");
    }

    // Validar carteira Bitcoin se pagamento externo
    if ($payment_method === 'external') {
        if (empty($btc_wallet_comprador)) {
            die("Erro: Carteira Bitcoin é obrigatória para pagamento externo!");
        }
        if (!preg_match('/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/', $btc_wallet_comprador)) {
            die("Erro: Formato de carteira Bitcoin inválido!");
        }
    }

    // ✅ CORRIGIDO: Buscar produto e vendedor na tabela USERS
    $stmt = $conn->prepare("SELECT p.*, u.id as vendedor_id, u.name as vendedor_nome 
                           FROM produtos p 
                           JOIN users u ON p.vendedor_id = u.id 
                           WHERE p.id = ? AND u.is_vendor = 1");
    $stmt->bind_param("i", $produto_id);
    $stmt->execute();
    $produto = $stmt->get_result()->fetch_assoc();

    if (!$produto) {
        die("Erro: Produto não encontrado ou vendedor inativo!");
    }

    // ========== CONFIGURAÇÕES DE TAXAS E CARTEIRAS ========== //
    
    // Obter configurações do sistema
    $taxa_percentual = floatval(getSystemConfig('platform_fee_percent', 2.5)) / 100; // 2.5%
    $platform_wallet = getSystemConfig('platform_wallet', 'bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m');
    $modo_real = (bool)getSystemConfig('real_mode', 1);
    
    // Obter cotação atual do Bitcoin
    $btc_price_usd = getBitcoinPrice();
    
    // Calcular preços em BTC
    $valor_total_btc = $produto['preco'] / $btc_price_usd;
    $taxa_plataforma_btc = $valor_total_btc * $taxa_percentual;
    $valor_vendedor_btc = $valor_total_btc - $taxa_plataforma_btc;
    
    // Validações de segurança
    if ($valor_vendedor_btc <= 0) {
        die("Erro: Valor do produto muito baixo para cobrir taxas!");
    }
    
    if ($valor_total_btc < 0.00001) {
        die("Erro: Valor mínimo não atingido (0.00001 BTC)!");
    }

    // ========== VERIFICAR SALDO SE PAGAMENTO INTERNO ========== //
    
    $user_id = null;
    $saldo_usuario = 0;
    
    if ($payment_method === 'balance') {
        if (!isLoggedIn()) {
            die("Erro: Faça login para usar pagamento com saldo!");
        }
        
        $user_id = $_SESSION['user_id'];
        
        // Verificar saldo do usuário
        $stmt = $conn->prepare("SELECT btc_balance FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $user_data = $stmt->get_result()->fetch_assoc();
        
        if (!$user_data) {
            die("Erro: Usuário não encontrado!");
        }
        
        $saldo_usuario = floatval($user_data['btc_balance']);
        
        if ($saldo_usuario < $valor_total_btc) {
            die("Erro: Saldo insuficiente! Saldo: " . number_format($saldo_usuario, 8) . " BTC - Necessário: " . number_format($valor_total_btc, 8) . " BTC");
        }
    }
    
    // Log para debug
    error_log("Nova compra iniciada - Produto: {$produto['nome']} - Valor: {$produto['preco']} BRL - BTC: {$valor_total_btc} - Método: {$payment_method}");

    // ========== PROCESSAR COMPRA ========== //
    
    $conn->begin_transaction();
    
    try {
        // Dados para inserção
        $vendedor_id = $produto['vendedor_id'];
        $is_paid = ($payment_method === 'balance'); // Definir se está pago imediatamente
        
        // ✅ CORRIGIDO: Inserir na tabela PURCHASES com estrutura correta
        $sql = "INSERT INTO purchases 
                (produto_id, vendedor_id, user_id, nome, endereco, btc_wallet_comprador, 
                 payment_method, preco_usd, preco_btc_cotacao, valor_btc_total, 
                 taxa_plataforma_percent, taxa_plataforma_btc, valor_vendedor_btc,
                 payment_address, ip_address, user_agent, status, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";
        
        $stmt = $conn->prepare($sql);
        if ($stmt === false) {
            error_log("Prepare failed em processar_compra: " . $conn->error);
            throw new Exception("Erro no sistema de compras. Tente novamente.");
        }
        
        // Dados para inserção
        $status = $is_paid ? 'paid' : 'pending';
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $stmt->bind_param(
            "iiissssddddddssss",
            $produto_id,
            $vendedor_id,
            $user_id,
            $nome_comprador,
            $endereco_comprador,
            $btc_wallet_comprador,
            $payment_method,
            $produto['preco'],
            $btc_price_usd,
            $valor_total_btc,
            $taxa_percentual,
            $taxa_plataforma_btc,
            $valor_vendedor_btc,
            $platform_wallet,
            $ip_address,
            $user_agent,
            $status
        );
        
        if (!$stmt->execute()) {
            error_log("Execute failed em processar_compra: " . $stmt->error);
            throw new Exception("Não foi possível processar sua compra. Por favor, tente novamente.");
        }
        
        $compra_id = $stmt->insert_id;
        $stmt->close();

        // ========== PROCESSAR PAGAMENTO COM SALDO (SE APLICÁVEL) ========== //
        
        $tx_hash_interno = null;
        
        if ($payment_method === 'balance' && $user_id) {
            // Deduzir saldo do usuário
            $stmt = $conn->prepare("UPDATE users SET btc_balance = btc_balance - ? WHERE id = ?");
            $stmt->bind_param("di", $valor_total_btc, $user_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Erro ao deduzir saldo: " . $conn->error);
            }
            
            // Gerar hash interno único
            $tx_hash_interno = 'internal_' . $compra_id . '_' . time();
            
            // Registrar transação de débito
            $stmt = $conn->prepare("INSERT INTO btc_transactions 
                                  (user_id, type, amount, status, crypto_type, tx_hash, created_at) 
                                  VALUES (?, 'withdrawal', ?, 'confirmed', 'BTC', ?, NOW())");
            $stmt->bind_param("ids", $user_id, $valor_total_btc, $tx_hash_interno);
            
            if (!$stmt->execute()) {
                throw new Exception("Erro ao registrar transação: " . $conn->error);
            }
            
            // Obter novo saldo
            $stmt = $conn->prepare("SELECT btc_balance FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $novo_saldo = $stmt->get_result()->fetch_assoc()['btc_balance'];
            
            // Registrar no histórico de saldo
            $stmt = $conn->prepare("INSERT INTO btc_balance_history 
                                  (user_id, type, amount, balance_before, balance_after, description, tx_hash, crypto_type) 
                                  VALUES (?, 'debit', ?, ?, ?, 'Compra com saldo interno', ?, 'BTC')");
            $stmt->bind_param("idddss", $user_id, $valor_total_btc, $saldo_usuario, $novo_saldo, $tx_hash_interno);
            
            if (!$stmt->execute()) {
                throw new Exception("Erro ao registrar histórico de saldo: " . $conn->error);
            }
            
            // ✅ CORRIGIDO: Atualizar na tabela PURCHASES
            $stmt = $conn->prepare("UPDATE purchases SET tx_hash = ?, confirmations = 999, status = 'confirmed' WHERE id = ?");
            $stmt->bind_param("si", $tx_hash_interno, $compra_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Erro ao atualizar compra com hash: " . $conn->error);
            }
            
            // Atualizar saldo na sessão
            if (isset($_SESSION['btc_balance'])) {
                $_SESSION['btc_balance'] = floatval($novo_saldo);
            }
        }
        
        // Atualizar preço BTC do produto com cotação atual
        $stmt = $conn->prepare("UPDATE produtos SET preco_btc = ? WHERE id = ?");
        $stmt->bind_param("di", $valor_total_btc, $produto_id);
        $stmt->execute();
        
        // Registrar log de compra
        $stmt = $conn->prepare("INSERT INTO admin_logs 
                              (user_id, action, details, ip_address, user_agent) 
                              VALUES (?, 'purchase_created', ?, ?, ?)");
        $details = json_encode([
            'compra_id' => $compra_id,
            'produto_id' => $produto_id,
            'valor_btc' => $valor_total_btc,
            'taxa_plataforma' => $taxa_plataforma_btc,
            'btc_price_usd' => $btc_price_usd,
            'payment_method' => $payment_method,
            'paid_immediately' => $is_paid,
            'tx_hash' => $tx_hash_interno
        ]);
        $log_user_id = $user_id ?? 0;
        
        $stmt->bind_param("isss", $log_user_id, $details, $ip_address, $user_agent);
        $stmt->execute();
        
        // Confirmar transação
        $conn->commit();
        
        // Log de sucesso
        $status_msg = ($payment_method === 'balance') ? 'PAGO COM SALDO' : 'AGUARDANDO PAGAMENTO';
        error_log("Compra #{$compra_id} criada - Total: {$valor_total_btc} BTC - Taxa: {$taxa_plataforma_btc} BTC - Vendedor: {$valor_vendedor_btc} BTC - Status: {$status_msg}");
        
        // Redirecionar baseado no método de pagamento
        if ($payment_method === 'balance' && $is_paid) {
            // Compra paga - redirecionar para confirmação
            header("Location: compra_confirmada.php?id=" . $compra_id);
        } else {
            // Pagamento externo - redirecionar para pagamento
            header("Location: pagamento_btc.php?id=" . $compra_id);
        }
        exit();
        
    } catch (Exception $e) {
        $conn->rollback();
        error_log("Erro ao processar compra: " . $e->getMessage());
        die("Erro ao processar compra: " . $e->getMessage());
    }
    
} else {
    // Se não é POST, redirecionar para home
    header("Location: index.php");
    exit();
}
?>