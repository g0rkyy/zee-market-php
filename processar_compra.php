<?php
require_once 'includes/config.php';

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
    $produto_id = (int)$_POST['produto_id'];
    $nome = trim($_POST['nome']);
    $endereco = trim($_POST['endereco']);
    $btc_wallet = trim($_POST['btc_wallet']);

    // Validações básicas
    if (empty($nome) || empty($endereco) || empty($btc_wallet)) {
        die("Erro: Todos os campos são obrigatórios!");
    }

    // Validar formato da carteira Bitcoin
    if (!preg_match('/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$/', $btc_wallet)) {
        die("Erro: Formato de carteira Bitcoin inválido!");
    }

    // Busca o produto e vendedor
    $stmt = $conn->prepare("SELECT p.*, v.id as vendedor_id, v.nome as vendedor_nome 
                           FROM produtos p 
                           JOIN vendedores v ON p.vendedor_id = v.id 
                           WHERE p.id = ?");
    $stmt->bind_param("i", $produto_id);
    $stmt->execute();
    $produto = $stmt->get_result()->fetch_assoc();

    if (!$produto) {
        die("Erro: Produto não encontrado!");
    }

    // ========== CONFIGURAÇÕES DE TAXAS E CARTEIRAS ========== //
    
    // Obter configurações do sistema
    $taxa_percentual = floatval(getSystemConfig('platform_fee_percent', 2.5)) / 100; // 2.5%
    $platform_wallet = getSystemConfig('platform_wallet', 'bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m');
    $modo_real = (bool)getSystemConfig('real_mode', 1);
    
    // Obter cotação atual do Bitcoin
    $btc_price_usd = getBitcoinPrice();
    
    // Recalcular preço BTC com cotação atual
    $valor_total_btc = $produto['preco'] / $btc_price_usd;
    $taxa_plataforma = $valor_total_btc * $taxa_percentual;
    $valor_vendedor = $valor_total_btc - $taxa_plataforma;
    
    // Validações de segurança
    if ($valor_vendedor <= 0) {
        die("Erro: Valor do produto muito baixo para cobrir taxas!");
    }
    
    if ($valor_total_btc < 0.00001) {
        die("Erro: Valor mínimo não atingido (0.00001 BTC)!");
    }
    
    // Log para debug
    error_log("Nova compra iniciada - Produto: {$produto['nome']} - Valor: {$produto['preco']} BRL - BTC: {$valor_total_btc}");

    // ========== INSERIR COMPRA NO BANCO ========== //
    
    $conn->begin_transaction();
    
    try {
        // Inserir dados da compra
        $stmt = $conn->prepare("INSERT INTO compras 
                              (produto_id, vendedor_id, nome, endereco, btc_wallet_comprador, 
                               valor_btc, taxa_plataforma, wallet_plataforma, data_compra) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())");
        $stmt->bind_param("iisssdds", 
                         $produto_id, 
                         $produto['vendedor_id'], 
                         $nome, 
                         $endereco, 
                         $btc_wallet,
                         $valor_total_btc,      // Valor total que o cliente paga
                         $taxa_plataforma,      // Taxa da plataforma (2.5%)
                         $platform_wallet       // Carteira da plataforma
                        );

        if (!$stmt->execute()) {
            throw new Exception("Erro ao inserir compra: " . $conn->error);
        }
        
        $compra_id = $conn->insert_id;
        
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
            'taxa_plataforma' => $taxa_plataforma,
            'btc_price_usd' => $btc_price_usd
        ]);
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $user_id = 0; // Compra anônima
        
        $stmt->bind_param("isss", $user_id, $details, $ip_address, $user_agent);
        $stmt->execute();
        
        $conn->commit();
        
        // Log de sucesso
        error_log("Compra #{$compra_id} criada com sucesso - Total: {$valor_total_btc} BTC - Taxa: {$taxa_plataforma} BTC - Vendedor: {$valor_vendedor} BTC");
        
        // Redirecionar para pagamento
        header("Location: pagamento_btc.php?id=" . $compra_id);
        exit();
        
    } catch (Exception $e) {
        $conn->rollback();
        error_log("Erro ao processar compra: " . $e->getMessage());
        die("Erro ao processar compra. Tente novamente em alguns minutos.");
    }
    
} else {
    // Se não é POST, redirecionar para home
    header("Location: index.php");
    exit();
}
?>