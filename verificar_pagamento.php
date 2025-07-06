<?php
/**
 * VERIFICADOR DE PAGAMENTO - VERSÃO RECALIBRADA
 * ✅ SINCRONIZADO COM NOVA ARQUITETURA DA BASE DE DADOS
 * ✅ purchases TABLE (NÃO MAIS compras)
 * ✅ users TABLE (NÃO MAIS vendedores)
 */

require_once 'includes/config.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

// Headers para AJAX
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// Verificar se ID foi fornecido
if (!isset($_GET['id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'ID da compra não fornecido']);
    exit();
}

$compra_id = (int)$_GET['id'];

try {
    // ✅ CORRIGIDO: Buscar na tabela PURCHASES
    $stmt = $conn->prepare("
        SELECT 
            p.id, p.status, p.tx_hash, p.confirmations, p.valor_btc_total, p.payment_address,
            p.created_at, p.preco_usd,
            pr.nome as produto_nome
        FROM purchases p
        JOIN produtos pr ON p.produto_id = pr.id
        WHERE p.id = ?
    ");
    $stmt->bind_param("i", $compra_id);
    $stmt->execute();
    $compra = $stmt->get_result()->fetch_assoc();
    
    if (!$compra) {
        http_response_code(404);
        echo json_encode(['error' => 'Compra não encontrada']);
        exit();
    }
    
    // Se já está pago, retornar status
    $status_pago = in_array($compra['status'], ['paid', 'confirmed']);
    if ($status_pago) {
        echo json_encode([
            'pago' => true,
            'tx_hash' => $compra['tx_hash'],
            'confirmations' => (int)($compra['confirmations'] ?? 0),
            'status' => $compra['status'],
            'message' => 'Pagamento confirmado!'
        ]);
        exit();
    }
    
    // Se não está pago, verificar na blockchain (modo real)
    $wallet_address = $compra['payment_address'];
    $valor_esperado = (float)$compra['valor_btc_total'];
    
    // Verificar transações recentes no endereço
    $transacoes_encontradas = verificarTransacoesBlockchain($wallet_address, $valor_esperado);
    
    if (!empty($transacoes_encontradas)) {
        $transacao = $transacoes_encontradas[0]; // Primeira transação encontrada
        
        // Atualizar no banco
        $conn->begin_transaction();
        
        try {
            // ✅ CORRIGIDO: Atualizar na tabela PURCHASES
            $stmt = $conn->prepare("
                UPDATE purchases SET 
                    status = 'confirmed', 
                    tx_hash = ?, 
                    confirmations = ?
                WHERE id = ?
            ");
            $stmt->bind_param("sii", 
                $transacao['txid'], 
                $transacao['confirmations'],
                $compra_id
            );
            $stmt->execute();
            
            $conn->commit();
            
            // Log da confirmação
            error_log("Pagamento confirmado automaticamente - Compra #{$compra_id} - TX: {$transacao['txid']}");
            
            echo json_encode([
                'pago' => true,
                'tx_hash' => $transacao['txid'],
                'confirmations' => $transacao['confirmations'],
                'status' => 'newly_confirmed',
                'message' => 'Pagamento detectado e confirmado!'
            ]);
            
        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }
        
    } else {
        // Ainda não foi pago
        echo json_encode([
            'pago' => false,
            'status' => 'pending',
            'message' => 'Aguardando pagamento...',
            'valor_esperado' => $valor_esperado,
            'wallet_address' => $wallet_address
        ]);
    }
    
} catch (Exception $e) {
    error_log("Erro ao verificar pagamento: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Erro interno do servidor',
        'message' => 'Tente novamente em alguns minutos'
    ]);
}

/**
 * Verificar transações na blockchain usando APIs reais
 */
function verificarTransacoesBlockchain($address, $valorEsperado) {
    $transacoes = [];
    
    // API 1: BlockStream (Gratuita e confiável)
    $transacoes = verificarBlockstream($address, $valorEsperado);
    
    // Se não encontrou, tentar API 2: BlockCypher
    if (empty($transacoes)) {
        $transacoes = verificarBlockCypher($address, $valorEsperado);
    }
    
    return $transacoes;
}

/**
 * Verificar via Blockstream API
 */
function verificarBlockstream($address, $valorEsperado) {
    $url = "https://blockstream.info/api/address/{$address}/txs";
    
    $context = stream_context_create([
        'http' => [
            'timeout' => 15,
            'user_agent' => 'ZeeMarket/1.0'
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        return [];
    }
    
    $data = json_decode($response, true);
    if (!$data || !is_array($data)) {
        return [];
    }
    
    $transacoes_validas = [];
    
    foreach ($data as $tx) {
        $valor_recebido = 0;
        
        // Verificar outputs para este endereço
        foreach ($tx['vout'] as $output) {
            if (isset($output['scriptpubkey_address']) && 
                $output['scriptpubkey_address'] === $address) {
                $valor_recebido += $output['value'];
            }
        }
        
        if ($valor_recebido > 0) {
            $valor_btc = $valor_recebido / 100000000; // Satoshis para BTC
            
            // Verificar se o valor está próximo do esperado (tolerância de 1%)
            $tolerancia = $valorEsperado * 0.01;
            if (abs($valor_btc - $valorEsperado) <= $tolerancia) {
                
                // Calcular confirmações
                $confirmations = 0;
                if (isset($tx['status']['confirmed']) && $tx['status']['confirmed']) {
                    $confirmations = 6; // Assumir confirmado se está em bloco
                }
                
                $transacoes_validas[] = [
                    'txid' => $tx['txid'],
                    'amount' => $valor_btc,
                    'confirmations' => $confirmations,
                    'timestamp' => $tx['status']['block_time'] ?? time(),
                    'source' => 'blockstream'
                ];
            }
        }
    }
    
    // Ordenar por timestamp (mais recente primeiro)
    usort($transacoes_validas, function($a, $b) {
        return $b['timestamp'] - $a['timestamp'];
    });
    
    return $transacoes_validas;
}

/**
 * Verificar via BlockCypher API (backup)
 */
function verificarBlockCypher($address, $valorEsperado) {
    $token = 'BLOCKCYPHER_API_KEY'; // Sua API key
    $url = "https://api.blockcypher.com/v1/btc/main/addrs/{$address}";
    
    if (!empty($token)) {
        $url .= "?token={$token}";
    }
    
    $context = stream_context_create([
        'http' => [
            'timeout' => 15,
            'user_agent' => 'ZeeMarket/1.0'
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        return [];
    }
    
    $data = json_decode($response, true);
    if (!$data || !isset($data['txrefs'])) {
        return [];
    }
    
    $transacoes_validas = [];
    
    foreach ($data['txrefs'] as $tx) {
        // Apenas transações de entrada (recebidas)
        if (isset($tx['tx_output_n']) && $tx['value'] > 0) {
            $valor_btc = $tx['value'] / 100000000;
            
            // Verificar se o valor está próximo do esperado
            $tolerancia = $valorEsperado * 0.01;
            if (abs($valor_btc - $valorEsperado) <= $tolerancia) {
                
                $transacoes_validas[] = [
                    'txid' => $tx['tx_hash'],
                    'amount' => $valor_btc,
                    'confirmations' => $tx['confirmations'] ?? 0,
                    'timestamp' => strtotime($tx['confirmed'] ?? 'now'),
                    'source' => 'blockcypher'
                ];
            }
        }
    }
    
    return $transacoes_validas;
}
?>