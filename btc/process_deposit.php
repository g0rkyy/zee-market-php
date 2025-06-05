<?php
/**
 * Process Deposit - Sistema de Processamento Manual de Depósitos
 * Para verificar e processar depósitos manualmente quando necessário
 */

require_once '../includes/config.php';
require_once '../includes/blockchain_real.php';

// Verificar se usuário é admin
if (!isset($_SESSION['user_id']) || !isAdmin($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit;
}

$message = '';
$error = '';
$result_data = null;

// Processar formulário
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'check_address':
            $result = checkAddressTransactions($_POST['address'] ?? '');
            break;
            
        case 'process_tx':
            $result = processTransactionManually($_POST);
            break;
            
        case 'verify_balance':
            $result = verifyUserBalance($_POST['user_id'] ?? 0);
            break;
            
        case 'sync_pending':
            $result = syncPendingTransactions();
            break;
            
        case 'bulk_confirm':
            $result = bulkConfirmDeposits($_POST['tx_ids'] ?? []);
            break;
            
        case 'reject_tx':
            $result = rejectTransaction($_POST['tx_id'] ?? 0, $_POST['reason'] ?? '');
            break;
    }
    
    if (isset($result)) {
        if ($result['success']) {
            $message = $result['message'];
            $result_data = $result['data'] ?? null;
        } else {
            $error = $result['error'];
        }
    }
}

// Buscar dados para exibição
$pendingDeposits = getPendingDepositsAll();
$recentTransactions = getRecentTransactions(50);
$systemStats = getSystemStats();

/**
 * Verifica transações de um endereço via API
 */
function checkAddressTransactions($address) {
    if (empty($address)) {
        return ['success' => false, 'error' => 'Endereço não informado'];
    }
    
    if (!isValidBitcoinAddress($address)) {
        return ['success' => false, 'error' => 'Endereço Bitcoin inválido'];
    }
    
    try {
        // Usar múltiplas APIs para redundância
        $apis = [
            "https://api.blockcypher.com/v1/btc/main/addrs/{$address}/full",
            "https://blockstream.info/api/address/{$address}/txs"
        ];
        
        $transactions = [];
        
        foreach ($apis as $apiUrl) {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 30,
                    'user_agent' => 'Mozilla/5.0 (compatible; BTCWallet/1.0)'
                ]
            ]);
            
            $response = @file_get_contents($apiUrl, false, $context);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                
                if ($data) {
                    // Parse BlockCypher format
                    if (isset($data['txs'])) {
                        foreach ($data['txs'] as $tx) {
                            $transactions[] = [
                                'hash' => $tx['hash'],
                                'confirmations' => $tx['confirmations'] ?? 0,
                                'received' => isset($tx['received']) ? date('Y-m-d H:i:s', strtotime($tx['received'])) : date('Y-m-d H:i:s'),
                                'value' => ($tx['total'] ?? 0) / 100000000,
                                'block_height' => $tx['block_height'] ?? 0,
                                'fees' => ($tx['fees'] ?? 0) / 100000000
                            ];
                        }
                        break;
                    }
                    // Parse Blockstream format
                    elseif (is_array($data)) {
                        foreach ($data as $tx) {
                            $value = 0;
                            if (isset($tx['vout'])) {
                                foreach ($tx['vout'] as $output) {
                                    if (isset($output['scriptpubkey_address']) && $output['scriptpubkey_address'] === $address) {
                                        $value += $output['value'] / 100000000;
                                    }
                                }
                            }
                            
                            $transactions[] = [
                                'hash' => $tx['txid'],
                                'confirmations' => isset($tx['status']['confirmed']) ? ($tx['status']['confirmed'] ? 6 : 0) : 0,
                                'received' => isset($tx['status']['block_time']) ? date('Y-m-d H:i:s', $tx['status']['block_time']) : date('Y-m-d H:i:s'),
                                'value' => $value,
                                'block_height' => $tx['status']['block_height'] ?? 0,
                                'fees' => ($tx['fee'] ?? 0) / 100000000
                            ];
                        }
                        break;
                    }
                }
            }
            
            // Rate limiting entre APIs
            usleep(500000);
        }
        
        if (empty($transactions)) {
            return ['success' => false, 'error' => 'Nenhuma transação encontrada ou APIs indisponíveis'];
        }
        
        // Ordenar por data mais recente
        usort($transactions, function($a, $b) {
            return strtotime($b['received']) - strtotime($a['received']);
        });
        
        return [
            'success' => true, 
            'message' => count($transactions) . ' transação(ões) encontrada(s)',
            'data' => $transactions
        ];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => 'Erro ao consultar APIs: ' . $e->getMessage()];
    }
}

/**
 * Processa transação manualmente
 */
function processTransactionManually($data) {
    global $conn;
    
    $txHash = trim($data['tx_hash'] ?? '');
    $userId = intval($data['user_id'] ?? 0);
    $amount = floatval($data['amount'] ?? 0);
    $confirmations = intval($data['confirmations'] ?? 0);
    $notes = trim($data['notes'] ?? '');
    
    if (empty($txHash) || $userId <= 0 || $amount <= 0) {
        return ['success' => false, 'error' => 'Dados inválidos fornecidos'];
    }
    
    if (!isValidTxHash($txHash)) {
        return ['success' => false, 'error' => 'Hash da transação inválido'];
    }
    
    try {
        $conn->begin_transaction();
        
        // Verificar se usuário existe
        $stmt = $conn->prepare("SELECT id, username, btc_balance FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        
        if (!$user) {
            throw new Exception('Usuário não encontrado');
        }
        
        // Verificar se transação já existe
        $stmt = $conn->prepare("SELECT id, status FROM btc_transactions WHERE tx_hash = ?");
        $stmt->bind_param("s", $txHash);
        $stmt->execute();
        $existingTx = $stmt->get_result()->fetch_assoc();
        
        if ($existingTx) {
            if ($existingTx['status'] === 'confirmed') {
                throw new Exception('Transação já confirmada anteriormente');
            } else {
                // Atualizar transação existente
                $status = $confirmations >= 3 ? 'confirmed' : 'pending';
                $stmt = $conn->prepare("
                    UPDATE btc_transactions 
                    SET amount = ?, status = ?, confirmations = ?, notes = ?, updated_at = NOW()
                    WHERE id = ?
                ");
                $stmt->bind_param("dsisi", $amount, $status, $confirmations, $notes, $existingTx['id']);
                $stmt->execute();
                $txId = $existingTx['id'];
            }
        } else {
            // Inserir nova transação
            $status = $confirmations >= 3 ? 'confirmed' : 'pending';
            $stmt = $conn->prepare("
                INSERT INTO btc_transactions 
                (user_id, tx_hash, type, amount, status, confirmations, notes, created_at, updated_at) 
                VALUES (?, ?, 'deposit', ?, ?, ?, ?, NOW(), NOW())
            ");
            $stmt->bind_param("issdis", $userId, $txHash, $amount, $status, $confirmations, $notes);
            $stmt->execute();
            $txId = $conn->insert_id;
        }
        
        // Se confirmado, creditar saldo
        if ($status === 'confirmed') {
            $oldBalance = floatval($user['btc_balance']);
            $newBalance = $oldBalance + $amount;
            
            $stmt = $conn->prepare("UPDATE users SET btc_balance = ?, updated_at = NOW() WHERE id = ?");
            $stmt->bind_param("di", $newBalance, $userId);
            $stmt->execute();
            
            // Registrar no histórico
            $description = "Depósito processado manualmente" . (!empty($notes) ? " - {$notes}" : "");
            $stmt = $conn->prepare("
                INSERT INTO btc_balance_history 
                (user_id, type, amount, balance_before, balance_after, description, tx_hash, created_at) 
                VALUES (?, 'credit', ?, ?, ?, ?, ?, NOW())
            ");
            $stmt->bind_param("idddss", $userId, $amount, $oldBalance, $newBalance, $description, $txHash);
            $stmt->execute();
            
            // Log de admin
            logAdminAction($_SESSION['user_id'], 'btc_deposit_confirmed', [
                'tx_id' => $txId,
                'tx_hash' => $txHash,
                'user_id' => $userId,
                'username' => $user['username'],
                'amount' => $amount
            ]);
        }
        
        $conn->commit();
        
        $statusText = $status === 'confirmed' ? 'confirmada e creditada' : 'registrada como pendente';
        return [
            'success' => true, 
            'message' => "Transação {$statusText} com sucesso para o usuário {$user['username']}"
        ];
        
    } catch (Exception $e) {
        $conn->rollback();
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Verifica saldo de um usuário
 */
function verifyUserBalance($userId) {
    global $conn;
    
    if ($userId <= 0) {
        return ['success' => false, 'error' => 'ID do usuário inválido'];
    }
    
    try {
        // Buscar dados do usuário
        $stmt = $conn->prepare("SELECT username, btc_balance FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        
        if (!$user) {
            return ['success' => false, 'error' => 'Usuário não encontrado'];
        }
        
        // Calcular saldo baseado nas transações
        $stmt = $conn->prepare("
            SELECT 
                SUM(CASE WHEN type = 'deposit' AND status = 'confirmed' THEN amount ELSE 0 END) as total_deposits,
                SUM(CASE WHEN type = 'withdrawal' AND status = 'confirmed' THEN amount ELSE 0 END) as total_withdrawals,
                COUNT(CASE WHEN type = 'deposit' AND status = 'confirmed' THEN 1 END) as deposit_count,
                COUNT(CASE WHEN type = 'withdrawal' AND status = 'confirmed' THEN 1 END) as withdrawal_count,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_count
            FROM btc_transactions 
            WHERE user_id = ?
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        $totalDeposits = floatval($result['total_deposits']);
        $totalWithdrawals = floatval($result['total_withdrawals']);
        $calculatedBalance = $totalDeposits - $totalWithdrawals;
        $currentBalance = floatval($user['btc_balance']);
        $difference = $currentBalance - $calculatedBalance;
        
        // Buscar últimas transações
        $stmt = $conn->prepare("
            SELECT type, amount, status, tx_hash, created_at 
            FROM btc_transactions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $recentTxs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        $data = [
            'user_id' => $userId,
            'username' => $user['username'],
            'calculated_balance' => $calculatedBalance,
            'current_balance' => $currentBalance,
            'difference' => $difference,
            'total_deposits' => $totalDeposits,
            'total_withdrawals' => $totalWithdrawals,
            'deposit_count' => intval($result['deposit_count']),
            'withdrawal_count' => intval($result['withdrawal_count']),
            'pending_count' => intval($result['pending_count']),
            'recent_transactions' => $recentTxs,
            'is_balanced' => abs($difference) < 0.00000001
        ];
        
        $statusMsg = $data['is_balanced'] ? 'Saldo está correto' : 'ATENÇÃO: Diferença encontrada no saldo';
        
        return [
            'success' => true, 
            'message' => $statusMsg,
            'data' => $data
        ];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => 'Erro ao verificar saldo: ' . $e->getMessage()];
    }
}

/**
 * Sincroniza transações pendentes
 */
function syncPendingTransactions() {
    global $conn;
    
    try {
        $stmt = $conn->prepare("
            SELECT bt.*, u.btc_deposit_address, u.username 
            FROM btc_transactions bt 
            JOIN users u ON bt.user_id = u.id 
            WHERE bt.status = 'pending' AND bt.type = 'deposit' AND bt.tx_hash IS NOT NULL
            ORDER BY bt.created_at DESC
            LIMIT 50
        ");
        $stmt->execute();
        $pending = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        if (empty($pending)) {
            return ['success' => true, 'message' => 'Nenhuma transação pendente encontrada'];
        }
        
        $updated = 0;
        $confirmed = 0;
        $errors = [];
        
        foreach ($pending as $tx) {
            try {
                // Verificar status via múltiplas APIs
                $txInfo = getTransactionInfo($tx['tx_hash']);
                
                if (!$txInfo) {
                    $errors[] = "Não foi possível obter informações da transação {$tx['tx_hash']}";
                    continue;
                }
                
                $confirmations = intval($txInfo['confirmations']);
                $blockHeight = intval($txInfo['block_height']);
                
                // Atualizar confirmações se houver mudança
                if ($confirmations !== intval($tx['confirmations']) || $blockHeight !== intval($tx['block_height'])) {
                    $stmt = $conn->prepare("
                        UPDATE btc_transactions 
                        SET confirmations = ?, block_height = ?, updated_at = NOW() 
                        WHERE id = ?
                    ");
                    $stmt->bind_param("iii", $confirmations, $blockHeight, $tx['id']);
                    $stmt->execute();
                    $updated++;
                }
                
                // Se atingiu confirmações suficientes, confirmar
                if ($confirmations >= 3 && $tx['status'] === 'pending') {
                    $conn->begin_transaction();
                    
                    try {
                        // Atualizar status da transação
                        $stmt = $conn->prepare("UPDATE btc_transactions SET status = 'confirmed', updated_at = NOW() WHERE id = ?");
                        $stmt->bind_param("i", $tx['id']);
                        $stmt->execute();
                        
                        // Obter saldo atual do usuário
                        $stmt = $conn->prepare("SELECT btc_balance FROM users WHERE id = ?");
                        $stmt->bind_param("i", $tx['user_id']);
                        $stmt->execute();
                        $userResult = $stmt->get_result()->fetch_assoc();
                        $oldBalance = floatval($userResult['btc_balance']);
                        $newBalance = $oldBalance + floatval($tx['amount']);
                        
                        // Creditar saldo
                        $stmt = $conn->prepare("UPDATE users SET btc_balance = ?, updated_at = NOW() WHERE id = ?");
                        $stmt->bind_param("di", $newBalance, $tx['user_id']);
                        $stmt->execute();
                        
                        // Registrar no histórico
                        $stmt = $conn->prepare("
                            INSERT INTO btc_balance_history 
                            (user_id, type, amount, balance_before, balance_after, description, tx_hash, created_at) 
                            VALUES (?, 'credit', ?, ?, ?, 'Depósito confirmado automaticamente', ?, NOW())
                        ");
                        $stmt->bind_param("iddds", $tx['user_id'], $tx['amount'], $oldBalance, $newBalance, $tx['tx_hash']);
                        $stmt->execute();
                        
                        $conn->commit();
                        $confirmed++;
                        
                    } catch (Exception $e) {
                        $conn->rollback();
                        $errors[] = "Erro ao confirmar transação {$tx['tx_hash']}: " . $e->getMessage();
                    }
                }
                
                // Rate limiting
                usleep(1000000); // 1 segundo entre requests para evitar rate limit
                
            } catch (Exception $e) {
                $errors[] = "Erro ao processar transação {$tx['tx_hash']}: " . $e->getMessage();
                continue;
            }
        }
        
        $message = "Sincronização concluída. {$updated} transação(ões) atualizada(s), {$confirmed} confirmada(s).";
        if (!empty($errors)) {
            $message .= " Erros: " . implode('; ', array_slice($errors, 0, 3));
            if (count($errors) > 3) {
                $message .= " e mais " . (count($errors) - 3) . " erro(s).";
            }
        }
        
        return ['success' => true, 'message' => $message];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => 'Erro na sincronização: ' . $e->getMessage()];
    }
}

/**
 * Confirma múltiplas transações em lote
 */
function bulkConfirmDeposits($txIds) {
    global $conn;
    
    if (empty($txIds) || !is_array($txIds)) {
        return ['success' => false, 'error' => 'Nenhuma transação selecionada'];
    }
    
    $txIds = array_map('intval', $txIds);
    $txIds = array_filter($txIds, function($id) { return $id > 0; });
    
    if (empty($txIds)) {
        return ['success' => false, 'error' => 'IDs de transação inválidos'];
    }
    
    try {
        $placeholders = str_repeat('?,', count($txIds) - 1) . '?';
        
        // Buscar transações pendentes
        $stmt = $conn->prepare("
            SELECT bt.*, u.username, u.btc_balance 
            FROM btc_transactions bt 
            JOIN users u ON bt.user_id = u.id 
            WHERE bt.id IN ($placeholders) AND bt.status = 'pending' AND bt.type = 'deposit'
        ");
        $stmt->bind_param(str_repeat('i', count($txIds)), ...$txIds);
        $stmt->execute();
        $transactions = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        if (empty($transactions)) {
            return ['success' => false, 'error' => 'Nenhuma transação pendente encontrada'];
        }
        
        $confirmed = 0;
        $errors = [];
        
        foreach ($transactions as $tx) {
            $conn->begin_transaction();
            
            try {
                // Atualizar status da transação
                $stmt = $conn->prepare("UPDATE btc_transactions SET status = 'confirmed', updated_at = NOW() WHERE id = ?");
                $stmt->bind_param("i", $tx['id']);
                $stmt->execute();
                
                $oldBalance = floatval($tx['btc_balance']);
                $newBalance = $oldBalance + floatval($tx['amount']);
                
                // Creditar saldo
                $stmt = $conn->prepare("UPDATE users SET btc_balance = ?, updated_at = NOW() WHERE id = ?");
                $stmt->bind_param("di", $newBalance, $tx['user_id']);
                $stmt->execute();
                
                // Registrar no histórico
                $stmt = $conn->prepare("
                    INSERT INTO btc_balance_history 
                    (user_id, type, amount, balance_before, balance_after, description, tx_hash, created_at) 
                    VALUES (?, 'credit', ?, ?, ?, 'Depósito confirmado em lote', ?, NOW())
                ");
                $stmt->bind_param("iddds", $tx['user_id'], $tx['amount'], $oldBalance, $newBalance, $tx['tx_hash']);
                $stmt->execute();
                
                // Log de admin
                logAdminAction($_SESSION['user_id'], 'btc_bulk_confirm', [
                    'tx_id' => $tx['id'],
                    'user_id' => $tx['user_id'],
                    'amount' => $tx['amount']
                ]);
                
                $conn->commit();
                $confirmed++;
                
            } catch (Exception $e) {
                $conn->rollback();
                $errors[] = "Erro ao confirmar transação ID {$tx['id']}: " . $e->getMessage();
            }
        }
        
        $message = "{$confirmed} transação(ões) confirmada(s) com sucesso.";
        if (!empty($errors)) {
            $message .= " Erros: " . implode('; ', $errors);
        }
        
        return ['success' => true, 'message' => $message];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => 'Erro na confirmação em lote: ' . $e->getMessage()];
    }
}

/**
 * Rejeita uma transação
 */
function rejectTransaction($txId, $reason) {
    global $conn;
    
    $txId = intval($txId);
    $reason = trim($reason);
    
    if ($txId <= 0) {
        return ['success' => false, 'error' => 'ID da transação inválido'];
    }
    
    if (empty($reason)) {
        return ['success' => false, 'error' => 'Motivo da rejeição é obrigatório'];
    }
    
    try {
        // Buscar transação
        $stmt = $conn->prepare("
            SELECT bt.*, u.username 
            FROM btc_transactions bt 
            JOIN users u ON bt.user_id = u.id 
            WHERE bt.id = ? AND bt.status = 'pending'
        ");
        $stmt->bind_param("i", $txId);
        $stmt->execute();
        $tx = $stmt->get_result()->fetch_assoc();
        
        if (!$tx) {
            return ['success' => false, 'error' => 'Transação não encontrada ou já processada'];
        }
        
        // Atualizar status para rejeitada
        $stmt = $conn->prepare("
            UPDATE btc_transactions 
            SET status = 'rejected', notes = CONCAT(COALESCE(notes, ''), ' | REJEITADA: ', ?), updated_at = NOW() 
            WHERE id = ?
        ");
        $stmt->bind_param("si", $reason, $txId);
        $stmt->execute();
        
        // Log de admin
        logAdminAction($_SESSION['user_id'], 'btc_tx_rejected', [
            'tx_id' => $txId,
            'user_id' => $tx['user_id'],
            'username' => $tx['username'],
            'reason' => $reason
        ]);
        
        return [
            'success' => true, 
            'message' => "Transação rejeitada com sucesso. Usuário: {$tx['username']}"
        ];
        
    } catch (Exception $e) {
        return ['success' => false, 'error' => 'Erro ao rejeitar transação: ' . $e->getMessage()];
    }
}

/**
 * Busca todos os depósitos pendentes
 */
function getPendingDepositsAll() {
    global $conn;
    
    $stmt = $conn->prepare("
        SELECT 
            bt.*,
            u.username,
            u.email,
            u.btc_deposit_address,
            TIMESTAMPDIFF(HOUR, bt.created_at, NOW()) as hours_pending
        FROM btc_transactions bt 
        JOIN users u ON bt.user_id = u.id 
        WHERE bt.status = 'pending' AND bt.type = 'deposit'
        ORDER BY bt.created_at DESC
    ");
    $stmt->execute();
    return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
}

/**
 * Busca transações recentes
 */
function getRecentTransactions($limit = 50) {
    global $conn;
    
    $stmt = $conn->prepare("
        SELECT 
            bt.*,
            u.username,
            CASE 
                WHEN bt.type = 'deposit' THEN 'Depósito'
                WHEN bt.type = 'withdrawal' THEN 'Saque'
                ELSE bt.type
            END as type_label,
            CASE 
                WHEN bt.status = 'pending' THEN 'Pendente'
                WHEN bt.status = 'confirmed' THEN 'Confirmado'
                WHEN bt.status = 'rejected' THEN 'Rejeitado'
                ELSE bt.status
            END as status_label
        FROM btc_transactions bt 
        JOIN users u ON bt.user_id = u.id 
        ORDER BY bt.created_at DESC 
        LIMIT ?
    ");
    $stmt->bind_param("i", $limit);
    $stmt->execute();
    return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
}

/**
 * Obtém estatísticas do sistema
 */
function getSystemStats() {
    global $conn;
    
    $stmt = $conn->prepare("
        SELECT 
            COUNT(CASE WHEN status = 'pending' AND type = 'deposit' THEN 1 END) as pending_deposits,
            COUNT(CASE WHEN status = 'pending' AND type = 'withdrawal' THEN 1 END) as pending_withdrawals,
            COUNT(CASE WHEN status = 'confirmed' AND type = 'deposit' THEN 1 END) as confirmed_deposits,
            COUNT(CASE WHEN status = 'confirmed' AND type = 'withdrawal' THEN 1 END) as confirmed_withdrawals,
            SUM(CASE WHEN status = 'confirmed' AND type = 'deposit' THEN amount ELSE 0 END) as total_deposits,
            SUM(CASE WHEN status = 'confirmed' AND type = 'withdrawal' THEN amount ELSE 0 END) as total_withdrawals,
            SUM(CASE WHEN status = 'pending' AND type = 'deposit' THEN amount ELSE 0 END) as pending_deposit_amount,
            COUNT(DISTINCT user_id) as active_users
        FROM btc_transactions
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $stmt->execute();
    $stats = $stmt->get_result()->fetch_assoc();
    
    // Adicionar estatísticas de usuários
    $stmt = $conn->prepare("
        SELECT 
            COUNT(*) as total_users,
            SUM(btc_balance) as total_balance,
            AVG(btc_balance) as avg_balance
        FROM users 
        WHERE btc_balance > 0
    ");
    $stmt->execute();
    $userStats = $stmt->get_result()->fetch_assoc();
    
    return array_merge($stats, $userStats);
}

// Funções auxiliares
function isValidBitcoinAddress($address) {
    // Validação básica de endereço Bitcoin
    if (strlen($address) < 26 || strlen($address) > 62) {
        return false;
    }
    
    // Verificar prefixos válidos (Mainnet: 1, 3, bc1 | Testnet: 2, m, n, tb1)
    $prefix = substr($address, 0, 3);
    if (!preg_match('/^(1|3|bc1|2|m|n|tb1)/', $prefix)) {
        return false;
    }
    
    return true;
}
function getTransactionInfo($txHash) {
    $apis = [
        "https://blockstream.info/api/tx/{$txHash}",
        "https://api.blockcypher.com/v1/btc/main/txs/{$txHash}"
    ];
    
    foreach ($apis as $apiUrl) {
        $response = @file_get_contents($apiUrl);
        if ($response !== false) {
            $data = json_decode($response, true);
            if ($data) {
                // Formato Blockstream
                if (isset($data['txid'])) {
                    return [
                        'confirmations' => $data['status']['confirmed'] ? 6 : 0,
                        'block_height' => $data['status']['block_height'] ?? 0
                    ];
                }
                // Formato BlockCypher
                elseif (isset($data['confirmations'])) {
                    return [
                        'confirmations' => $data['confirmations'],
                        'block_height' => $data['block_height'] ?? 0
                    ];
                }
            }
        }
        usleep(500000); // Espera 0.5s entre APIs
    }
    return false;
}
function logAdminAction($adminId, $action, $details = []) {
    global $conn;
    $detailsJson = json_encode($details);
    $stmt = $conn->prepare("
        INSERT INTO admin_logs 
        (user_id, action, details, ip_address, user_agent, created_at) 
        VALUES (?, ?, ?, ?, ?, NOW())
    ");
    $stmt->bind_param(
        "issss",
        $adminId,
        $action,
        $detailsJson,
        $_SERVER['REMOTE_ADDR'],
        $_SERVER['HTTP_USER_AGENT']
    );
    $stmt->execute();
}
function isAdmin($userId) {
    global $conn;
    $stmt = $conn->prepare("SELECT is_admin FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result && $result['is_admin'] == 1;
}
?>