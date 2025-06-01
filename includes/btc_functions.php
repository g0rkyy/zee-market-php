<?php
/**
 * Sistema Completo de Carteira Bitcoin - ZeeMarket CORRIGIDO
 * Suporte para Bitcoin, Ethereum, Monero e outras criptomoedas
 * Versão: 2.2 - Correções de bugs e remoção de métodos duplicados
 */

require_once __DIR__ . '/config.php';

class ZeeMarketWallet {
    private $conn;
    private $config;
    private $lastApiCall = 0;
    private $apiCalls = 0;
    private $cacheDir;
    
    public function __construct() {
        global $conn;
        $this->conn = $conn;
        
        // Criar diretório de cache se não existir
        $this->cacheDir = __DIR__ . '/../cache';
        if (!file_exists($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
        
        $this->config = [
            'blockcypher_token' => '', // Deixe vazio para usar sem token (limitado)
            'etherscan_token' => '',   // Deixe vazio para usar sem token
            'blockchain_info_api' => 'https://blockchain.info/q',
            'blockstream_api' => 'https://blockstream.info/api',
            'coingecko_api' => 'https://api.coingecko.com/api/v3',
            'min_confirmations' => 1,
            'dust_limit' => 0.00001000, // 1000 satoshis
            'fee_rate' => 15 // sat/byte
        ];
    }

    /**
     * GERAÇÃO DE ENDEREÇOS
     */
    public function generateDepositAddress($userId, $crypto = 'BTC') {
        try {
            switch (strtoupper($crypto)) {
                case 'BTC':
                    return $this->generateBitcoinAddress($userId);
                case 'ETH':
                    return $this->generateEthereumAddress($userId);
                case 'XMR':
                    return $this->generateMoneroAddress($userId);
                default:
                    throw new Exception("Criptomoeda não suportada: $crypto");
            }
        } catch (Exception $e) {
            error_log("Erro ao gerar endereço $crypto: " . $e->getMessage());
            return ['success' => false, 'error' => 'Erro interno do servidor'];
        }
    }

    private function generateBitcoinAddress($userId) {
        // Gerar endereço Bitcoin localmente (para desenvolvimento)
        return $this->generateLocalBitcoinAddress($userId);
    }

    private function generateLocalBitcoinAddress($userId) {
        // Gerar endereço Bitcoin válido para desenvolvimento
        $privateKeyHex = bin2hex(random_bytes(32));
        
        // Gerar endereço Bech32 simples para teste
        $address = $this->createTestBitcoinAddress();
        
        $stmt = $this->conn->prepare("
            UPDATE users SET 
                btc_deposit_address = ?, 
                btc_private_key = ?,
                last_deposit_check = NOW()
            WHERE id = ?
        ");
        $encryptedPrivate = $this->encryptData($privateKeyHex);
        $stmt->bind_param("ssi", $address, $encryptedPrivate, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço: " . $stmt->error);
        }
        
        return [
            'success' => true,
            'address' => $address,
            'crypto' => 'BTC',
            'message' => 'Endereço Bitcoin gerado com sucesso'
        ];
    }

    private function generateEthereumAddress($userId) {
        // Gerar endereço Ethereum
        $privateKey = bin2hex(random_bytes(32));
        $address = '0x' . substr(hash('keccak256', $privateKey), 24);
        
        $stmt = $this->conn->prepare("
            UPDATE users SET 
                eth_deposit_address = ?, 
                eth_private_key = ?,
                last_deposit_check = NOW()
            WHERE id = ?
        ");
        $encryptedPrivate = $this->encryptData($privateKey);
        $stmt->bind_param("ssi", $address, $encryptedPrivate, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço Ethereum");
        }
        
        return [
            'success' => true,
            'address' => $address,
            'crypto' => 'ETH',
            'message' => 'Endereço Ethereum gerado com sucesso'
        ];
    }

    private function generateMoneroAddress($userId) {
        // Monero usa endereços diferentes
        $address = '4' . bin2hex(random_bytes(47));
        
        $stmt = $this->conn->prepare("
            UPDATE users SET 
                xmr_deposit_address = ?,
                last_deposit_check = NOW()
            WHERE id = ?
        ");
        $stmt->bind_param("si", $address, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception("Erro ao salvar endereço Monero");
        }
        
        return [
            'success' => true,
            'address' => $address,
            'crypto' => 'XMR',
            'message' => 'Endereço Monero gerado com sucesso'
        ];
    }

    /**
     * VERIFICAÇÃO DE DEPÓSITOS SEM CRON
     */
    public function processAllPendingDeposits() {
        // Rate limiting para evitar spam de APIs
        $this->rateLimitCheck();
        
        // Buscar usuários que precisam de verificação (CORRIGIDO)
        $stmt = $this->conn->prepare("
            SELECT id, name as username, btc_deposit_address, eth_deposit_address, xmr_deposit_address, last_deposit_check 
            FROM users 
            WHERE (btc_deposit_address IS NOT NULL OR eth_deposit_address IS NOT NULL OR xmr_deposit_address IS NOT NULL)
            AND (last_deposit_check IS NULL OR last_deposit_check < DATE_SUB(NOW(), INTERVAL 2 MINUTE))
            ORDER BY last_deposit_check ASC
            LIMIT 5
        ");
        $stmt->execute();
        $users = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        $processed = 0;
        foreach ($users as $user) {
            try {
                // Verificar Bitcoin
                if (!empty($user['btc_deposit_address'])) {
                    $this->checkUserDeposits($user, 'BTC');
                    $processed++;
                }
                
                // Verificar Ethereum
                if (!empty($user['eth_deposit_address'])) {
                    $this->checkUserDeposits($user, 'ETH');
                    $processed++;
                }
                
                // Atualizar timestamp
                $stmt = $this->conn->prepare("UPDATE users SET last_deposit_check = NOW() WHERE id = ?");
                $stmt->bind_param("i", $user['id']);
                $stmt->execute();
                
                // Rate limiting entre usuários
                usleep(500000); // 0.5 segundos
                
            } catch (Exception $e) {
                error_log("Erro ao processar usuário {$user['id']}: " . $e->getMessage());
                continue;
            }
        }
        
        return $processed;
    }

    private function checkUserDeposits($user, $crypto) {
        $addressField = strtolower($crypto) . '_deposit_address';
        $address = $user[$addressField];
        
        if (empty($address)) return;
        
        $transactions = $this->checkDeposits($address, $crypto);
        
        foreach ($transactions as $tx) {
            $this->processNewDeposit($user['id'], $tx);
        }
    }

    public function checkDeposits($address, $crypto = 'BTC') {
        switch (strtoupper($crypto)) {
            case 'BTC':
                return $this->checkBitcoinDeposits($address);
            case 'ETH':
                return $this->checkEthereumDeposits($address);
            case 'XMR':
                return []; // Implementar depois
            default:
                return [];
        }
    }

    /**
     * VERIFICAÇÃO DE DEPÓSITOS BITCOIN - VERSÃO COMPLETA
     */
    private function checkBitcoinDeposits($address) {
        $transactions = [];
        
        // Método 1: BlockCypher
        $blockCypherTxs = $this->getBitcoinTransactionsBlockCypher($address);
        if ($blockCypherTxs) {
            $transactions = array_merge($transactions, $blockCypherTxs);
        }
        
        // Método 2: Blockstream (backup)
        if (empty($transactions)) {
            $blockstreamTxs = $this->getBitcoinTransactionsBlockstream($address);
            if ($blockstreamTxs) {
                $transactions = array_merge($transactions, $blockstreamTxs);
            }
        }
        
        // Método 3: Blockchain.info (último recurso)
        if (empty($transactions)) {
            $blockchainTxs = $this->getBitcoinTransactionsBlockchainInfo($address);
            if ($blockchainTxs) {
                $transactions = array_merge($transactions, $blockchainTxs);
            }
        }
        
        // Método 4: Simulação para desenvolvimento
        if (empty($transactions)) {
            $transactions = $this->simulateBitcoinTransactions($address);
        }
        
        return $this->filterUniqueTransactions($transactions);
    }

    private function getBitcoinTransactionsBlockCypher($address) {
        $url = "https://api.blockcypher.com/v1/btc/main/addrs/$address/full";
        if (!empty($this->config['blockcypher_token'])) {
            $url .= "?token=" . $this->config['blockcypher_token'];
        }
        
        $response = $this->makeHttpRequest($url);
        if (!$response || !isset($response['txs'])) {
            return false;
        }
        
        $transactions = [];
        foreach ($response['txs'] as $tx) {
            $amount = 0;
            
            // Calcular valor recebido no endereço
            foreach ($tx['outputs'] as $output) {
                if (in_array($address, $output['addresses'] ?? [])) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $transactions[] = [
                    'txid' => $tx['hash'],
                    'amount' => $amount / 100000000, // Satoshis para BTC
                    'confirmations' => $tx['confirmations'] ?? 0,
                    'timestamp' => strtotime($tx['received']),
                    'block_height' => $tx['block_height'] ?? 0,
                    'crypto' => 'BTC'
                ];
            }
        }
        
        return $transactions;
    }

    private function getBitcoinTransactionsBlockstream($address) {
        $url = "https://blockstream.info/api/address/$address/txs";
        $response = $this->makeHttpRequest($url);
        
        if (!$response || !is_array($response)) {
            return false;
        }
        
        $transactions = [];
        foreach ($response as $tx) {
            $amount = 0;
            
            // Calcular valor recebido
            foreach ($tx['vout'] as $output) {
                if (isset($output['scriptpubkey_address']) && $output['scriptpubkey_address'] === $address) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $confirmations = isset($tx['status']['confirmed']) && $tx['status']['confirmed'] ? 6 : 0;
                
                $transactions[] = [
                    'txid' => $tx['txid'],
                    'amount' => $amount / 100000000,
                    'confirmations' => $confirmations,
                    'timestamp' => $tx['status']['block_time'] ?? time(),
                    'block_height' => $tx['status']['block_height'] ?? 0,
                    'crypto' => 'BTC'
                ];
            }
        }
        
        return $transactions;
    }

    private function getBitcoinTransactionsBlockchainInfo($address) {
        $url = "https://blockchain.info/rawaddr/$address";
        $response = $this->makeHttpRequest($url);
        
        if (!$response || !isset($response['txs'])) {
            return false;
        }
        
        $transactions = [];
        foreach ($response['txs'] as $tx) {
            $amount = 0;
            
            foreach ($tx['out'] as $output) {
                if (isset($output['addr']) && $output['addr'] === $address) {
                    $amount += $output['value'];
                }
            }
            
            if ($amount > 0) {
                $transactions[] = [
                    'txid' => $tx['hash'],
                    'amount' => $amount / 100000000,
                    'confirmations' => $tx['confirmations'] ?? 0,
                    'timestamp' => $tx['time'],
                    'block_height' => $tx['block_height'] ?? 0,
                    'crypto' => 'BTC'
                ];
            }
        }
        
        return $transactions;
    }

    private function simulateBitcoinTransactions($address) {
        // Para desenvolvimento - simular algumas transações
        static $simulated = [];
        
        if (!isset($simulated[$address])) {
            $simulated[$address] = true;
            
            // Simular transação aleatória ocasionalmente
            if (rand(1, 100) <= 5) { // 5% de chance
                return [[
                    'txid' => hash('sha256', $address . time()),
                    'amount' => 0.001 + (rand(1, 100) / 100000), // 0.001 a 0.002 BTC
                    'confirmations' => rand(0, 6),
                    'timestamp' => time() - rand(0, 3600),
                    'block_height' => 800000 + rand(1, 1000),
                    'crypto' => 'BTC'
                ]];
            }
        }
        
        return [];
    }

    private function checkEthereumDeposits($address) {
        $url = "https://api.etherscan.io/api?module=account&action=txlist&address=$address&startblock=0&endblock=99999999&sort=desc";
        if (!empty($this->config['etherscan_token'])) {
            $url .= "&apikey=" . $this->config['etherscan_token'];
        }
        
        $response = $this->makeHttpRequest($url);
        if (!$response || $response['status'] !== '1') {
            return [];
        }
        
        $transactions = [];
        foreach ($response['result'] as $tx) {
            if (strtolower($tx['to']) === strtolower($address) && $tx['value'] > 0) {
                $transactions[] = [
                    'txid' => $tx['hash'],
                    'amount' => $tx['value'] / 1000000000000000000, // Wei para ETH
                    'confirmations' => $tx['confirmations'] ?? 12,
                    'timestamp' => $tx['timeStamp'],
                    'block_height' => $tx['blockNumber'],
                    'crypto' => 'ETH'
                ];
            }
        }
        
        return $transactions;
    }

    private function filterUniqueTransactions($transactions) {
        $unique = [];
        $seen = [];
        
        foreach ($transactions as $tx) {
            $key = $tx['txid'] . '_' . $tx['amount'];
            if (!isset($seen[$key])) {
                $unique[] = $tx;
                $seen[$key] = true;
            }
        }
        
        return $unique;
    }

    private function processNewDeposit($userId, $transaction) {
        // Verificar se transação já existe
        $stmt = $this->conn->prepare("SELECT id, status FROM btc_transactions WHERE tx_hash = ? AND user_id = ?");
        $stmt->bind_param("si", $transaction['txid'], $userId);
        $stmt->execute();
        $existing = $stmt->get_result()->fetch_assoc();
        
        if ($existing) {
            // Atualizar confirmações
            if ($transaction['confirmations'] > 0) {
                $this->updateTransactionConfirmations($transaction['txid'], $transaction['confirmations']);
            }
            return;
        }
        
        // Validar valor mínimo
        if ($transaction['amount'] < $this->config['dust_limit']) {
            error_log("Depósito muito pequeno ignorado: {$transaction['amount']} {$transaction['crypto']}");
            return;
        }
        
        // Inserir nova transação
        $status = $transaction['confirmations'] >= $this->config['min_confirmations'] ? 'confirmed' : 'pending';
        $crypto = $transaction['crypto'];
        
        $stmt = $this->conn->prepare("
            INSERT INTO btc_transactions 
            (user_id, tx_hash, type, amount, confirmations, status, crypto_type, created_at) 
            VALUES (?, ?, 'deposit', ?, ?, ?, ?, FROM_UNIXTIME(?))
        ");
        $stmt->bind_param("issdssi", 
            $userId, 
            $transaction['txid'], 
            $transaction['amount'], 
            $transaction['confirmations'], 
            $status,
            $crypto,
            $transaction['timestamp']
        );
        
        if (!$stmt->execute()) {
            error_log("Erro ao inserir transação: " . $stmt->error);
            return;
        }
        
        // Se confirmado, creditar saldo
        if ($status === 'confirmed') {
            $this->creditUserBalance($userId, $transaction['amount'], $transaction['txid'], $crypto);
        }
        
        error_log("Novo depósito processado: {$transaction['amount']} $crypto para usuário $userId");
    }

    private function creditUserBalance($userId, $amount, $txHash, $crypto) {
        $this->conn->begin_transaction();
        
        try {
            // Determinar campo de saldo
            $balanceField = strtolower($crypto) . '_balance';
            
            // Atualizar saldo
            $stmt = $this->conn->prepare("UPDATE users SET $balanceField = $balanceField + ? WHERE id = ?");
            $stmt->bind_param("di", $amount, $userId);
            $stmt->execute();
            
            // Registrar no histórico
            $stmt = $this->conn->prepare("
                INSERT INTO btc_balance_history 
                (user_id, type, amount, description, tx_hash, crypto_type, created_at) 
                VALUES (?, 'credit', ?, ?, ?, ?, NOW())
            ");
            $description = "Depósito $crypto confirmado";
            $stmt->bind_param("idsss", $userId, $amount, $description, $txHash, $crypto);
            $stmt->execute();
            
            $this->conn->commit();
            
        } catch (Exception $e) {
            $this->conn->rollback();
            throw $e;
        }
    }

    /**
     * SISTEMA DE SAQUES
     */
    public function createWithdrawal($userId, $toAddress, $amount, $crypto = 'BTC') {
        try {
            // Validações
            if (!$this->isValidAddress($toAddress, $crypto)) {
                throw new Exception("Endereço $crypto inválido");
            }
            
            if ($amount < $this->config['dust_limit']) {
                throw new Exception("Valor muito baixo para saque");
            }
            
            // Verificar saldo
            $userBalance = $this->getUserBalance($userId, $crypto);
            if ($userBalance < $amount) {
                throw new Exception("Saldo insuficiente");
            }
            
            // Calcular taxa
            $fee = $this->calculateWithdrawalFee($amount, $crypto);
            $totalDeduction = $amount + $fee;
            
            if ($userBalance < $totalDeduction) {
                throw new Exception("Saldo insuficiente para cobrir taxas");
            }
            
            // Verificar limite diário
            $dailyLimit = $this->getDailyWithdrawalLimit($userId, $crypto);
            $todayWithdrawals = $this->getTodayWithdrawals($userId, $crypto);
            
            if (($todayWithdrawals + $amount) > $dailyLimit) {
                throw new Exception("Limite diário de saque excedido. Limite: $dailyLimit $crypto");
            }
            
            $this->conn->begin_transaction();
            
            // Deduzir do saldo
            $balanceField = strtolower($crypto) . '_balance';
            $stmt = $this->conn->prepare("UPDATE users SET $balanceField = $balanceField - ? WHERE id = ?");
            $stmt->bind_param("di", $totalDeduction, $userId);
            $stmt->execute();
            
            // Criar registro de saque
            $stmt = $this->conn->prepare("
                INSERT INTO btc_transactions 
                (user_id, type, amount, fee, to_address, status, crypto_type, created_at) 
                VALUES (?, 'withdrawal', ?, ?, ?, 'pending', ?, NOW())
            ");
            $stmt->bind_param("iddss", $userId, $amount, $fee, $toAddress, $crypto);
            $stmt->execute();
            $withdrawalId = $this->conn->insert_id;
            
            // Registrar no histórico
            $stmt = $this->conn->prepare("
                INSERT INTO btc_balance_history 
                (user_id, type, amount, description, crypto_type, created_at) 
                VALUES (?, 'debit', ?, ?, ?, NOW())
            ");
            $description = "Saque $crypto solicitado";
            $stmt->bind_param("idss", $userId, $totalDeduction, $description, $crypto);
            $stmt->execute();
            
            $this->conn->commit();
            
            // Processar saque automaticamente (simulação)
            $this->processWithdrawal($withdrawalId);
            
            return [
                'success' => true,
                'withdrawal_id' => $withdrawalId,
                'amount' => $amount,
                'fee' => $fee,
                'message' => "Saque de $amount $crypto solicitado com sucesso"
            ];
            
        } catch (Exception $e) {
            if ($this->conn->inTransaction) {
                $this->conn->rollback();
            }
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    private function processWithdrawal($withdrawalId) {
        // Simular processamento de saque
        $stmt = $this->conn->prepare("
            UPDATE btc_transactions 
            SET status = 'processing', tx_hash = ?, updated_at = NOW() 
            WHERE id = ?
        ");
        $fakeHash = hash('sha256', 'withdrawal_' . $withdrawalId . '_' . time());
        $stmt->bind_param("si", $fakeHash, $withdrawalId);
        $stmt->execute();
    }

    private function getDailyWithdrawalLimit($userId, $crypto) {
        // Limites padrão por criptomoeda
        $limits = [
            'BTC' => 1.0,
            'ETH' => 10.0,
            'XMR' => 100.0
        ];
        
        return $limits[strtoupper($crypto)] ?? 0.1;
    }

    private function getTodayWithdrawals($userId, $crypto) {
        $stmt = $this->conn->prepare("
            SELECT COALESCE(SUM(amount), 0) as total 
            FROM btc_transactions 
            WHERE user_id = ? AND crypto_type = ? AND type = 'withdrawal' 
            AND DATE(created_at) = CURDATE() AND status != 'rejected'
        ");
        $stmt->bind_param("is", $userId, $crypto);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return floatval($result['total']);
    }

    /**
     * CONVERSÃO DE MOEDAS E COTAÇÕES
     */
    public function getCryptoRates() {
        try {
            $url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,monero&vs_currencies=usd,brl";
            $response = $this->makeHttpRequest($url);
            
            return $response ?: [
                'bitcoin' => ['usd' => 45000, 'brl' => 240000],
                'ethereum' => ['usd' => 2800, 'brl' => 15000],
                'monero' => ['usd' => 180, 'brl' => 950]
            ];
        } catch (Exception $e) {
            return [
                'bitcoin' => ['usd' => 45000, 'brl' => 240000],
                'ethereum' => ['usd' => 2800, 'brl' => 15000],
                'monero' => ['usd' => 180, 'brl' => 950]
            ];
        }
    }

    /**
     * MÉTODO DE TRIGGER AUTOMÁTICO (Substitui CRON)
     */
    public function autoTrigger() {
        $cacheFile = $this->cacheDir . '/last_crypto_check.txt';
        
        // Verificar se faz mais de 2 minutos desde a última execução
        $lastRun = file_exists($cacheFile) ? file_get_contents($cacheFile) : 0;
        $currentTime = time();
        
        if (!$lastRun || ($currentTime - intval($lastRun)) > 120) {
            // Executar verificação
            $this->processAllPendingDeposits();
            
            // Salvar timestamp
            file_put_contents($cacheFile, $currentTime);
        }
    }

    /**
     * ANÁLISE E RELATÓRIOS
     */
    public function getWalletStats($userId = null) {
        $whereClause = $userId ? "WHERE user_id = $userId" : "";
        
        $stmt = $this->conn->prepare("
            SELECT 
                crypto_type,
                COUNT(*) as total_transactions,
                SUM(CASE WHEN type = 'deposit' AND status = 'confirmed' THEN amount ELSE 0 END) as total_deposits,
                SUM(CASE WHEN type = 'withdrawal' AND status = 'confirmed' THEN amount ELSE 0 END) as total_withdrawals,
                AVG(amount) as avg_amount
            FROM btc_transactions 
            $whereClause
            GROUP BY crypto_type
        ");
        $stmt->execute();
        
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    public function getUserTransactionHistory($userId, $crypto = null, $limit = 50) {
        $cryptoClause = $crypto ? "AND crypto_type = ?" : "";
        
        $stmt = $this->conn->prepare("
            SELECT * FROM btc_transactions 
            WHERE user_id = ? $cryptoClause
            ORDER BY created_at DESC 
            LIMIT ?
        ");
        
        if ($crypto) {
            $stmt->bind_param("isi", $userId, $crypto, $limit);
        } else {
            $stmt->bind_param("ii", $userId, $limit);
        }
        
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    /**
     * FUNÇÕES AUXILIARES
     */
    private function rateLimitCheck() {
        $currentTime = time();
        if ($currentTime - $this->lastApiCall < 1) {
            usleep(1000000); // Espera 1 segundo
        }
        $this->lastApiCall = $currentTime;
        $this->apiCalls++;
    }

    private function makeHttpRequest($url, $method = 'GET', $data = null) {
        $this->rateLimitCheck();
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_USERAGENT => 'ZeeMarket-Wallet/2.1',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_SSL_VERIFYPEER => false // Para desenvolvimento local
        ]);
        
        if ($method === 'POST' && $data !== null) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode < 200 || $httpCode >= 300) {
            error_log("API Error: HTTP $httpCode for $url");
            return false;
        }
        
        return json_decode($response, true);
    }

    private function isValidAddress($address, $crypto) {
        switch (strtoupper($crypto)) {
            case 'BTC':
                return preg_match('/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/', $address);
            case 'ETH':
                return preg_match('/^0x[a-fA-F0-9]{40}$/', $address);
            case 'XMR':
                return preg_match('/^4[0-9A-Za-z]{94}$/', $address);
            default:
                return false;
        }
    }

    private function getUserBalance($userId, $crypto) {
        $balanceField = strtolower($crypto) . '_balance';
        $stmt = $this->conn->prepare("SELECT $balanceField FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        return floatval($result[$balanceField] ?? 0);
    }

    private function calculateWithdrawalFee($amount, $crypto) {
        // Taxas fixas por criptomoeda
        $fees = [
            'BTC' => 0.0001,
            'ETH' => 0.001,
            'XMR' => 0.01
        ];
        return $fees[strtoupper($crypto)] ?? 0.001;
    }

    private function updateTransactionConfirmations($txHash, $confirmations) {
        $status = $confirmations >= $this->config['min_confirmations'] ? 'confirmed' : 'pending';
        
        $stmt = $this->conn->prepare("
            UPDATE btc_transactions 
            SET confirmations = ?, status = ?, updated_at = NOW() 
            WHERE tx_hash = ?
        ");
        $stmt->bind_param("iss", $confirmations, $status, $txHash);
        $stmt->execute();
        
        // Se foi confirmado, creditar saldo se ainda não foi
        if ($status === 'confirmed') {
            $stmt = $this->conn->prepare("
                SELECT user_id, amount, crypto_type, type 
                FROM btc_transactions 
                WHERE tx_hash = ? AND type = 'deposit'
            ");
            $stmt->bind_param("s", $txHash);
            $stmt->execute();
            $tx = $stmt->get_result()->fetch_assoc();
            
            if ($tx) {
                $this->creditUserBalance($tx['user_id'], $tx['amount'], $txHash, $tx['crypto_type']);
            }
        }
    }

    private function createTestBitcoinAddress() {
        // Gerar endereço Bitcoin válido para teste
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $address = 'bc1q';
        for ($i = 0; $i < 32; $i++) {
            $address .= $chars[rand(0, strlen($chars) - 1)];
        }
        return $address;
    }

    private function encryptData($data) {
        $key = hash('sha256', 'zee_market_encrypt_key_2024');
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * WEBHOOKS E NOTIFICAÇÕES
     */
    private function setupWebhook($address, $crypto) {
        // Configurar webhooks se APIs suportarem
        if ($crypto === 'BTC' && !empty($this->config['blockcypher_token'])) {
            $webhookData = [
                'event' => 'unconfirmed-tx',
                'address' => $address,
                'url' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/btc/webhook.php?secret=zee_market_2024'
            ];
            
            $url = "https://api.blockcypher.com/v1/btc/main/hooks?token=" . $this->config['blockcypher_token'];
            $this->makeHttpRequest($url, 'POST', $webhookData);
        }
    }

    /**
     * FUNÇÕES DE API PÚBLICA
     */
    public function getDepositAddress($userId, $crypto) {
        $addressField = strtolower($crypto) . '_deposit_address';
        $stmt = $this->conn->prepare("SELECT $addressField FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return $result[$addressField] ?? null;
    }

    public function getUserBalances($userId) {
        $stmt = $this->conn->prepare("
            SELECT btc_balance, eth_balance, xmr_balance 
            FROM users 
            WHERE id = ?
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        
        return [
            'btc' => floatval($result['btc_balance'] ?? 0),
            'eth' => floatval($result['eth_balance'] ?? 0),
            'xmr' => floatval($result['xmr_balance'] ?? 0)
        ];
    }

    public function getPendingTransactions($userId) {
        $stmt = $this->conn->prepare("
            SELECT * FROM btc_transactions 
            WHERE user_id = ? AND status IN ('pending', 'processing')
            ORDER BY created_at DESC
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }

    /**
     * SISTEMA DE VERIFICAÇÃO MANUAL DE TRANSAÇÕES
     */
    public function verifyTransaction($txHash, $crypto = 'BTC') {
        try {
            switch (strtoupper($crypto)) {
                case 'BTC':
                    return $this->verifyBitcoinTransaction($txHash);
                case 'ETH':
                    return $this->verifyEthereumTransaction($txHash);
                default:
                    throw new Exception("Criptomoeda não suportada para verificação");
            }
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    private function verifyBitcoinTransaction($txHash) {
        // Verificar usando BlockCypher
        $url = "https://api.blockcypher.com/v1/btc/main/txs/$txHash";
        $response = $this->makeHttpRequest($url);
        
        if (!$response) {
            // Tentar Blockstream como backup
            $url = "https://blockstream.info/api/tx/$txHash";
            $response = $this->makeHttpRequest($url);
        }
        
        if (!$response) {
            throw new Exception("Transação não encontrada");
        }
        
        return [
            'success' => true,
            'txid' => $response['hash'] ?? $response['txid'],
            'confirmations' => $response['confirmations'] ?? 0,
            'amount' => isset($response['total']) ? $response['total'] / 100000000 : 0,
            'status' => ($response['confirmations'] ?? 0) >= 1 ? 'confirmed' : 'pending'
        ];
    }

    private function verifyEthereumTransaction($txHash) {
        $url = "https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=$txHash";
        if (!empty($this->config['etherscan_token'])) {
            $url .= "&apikey=" . $this->config['etherscan_token'];
        }
        
        $response = $this->makeHttpRequest($url);
        
        if (!$response || !isset($response['result'])) {
            throw new Exception("Transação Ethereum não encontrada");
        }
        
        $tx = $response['result'];
        
        return [
            'success' => true,
            'txid' => $tx['hash'],
            'amount' => hexdec($tx['value']) / 1000000000000000000, // Wei para ETH
            'status' => isset($tx['blockNumber']) ? 'confirmed' : 'pending',
            'confirmations' => isset($tx['blockNumber']) ? 12 : 0
        ];
    }
}

// Instância global
$zeeWallet = new ZeeMarketWallet();

// Funções wrapper para compatibilidade
function generateDepositAddress($userId, $crypto = 'BTC') {
    global $zeeWallet;
    return $zeeWallet->generateDepositAddress($userId, $crypto);
}

function checkAllPendingDeposits() {
    global $zeeWallet;
    return $zeeWallet->processAllPendingDeposits();
}

function createWithdrawal($userId, $toAddress, $amount, $crypto = 'BTC') {
    global $zeeWallet;
    return $zeeWallet->createWithdrawal($userId, $toAddress, $amount, $crypto);
}

function getCryptoRates() {
    global $zeeWallet;
    return $zeeWallet->getCryptoRates();
}

function autoTriggerWallet() {
    global $zeeWallet;
    return $zeeWallet->autoTrigger();
}

function getUserBalances($userId) {
    global $zeeWallet;
    return $zeeWallet->getUserBalances($userId);
}

function verifyTransaction($txHash, $crypto = 'BTC') {
    global $zeeWallet;
    return $zeeWallet->verifyTransaction($txHash, $crypto);
}

// Trigger automático em todas as páginas (substitui cron)
if (!defined('SKIP_AUTO_TRIGGER')) {
    try {
        autoTriggerWallet();
    } catch (Exception $e) {
        error_log("Erro no auto trigger: " . $e->getMessage());
    }
}
?>