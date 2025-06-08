<?php
/**
 * SISTEMA TOR INTEGRATION COMPLETO - ZEEMARKET
 * Hidden Service + Proxy + Security Layer
 * Arquivo: includes/tor_system.php
 */

require_once __DIR__ . '/config.php';

class ZeeMarketTor {
    private $conn;
    private $torConfig;
    private $hiddenServiceDir;
    private $socksProxy;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->initializeTorConfig();
        $this->createTablesIfNotExist();
    }
    
    private function initializeTorConfig() {
        $this->torConfig = [
            'socks_proxy' => '127.0.0.1:9050',
            'control_port' => '127.0.0.1:9051',
            'control_password' => 'zee_tor_control_2024',
            'hidden_service_dir' => '/var/lib/tor/zeemarket/',
            'hidden_service_port' => '80 127.0.0.1:8080',
            'data_directory' => '/var/lib/tor/',
            'circuit_renewal_time' => 600, // 10 minutos
            'max_circuits' => 3,
            'user_agent_rotation' => true
        ];
        
        $this->hiddenServiceDir = $this->torConfig['hidden_service_dir'];
        $this->socksProxy = $this->torConfig['socks_proxy'];
    }
    
    /**
     * ✅ CONFIGURAR HIDDEN SERVICE
     */
    public function setupHiddenService() {
        try {
            // Criar configuração do Tor
            $torrcContent = $this->generateTorrcConfig();
            
            // Salvar arquivo torrc
            $torrcPath = '/etc/tor/torrc.zeemarket';
            if (!file_put_contents($torrcPath, $torrcContent)) {
                throw new Exception('Não foi possível criar arquivo torrc');
            }
            
            // Criar diretório do hidden service
            if (!file_exists($this->hiddenServiceDir)) {
                mkdir($this->hiddenServiceDir, 0700, true);
                chown($this->hiddenServiceDir, 'debian-tor');
                chgrp($this->hiddenServiceDir, 'debian-tor');
            }
            
            // Reiniciar serviço Tor
            $result = shell_exec('sudo systemctl restart tor 2>&1');
            
            // Aguardar geração do endereço .onion
            sleep(5);
            
            $onionAddress = $this->getOnionAddress();
            
            if ($onionAddress) {
                // Salvar endereço no banco
                $this->saveOnionAddress($onionAddress);
                
                return [
                    'success' => true,
                    'onion_address' => $onionAddress,
                    'message' => 'Hidden service configurado com sucesso'
                ];
            } else {
                throw new Exception('Falha ao gerar endereço .onion');
            }
            
        } catch (Exception $e) {
            error_log("Erro ao configurar hidden service: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ FAZER REQUISIÇÕES VIA TOR
     */
    public function makeRequestViaTor($url, $method = 'GET', $data = null, $headers = []) {
        try {
            $ch = curl_init();
            
            // Configurações básicas do cURL
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 60,
                CURLOPT_CONNECTTIMEOUT => 30,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                
                // Configurações do proxy Tor
                CURLOPT_PROXY => $this->socksProxy,
                CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5_HOSTNAME,
                
                // Headers personalizados
                CURLOPT_HTTPHEADER => array_merge([
                    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language: en-US,en;q=0.5',
                    'Accept-Encoding: gzip, deflate',
                    'Connection: keep-alive',
                    'Upgrade-Insecure-Requests: 1'
                ], $headers),
                
                // User-Agent rotativo
                CURLOPT_USERAGENT => $this->getRandomUserAgent()
            ]);
            
            // Configurar método HTTP
            if ($method === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                if ($data) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                }
            } elseif ($method === 'PUT') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                if ($data) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                }
            }
            
            // Executar requisição
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);
            
            if ($response === false) {
                throw new Exception("Erro cURL: $error");
            }
            
            // Log da requisição
            $this->logTorRequest($url, $method, $httpCode);
            
            return [
                'success' => true,
                'response' => $response,
                'http_code' => $httpCode
            ];
            
        } catch (Exception $e) {
            error_log("Erro na requisição Tor: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ VERIFICAR STATUS DO TOR
     */
    public function checkTorStatus() {
        try {
            // Verificar se Tor está rodando
            $torProcess = shell_exec('pgrep tor');
            if (empty($torProcess)) {
                return [
                    'running' => false,
                    'message' => 'Serviço Tor não está rodando'
                ];
            }
            
            // Testar conexão SOCKS
            $socksTest = $this->testSocksConnection();
            
            // Testar acesso ao .onion
            $onionTest = $this->testOnionAccess();
            
            // Verificar circuitos
            $circuits = $this->getCircuitInfo();
            
            return [
                'running' => true,
                'socks_working' => $socksTest,
                'onion_accessible' => $onionTest,
                'circuits' => count($circuits),
                'onion_address' => $this->getOnionAddress()
            ];
            
        } catch (Exception $e) {
            return [
                'running' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * ✅ RENOVAR CIRCUITOS TOR
     */
    public function renewCircuits() {
        try {
            $controlSocket = $this->connectToControlPort();
            
            if ($controlSocket) {
                // Autenticar
                fwrite($controlSocket, "AUTHENTICATE \"{$this->torConfig['control_password']}\"\r\n");
                $response = fgets($controlSocket);
                
                if (strpos($response, '250') === 0) {
                    // Renovar circuitos
                    fwrite($controlSocket, "SIGNAL NEWNYM\r\n");
                    $response = fgets($controlSocket);
                    
                    if (strpos($response, '250') === 0) {
                        fclose($controlSocket);
                        return ['success' => true, 'message' => 'Circuitos renovados'];
                    }
                }
                
                fclose($controlSocket);
            }
            
            throw new Exception('Falha ao renovar circuitos');
            
        } catch (Exception $e) {
            error_log("Erro ao renovar circuitos: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ DETECTOR DE TOR BROWSER
     */
    public function detectTorBrowser() {
        $indicators = [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
            'http_x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''
        ];
        
        $torScore = 0;
        
        // Verificar User-Agent típico do Tor Browser
        if (strpos($indicators['user_agent'], 'Firefox') !== false && 
            !strpos($indicators['user_agent'], 'Chrome') && 
            !strpos($indicators['user_agent'], 'Safari')) {
            $torScore += 30;
        }
        
        // Verificar configurações de linguagem padrão
        if ($indicators['accept_language'] === 'en-US,en;q=0.5') {
            $torScore += 25;
        }
        
        // Verificar se vem de exit node conhecido
        if ($this->isKnownTorExitNode($indicators['remote_addr'])) {
            $torScore += 40;
        }
        
        // Verificar headers ausentes (Tor remove alguns)
        if (empty($_SERVER['HTTP_CACHE_CONTROL']) && 
            empty($_SERVER['HTTP_PRAGMA'])) {
            $torScore += 15;
        }
        
        return [
            'is_tor' => $torScore >= 70,
            'confidence' => $torScore,
            'indicators' => $indicators
        ];
    }
    
    /**
     * ✅ MIXER/TUMBLER INTEGRATION
     */
    public function mixBitcoin($amount, $inputAddress, $outputAddresses, $mixingFee = 0.01) {
        try {
            // Validações
            if ($amount < 0.001) {
                throw new Exception('Valor mínimo para mixing: 0.001 BTC');
            }
            
            if (count($outputAddresses) < 2) {
                throw new Exception('Mínimo 2 endereços de saída necessários');
            }
            
            // Calcular taxas
            $totalFee = $amount * $mixingFee;
            $amountAfterFee = $amount - $totalFee;
            $amountPerAddress = $amountAfterFee / count($outputAddresses);
            
            // Criar transação de mixing
            $mixingTx = [
                'id' => $this->generateMixingId(),
                'input_address' => $inputAddress,
                'input_amount' => $amount,
                'output_addresses' => $outputAddresses,
                'amount_per_output' => $amountPerAddress,
                'mixing_fee' => $totalFee,
                'delay_blocks' => rand(1, 6), // Delay aleatório
                'status' => 'pending',
                'created_at' => time()
            ];
            
            // Salvar no banco
            $stmt = $this->conn->prepare("
                INSERT INTO bitcoin_mixing 
                (mixing_id, input_address, input_amount, output_data, mixing_fee, delay_blocks, status, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, 'pending', NOW())
            ");
            
            $outputData = json_encode([
                'addresses' => $outputAddresses,
                'amount_each' => $amountPerAddress
            ]);
            
            $stmt->bind_param("ssdsdi", 
                $mixingTx['id'],
                $inputAddress,
                $amount,
                $outputData,
                $totalFee,
                $mixingTx['delay_blocks']
            );
            $stmt->execute();
            
            // Processar mixing (simulado - em produção usar serviços reais)
            $this->processMixingTransaction($mixingTx);
            
            return [
                'success' => true,
                'mixing_id' => $mixingTx['id'],
                'expected_completion' => time() + ($mixingTx['delay_blocks'] * 600),
                'message' => 'Mixing iniciado com sucesso'
            ];
            
        } catch (Exception $e) {
            error_log("Erro no mixing: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ PRIVACY ANALYZER
     */
    public function analyzePrivacyLevel($userId) {
        try {
            $privacyScore = 0;
            $recommendations = [];
            
            // Verificar uso do Tor
            $torDetection = $this->detectTorBrowser();
            if ($torDetection['is_tor']) {
                $privacyScore += 30;
            } else {
                $recommendations[] = 'Use Tor Browser para melhor privacidade';
            }
            
            // Verificar chaves PGP
            $stmt = $this->conn->prepare("SELECT id FROM user_pgp_keys WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            if ($stmt->get_result()->num_rows > 0) {
                $privacyScore += 25;
            } else {
                $recommendations[] = 'Configure chaves PGP para comunicação segura';
            }
            
            // Verificar histórico de mixing
            $stmt = $this->conn->prepare("
                SELECT COUNT(*) as mix_count 
                FROM bitcoin_mixing 
                WHERE input_address IN (
                    SELECT btc_wallet FROM users WHERE id = ?
                ) AND status = 'completed'
            ");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $mixCount = $stmt->get_result()->fetch_assoc()['mix_count'];
            
            if ($mixCount > 0) {
                $privacyScore += 20;
            } else {
                $recommendations[] = 'Considere usar Bitcoin mixing para transações';
            }
            
            // Verificar padrões de acesso
            $accessPatterns = $this->analyzeAccessPatterns($userId);
            if ($accessPatterns['consistent_tor']) {
                $privacyScore += 15;
            }
            
            // Verificar uso de endereços únicos
            $addressReuse = $this->checkAddressReuse($userId);
            if (!$addressReuse) {
                $privacyScore += 10;
            } else {
                $recommendations[] = 'Evite reutilizar endereços Bitcoin';
            }
            
            return [
                'privacy_score' => $privacyScore,
                'level' => $this->getPrivacyLevel($privacyScore),
                'recommendations' => $recommendations,
                'tor_usage' => $torDetection,
                'pgp_configured' => $privacyScore >= 25,
                'mixing_history' => $mixCount
            ];
            
        } catch (Exception $e) {
            error_log("Erro na análise de privacidade: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }
    
    /**
     * ✅ SECURITY HEADERS PARA TOR
     */
    public function setTorSecurityHeaders() {
        // Headers específicos para uso com Tor
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: no-referrer');
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'; font-src \'self\'; object-src \'none\'; media-src \'self\'; frame-src \'none\';');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
        
        // Headers específicos para privacidade
        header('Cache-Control: no-cache, no-store, must-revalidate, private');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        // Remover headers que podem vazar informações
        header_remove('Server');
        header_remove('X-Powered-By');
        header_remove('X-AspNet-Version');
    }
    
    // ===============================================
    // FUNÇÕES AUXILIARES
    // ===============================================
    
    private function generateTorrcConfig() {
        return "
# ZeeMarket Tor Configuration
SocksPort {$this->torConfig['socks_proxy']}
ControlPort {$this->torConfig['control_port']}
HashedControlPassword " . $this->hashControlPassword() . "

# Hidden Service Configuration
HiddenServiceDir {$this->hiddenServiceDir}
HiddenServicePort {$this->torConfig['hidden_service_port']}

# Security Settings
DataDirectory {$this->torConfig['data_directory']}
CookieAuthentication 1
AvoidDiskWrites 1
SafeLogging 1
RunAsDaemon 1

# Circuit Settings
NewCircuitPeriod {$this->torConfig['circuit_renewal_time']}
MaxCircuitDirtiness 600
CircuitBuildTimeout 60
NumEntryGuards 3

# Performance Settings
KeepalivePeriod 60
CircuitStreamTimeout 10
CircuitIdleTimeout 3600

# Exit Policy (no exit traffic)
ExitPolicy reject *:*
";
    }
    
    private function hashControlPassword() {
        // Gerar hash da senha de controle
        return shell_exec("tor --hash-password '{$this->torConfig['control_password']}'");
    }
    
    public function getOnionAddress() {
        $hostnameFile = $this->hiddenServiceDir . 'hostname';
        if (file_exists($hostnameFile)) {
            return trim(file_get_contents($hostnameFile));
        }
        return false;
    }
    
    private function saveOnionAddress($onionAddress) {
        $stmt = $this->conn->prepare("
            INSERT INTO tor_hidden_services (onion_address, created_at, active) 
            VALUES (?, NOW(), 1)
            ON DUPLICATE KEY UPDATE 
            onion_address = VALUES(onion_address), 
            updated_at = NOW()
        ");
        $stmt->bind_param("s", $onionAddress);
        $stmt->execute();
    }
    
    private function getRandomUserAgent() {
        $userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0'
        ];
        
        return $userAgents[array_rand($userAgents)];
    }
    
    private function testSocksConnection() {
        $context = stream_context_create([
            'http' => [
                'proxy' => 'tcp://' . $this->socksProxy,
                'request_fulluri' => true,
                'timeout' => 10
            ]
        ]);
        
        $result = @file_get_contents('http://check.torproject.org/', false, $context);
        return strpos($result, 'Congratulations') !== false;
    }
    
    private function testOnionAccess() {
        // Testar acesso ao próprio .onion
        $onionAddress = $this->getOnionAddress();
        if (!$onionAddress) return false;
        
        $result = $this->makeRequestViaTor("http://$onionAddress");
        return $result['success'] && $result['http_code'] === 200;
    }
    
    private function connectToControlPort() {
        $socket = @fsockopen('127.0.0.1', 9051, $errno, $errstr, 5);
        return $socket;
    }
    
    private function getCircuitInfo() {
        // Implementar via controller Tor
        return [];
    }
    
    private function isKnownTorExitNode($ip) {
        // Verificar em lista de exit nodes (implementar cache)
        $torExitNodes = $this->getTorExitNodesList();
        return in_array($ip, $torExitNodes);
    }
    
    private function getTorExitNodesList() {
        // Cache da lista de exit nodes
        $cacheFile = __DIR__ . '/../cache/tor_exit_nodes.json';
        
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 3600)) {
            return json_decode(file_get_contents($cacheFile), true);
        }
        
        // Baixar lista atualizada
        $result = $this->makeRequestViaTor('https://check.torproject.org/torbulkexitlist');
        if ($result['success']) {
            $exitNodes = explode("\n", trim($result['response']));
            file_put_contents($cacheFile, json_encode($exitNodes));
            return $exitNodes;
        }
        
        return [];
    }
    
    private function generateMixingId() {
        return 'mix_' . bin2hex(random_bytes(16));
    }
    
    private function processMixingTransaction($mixingTx) {
        // Em produção, integrar com serviços de mixing reais
        // Por agora, simular o processo
        
        $stmt = $this->conn->prepare("
            UPDATE bitcoin_mixing 
            SET status = 'processing', updated_at = NOW() 
            WHERE mixing_id = ?
        ");
        $stmt->bind_param("s", $mixingTx['id']);
        $stmt->execute();
        
        // Simular delay
        sleep($mixingTx['delay_blocks']);
        
        $stmt = $this->conn->prepare("
            UPDATE bitcoin_mixing 
            SET status = 'completed', completed_at = NOW() 
            WHERE mixing_id = ?
        ");
        $stmt->bind_param("s", $mixingTx['id']);
        $stmt->execute();
    }
    
    private function analyzeAccessPatterns($userId) {
        $stmt = $this->conn->prepare("
            SELECT is_tor, COUNT(*) as count
            FROM user_access_logs 
            WHERE user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY is_tor
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $results = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        $torCount = 0;
        $totalCount = 0;
        
        foreach ($results as $row) {
            if ($row['is_tor']) {
                $torCount = $row['count'];
            }
            $totalCount += $row['count'];
        }
        
        return [
            'consistent_tor' => $totalCount > 0 && ($torCount / $totalCount) > 0.8,
            'tor_percentage' => $totalCount > 0 ? ($torCount / $totalCount) * 100 : 0
        ];
    }
    
    private function checkAddressReuse($userId) {
        $stmt = $this->conn->prepare("
            SELECT btc_wallet, COUNT(*) as usage_count
            FROM btc_transactions 
            WHERE user_id = ?
            GROUP BY btc_wallet
            HAVING usage_count > 1
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        
        return $stmt->get_result()->num_rows > 0;
    }
    
    private function getPrivacyLevel($score) {
        if ($score >= 80) return 'Excelente';
        if ($score >= 60) return 'Boa';
        if ($score >= 40) return 'Média';
        if ($score >= 20) return 'Baixa';
        return 'Muito Baixa';
    }
    
    private function logTorRequest($url, $method, $httpCode) {
        $stmt = $this->conn->prepare("
            INSERT INTO tor_request_logs 
            (url, method, http_code, created_at) 
            VALUES (?, ?, ?, NOW())
        ");
        $stmt->bind_param("ssi", $url, $method, $httpCode);
        $stmt->execute();
    }
    
    private function createTablesIfNotExist() {
        $tables = [
            "CREATE TABLE IF NOT EXISTS tor_hidden_services (
                id INT AUTO_INCREMENT PRIMARY KEY,
                onion_address VARCHAR(62) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1
            )",
            
            "CREATE TABLE IF NOT EXISTS bitcoin_mixing (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mixing_id VARCHAR(50) UNIQUE NOT NULL,
                input_address VARCHAR(100) NOT NULL,
                input_amount DECIMAL(18,8) NOT NULL,
                output_data JSON NOT NULL,
                mixing_fee DECIMAL(18,8) NOT NULL,
                delay_blocks INT DEFAULT 1,
                status ENUM('pending','processing','completed','failed') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                INDEX idx_status (status),
                INDEX idx_input_address (input_address)
            )",
            
            "CREATE TABLE IF NOT EXISTS user_access_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                is_tor BOOLEAN DEFAULT 0,
                tor_confidence INT DEFAULT 0,
                page_accessed VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_is_tor (is_tor),
                INDEX idx_created_at (created_at)
            )",
            
            "CREATE TABLE IF NOT EXISTS tor_request_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(500) NOT NULL,
                method VARCHAR(10) NOT NULL,
                http_code INT NOT NULL,
                response_time_ms INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_created_at (created_at)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->conn->query($sql);
        }
    }
}

/**
 * ✅ MIDDLEWARE PARA DETECÇÃO AUTOMÁTICA
 */
class TorMiddleware {
    private $torSystem;
    
    public function __construct($torSystem) {
        $this->torSystem = $torSystem;
    }
    
    public function handle() {
        // Detectar Tor Browser
        $torDetection = $this->torSystem->detectTorBrowser();
        
        // Configurar headers de segurança
        $this->torSystem->setTorSecurityHeaders();
        
        // Log do acesso
        $this->logAccess($torDetection);
        
        // Adicionar informações à sessão
        $_SESSION['is_tor'] = $torDetection['is_tor'];
        $_SESSION['tor_confidence'] = $torDetection['confidence'];
        
        return $torDetection;
    }
    
    private function logAccess($torDetection) {
        global $conn;
        
        $stmt = $conn->prepare("
            INSERT INTO user_access_logs 
            (user_id, ip_address, user_agent, is_tor, tor_confidence, page_accessed, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $userId = $_SESSION['user_id'] ?? null;
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $pageAccessed = $_SERVER['REQUEST_URI'] ?? '';
        
        $stmt->bind_param("isssis", 
            $userId,
            $ipAddress,
            $userAgent,
            $torDetection['is_tor'],
            $torDetection['confidence'],
            $pageAccessed
        );
        $stmt->execute();
    }
}

// Uso do sistema
try {
    $torSystem = new ZeeMarketTor($conn);
    $torMiddleware = new TorMiddleware($torSystem);
    
    // Executar middleware em todas as páginas
    $torDetection = $torMiddleware->handle();
    
    // Exemplo de uso das funcionalidades
    if ($_POST['action'] === 'setup_hidden_service') {
        $result = $torSystem->setupHiddenService();
        echo json_encode($result);
    }
    
    if ($_POST['action'] === 'check_privacy') {
        $privacy = $torSystem->analyzePrivacyLevel($_SESSION['user_id']);
        echo json_encode($privacy);
    }
    
} catch (Exception $e) {
    error_log("Erro no sistema Tor: " . $e->getMessage());
}