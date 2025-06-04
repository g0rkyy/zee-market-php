<?php
/**
 * CONFIGURAÇÃO DE APIS REAIS
 * Salve como: includes/real_api_config.php
 */

// ============= CONFIGURAÇÕES DE PRODUÇÃO ============= //

$REAL_API_CONFIG = [
    // BLOCKCYPHER - Para Bitcoin (OBRIGATÓRIO)
    'blockcypher' => [
        'token' => '1a406e8d527943418bd99f7afaf3d461', // COLE SUA CHAVE AQUI - Obtenha em: https://www.blockcypher.com/dev/
        'base_url' => 'https://api.blockcypher.com/v1/btc/main',
        'rate_limit' => 3 // 3 requests/segundo no plano gratuito
    ],
    
    // ETHERSCAN - Para Ethereum (OBRIGATÓRIO)
    'etherscan' => [
        'token' => 'D43Q7D5AAG2V4YSVXMVHEQ2NUDECJMFKKJ', // COLE SUA CHAVE AQUI - Obtenha em: https://etherscan.io/apis
        'base_url' => 'https://api.etherscan.io/api',
        'rate_limit' => 5 // 5 requests/segundo no plano gratuito
    ],
    
    // INFURA - Para transações Ethereum (OPCIONAL)
    'infura' => [
        'project_id' => '', // Obtenha em: https://infura.io/
        'project_secret' => '',
        'endpoint' => 'https://mainnet.infura.io/v3/'
    ],
    
    // COINGECKO - Para cotações (GRATUITO)
    'coingecko' => [
        'base_url' => 'https://api.coingecko.com/api/v3',
        'rate_limit' => 50 // 50 requests/minuto no plano gratuito
    ],
    
    // BLOCKSTREAM - Backup gratuito para Bitcoin
    'blockstream' => [
        'base_url' => 'https://blockstream.info/api',
        'rate_limit' => 10 // Sem limite oficial, mas seja respeitoso
    ],
    
    // CONFIGURAÇÕES DE WEBHOOK
    'webhook' => [
        'secret' => 'ZeeMarket_Webhook_2024_' . hash('sha256', $_SERVER['HTTP_HOST'] ?? 'localhost'),
        'url' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/btc/webhook.php'
    ],
    
    // CARTEIRAS DA PLATAFORMA
    'platform_wallets' => [
        'btc' => 'bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m', // SUA CARTEIRA BITCOIN REAL
        'eth' => '', // SUA CARTEIRA ETHEREUM REAL
        'fees' => 0.025 // 2.5% de taxa
    ],
    
    // CONFIGURAÇÕES DE SEGURANÇA
    'security' => [
        'min_confirmations' => [
            'BTC' => 1,
            'ETH' => 12,
            'XMR' => 10
        ],
        'max_daily_withdrawal' => [
            'BTC' => 1.0,
            'ETH' => 10.0,
            'XMR' => 100.0
        ],
        'min_deposits' => [
            'BTC' => 0.0001,
            'ETH' => 0.001,
            'XMR' => 0.01
        ]
    ]
];

// ============= FUNÇÕES DE VALIDAÇÃO ============= //

function validateApiConfig() {
    global $REAL_API_CONFIG;
    
    $required = [
        'blockcypher.token' => 'BlockCypher API key é obrigatória para Bitcoin',
        'etherscan.token' => 'Etherscan API key é obrigatória para Ethereum',
        'platform_wallets.btc' => 'Carteira Bitcoin da plataforma é obrigatória'
    ];
    
    $errors = [];
    
    foreach ($required as $key => $message) {
        $value = getNestedValue($REAL_API_CONFIG, $key);
        if (empty($value)) {
            $errors[] = $message;
        }
    }
    
    return $errors;
}

function getNestedValue($array, $key) {
    $keys = explode('.', $key);
    $value = $array;
    
    foreach ($keys as $k) {
        if (!isset($value[$k])) {
            return null;
        }
        $value = $value[$k];
    }
    
    return $value;
}

// ============= INSTRUÇÕES DE CONFIGURAÇÃO ============= //

echo "
<h2>🔧 Configuração de APIs Reais - ZeeMarket</h2>

<div style='background: #f0f8ff; padding: 20px; border-radius: 10px; margin: 20px 0;'>
    <h3>📋 Passos para Configurar:</h3>
    
    <h4>1. 🔑 Obter Chaves de API:</h4>
    <ul>
        <li><strong>BlockCypher:</strong> <a href='https://www.blockcypher.com/dev/' target='_blank'>blockcypher.com/dev</a> (Gratuito - 3 req/sec)</li>
        <li><strong>Etherscan:</strong> <a href='https://etherscan.io/apis' target='_blank'>etherscan.io/apis</a> (Gratuito - 5 req/sec)</li>
        <li><strong>Infura (opcional):</strong> <a href='https://infura.io/' target='_blank'>infura.io</a> (Para transações ETH)</li>
    </ul>
    
    <h4>2. 💰 Configurar Carteiras:</h4>
    <ul>
        <li><strong>Bitcoin:</strong> bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m (JÁ CONFIGURADA)</li>
        <li><strong>Ethereum:</strong> Adicione sua carteira ETH real</li>
        <li><strong>Taxa:</strong> 2.5% já configurada</li>
    </ul>
    
    <h4>3. 🔐 Configurar Webhook:</h4>
    <p>URL do webhook: <code>{$REAL_API_CONFIG['webhook']['url']}</code></p>
    <p>Secret: <code>{$REAL_API_CONFIG['webhook']['secret']}</code></p>
</div>

<div style='background: #ffe4e1; padding: 20px; border-radius: 10px; margin: 20px 0;'>
    <h3>⚠️ IMPORTANTE - Segurança:</h3>
    <ul>
        <li>🔒 Mantenha as chaves privadas seguras</li>
        <li>🧪 Teste primeiro com valores pequenos</li>
        <li>📊 Monitore todas as transações</li>
        <li>🔄 Configure backups regulares</li>
        <li>🛡️ Use HTTPS em produção</li>
    </ul>
</div>
";

// Verificar configuração atual
$errors = validateApiConfig();

if (!empty($errors)) {
    echo "<div style='background: #ffebee; padding: 15px; border-radius: 5px; color: #c62828;'>";
    echo "<h4>❌ Configurações Pendentes:</h4>";
    foreach ($errors as $error) {
        echo "<li>$error</li>";
    }
    echo "</div>";
} else {
    echo "<div style='background: #e8f5e8; padding: 15px; border-radius: 5px; color: #2e7d32;'>";
    echo "<h4>✅ Todas as configurações estão corretas!</h4>";
    echo "</div>";
}

?>