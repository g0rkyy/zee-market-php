<?php
/**
 * SCRIPT PARA ATUALIZAR CONFIGURAÇÕES
 * Salve como: update_config.php
 */

require_once 'includes/config.php';

echo "<h2>🔧 Atualizando Configurações do Sistema</h2>";

try {
    // Atualizar carteira da plataforma no banco
    $platform_wallet = "bc1qxvkeglgc745f7ekah7w4evkjg65j5qm0n3ex9m";
    
    // Verificar se configuração existe
    $stmt = $conn->prepare("SELECT * FROM system_config WHERE config_key = 'platform_wallet'");
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        // Atualizar existente
        $stmt = $conn->prepare("UPDATE system_config SET config_value = ? WHERE config_key = 'platform_wallet'");
        $stmt->bind_param("s", $platform_wallet);
        $stmt->execute();
        echo "<p style='color: green;'>✅ Carteira da plataforma atualizada!</p>";
    } else {
        // Criar nova configuração
        $stmt = $conn->prepare("INSERT INTO system_config (config_key, config_value, description) VALUES ('platform_wallet', ?, 'Carteira para receber taxas da plataforma')");
        $stmt->bind_param("s", $platform_wallet);
        $stmt->execute();
        echo "<p style='color: green;'>✅ Configuração da carteira criada!</p>";
    }
    
    // Outras configurações importantes
    $configs = [
        ['platform_fee_percent', '2.5', 'Taxa da plataforma em porcentagem'],
        ['btc_min_deposit', '0.0001', 'Depósito mínimo de Bitcoin'],
        ['daily_withdrawal_limit_btc', '0.1', 'Limite diário de saque BTC'],
    ];
    
    foreach ($configs as $config) {
        $stmt = $conn->prepare("INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $config[0], $config[1], $config[2]);
        $stmt->execute();
    }
    
    echo "<p style='color: green;'>✅ Todas as configurações atualizadas!</p>";
    
    // Mostrar configurações atuais
    echo "<h3>📋 Configurações Atuais:</h3>";
    $result = $conn->query("SELECT * FROM system_config ORDER BY config_key");
    echo "<table border='1' style='border-collapse: collapse; width: 100%;'>";
    echo "<tr><th>Chave</th><th>Valor</th><th>Descrição</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($row['config_key']) . "</td>";
        echo "<td><strong>" . htmlspecialchars($row['config_value']) . "</strong></td>";
        echo "<td>" . htmlspecialchars($row['description']) . "</td>";
        echo "</tr>";
    }
    echo "</table>";
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ Erro: " . $e->getMessage() . "</p>";
}

echo "<hr>";
echo "<h3>📝 Próximos Passos:</h3>";
echo "<ol>";
echo "<li>✅ Carteira configurada</li>";
echo "<li>🔄 Configure as APIs blockchain (BlockCypher, Etherscan)</li>";
echo "<li>🧪 Teste com valores pequenos primeiro</li>";
echo "<li>🔐 Configure segurança adicional</li>";
echo "</ol>";

echo "<p><a href='dashboard.php'>← Voltar ao Dashboard</a></p>";
?>