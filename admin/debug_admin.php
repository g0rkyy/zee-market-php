<?php
/**
 * Script de Debug para o Painel Admin
 * Salve como: debug_admin.php na pasta admin/
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>🔍 Debug do Painel Admin</h2>";

// Verificar se estamos na pasta correta
echo "<h3>📁 Verificação de Arquivos:</h3>";
echo "<p><strong>Diretório atual:</strong> " . __DIR__ . "</p>";
echo "<p><strong>Arquivo atual:</strong> " . __FILE__ . "</p>";

// Listar arquivos na pasta admin
echo "<h4>Arquivos na pasta admin:</h4>";
if (is_dir('.')) {
    $files = scandir('.');
    echo "<ul>";
    foreach ($files as $file) {
        if ($file != '.' && $file != '..') {
            $type = is_dir($file) ? '📁' : '📄';
            echo "<li>$type $file</li>";
        }
    }
    echo "</ul>";
} else {
    echo "<p style='color: red;'>❌ Pasta admin não encontrada!</p>";
}

// Verificar se admin_panel.php existe
echo "<h4>Verificação do admin_panel.php:</h4>";
if (file_exists('admin_painel.php')) {
    echo "<p style='color: green;'>✅ admin_panel.php encontrado!</p>";
    echo "<p><strong>Tamanho:</strong> " . filesize('admin_painel.php') . " bytes</p>";
    echo "<p><strong>Última modificação:</strong> " . date('d/m/Y H:i:s', filemtime('admin_painel.php')) . "</p>";
} else {
    echo "<p style='color: red;'>❌ admin_panel.php NÃO encontrado!</p>";
}

// Verificar se config.php existe
echo "<h4>Verificação do config.php:</h4>";
if (file_exists('../includes/config.php')) {
    echo "<p style='color: green;'>✅ config.php encontrado!</p>";
} else {
    echo "<p style='color: red;'>❌ config.php NÃO encontrado!</p>";
}

// Testar conexão com banco
echo "<h3>🗄️ Teste de Conexão com Banco:</h3>";
try {
    require_once '../includes/config.php';
    if ($conn) {
        echo "<p style='color: green;'>✅ Conexão com banco OK!</p>";
        
        // Verificar tabela system_config
        $result = $conn->query("SHOW TABLES LIKE 'system_config'");
        if ($result && $result->num_rows > 0) {
            echo "<p style='color: green;'>✅ Tabela system_config existe!</p>";
            
            // Verificar configuração real_mode
            $stmt = $conn->query("SELECT * FROM system_config WHERE config_key = 'real_mode'");
            if ($stmt && $stmt->num_rows > 0) {
                $config = $stmt->fetch_assoc();
                echo "<p style='color: green;'>✅ Configuração real_mode encontrada!</p>";
                echo "<p><strong>Valor atual:</strong> " . $config['config_value'] . "</p>";
            } else {
                echo "<p style='color: orange;'>⚠️ Configuração real_mode não encontrada!</p>";
                echo "<p>Criando configuração...</p>";
                $conn->query("INSERT INTO system_config (config_key, config_value, description) VALUES ('real_mode', '0', 'Modo real/simulado')");
                echo "<p style='color: green;'>✅ Configuração criada!</p>";
            }
        } else {
            echo "<p style='color: red;'>❌ Tabela system_config não existe!</p>";
        }
    } else {
        echo "<p style='color: red;'>❌ Erro na conexão com banco!</p>";
    }
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ Erro: " . $e->getMessage() . "</p>";
}

// Verificar URLs
echo "<h3>🔗 URLs de Teste:</h3>";
$base_url = 'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']);
echo "<p><a href='{$base_url}/admin_panel.php' target='_blank'>🔗 Testar admin_panel.php</a></p>";
echo "<p><a href='{$base_url}/../dashboard.php' target='_blank'>🔗 Testar dashboard.php</a></p>";

// Informações do servidor
echo "<h3>🖥️ Informações do Servidor:</h3>";
echo "<p><strong>PHP Version:</strong> " . PHP_VERSION . "</p>";
echo "<p><strong>Document Root:</strong> " . $_SERVER['DOCUMENT_ROOT'] . "</p>";
echo "<p><strong>Server Software:</strong> " . $_SERVER['SERVER_SOFTWARE'] . "</p>";

echo "<hr>";
echo "<p><strong>👨‍💻 Próximos passos:</strong></p>";
echo "<ol>";
echo "<li>Se admin_panel.php não existe, renomeie admin_painel.php para admin_panel.php</li>";
echo "<li>Verifique se está acessando a URL correta</li>";
echo "<li>Execute o fix_database_complete.php se houver problemas no banco</li>";
echo "</ol>";
?>