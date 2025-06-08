<?php
// test_pgp.php - Arquivo para testar o sistema PGP
require_once 'includes/config.php';
require_once 'includes/pgp_system.php';

echo "<h2>🔧 Teste do Sistema PGP</h2>";

// 1. Verificar phpseclib3
echo "<h3>1. Verificando phpseclib3:</h3>";
if (class_exists('\phpseclib3\Crypt\RSA')) {
    echo "✅ phpseclib3 instalada corretamente!<br>";
    
    try {
        $rsa = \phpseclib3\Crypt\RSA::createKey(2048);
        echo "✅ Geração de chaves RSA funcionando!<br>";
    } catch (Exception $e) {
        echo "❌ Erro na geração RSA: " . $e->getMessage() . "<br>";
    }
} else {
    echo "❌ phpseclib3 não encontrada<br>";
}

// 2. Verificar conexão com banco
echo "<h3>2. Verificando conexão com banco:</h3>";
if (isset($conn) && $conn->ping()) {
    echo "✅ Conexão com banco funcionando!<br>";
} else {
    echo "❌ Problema na conexão com banco<br>";
}

// 3. Testar inicialização do PGP
echo "<h3>3. Testando inicialização do PGP:</h3>";
try {
    $pgpSystem = new ZeeMarketPGP($conn);
    echo "✅ Sistema PGP inicializado com sucesso!<br>";
    
    // 4. Verificar se usuário tem chaves (se logado)
    if (isset($_SESSION['user_id'])) {
        echo "<h3>4. Verificando chaves do usuário:</h3>";
        $hasKeys = $pgpSystem->userHasPgpKey($_SESSION['user_id']);
        echo $hasKeys ? "✅ Usuário tem chaves PGP<br>" : "ℹ️ Usuário ainda não tem chaves PGP<br>";
    }
    
    // 5. Testar geração de chaves mock
    echo "<h3>5. Testando geração de chaves (mock):</h3>";
    $testResult = $pgpSystem->generateUserKeyPair(
        9999, // ID fictício
        "Teste",
        "teste@zeemarket.local",
        "senhateste123"
    );
    
    if ($testResult['success']) {
        echo "✅ Geração de chaves funcionando!<br>";
        echo "Key ID: " . $testResult['key_id'] . "<br>";
        echo "Fingerprint: " . substr($testResult['fingerprint'], 0, 20) . "...<br>";
    } else {
        echo "❌ Erro na geração: " . $testResult['error'] . "<br>";
    }
    
} catch (Exception $e) {
    echo "❌ Erro ao inicializar PGP: " . $e->getMessage() . "<br>";
}

// 6. Verificar tabelas do banco
echo "<h3>6. Verificando tabelas do banco:</h3>";
$tables = ['user_pgp_keys', 'encrypted_messages', 'pgp_signatures'];
foreach ($tables as $table) {
    $result = $conn->query("SHOW TABLES LIKE '$table'");
    echo $result->num_rows > 0 ? "✅ Tabela $table existe<br>" : "❌ Tabela $table não existe<br>";
}

echo "<h3>🎯 Resultado:</h3>";
echo "Se todos os itens acima estão com ✅, o sistema PGP está funcionando!<br>";
echo "Você pode acessar <a href='privacy_settings.php'>privacy_settings.php</a> para gerar suas chaves reais.";
?>