#!/bin/bash
# CORRIGIR BANCO DE DADOS PGP

echo "🔧 CORRIGINDO BANCO DE DADOS PGP"
echo "================================="

cd /var/www/html/zee-market-php

# 1. Verificar se as chaves ainda existem no GPG
echo "🔍 Verificando chaves GPG..."
gpg --list-keys

if gpg --list-keys | grep -q "ZeeMarket"; then
    echo "✅ Chaves encontradas no GPG!"
    
    # 2. Exportar novamente
    echo "📤 Exportando chaves..."
    gpg --armor --export "admin@zeemarket.onion" > public_key_new.asc
    gpg --armor --export-secret-keys "admin@zeemarket.onion" > private_key_new.asc
    
    # 3. Verificar se exportou
    if [ -s public_key_new.asc ] && [ -s private_key_new.asc ]; then
        echo "✅ Chaves exportadas!"
        
        # 4. Criar script PHP para inserir corretamente
        cat > fix_pgp_db.php << 'EOF'
<?php
require_once 'includes/config.php';

echo "🔧 Corrigindo banco PGP...\n";

// Ler chaves dos arquivos
$publicKey = file_get_contents('public_key_new.asc');
$privateKey = file_get_contents('private_key_new.asc');

if ($publicKey && $privateKey) {
    echo "✅ Chaves lidas dos arquivos\n";
    echo "Tamanho chave pública: " . strlen($publicKey) . " bytes\n";
    echo "Tamanho chave privada: " . strlen($privateKey) . " bytes\n";
    
    // Limpar dados antigos
    $conn->query("DELETE FROM site_pgp_keys WHERE site_name = 'zeemarket'");
    echo "🧹 Registros antigos removidos\n";
    
    // Inserir chaves
    $stmt = $conn->prepare("INSERT INTO site_pgp_keys (site_name, public_key, private_key_encrypted, passphrase) VALUES (?, ?, ?, ?)");
    
    if ($stmt) {
        $siteName = 'zeemarket';
        $passphrase = ''; // Sem senha
        
        $stmt->bind_param("ssss", $siteName, $publicKey, $privateKey, $passphrase);
        
        if ($stmt->execute()) {
            echo "✅ SUCESSO! Chaves inseridas no banco!\n";
            echo "ID da inserção: " . $conn->insert_id . "\n";
            
            // Verificar se realmente inseriu
            $check = $conn->query("SELECT COUNT(*) as total FROM site_pgp_keys WHERE site_name = 'zeemarket'");
            $result = $check->fetch_assoc();
            echo "✅ Verificação: " . $result['total'] . " registro(s) no banco\n";
            
            // Mostrar parte da chave pública
            echo "\n📋 Chave pública inserida:\n";
            echo substr($publicKey, 0, 200) . "...\n";
            
        } else {
            echo "❌ ERRO ao inserir: " . $stmt->error . "\n";
        }
    } else {
        echo "❌ ERRO ao preparar statement: " . $conn->error . "\n";
    }
} else {
    echo "❌ ERRO: Não foi possível ler os arquivos de chaves\n";
    echo "Arquivo público existe: " . (file_exists('public_key_new.asc') ? 'SIM' : 'NÃO') . "\n";
    echo "Arquivo privado existe: " . (file_exists('private_key_new.asc') ? 'SIM' : 'NÃO') . "\n";
}
?>
EOF

        # 5. Executar script PHP
        echo "🚀 Executando inserção no banco..."
        php fix_pgp_db.php
        
        # 6. Limpar arquivos temporários
        echo "🧹 Limpando arquivos temporários..."
        rm -f public_key_new.asc private_key_new.asc fix_pgp_db.php
        
    else
        echo "❌ Falha ao exportar chaves"
        ls -la *key*.asc
    fi
    
else
    echo "❌ Nenhuma chave encontrada no GPG"
    echo "As chaves podem ter sido perdidas. Vamos gerar novas..."
    
    # Gerar chaves rapidamente
    gpg --batch --gen-key << 'EOF'
Key-Type: RSA
Key-Length: 2048
Name-Real: ZeeMarket
Name-Email: admin@zeemarket.onion
Expire-Date: 0
%no-protection
%commit
EOF
    
    echo "✅ Novas chaves geradas!"
    # Repetir processo de exportação...
fi

echo ""
echo "🎯 TESTE AGORA:"
echo "1. Acesse privacy_settings.php"
echo "2. Deve mostrar PGP como CONFIGURADO"
echo "3. Botão 'Ver Nossa Chave Pública' deve aparecer"
