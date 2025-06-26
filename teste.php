#!/bin/bash
echo "🔧 Correção Completa do Problema de Permissões"

cd /var/www/html/zee-market-php

echo "=== 1. Diagnosticando o problema atual ==="
echo "Diretório atual: $(pwd)"
echo "Usuário atual: $(whoami)"
echo "Permissões do diretório raiz do projeto:"
ls -la /var/www/html/zee-market-php

echo ""
echo "=== 2. Criando diretório assets/uploads com permissões corretas ==="

# Criar o diretório com as permissões corretas
sudo mkdir -p assets/uploads
sudo chmod 755 assets/
sudo chmod 775 assets/uploads/
sudo chown -R www-data:www-data assets/

echo "✅ Diretório criado e permissões definidas"

echo ""
echo "=== 3. Verificando se www-data pode escrever ==="
sudo -u www-data test -w assets/uploads/ && echo "✅ www-data pode escrever" || echo "❌ www-data NÃO pode escrever"

echo ""
echo "=== 4. Testando criação de arquivo ==="
sudo -u www-data touch assets/uploads/test_file.txt && echo "✅ Criação de arquivo OK" || echo "❌ Criação de arquivo FALHOU"
sudo -u www-data rm -f assets/uploads/test_file.txt

echo ""
echo "=== 5. Verificando se o diretório pai permite criação ==="
echo "Permissões do diretório raiz do projeto:"
ls -la . | grep -E "^d"

echo ""
echo "=== 6. Corrigindo permissões do diretório raiz se necessário ==="
# O diretório raiz precisa permitir que www-data crie subdiretórios
sudo chown www-data:www-data .
sudo chmod 755 .

echo ""
echo "=== 7. Teste final completo ==="
sudo -u www-data php -r "
echo 'Teste final como www-data executando de admin/:' . PHP_EOL;
chdir('admin');
echo 'Diretório atual: ' . getcwd() . PHP_EOL;

\$upload_dir = '../assets/uploads/';
echo 'Diretório de upload: ' . \$upload_dir . PHP_EOL;
echo 'Existe: ' . (is_dir(\$upload_dir) ? 'SIM' : 'NÃO') . PHP_EOL;
echo 'Gravável: ' . (is_writable(\$upload_dir) ? 'SIM' : 'NÃO') . PHP_EOL;

if (!is_dir(\$upload_dir)) {
    echo 'Tentando criar diretório...' . PHP_EOL;
    if (mkdir(\$upload_dir, 0775, true)) {
        echo 'SUCESSO: Diretório criado!' . PHP_EOL;
    } else {
        echo 'FALHA: Não foi possível criar!' . PHP_EOL;
    }
}

\$test_file = \$upload_dir . 'test_final.txt';
if (file_put_contents(\$test_file, 'teste final')) {
    echo 'SUCESSO: Arquivo criado!' . PHP_EOL;
    unlink(\$test_file);
} else {
    echo 'FALHA: Não foi possível criar arquivo!' . PHP_EOL;
}
"

echo ""
echo "=== 8. Status final ==="
echo "Estrutura de diretórios:"
find assets/ -type d -exec ls -la {} \;

echo ""
echo "Permissões finais:"
ls -la assets/uploads/