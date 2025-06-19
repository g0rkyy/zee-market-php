<?php
/**
 * SCRIPT DE DIAGNÓSTICO E CORREÇÃO DE PERMISSÕES
 * Salvar como: check_permissions.php na raiz do projeto
 * Executar via navegador: http://seusite.com/check_permissions.php
 */

echo "<h2>🔍 Diagnóstico de Permissões - ZeeMarket</h2>";

// Configurações
$uploadsDir = './assets/uploads/';
$relativeUploadsDir = '../assets/uploads/'; // Como usado no cadastrar_produto.php

echo "<h3>📁 Verificação de Diretórios</h3>";

// Verificar diretório atual
echo "<strong>Diretório atual:</strong> " . getcwd() . "<br>";
echo "<strong>Usuario PHP:</strong> " . (function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'desconhecido') . "<br>";
echo "<strong>Grupo PHP:</strong> " . (function_exists('posix_getgrgid') ? posix_getgrgid(posix_getegid())['name'] : 'desconhecido') . "<br><br>";

// Verificar ambos os caminhos
$caminhos = [
    'Relativo (usado no admin/)' => $relativeUploadsDir,
    'Absoluto (a partir da raiz)' => $uploadsDir
];

foreach ($caminhos as $desc => $caminho) {
    echo "<h4>$desc: <code>$caminho</code></h4>";
    
    $caminhoReal = realpath($caminho);
    echo "Caminho real: " . ($caminhoReal ?: 'NÃO EXISTE') . "<br>";
    
    if (!is_dir($caminho)) {
        echo "❌ <strong>Diretório NÃO EXISTE</strong><br>";
        
        if (mkdir($caminho, 0775, true)) {
            echo "✅ Diretório CRIADO com sucesso<br>";
        } else {
            echo "❌ FALHA ao criar diretório<br>";
        }
    } else {
        echo "✅ Diretório existe<br>";
    }
    
    if (is_dir($caminho)) {
        $perms = substr(sprintf('%o', fileperms($caminho)), -4);
        $writable = is_writable($caminho) ? '✅ SIM' : '❌ NÃO';
        $readable = is_readable($caminho) ? '✅ SIM' : '❌ NÃO';
        
        echo "Permissões: $perms<br>";
        echo "Gravável: $writable<br>";
        echo "Legível: $readable<br>";
        
        if (function_exists('fileowner')) {
            $owner = posix_getpwuid(fileowner($caminho))['name'] ?? 'unknown';
            $group = posix_getgrgid(filegroup($caminho))['name'] ?? 'unknown';
            echo "Proprietário: $owner:$group<br>";
        }
    }
    
    echo "<br>";
}

// Teste de escrita
echo "<h3>✍️ Teste de Escrita</h3>";

$testFile = $uploadsDir . 'test_permissions_' . time() . '.txt';
$testContent = "Teste de permissões: " . date('Y-m-d H:i:s');

if (file_put_contents($testFile, $testContent)) {
    echo "✅ <strong>Sucesso!</strong> Arquivo de teste criado: $testFile<br>";
    
    if (unlink($testFile)) {
        echo "✅ Arquivo de teste removido com sucesso<br>";
    } else {
        echo "⚠️ Arquivo criado mas não pôde ser removido<br>";
    }
} else {
    echo "❌ <strong>FALHA!</strong> Não foi possível criar arquivo de teste<br>";
    
    $error = error_get_last();
    if ($error) {
        echo "Erro PHP: " . $error['message'] . "<br>";
    }
}

// Informações do sistema
echo "<h3>🖥️ Informações do Sistema</h3>";
echo "PHP Version: " . PHP_VERSION . "<br>";
echo "OS: " . PHP_OS . "<br>";
echo "Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'desconhecido') . "<br>";
echo "Document Root: " . ($_SERVER['DOCUMENT_ROOT'] ?? 'desconhecido') . "<br>";

// Verificar configurações de upload
echo "<h3>📤 Configurações de Upload</h3>";
echo "upload_max_filesize: " . ini_get('upload_max_filesize') . "<br>";
echo "post_max_size: " . ini_get('post_max_size') . "<br>";
echo "max_file_uploads: " . ini_get('max_file_uploads') . "<br>";
echo "file_uploads: " . (ini_get('file_uploads') ? 'Habilitado' : 'Desabilitado') . "<br>";
echo "upload_tmp_dir: " . (ini_get('upload_tmp_dir') ?: 'padrão do sistema') . "<br>";

// Verificar espaço em disco
$freeSpace = disk_free_space('.');
$totalSpace = disk_total_space('.');
if ($freeSpace !== false && $totalSpace !== false) {
    echo "<h3>💾 Espaço em Disco</h3>";
    echo "Espaço livre: " . round($freeSpace / 1024 / 1024, 2) . " MB<br>";
    echo "Espaço total: " . round($totalSpace / 1024 / 1024, 2) . " MB<br>";
    echo "Uso: " . round((($totalSpace - $freeSpace) / $totalSpace) * 100, 1) . "%<br>";
}

// Sugestões de correção
echo "<h3>🔧 Comandos para Correção</h3>";
echo "<pre>";
echo "# Execute no terminal do servidor:\n";
echo "cd " . getcwd() . "\n";
echo "mkdir -p assets/uploads\n";
echo "chmod 755 assets/\n";
echo "chmod 775 assets/uploads/\n";
echo "chown -R www-data:www-data assets/  # Para Apache\n";
echo "# ou\n";
echo "chown -R nginx:nginx assets/  # Para Nginx\n\n";

echo "# Verificar usuário do servidor web:\n";
echo "ps aux | grep -E '(apache|nginx|httpd)'\n";
echo "</pre>";

// Listar arquivos existentes
if (is_dir($uploadsDir)) {
    $files = scandir($uploadsDir);
    $files = array_filter($files, function($file) { return $file !== '.' && $file !== '..'; });
    
    echo "<h3>📁 Arquivos Existentes</h3>";
    if (empty($files)) {
        echo "Nenhum arquivo encontrado.<br>";
    } else {
        echo "<ul>";
        foreach ($files as $file) {
            $filePath = $uploadsDir . $file;
            $size = filesize($filePath);
            $perms = substr(sprintf('%o', fileperms($filePath)), -4);
            echo "<li><code>$file</code> - $size bytes - permissões: $perms</li>";
        }
        echo "</ul>";
    }
}

echo "<hr>";
echo "<p><strong>💡 Dica:</strong> Se as permissões estiverem corretas mas ainda não funcionar, verifique:</p>";
echo "<ul>";
echo "<li>🔥 Firewall/SELinux (se estiver ativo)</li>";
echo "<li>🐳 Se está usando Docker, verifique os volumes</li>";
echo "<li>☁️ Se está em hosting compartilhado, contate o suporte</li>";
echo "<li>🔒 Políticas de segurança específicas do servidor</li>";
echo "</ul>";
?>