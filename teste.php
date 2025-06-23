<?php
/**
 * DIAGNÓSTICO ESPECÍFICO - Criar como: admin/debug_upload_change.php
 * Execute via navegador para descobrir o que mudou
 */

echo "<h2>🔍 Diagnóstico: O que Mudou no Upload?</h2>";

// 1. Verificar estrutura atual vs esperada
echo "<h3>📁 1. Verificação de Estrutura de Diretórios</h3>";

echo "<strong>Diretório atual do script:</strong> " . __DIR__ . "<br>";
echo "<strong>Diretório pai:</strong> " . dirname(__DIR__) . "<br>";

$expected_uploads = '../assets/uploads/';
$current_working_dir = getcwd();
echo "<strong>Working directory:</strong> $current_working_dir<br>";
echo "<strong>Caminho relativo esperado:</strong> $expected_uploads<br>";
echo "<strong>Caminho absoluto esperado:</strong> " . realpath(dirname(__DIR__)) . "/assets/uploads/<br>";

// 2. Verificar se o caminho mudou
echo "<h3>🗂️ 2. Teste de Caminhos Relativos</h3>";

$test_paths = [
    '../assets/uploads/',
    './assets/uploads/',
    '../../assets/uploads/',
    'assets/uploads/',
    dirname(__DIR__) . '/assets/uploads/'
];

foreach ($test_paths as $path) {
    $real_path = realpath($path);
    $exists = is_dir($path);
    $writable = $exists ? is_writable($path) : false;
    
    echo "<div style='margin: 5px 0; padding: 5px; background: " . ($exists && $writable ? '#d4edda' : '#f8d7da') . "'>";
    echo "<strong>$path</strong><br>";
    echo "• Existe: " . ($exists ? '✅' : '❌') . "<br>";
    echo "• Gravável: " . ($writable ? '✅' : '❌') . "<br>";
    echo "• Caminho real: " . ($real_path ?: 'não existe') . "<br>";
    echo "</div>";
}

// 3. Verificar se o caminho mudou por causa do include/require
echo "<h3>🔗 3. Análise de Includes</h3>";

echo "<strong>Script atual:</strong> " . __FILE__ . "<br>";
echo "<strong>Diretório do script:</strong> " . dirname(__FILE__) . "<br>";

// Verificar se config.php e functions.php estão no lugar certo
$config_path = '../includes/config.php';
$functions_path = '../includes/functions.php';

echo "<strong>Config.php existe?</strong> " . (file_exists($config_path) ? '✅' : '❌') . "<br>";
echo "<strong>Functions.php existe?</strong> " . (file_exists($functions_path) ? '✅' : '❌') . "<br>";

// 4. Simulação exata do código de upload
echo "<h3>💾 4. Simulação do Código de Upload</h3>";

// Reproduzir exatamente o que o código faz
$extensao = 'jpeg'; // Simular
$nomeImagem = 'test_' . time() . '.' . $extensao;
$diretorioUploads = '../assets/uploads/';
$caminhoImagem = $diretorioUploads . $nomeImagem;

echo "<strong>Diretório de uploads:</strong> $diretorioUploads<br>";
echo "<strong>Nome da imagem:</strong> $nomeImagem<br>";
echo "<strong>Caminho completo:</strong> $caminhoImagem<br>";
echo "<strong>Caminho absoluto:</strong> " . realpath(dirname($caminhoImagem)) . "<br>";

// Verificar se pode criar diretório
if (!is_dir($diretorioUploads)) {
    echo "<div style='background: #fff3cd; padding: 10px; margin: 10px 0;'>";
    echo "⚠️ <strong>Diretório não existe!</strong><br>";
    echo "Tentando criar: $diretorioUploads<br>";
    
    if (mkdir($diretorioUploads, 0775, true)) {
        echo "✅ Diretório criado com sucesso!<br>";
        chown($diretorioUploads, 'www-data');
    } else {
        echo "❌ Falha ao criar diretório!<br>";
        $error = error_get_last();
        echo "Erro: " . ($error['message'] ?? 'desconhecido') . "<br>";
    }
    echo "</div>";
}

// 5. Teste real de escrita
echo "<h3>✍️ 5. Teste Real de Escrita</h3>";

$test_file = $diretorioUploads . 'test_write_' . time() . '.txt';
$test_content = "Teste de escrita: " . date('Y-m-d H:i:s');

echo "<strong>Tentando criar:</strong> $test_file<br>";

if (file_put_contents($test_file, $test_content)) {
    echo "✅ <strong>Sucesso!</strong> Arquivo criado com sucesso!<br>";
    echo "Conteúdo: " . file_get_contents($test_file) . "<br>";
    
    // Tentar simular move_uploaded_file (que é o que falha)
    $temp_file = tempnam(sys_get_temp_dir(), 'upload_test_');
    file_put_contents($temp_file, $test_content);
    
    $test_move_target = $diretorioUploads . 'test_move_' . time() . '.txt';
    
    echo "<strong>Simulando move_uploaded_file:</strong><br>";
    echo "• Origem: $temp_file<br>";
    echo "• Destino: $test_move_target<br>";
    
    // ATENÇÃO: move_uploaded_file só funciona com uploads reais
    // Vamos usar copy para simular
    if (copy($temp_file, $test_move_target)) {
        echo "✅ Simulação de move bem-sucedida!<br>";
        unlink($test_move_target);
    } else {
        echo "❌ Falha na simulação de move!<br>";
    }
    
    unlink($temp_file);
    unlink($test_file);
    
} else {
    echo "❌ <strong>Falha!</strong> Não foi possível criar arquivo de teste!<br>";
    $error = error_get_last();
    echo "Erro: " . ($error['message'] ?? 'desconhecido') . "<br>";
}

// 6. Verificar mudanças no servidor
echo "<h3>🖥️ 6. Informações do Servidor</h3>";

echo "<strong>Usuário do processo PHP:</strong> " . (function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'desconhecido') . "<br>";
echo "<strong>Grupo do processo PHP:</strong> " . (function_exists('posix_getgrgid') ? posix_getgrgid(posix_getegid())['name'] : 'desconhecido') . "<br>";
echo "<strong>Umask atual:</strong> " . sprintf('%04o', umask()) . "<br>";
echo "<strong>Diretório temp:</strong> " . sys_get_temp_dir() . "<br>";
echo "<strong>Upload tmp dir:</strong> " . (ini_get('upload_tmp_dir') ?: 'padrão do sistema') . "<br>";

// 7. Verificar se mudou algo na configuração
echo "<h3>⚙️ 7. Configurações que Podem Ter Mudado</h3>";

$configs = [
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'post_max_size' => ini_get('post_max_size'),
    'file_uploads' => ini_get('file_uploads') ? 'Habilitado' : 'Desabilitado',
    'upload_tmp_dir' => ini_get('upload_tmp_dir') ?: 'padrão',
    'open_basedir' => ini_get('open_basedir') ?: 'não definido'
];

foreach ($configs as $key => $value) {
    echo "<strong>$key:</strong> $value<br>";
}

// 8. Verificar logs recentes
echo "<h3>📋 8. Logs de Erro Recentes</h3>";

$error_log = '/var/log/apache2/error.log';
if (file_exists($error_log) && is_readable($error_log)) {
    $recent_errors = shell_exec("tail -20 $error_log | grep -i 'upload\\|permission\\|denied' | tail -5");
    if ($recent_errors) {
        echo "<pre style='background: #f8f9fa; padding: 10px;'>$recent_errors</pre>";
    } else {
        echo "Nenhum erro relacionado a upload encontrado nos logs recentes.<br>";
    }
} else {
    echo "Log de erro do Apache não acessível.<br>";
}

echo "<hr>";
echo "<h3>🎯 Conclusão</h3>";
echo "Se todos os testes passaram mas o cadastro de produto ainda falha, o problema pode ser:<br>";
echo "• <strong>Timing:</strong> O diretório é recriado entre os testes<br>";
echo "• <strong>Contexto específico:</strong> Algo diferente quando executado via formulário<br>";
echo "• <strong>Mudança no código:</strong> Alguma alteração no cadastrar_produto.php<br>";
echo "• <strong>Permissões específicas:</strong> Apache vs linha de comando<br>";

?>