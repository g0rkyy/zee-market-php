<?php
// CAPTCHA SCRIPT BLINDADO - V2.1 - by Blackcat
// Inclui log de erros detalhado para diagnóstico final.

// Inicia o buffer de saída para capturar qualquer erro antes da saída da imagem.
ob_start();

// Configuração de erros para diagnóstico
error_reporting(E_ALL);
ini_set('display_errors', 0); // Crucial: nunca mostrar erros ao usuário.

// Iniciar sessão de forma segura, apenas se não houver uma ativa.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$log_path = __DIR__ . '/logs/captcha_errors.log';

try {
    // Definições
    $width = 200;
    $height = 50;
    $font = __DIR__ . '/arial.ttf';
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $code = '';

    // Verificações de pré-requisitos antes de qualquer coisa
    if (!function_exists('imagecreatetruecolor')) {
        throw new Exception('A biblioteca GD para PHP (php-gd) não está funcionando ou não foi encontrada.');
    }
    if (!is_readable($font)) {
        throw new Exception('Não consigo ler o arquivo de fonte. Verifique o caminho e as permissões: ' . $font);
    }

    // Geração do código aleatório
    for ($i = 0; $i < 6; $i++) {
        $code .= $chars[random_int(0, strlen($chars) - 1)];
    }
    $_SESSION['captcha_text'] = $code;

    // Criação da Imagem
    $image = @imagecreatetruecolor($width, $height);
    if (!$image) throw new Exception('imagecreatetruecolor() falhou.');

    
    $bg_color = imagecolorallocate($image, 10, 10, 10);
    $text_color = imagecolorallocate($image, 150, 255, 150);
    $noise_color = imagecolorallocate($image, 50, 50, 50);

    imagefill($image, 0, 0, $bg_color);

    // Desenha o texto na imagem
    for ($i = 0; $i < strlen($code); $i++) {
        $angle = random_int(-15, 15);
        $x = 20 + ($i * 30);
        $y = 35 + random_int(-5, 5);
        @imagettftext($image, 20, $angle, $x, $y, $text_color, $font, $code[$i]);
    }

    // Adiciona ruído
    for ($i = 0; $i < 10; $i++) {
        @imageline($image, 0, random_int(0, $height), $width, random_int(0, $height), $noise_color);
    }

    // Limpa qualquer saída de texto indesejada (avisos, etc.) que possa ter sido capturada.
    ob_end_clean();

    // Envia a imagem para o navegador
    header('Content-Type: image/png');
    imagepng($image);
    imagedestroy($image);
    exit();

} catch (Throwable $t) {
    // Se qualquer erro (Exception ou Error) ocorrer, ele será capturado aqui.
    ob_end_clean(); // Limpa o buffer para garantir que possamos registrar o erro.
    $error_message = date('[Y-m-d H:i:s] ') . "CAPTCHA FATAL ERROR: " . $t->getMessage() . " in " . $t->getFile() . " on line " . $t->getLine();
    file_put_contents($log_path, $error_message . "\n", FILE_APPEND);
    
    // Cria uma imagem de erro vermelha para indicar visualmente a falha.
    $error_image = imagecreatetruecolor(200, 50);
    $bg_error = imagecolorallocate($error_image, 255, 0, 0);
    imagefill($error_image, 0, 0, $bg_error);
    imagestring($error_image, 5, 5, 15, "ERROR", imagecolorallocate($error_image, 255, 255, 255));
    header('Content-Type: image/png');
    imagepng($error_image);
    imagedestroy($error_image);
    exit();
}
