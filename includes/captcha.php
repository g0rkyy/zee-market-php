// includes/captcha.php
<?php
session_start();

class DarknetCaptcha {
    private $width = 200;
    private $height = 50;
    private $font = __DIR__.'/arial.ttf'; // Você precisa ter uma fonte TTF
    private $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Caracteres permitidos
    
    public function generate() {
        $image = imagecreatetruecolor($this->width, $this->height);
        $bg = imagecolorallocate($image, 0, 0, 0); // Fundo preto
        $textcolor = imagecolorallocate($image, 0, 255, 0); // Texto verde
        
        imagefill($image, 0, 0, $bg);
        
        // Gera código aleatório
        $code = '';
        for ($i = 0; $i < 6; $i++) {
            $code .= $this->chars[rand(0, strlen($this->chars)-1)];
        }
        
        $_SESSION['darknet_captcha'] = $code;
        
        // Adiciona distorções
        for ($i = 0; $i < strlen($code); $i++) {
            $angle = rand(-15, 15);
            $x = 20 + ($i * 30);
            $y = rand(30, 40);
            imagettftext($image, 20, $angle, $x, $y, $textcolor, $this->font, $code[$i]);
        }
        
        // Adiciona ruído
        for ($i = 0; $i < 50; $i++) {
            imagesetpixel($image, rand(0, $this->width), rand(0, $this->height), $textcolor);
        }
        
        header('Content-type: image/png');
        imagepng($image);
        imagedestroy($image);
    }
    
    public static function verify($input) {
        if (isset($_SESSION['darknet_captcha'])) {
            $result = strtolower($input) === strtolower($_SESSION['darknet_captcha']);
            unset($_SESSION['darknet_captcha']);
            return $result;
        }
        return false;
    }
}