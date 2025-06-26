<?php
// gate.php - VERSÃO CORRIGIDA
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Se o usuário já passou pelo captcha, redireciona
if (isset($_SESSION['captcha_verified']) && $_SESSION['captcha_verified'] === true) {
    header('Location: index.php');
    exit();
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['captcha_code']) && isset($_SESSION['captcha_text'])) {
        if (strtolower(trim($_POST['captcha_code'])) === strtolower(trim($_SESSION['captcha_text']))) {
            // ✅ CAPTCHA correto - marcar como verificado
            $_SESSION['captcha_verified'] = true;
            $_SESSION['captcha_verified_time'] = time(); // Timestamp para debug
            
            // Limpar o captcha usado
            unset($_SESSION['captcha_text']);
            
            // ✅ DEBUG: Verificar se a sessão foi salva
            error_log("CAPTCHA verificado com sucesso. Session ID: " . session_id());
            error_log("Session data: " . json_encode($_SESSION));
            
            // Force session write
            session_write_close();
            
            // Redirecionar
            header('Location: index.php');
            exit();
        } else {
            $error = 'Código incorreto. Tente novamente.';
            error_log("CAPTCHA incorreto. Esperado: " . $_SESSION['captcha_text'] . ", Recebido: " . $_POST['captcha_code']);
        }
    } else {
        $error = 'Por favor, digite o código do captcha.';
    }
}
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Verificação de Segurança - Zee Market</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            min-height: 100vh; 
            background-color: #212529; 
        }
        .captcha-box { 
            background: #343a40; 
            padding: 40px; 
            border-radius: 15px; 
            text-align: center; 
            color: white; 
            max-width: 400px;
        }
        .captcha-img { 
            border: 2px solid #495057; 
            border-radius: 10px; 
            margin-bottom: 20px; 
            cursor: pointer;
        }
        .refresh-btn {
            background: none;
            border: none;
            color: #ffc107;
            text-decoration: underline;
            cursor: pointer;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="captcha-box">
        <h2 class="mb-3"> Verificação de Segurança</h2>
        <p class="text-muted">Digite os caracteres que você vê na imagem:</p>
        
        <div class="mb-3">
            <img src="includes/captcha.php?<?= time() ?>" 
                 alt="Código Captcha" 
                 class="captcha-img" 
                 onclick="this.src='includes/captcha.php?'+Math.random()" 
                 title="Clique para atualizar">
            <br>
            <button type="button" 
                    class="refresh-btn" 
                    onclick="document.querySelector('.captcha-img').src='includes/captcha.php?'+Math.random()">
                Gerar novo código
            </button>
        </div>
        
        <form method="POST">
            <div class="mb-3">
                <input type="text" 
                       name="captcha_code" 
                       class="form-control form-control-lg text-center" 
                       placeholder="Digite o código"
                       required 
                       autofocus
                       autocomplete="off">
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            
            <button type="submit" class="btn btn-primary w-100 btn-lg">
                Verificar e Entrar
            </button>
        </form>
        
        <!-- DEBUG INFO (remover em produção) -->
        <?php if (defined('DEBUG_MODE') && DEBUG_MODE): ?>
        <div class="mt-3" style="font-size: 0.8em; color: #6c757d;">
            <strong>Debug:</strong><br>
            Session ID: <?= session_id() ?><br>
            CAPTCHA verificado: <?= isset($_SESSION['captcha_verified']) ? ($_SESSION['captcha_verified'] ? 'SIM' : 'NÃO') : 'NÃO DEFINIDO' ?><br>
            Código atual: <?= $_SESSION['captcha_text'] ?? 'N/A' ?>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>