<?php
/**
 * FORMULÁRIO PARA ENVIAR MENSAGENS CRIPTOGRAFADAS
 * Versão corrigida e modernizada
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'includes/config.php';
require_once 'includes/functions.php';

// ✅ VERIFICAR LOGIN COM FUNÇÃO CORRETA
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$publicKey = '';
$pgpAvailable = false;

// ✅ VERIFICAR PGP COM TRATAMENTO DE ERRO
try {
    if (file_exists('includes/simple_pgp.php')) {
        require_once 'includes/simple_pgp.php';
        if (class_exists('SimplePGP')) {
            $simplePGP = new SimplePGP($conn);
            $publicKey = $simplePGP->getPublicKey();
            $pgpAvailable = !empty($publicKey);
        }
    }
    
    // Fallback: buscar diretamente no banco
    if (!$pgpAvailable) {
        $stmt_pgp = $conn->prepare("SHOW TABLES LIKE 'site_pgp_keys'");
        $stmt_pgp->execute();
        if ($stmt_pgp->get_result()->num_rows > 0) {
            $stmt_key = $conn->prepare("SELECT public_key FROM site_pgp_keys WHERE site_name = 'zeemarket' LIMIT 1");
            $stmt_key->execute();
            $result = $stmt_key->get_result();
            if ($result->num_rows > 0) {
                $publicKey = $result->fetch_assoc()['public_key'];
                $pgpAvailable = !empty($publicKey);
            }
            $stmt_key->close();
        }
        $stmt_pgp->close();
    }
} catch (Exception $e) {
    error_log("Erro ao verificar PGP: " . $e->getMessage());
    $pgpAvailable = false;
    $publicKey = '';
}

// ✅ CHAVE PGP DE FALLBACK PARA DEMONSTRAÇÃO
if (!$pgpAvailable) {
    $publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGZ1234ABBAC1234567890abcdef... (Chave de demonstração)
Esta é uma chave PGP de exemplo para fins de demonstração.
Em produção, substitua por uma chave real gerada especificamente
para o ZeeMarket.

Para gerar uma chave real, use:
gpg --full-generate-key

-----END PGP PUBLIC KEY BLOCK-----";
    $pgpAvailable = true; // Para demonstração
}

// ✅ PROCESSAR FORMULÁRIO COM TRATAMENTO DE ERRO
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar CSRF
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $encryptedMessage = trim($_POST['encrypted_message'] ?? '');
        $messageType = $_POST['message_type'] ?? 'contact';
        
        if (empty($encryptedMessage)) {
            $error = "Mensagem criptografada não pode estar vazia";
        } elseif (strpos($encryptedMessage, '-----BEGIN PGP MESSAGE-----') === false) {
            $error = "Formato PGP inválido. Certifique-se de criptografar com nossa chave pública.";
        } else {
            try {
                // Simular processamento da mensagem
                if (isset($simplePGP) && method_exists($simplePGP, 'decryptMessage')) {
                    $result = $simplePGP->decryptMessage($encryptedMessage);
                    
                    if ($result['success']) {
                        // Salvar mensagem
                        $saveResult = $simplePGP->saveMessage($user_id, $encryptedMessage, $result['message'], $messageType);
                        
                        if ($saveResult['success']) {
                            $message = "✅ Mensagem recebida e descriptografada com sucesso! ID: #" . $saveResult['message_id'];
                        } else {
                            $error = "Erro ao salvar mensagem: " . $saveResult['error'];
                        }
                    } else {
                        $error = "Erro na descriptografia: " . $result['error'];
                    }
                } else {
                    // Fallback: salvar mensagem diretamente no banco
                    try {
                        // Verificar se tabela existe
                        $stmt_check = $conn->prepare("SHOW TABLES LIKE 'encrypted_messages'");
                        $stmt_check->execute();
                        if ($stmt_check->get_result()->num_rows === 0) {
                            // Criar tabela se não existir
                            $createTable = "CREATE TABLE IF NOT EXISTS encrypted_messages (
                                id INT AUTO_INCREMENT PRIMARY KEY,
                                user_id INT NOT NULL,
                                message_type VARCHAR(50) DEFAULT 'contact',
                                encrypted_content TEXT NOT NULL,
                                decrypted_content TEXT NULL,
                                status ENUM('pending', 'processed') DEFAULT 'pending',
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                INDEX idx_user_id (user_id),
                                INDEX idx_status (status)
                            )";
                            $conn->query($createTable);
                        }
                        $stmt_check->close();
                        
                        $stmt_save = $conn->prepare("INSERT INTO encrypted_messages (user_id, message_type, encrypted_content, status) VALUES (?, ?, ?, 'pending')");
                        $stmt_save->bind_param("iss", $user_id, $messageType, $encryptedMessage);
                        
                        if ($stmt_save->execute()) {
                            $messageId = $conn->insert_id;
                            $message = "✅ Mensagem criptografada recebida com sucesso! ID: #" . $messageId;
                        } else {
                            $error = "Erro ao salvar mensagem no banco de dados.";
                        }
                        $stmt_save->close();
                        
                    } catch (Exception $e) {
                        error_log("Erro ao salvar mensagem: " . $e->getMessage());
                        $error = "Erro interno ao processar mensagem.";
                    }
                }
            } catch (Exception $e) {
                error_log("Erro ao processar mensagem criptografada: " . $e->getMessage());
                $error = "Erro interno ao processar mensagem.";
            }
        }
    }
}

// ✅ GERAR TOKEN CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enviar Mensagem Criptografada - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {
            --primary: #8B5CF6;
            --primary-dark: #7C3AED;
            --primary-light: #A78BFA;
            --secondary: #10B981;
            --accent: #F59E0B;
            --danger: #EF4444;
            --warning: #F59E0B;
            --success: #10B981;
            --info: #3B82F6;
            
            --bg-primary: #0F0F0F;
            --bg-secondary: #1A1A1A;
            --bg-tertiary: #262626;
            --bg-quaternary: #333333;
            
            --text-primary: #FFFFFF;
            --text-secondary: #D1D5DB;
            --text-muted: #9CA3AF;
            --text-dim: #6B7280;
            
            --border: #374151;
            --border-light: #4B5563;
            
            --glass: rgba(255, 255, 255, 0.05);
            --glass-border: rgba(255, 255, 255, 0.1);
            
            --shadow-sm: 0 2px 4px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.5);
            --shadow-xl: 0 16px 48px rgba(0, 0, 0, 0.6);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, #1a1a2e 50%, var(--bg-primary) 100%);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .main-container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .glass-card {
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-lg);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .glass-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
        }
        
        .glass-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-xl);
            border-color: rgba(255,255,255,0.2);
        }
        
        .page-header {
            text-align: center;
            margin-bottom: 3rem;
        }
        
        .page-title {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }
        
        .page-subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
        }
        
        .nav-btn {
            position: fixed;
            top: 20px;
            left: 20px;
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 15px;
            padding: 0.75rem 1.25rem;
            color: var(--text-primary);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            z-index: 1000;
        }
        
        .nav-btn:hover {
            background: var(--primary);
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
            color: white;
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .code-display {
            background: #000;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.875rem;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            position: relative;
        }
        
        .code-display::before {
            content: 'PGP PUBLIC KEY';
            position: absolute;
            top: 8px;
            right: 12px;
            background: var(--primary);
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .form-control {
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            padding: 0.875rem 1rem;
            font-size: 0.925rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            background: rgba(255,255,255,0.08);
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1);
            color: var(--text-primary);
        }
        
        .form-control::placeholder {
            color: var(--text-muted);
        }
        
        .form-select {
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            padding: 0.875rem 1rem;
        }
        
        .form-select option {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .btn-modern {
            padding: 0.875rem 1.5rem;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.925rem;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            position: relative;
            overflow: hidden;
        }
        
        .btn-modern::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(255,255,255,0.2);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            transition: all 0.3s ease;
        }
        
        .btn-modern:hover::before {
            width: 200px;
            height: 200px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            color: white;
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.3);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success), #14B8A6);
            color: white;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, var(--warning), #FBBF24);
            color: white;
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
        }
        
        .btn-info {
            background: linear-gradient(135deg, var(--info), #60A5FA);
            color: white;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .btn-outline {
            background: transparent;
            border: 1px solid var(--glass-border);
            color: var(--text-primary);
        }
        
        .btn-modern:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
            color: white;
        }
        
        .alert {
            border: none;
            border-radius: 16px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
            border-color: var(--success);
        }
        
        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border-color: var(--danger);
        }
        
        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
            border-color: var(--warning);
        }
        
        .alert-info {
            background: rgba(59, 130, 246, 0.1);
            color: var(--info);
            border-color: var(--info);
        }
        
        .step-list {
            counter-reset: step-counter;
        }
        
        .step-list li {
            counter-increment: step-counter;
            padding: 0.75rem 0;
            padding-left: 3rem;
            position: relative;
            border-left: 2px solid rgba(255,255,255,0.1);
            margin-left: 1rem;
        }
        
        .step-list li::before {
            content: counter(step-counter);
            position: absolute;
            left: -1.25rem;
            top: 0.75rem;
            background: var(--primary);
            color: white;
            width: 2rem;
            height: 2rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.875rem;
        }
        
        .terminal-block {
            background: #000;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            margin: 1rem 0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            position: relative;
        }
        
        .terminal-block::before {
            content: '$ ';
            color: var(--success);
            font-weight: bold;
        }
        
        .copy-btn {
            position: absolute;
            top: 8px;
            right: 8px;
            background: rgba(255,255,255,0.1);
            border: none;
            border-radius: 6px;
            color: var(--text-muted);
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .copy-btn:hover {
            background: var(--primary);
            color: white;
        }
        
        .software-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        
        .software-card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }
        
        .software-icon {
            font-size: 2rem;
            margin-bottom: 1rem;
        }
        
        @media (max-width: 768px) {
            .main-container {
                padding: 1rem;
            }
            
            .page-title {
                font-size: 2rem;
            }
            
            .software-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Animação de digitação */
        .typing-effect {
            overflow: hidden;
            border-right: 2px solid var(--primary);
            white-space: nowrap;
            animation: typing 3s steps(40) 1s both, blink 1s infinite;
        }
        
        @keyframes typing {
            from { width: 0; }
            to { width: 100%; }
        }
        
        @keyframes blink {
            50% { border-color: transparent; }
        }
    </style>
</head>
<body>
    <a href="privacy_settings.php" class="nav-btn">
        <i class="bi bi-arrow-left"></i> Voltar às Configurações
    </a>

    <div class="main-container">
        <div class="page-header">
            <h1 class="page-title">
                <i class="bi bi-envelope-lock"></i> Enviar Mensagem Criptografada
            </h1>
            <p class="page-subtitle typing-effect">Comunicação segura e privada com criptografia PGP</p>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <i class="bi bi-check-circle"></i> <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <!-- Nossa Chave Pública -->
        <div class="glass-card">
            <h3 class="section-title">
                <i class="bi bi-key"></i> Nossa Chave Pública PGP
            </h3>
            <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                Use esta chave para criptografar sua mensagem antes de enviar:
            </p>
            
            <div class="code-display" id="pgpKeyText">
                <button class="copy-btn" onclick="copyPublicKey()" title="Copiar chave">
                    <i class="bi bi-copy"></i>
                </button>
                <?= htmlspecialchars($publicKey, ENT_QUOTES, 'UTF-8') ?>
            </div>
            
            <div style="margin-top: 1rem; text-align: center;">
                <button class="btn-modern btn-primary" onclick="copyPublicKey()">
                    <i class="bi bi-copy"></i> Copiar Chave Pública
                </button>
            </div>
        </div>

        <!-- Instruções -->
        <div class="glass-card">
            <h3 class="section-title">
                <i class="bi bi-info-circle"></i> Como Criptografar Sua Mensagem
            </h3>
            
            <ol class="step-list" style="color: var(--text-secondary);">
                <li>Copie nossa chave pública acima</li>
                <li>Use um software PGP (GPG, Kleopatra, Thunderbird + Enigmail)</li>
                <li>Importe nossa chave pública no seu software</li>
                <li>Criptografe sua mensagem usando nossa chave</li>
                <li>Cole o resultado no formulário abaixo</li>
            </ol>
        </div>

        <!-- Formulário -->
        <div class="glass-card">
            <h3 class="section-title">
                <i class="bi bi-send"></i> Enviar Mensagem Segura
            </h3>
            
            <form method="POST" id="encryptedForm">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                
                <div class="mb-3">
                    <label for="message_type" class="form-label">
                        <i class="bi bi-tag"></i> Tipo de mensagem:
                    </label>
                    <select name="message_type" id="message_type" class="form-select">
                        <option value="contact">Contato Geral</option>
                        <option value="support">Suporte Técnico</option>
                        <option value="complaint">Reclamação</option>
                        <option value="suggestion">Sugestão</option>
                        <option value="order_issue">Problema com Pedido</option>
                        <option value="security">Questão de Segurança</option>
                        <option value="partnership">Parceria/Negócios</option>
                    </select>
                </div>
                
                <div class="mb-3">
                    <label for="encrypted_message" class="form-label">
                        <i class="bi bi-lock"></i> Sua mensagem criptografada:
                    </label>
                    <textarea name="encrypted_message" id="encrypted_message" class="form-control" 
                              rows="12" placeholder="Cole aqui sua mensagem criptografada com nossa chave pública...

Deve começar com: -----BEGIN PGP MESSAGE-----
E terminar com: -----END PGP MESSAGE-----

Exemplo:
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

hQIMA1234567890abcDEF...
[conteúdo criptografado]
...xyz789
-----END PGP MESSAGE-----" required></textarea>
                    <small style="color: var(--text-muted); display: block; margin-top: 0.5rem;">
                        <i class="bi bi-shield-check"></i> A mensagem deve estar no formato PGP válido
                    </small>
                </div>
                
                <div style="text-align: center;">
                    <button type="submit" class="btn-modern btn-success" style="min-width: 200px;">
                        <i class="bi bi-send"></i> Enviar Mensagem Segura
                    </button>
                </div>
            </form>
        </div>

        <!-- Software Recomendado -->
        <div class="glass-card">
            <h3 class="section-title">
                <i class="bi bi-download"></i> Software PGP Recomendado
            </h3>
            
            <div class="software-grid">
                <div class="software-card">
                    <div class="software-icon">🖥️</div>
                    <h5>Desktop</h5>
                    <ul style="text-align: left; color: var(--text-secondary);">
                        <li><strong>Windows:</strong> Kleopatra (GPG4Win)</li>
                        <li><strong>macOS:</strong> GPG Suite</li>
                        <li><strong>Linux:</strong> GnuPG</li>
                    </ul>
                </div>
                
                <div class="software-card">
                    <div class="software-icon">📧</div>
                    <h5>Email</h5>
                    <ul style="text-align: left; color: var(--text-secondary);">
                        <li><strong>Thunderbird:</strong> + Enigmail</li>
                        <li><strong>Outlook:</strong> + Gpg4win</li>
                        <li><strong>Web:</strong> Mailvelope</li>
                    </ul>
                </div>
                
                <div class="software-card">
                    <div class="software-icon">📱</div>
                    <h5>Mobile</h5>
                    <ul style="text-align: left; color: var(--text-secondary);">
                        <li><strong>Android:</strong> OpenKeychain</li>
                        <li><strong>iOS:</strong> PGP Everywhere</li>
                        <li><strong>Web:</strong> ProtonMail</li>
                    </ul>
                </div>
            </div>
            
            <div class="alert alert-warning" style="margin-top: 2rem;">
                <i class="bi bi-exclamation-triangle"></i>
                <strong>Importante:</strong> Sempre verifique se você está criptografando com nossa chave pública correta!
            </div>
        </div>

        <!-- Exemplo Terminal -->
        <div class="glass-card">
            <h3 class="section-title">
                <i class="bi bi-terminal"></i> Exemplo via Terminal (Linux/macOS)
            </h3>
            
            <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                Para usuários avançados que preferem linha de comando:
            </p>
            
            <h6>1. Salvar nossa chave pública:</h6>
            <div class="terminal-block">echo "-----BEGIN PGP PUBLIC KEY BLOCK-----
[nossa chave aqui]
-----END PGP PUBLIC KEY BLOCK-----" > zeemarket_pubkey.asc</div>
            
            <h6>2. Importar a chave:</h6>
            <div class="terminal-block">gpg --import zeemarket_pubkey.asc</div>
            
            <h6>3. Criptografar mensagem:</h6>
            <div class="terminal-block"># Criar arquivo com sua mensagem
echo "Sua mensagem secreta aqui" > mensagem.txt

# Criptografar
gpg --armor --encrypt --recipient "admin@zeemarket.onion" mensagem.txt

# Resultado estará em mensagem.txt.asc</div>
            
            <h6>4. Copiar resultado:</h6>
            <div class="terminal-block">cat mensagem.txt.asc</div>
        </div>

        <!-- Navegação -->
        <div style="text-align: center; margin-top: 3rem;">
            <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                <a href="privacy_settings.php" class="btn-modern btn-outline">
                    <i class="bi bi-arrow-left"></i> Voltar às Configurações
                </a>
                <a href="dashboard.php" class="btn-modern btn-info">
                    <i class="bi bi-house"></i> Dashboard
                </a>
                <a href="https://gnupg.org/download/" target="_blank" class="btn-modern btn-warning">
                    <i class="bi bi-download"></i> Baixar GnuPG
                </a>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ✅ FUNÇÃO SEGURA PARA COPIAR CHAVE PÚBLICA
        function copyPublicKey() {
            const keyText = <?= json_encode($publicKey, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
            
            navigator.clipboard.writeText(keyText).then(() => {
                showAlert('success', 'Chave pública copiada para a área de transferência!');
            }).catch(() => {
                // Fallback para navegadores antigos
                try {
                    const textarea = document.createElement('textarea');
                    textarea.value = keyText;
                    textarea.style.position = 'fixed';
                    textarea.style.opacity = '0';
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    showAlert('success', 'Chave pública copiada!');
                } catch (err) {
                    showAlert('error', 'Erro ao copiar. Por favor, selecione e copie manualmente.');
                }
            });
        }

        // ✅ FUNÇÃO PARA MOSTRAR ALERTAS
        function showAlert(type, message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
            alertDiv.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
                min-width: 300px;
                max-width: 400px;
            `;
            alertDiv.innerHTML = `
                <i class="bi bi-${type === 'error' ? 'exclamation-triangle' : 'check-circle'}"></i> 
                ${message.replace(/[<>]/g, '')}
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            `;
            
            document.body.appendChild(alertDiv);
            
            // Auto-remover após 5 segundos
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    const bsAlert = bootstrap.Alert.getInstance(alertDiv);
                    if (bsAlert) {
                        bsAlert.close();
                    } else {
                        alertDiv.remove();
                    }
                }
            }, 5000);
        }

        // ✅ VALIDAÇÃO ROBUSTA DO FORMULÁRIO
        document.getElementById('encryptedForm').addEventListener('submit', function(e) {
            const message = document.getElementById('encrypted_message').value.trim();
            
            // Verificações de formato PGP
            if (!message) {
                e.preventDefault();
                showAlert('error', 'Por favor, cole sua mensagem criptografada.');
                return false;
            }
            
            if (!message.startsWith('-----BEGIN PGP MESSAGE-----')) {
                e.preventDefault();
                showAlert('error', 'Erro: A mensagem deve estar no formato PGP válido!\n\nVerifique se você criptografou corretamente com nossa chave pública.');
                return false;
            }
            
            if (!message.endsWith('-----END PGP MESSAGE-----')) {
                e.preventDefault();
                showAlert('error', 'Erro: Mensagem PGP incompleta!\n\nCertifique-se de copiar a mensagem completa.');
                return false;
            }
            
            // Verificar se não é uma chave pública por engano
            if (message.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
                e.preventDefault();
                showAlert('error', 'Erro: Você colou uma chave pública!\n\nVocê deve colar uma MENSAGEM criptografada, não uma chave.');
                return false;
            }
            
            // Verificar se não é uma chave privada por engano
            if (message.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----')) {
                e.preventDefault();
                showAlert('error', '⚠️ PERIGO: Nunca compartilhe sua chave privada!\n\nVocê deve colar uma MENSAGEM criptografada.');
                return false;
            }
            
            // Verificar tamanho mínimo razoável
            if (message.length < 100) {
                e.preventDefault();
                showAlert('error', 'A mensagem parece muito curta para ser uma mensagem PGP válida.');
                return false;
            }
            
            // Confirmação final
            const confirmed = confirm('✅ Enviar mensagem criptografada?\n\n' +
                'Verifique se você:\n' +
                '• Criptografou com nossa chave pública\n' +
                '• Copiou a mensagem completa\n' +
                '• Não incluiu informações pessoais não criptografadas\n\n' +
                'Continuar?');
                
            if (!confirmed) {
                e.preventDefault();
                return false;
            }
            
            // Mostrar loading
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processando...';
            submitBtn.disabled = true;
            
            // Restaurar botão se houver erro (o sucesso redirecionará)
            setTimeout(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }, 10000);
        });

        // ✅ VALIDAÇÃO EM TEMPO REAL
        document.getElementById('encrypted_message').addEventListener('input', function() {
            const message = this.value.trim();
            const messageType = document.getElementById('message_type');
            
            // Feedback visual
            if (message.length > 0) {
                if (message.startsWith('-----BEGIN PGP MESSAGE-----')) {
                    this.style.borderColor = 'var(--success)';
                    this.style.boxShadow = '0 0 0 3px rgba(16, 185, 129, 0.1)';
                } else {
                    this.style.borderColor = 'var(--warning)';
                    this.style.boxShadow = '0 0 0 3px rgba(245, 158, 11, 0.1)';
                }
            } else {
                this.style.borderColor = 'var(--border)';
                this.style.boxShadow = 'none';
            }
            
            // Auto-detectar tipo de mensagem baseado no conteúdo
            if (message.includes('suporte') || message.includes('help') || message.includes('problema')) {
                messageType.value = 'support';
            } else if (message.includes('reclamação') || message.includes('complaint')) {
                messageType.value = 'complaint';
            } else if (message.includes('sugestão') || message.includes('suggestion')) {
                messageType.value = 'suggestion';
            }
        });

        // ✅ CONTADOR DE CARACTERES
        document.getElementById('encrypted_message').addEventListener('input', function() {
            const charCount = this.value.length;
            let countDisplay = document.getElementById('charCount');
            
            if (!countDisplay) {
                countDisplay = document.createElement('small');
                countDisplay.id = 'charCount';
                countDisplay.style.cssText = 'position: absolute; bottom: 8px; right: 12px; color: var(--text-muted); background: var(--bg-secondary); padding: 2px 6px; border-radius: 4px; font-size: 0.75rem;';
                this.parentNode.style.position = 'relative';
                this.parentNode.appendChild(countDisplay);
            }
            
            countDisplay.textContent = `${charCount} caracteres`;
            
            if (charCount < 100) {
                countDisplay.style.color = 'var(--warning)';
            } else if (charCount > 500) {
                countDisplay.style.color = 'var(--success)';
            } else {
                countDisplay.style.color = 'var(--text-muted)';
            }
        });

        // ✅ DICAS CONTEXTUAIS
        function showContextualTips() {
            const messageField = document.getElementById('encrypted_message');
            const currentValue = messageField.value.trim();
            
            if (currentValue.length === 0) {
                showAlert('info', '💡 Dica: Primeiro copie nossa chave pública e importe no seu software PGP.');
            } else if (!currentValue.startsWith('-----BEGIN PGP MESSAGE-----')) {
                showAlert('warning', '⚠️ A mensagem deve começar com "-----BEGIN PGP MESSAGE-----"');
            }
        }

        // ✅ INICIALIZAÇÃO
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-focar no campo de mensagem após 2 segundos
            setTimeout(() => {
                document.getElementById('encrypted_message').focus();
            }, 2000);

            // Auto-fechar alertas
            setTimeout(() => {
                document.querySelectorAll('.alert').forEach(alert => {
                    const bsAlert = bootstrap.Alert.getInstance(alert);
                    if (bsAlert) {
                        bsAlert.close();
                    }
                });
            }, 5000);

            // Mostrar dica inicial
            setTimeout(showContextualTips, 3000);

            console.log('✅ Send Encrypted Message carregado com sucesso!');
        });

        // ✅ ATALHOS DE TECLADO
        document.addEventListener('keydown', function(e) {
            // Ctrl+Enter para enviar formulário
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                document.getElementById('encryptedForm').dispatchEvent(new Event('submit'));
            }
            
            // Ctrl+K para copiar chave pública
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                copyPublicKey();
            }
        });

        // ✅ DETECÇÃO DE PASTE DE CHAVE ERRADA
        document.getElementById('encrypted_message').addEventListener('paste', function(e) {
            setTimeout(() => {
                const pastedText = this.value;
                
                if (pastedText.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
                    showAlert('error', '❌ Você colou uma chave pública!\n\nVocê deve colar uma MENSAGEM criptografada.');
                    this.value = '';
                } else if (pastedText.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----')) {
                    showAlert('error', '🚨 PERIGO! Nunca compartilhe sua chave privada!');
                    this.value = '';
                }
            }, 100);
        });

        // ✅ PREVIEW DO FORMATO PGP
        function showPGPPreview() {
            const exampleMessage = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

hQIMA+1234567890abcDEF...
[conteúdo criptografado aqui]
...xyz789END_OF_MESSAGE
-----END PGP MESSAGE-----`;

            showAlert('info', `Exemplo de formato correto:\n\n${exampleMessage.substring(0, 100)}...`);
        }
    </script>
</body>
</html>