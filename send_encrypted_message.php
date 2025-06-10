<?php
/**
 * FORMULÁRIO PARA ENVIAR MENSAGENS CRIPTOGRAFADAS
 * Salve como: send_encrypted_message.php
 */

require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/simple_pgp.php';

verificarLogin();

$user_id = $_SESSION['user_id'];
$publicKey = $simplePGP->getPublicKey();

// Processar formulário
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $encryptedMessage = trim($_POST['encrypted_message'] ?? '');
    $messageType = $_POST['message_type'] ?? 'contact';
    
    if (empty($encryptedMessage)) {
        $error = "Mensagem criptografada não pode estar vazia";
    } elseif (strpos($encryptedMessage, '-----BEGIN PGP MESSAGE-----') === false) {
        $error = "Formato PGP inválido. Certifique-se de criptografar com nossa chave pública.";
    } else {
        // Tentar descriptografar
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
    }
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enviar Mensagem Criptografada - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: #1a1a1a; color: #e0e0e0; }
        .card { background: #2d2d2d; border: 1px solid #444; }
        .card-header { background: #333; border-bottom: 1px solid #444; }
        .code-display {
            background: #000;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <?php if (file_exists('includes/header.php')) include 'includes/header.php'; ?>
    
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8 mx-auto">
                <div class="card">
                    <div class="card-header">
                        <h4><i class="fas fa-lock"></i> Enviar Mensagem Criptografada</h4>
                    </div>
                    <div class="card-body">
                        
                        <?php if ($message): ?>
                            <div class="alert alert-success">
                                <?= htmlspecialchars($message) ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($error): ?>
                            <div class="alert alert-danger">
                                <?= htmlspecialchars($error) ?>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Nossa Chave Pública -->
                        <div class="mb-4">
                            <h5><i class="fas fa-key"></i> Nossa Chave Pública PGP</h5>
                            <p class="text-muted">Use esta chave para criptografar sua mensagem:</p>
                            
                            <div class="code-display mb-2">
                                <?= htmlspecialchars($publicKey) ?>
                            </div>
                            
                            <button class="btn btn-sm btn-outline-primary" onclick="copyPublicKey()">
                                <i class="fas fa-copy"></i> Copiar Chave Pública
                            </button>
                        </div>
                        
                        <!-- Instruções -->
                        <div class="alert alert-info mb-4">
                            <h6><i class="fas fa-info-circle"></i> Como criptografar sua mensagem:</h6>
                            <ol class="mb-0">
                                <li>Copie nossa chave pública acima</li>
                                <li>Use um software PGP (GPG, Kleopatra, Thunderbird + Enigmail)</li>
                                <li>Importe nossa chave pública</li>
                                <li>Criptografe sua mensagem com nossa chave</li>
                                <li>Cole o resultado no formulário abaixo</li>
                            </ol>
                        </div>
                        
                        <!-- Formulário -->
                        <form method="POST">
                            <div class="mb-3">
                                <label for="message_type" class="form-label">Tipo de mensagem:</label>
                                <select name="message_type" id="message_type" class="form-select">
                                    <option value="contact">Contato Geral</option>
                                    <option value="support">Suporte Técnico</option>
                                    <option value="complaint">Reclamação</option>
                                    <option value="suggestion">Sugestão</option>
                                    <option value="order_issue">Problema com Pedido</option>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label for="encrypted_message" class="form-label">Sua mensagem criptografada:</label>
                                <textarea name="encrypted_message" id="encrypted_message" class="form-control" 
                                          rows="12" placeholder="Cole aqui sua mensagem criptografada com nossa chave pública...
Deve começar com: -----BEGIN PGP MESSAGE-----
E terminar com: -----END PGP MESSAGE-----" required></textarea>
                                <small class="text-muted">
                                    A mensagem deve estar no formato PGP válido
                                </small>
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-success btn-lg">
                                    <i class="fas fa-paper-plane"></i> Enviar Mensagem Segura
                                </button>
                            </div>
                        </form>
                        
                        <!-- Links úteis -->
                        <div class="mt-4 text-center">
                            <a href="privacy_settings.php" class="btn btn-outline-light me-2">
                                <i class="fas fa-arrow-left"></i> Voltar às Configurações
                            </a>
                            <a href="index.php" class="btn btn-outline-secondary">
                                <i class="fas fa-home"></i> Dashboard
                            </a>
                        </div>
                    </div>
                </div>
                
                <!-- Exemplos de Software PGP -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5><i class="fas fa-download"></i> Software PGP Recomendado</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>🖥️ Desktop:</h6>
                                <ul>
                                    <li><strong>Windows:</strong> Kleopatra (GPG4Win)</li>
                                    <li><strong>macOS:</strong> GPG Suite</li>
                                    <li><strong>Linux:</strong> GnuPG (terminal)</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6>📧 Email:</h6>
                                <ul>
                                    <li><strong>Thunderbird:</strong> + Enigmail</li>
                                    <li><strong>Outlook:</strong> + Gpg4win</li>
                                    <li><strong>Web:</strong> Mailvelope (extensão)</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="alert alert-warning mt-3">
                            <i class="fas fa-exclamation-triangle"></i>
                            <strong>Importante:</strong> Sempre verifique se você está criptografando com nossa chave pública correta!
                        </div>
                    </div>
                </div>
                
                <!-- Exemplo de uso via terminal -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5><i class="fas fa-terminal"></i> Exemplo via Terminal (Linux/macOS)</h5>
                    </div>
                    <div class="card-body">
                        <p>Para usuários avançados que preferem linha de comando:</p>
                        
                        <h6>1. Salvar nossa chave pública:</h6>
                        <pre class="bg-dark p-2 rounded"><code># Salvar chave em arquivo
echo "-----BEGIN PGP PUBLIC KEY BLOCK-----
[nossa chave aqui]
-----END PGP PUBLIC KEY BLOCK-----" > zeemarket_pubkey.asc</code></pre>
                        
                        <h6>2. Importar a chave:</h6>
                        <pre class="bg-dark p-2 rounded"><code>gpg --import zeemarket_pubkey.asc</code></pre>
                        
                        <h6>3. Criptografar mensagem:</h6>
                        <pre class="bg-dark p-2 rounded"><code># Criar arquivo com sua mensagem
echo "Sua mensagem secreta aqui" > mensagem.txt

# Criptografar
gpg --armor --encrypt --recipient "admin@zeemarket.onion" mensagem.txt

# Resultado estará em mensagem.txt.asc</code></pre>
                        
                        <h6>4. Copiar resultado:</h6>
                        <pre class="bg-dark p-2 rounded"><code>cat mensagem.txt.asc</code></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
    function copyPublicKey() {
        const keyText = `<?= str_replace(["\r", "\n"], ["", "\\n"], htmlspecialchars($publicKey)) ?>`.replace(/\\n/g, '\n');
        
        navigator.clipboard.writeText(keyText).then(() => {
            alert('✅ Chave pública copiada para a área de transferência!');
        }).catch(() => {
            // Fallback para navegadores antigos
            const textarea = document.createElement('textarea');
            textarea.value = keyText;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert('✅ Chave pública copiada!');
        });
    }
    
    // Validação do formulário
    document.querySelector('form').addEventListener('submit', function(e) {
        const message = document.getElementById('encrypted_message').value.trim();
        
        if (!message.includes('-----BEGIN PGP MESSAGE-----')) {
            e.preventDefault();
            alert('❌ Erro: A mensagem deve estar no formato PGP válido!\n\nVerifique se você criptografou corretamente com nossa chave pública.');
            return false;
        }
        
        if (!message.includes('-----END PGP MESSAGE-----')) {
            e.preventDefault();
            alert('❌ Erro: Mensagem PGP incompleta!\n\nCertifique-se de copiar a mensagem completa.');
            return false;
        }
        
        // Confirmação
        if (!confirm('✅ Enviar mensagem criptografada?\n\nVerifique se você criptografou com nossa chave pública.')) {
            e.preventDefault();
            return false;
        }
    });
    </script>
</body>
</html>