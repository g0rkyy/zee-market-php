<?php
/**
 * 🔐 PÁGINA DE CONTATO PGP - ZEEMARKET
 * Para comunicação criptografada com administradores
 */

require_once 'includes/config.php';
require_once 'includes/functions.php';

// Verificar se sistema PGP está configurado
$pgpConfigured = false;
$sitePublicKey = '';

try {
    // Verificar se existe chave pública do site
    $stmt = $conn->prepare("SELECT public_key FROM site_pgp_keys WHERE site_name = 'zeemarket'");
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    if ($result) {
        $pgpConfigured = true;
        $sitePublicKey = $result['public_key'];
    }
} catch (Exception $e) {
    error_log("Erro ao verificar PGP: " . $e->getMessage());
}

// Detectar Tor para bonus de segurança
$torDetection = checkTorConnection();
$isTorUser = $torDetection['connected'];
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contato PGP Seguro - ZeeMarket</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
    <style>
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #2d2d30 100%);
            color: #e0e0e0;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
        }
        
        .pgp-container {
            margin-top: 2rem;
            margin-bottom: 2rem;
        }
        
        .pgp-card {
            background: rgba(20, 20, 20, 0.95);
            border: 1px solid #333;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 15px 35px rgba(0, 255, 0, 0.1);
        }
        
        .pgp-header {
            background: linear-gradient(135deg, #1b5e20, #2e7d32);
            color: white;
            border-radius: 15px 15px 0 0;
            padding: 2rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .pgp-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 30%, rgba(0, 255, 0, 0.1) 50%, transparent 70%);
            animation: scan 3s linear infinite;
        }
        
        @keyframes scan {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .pgp-body {
            padding: 2rem;
        }
        
        .key-display {
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
            word-break: break-all;
            position: relative;
        }
        
        .key-display::before {
            content: '📁 pgp_public_key.asc';
            display: block;
            color: #00ff00;
            font-weight: bold;
            margin-bottom: 10px;
            border-bottom: 1px solid #333;
            padding-bottom: 5px;
        }
        
        .form-control {
            background: rgba(10, 10, 10, 0.8);
            border: 1px solid #333;
            color: #e0e0e0;
            border-radius: 8px;
        }
        
        .form-control:focus {
            background: rgba(20, 20, 20, 0.9);
            border-color: #00ff00;
            box-shadow: 0 0 0 0.2rem rgba(0, 255, 0, 0.25);
            color: #e0e0e0;
        }
        
        .form-control::placeholder {
            color: #888;
        }
        
        .btn-matrix {
            background: linear-gradient(135deg, #1b5e20, #2e7d32);
            border: 1px solid #00ff00;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .btn-matrix:hover {
            background: linear-gradient(135deg, #2e7d32, #388e3c);
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            color: white;
        }
        
        .btn-matrix::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn-matrix:hover::before {
            left: 100%;
        }
        
        .alert-darkweb {
            background: rgba(0, 20, 0, 0.8);
            border: 1px solid #00ff00;
            color: #00ff00;
            border-radius: 8px;
        }
        
        .alert-warning-darkweb {
            background: rgba(20, 20, 0, 0.8);
            border: 1px solid #ffaa00;
            color: #ffaa00;
            border-radius: 8px;
        }
        
        .tor-status {
            position: fixed;
            top: 20px;
            right: 20px;
            background: <?= $isTorUser ? 'rgba(0, 100, 0, 0.9)' : 'rgba(100, 0, 0, 0.9)' ?>;
            color: white;
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            z-index: 1000;
            border: 1px solid <?= $isTorUser ? '#00ff00' : '#ff0000' ?>;
        }
        
        .matrix-text {
            color: #00ff00;
            text-shadow: 0 0 5px #00ff00;
        }
        
        .copy-button {
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 5px 10px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.7rem;
        }
        
        .copy-button:hover {
            background: rgba(0, 255, 0, 0.2);
        }
        
        .instructions-step {
            background: rgba(0, 50, 0, 0.3);
            border-left: 4px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 8px 8px 0;
        }
        
        .terminal {
            background: #000;
            color: #00ff00;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            border: 1px solid #333;
            position: relative;
        }
        
        .terminal::before {
            content: '> zeemarket@darkweb:~$ ';
            color: #ffaa00;
            font-weight: bold;
        }
        
        .navbar {
            background: rgba(0, 0, 0, 0.9) !important;
            border-bottom: 1px solid #333;
        }
    </style>
</head>
<body>
    <!-- Status Tor -->
    <div class="tor-status">
        <?php if ($isTorUser): ?>
            🟢 Tor Ativo (<?= $torDetection['confidence'] ?>%)
        <?php else: ?>
            🔴 Tor Inativo - Use Tor Browser para máxima segurança
        <?php endif; ?>
    </div>

    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand matrix-text" href="index.php">
                <i class="fas fa-shield-alt"></i> ZeeMarket
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="index.php">
                    <i class="fas fa-home"></i> Home
                </a>
                <a class="nav-link" href="login.php">
                    <i class="fas fa-sign-in-alt"></i> Login
                </a>
            </div>
        </div>
    </nav>

    <div class="container pgp-container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="pgp-card">
                    <div class="pgp-header">
                        <h1><i class="fas fa-key"></i> Comunicação PGP Criptografada</h1>
                        <p class="mb-0">Envie mensagens totalmente seguras para a administração</p>
                    </div>
                    
                    <div class="pgp-body">
                        <?php if (!$pgpConfigured): ?>
                            <div class="alert alert-warning-darkweb">
                                <h5><i class="fas fa-exclamation-triangle"></i> Sistema PGP Não Configurado</h5>
                                <p>As chaves PGP do servidor ainda não foram geradas. Entre em contato com o administrador.</p>
                            </div>
                        <?php else: ?>
                            <!-- Chave Pública do Site -->
                            <div class="mb-4">
                                <h3 class="matrix-text">
                                    <i class="fas fa-download"></i> Nossa Chave Pública PGP
                                </h3>
                                <p class="text-muted">Copie esta chave e importe no seu software PGP para criptografar mensagens:</p>
                                
                                <div class="key-display" id="publicKeyDisplay">
                                    <button class="copy-button" onclick="copyPublicKey()">
                                        <i class="fas fa-copy"></i> Copiar
                                    </button>
                                    <?= htmlspecialchars($sitePublicKey) ?>
                                </div>
                            </div>

                            <!-- Instruções Detalhadas -->
                            <div class="mb-4">
                                <h3 class="matrix-text">
                                    <i class="fas fa-terminal"></i> Como Usar PGP
                                </h3>
                                
                                <div class="instructions-step">
                                    <h6><strong>1. Instalar Software PGP</strong></h6>
                                    <p><strong>Windows:</strong> Kleopatra (gpg4win)</p>
                                    <p><strong>Linux:</strong> GnuPG (já instalado na maioria)</p>
                                    <p><strong>macOS:</strong> GPG Suite</p>
                                    
                                    <div class="terminal">
                                        # Linux - instalar GPG se necessário
                                        sudo apt install gnupg
                                    </div>
                                </div>

                                <div class="instructions-step">
                                    <h6><strong>2. Importar Nossa Chave Pública</strong></h6>
                                    <p>Salve nossa chave pública acima em um arquivo (ex: zeemarket_public.asc)</p>
                                    
                                    <div class="terminal">
                                        gpg --import zeemarket_public.asc
                                    </div>
                                </div>

                                <div class="instructions-step">
                                    <h6><strong>3. Criptografar Sua Mensagem</strong></h6>
                                    <p>Crie um arquivo com sua mensagem e criptografe:</p>
                                    
                                    <div class="terminal">
                                        echo "Sua mensagem secreta aqui" | gpg --armor --encrypt -r "admin@zeemarket.onion"
                                    </div>
                                </div>

                                <div class="instructions-step">
                                    <h6><strong>4. Enviar Mensagem Criptografada</strong></h6>
                                    <p>Cole o resultado criptografado no formulário abaixo</p>
                                </div>
                            </div>

                            <!-- Formulário para Mensagem Criptografada -->
                            <div class="mb-4">
                                <h3 class="matrix-text">
                                    <i class="fas fa-paper-plane"></i> Enviar Mensagem Criptografada
                                </h3>
                                
                                <?php if (!file_exists('process_encrypted_message.php')): ?>
                                    <div class="alert alert-warning-darkweb">
                                        <i class="fas fa-tools"></i> Sistema de processamento ainda não configurado. 
                                        Voltando em breve...
                                    </div>
                                <?php endif; ?>
                                
                                <form method="POST" action="process_encrypted_message.php" class="needs-validation" novalidate>
                                    <input type="hidden" name="csrf_token" value="<?= generateSecureCSRFToken() ?>">
                                    
                                    <div class="mb-3">
                                        <label class="form-label matrix-text">
                                            <i class="fas fa-tag"></i> Tipo de Mensagem:
                                        </label>
                                        <select name="message_type" class="form-select form-control" required>
                                            <option value="">Selecione o tipo...</option>
                                            <option value="support">🔧 Suporte Técnico</option>
                                            <option value="complaint">⚠️ Reclamação</option>
                                            <option value="suggestion">💡 Sugestão</option>
                                            <option value="security">🛡️ Questão de Segurança</option>
                                            <option value="vendor">👤 Solicitação de Vendor</option>
                                            <option value="other">📝 Outro</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label matrix-text">
                                            <i class="fas fa-lock"></i> Mensagem Criptografada:
                                        </label>
                                        <textarea 
                                            name="encrypted_message" 
                                            class="form-control font-monospace" 
                                            rows="12" 
                                            placeholder="-----BEGIN PGP MESSAGE-----&#10;Version: GnuPG v2&#10;&#10;Cole aqui sua mensagem criptografada...&#10;-----END PGP MESSAGE-----"
                                            required></textarea>
                                        <div class="form-text text-muted">
                                            <i class="fas fa-info-circle"></i> 
                                            A mensagem deve começar com "-----BEGIN PGP MESSAGE-----"
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <button type="submit" class="btn btn-matrix btn-lg">
                                            <i class="fas fa-rocket"></i> Enviar Mensagem Segura
                                        </button>
                                    </div>
                                </form>
                            </div>

                            <!-- Informações de Segurança -->
                            <div class="alert alert-darkweb">
                                <h5><i class="fas fa-shield-alt"></i> Garantias de Segurança</h5>
                                <ul class="mb-0">
                                    <li>✅ Suas mensagens são criptografadas end-to-end</li>
                                    <li>✅ Apenas nossa chave privada pode descriptografar</li>
                                    <li>✅ Não armazenamos dados não-criptografados</li>
                                    <li>✅ Logs são automaticamente limpos a cada 7 dias</li>
                                    <li>✅ <?= $isTorUser ? 'Tor detectado - máxima privacidade' : 'Use Tor Browser para anonimato total' ?></li>
                                </ul>
                            </div>
                        <?php endif; ?>

                        <!-- Exemplos de Uso -->
                        <div class="mt-4">
                            <h4 class="matrix-text">
                                <i class="fas fa-lightbulb"></i> Para Que Serve o PGP?
                            </h4>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="instructions-step">
                                        <h6>🛡️ Comunicação Segura com Admins</h6>
                                        <p>Reportar problemas, fazer sugestões ou solicitar suporte de forma totalmente privada.</p>
                                    </div>
                                    
                                    <div class="instructions-step">
                                        <h6>🔐 Dados Sensíveis</h6>
                                        <p>Enviar informações confidenciais que não devem ser interceptadas.</p>
                                    </div>
                                </div>
                                
                                <div class="col-md-6">
                                    <div class="instructions-step">
                                        <h6>⚠️ Relatos de Segurança</h6>
                                        <p>Reportar vulnerabilidades ou problemas de segurança do site.</p>
                                    </div>
                                    
                                    <div class="instructions-step">
                                        <h6>👤 Solicitações de Vendor</h6>
                                        <p>Candidatar-se para se tornar vendedor com informações verificadas.</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Rodapé -->
                        <div class="text-center mt-4 pt-4 border-top border-secondary">
                            <p class="text-muted">
                                <i class="fas fa-user-secret"></i> 
                                ZeeMarket - Privacidade e Segurança em Primeiro Lugar
                            </p>
                            <a href="index.php" class="btn btn-outline-light">
                                <i class="fas fa-arrow-left"></i> Voltar ao Site
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Copiar chave pública
        function copyPublicKey() {
            const keyDisplay = document.getElementById('publicKeyDisplay');
            const textToCopy = keyDisplay.textContent.replace('Copiar', '').trim();
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Feedback visual
                const button = keyDisplay.querySelector('.copy-button');
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copiado!';
                button.style.background = 'rgba(0, 255, 0, 0.3)';
                
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.style.background = 'rgba(0, 255, 0, 0.1)';
                }, 2000);
            }).catch(() => {
                alert('Erro ao copiar. Selecione o texto manualmente.');
            });
        }

        // Validação do formulário
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                const forms = document.getElementsByClassName('needs-validation');
                Array.prototype.filter.call(forms, function(form) {
                    form.addEventListener('submit', function(event) {
                        if (form.checkValidity() === false) {
                            event.preventDefault();
                            event.stopPropagation();
                        }
                        form.classList.add('was-validated');
                    }, false);
                });
            }, false);
        })();

        // Verificar se mensagem parece ser PGP
        document.querySelector('textarea[name="encrypted_message"]').addEventListener('blur', function() {
            const message = this.value.trim();
            if (message && !message.includes('-----BEGIN PGP MESSAGE-----')) {
                this.style.borderColor = '#ff6b6b';
                this.insertAdjacentHTML('afterend', 
                    '<div class="text-warning mt-1"><small><i class="fas fa-exclamation-triangle"></i> A mensagem não parece estar criptografada com PGP</small></div>'
                );
            } else if (message.includes('-----BEGIN PGP MESSAGE-----')) {
                this.style.borderColor = '#00ff00';
                const warning = this.parentNode.querySelector('.text-warning');
                if (warning) warning.remove();
            }
        });

        // Efeito Matrix no background (sutil)
        function createMatrixEffect() {
            const chars = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン01";
            const matrix = document.createElement('div');
            matrix.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                pointer-events: none; z-index: -1; opacity: 0.05;
                font-family: monospace; font-size: 10px; color: #00ff00;
                overflow: hidden;
            `;
            
            for (let i = 0; i < 50; i++) {
                const column = document.createElement('div');
                column.style.cssText = `
                    position: absolute; top: -100px; left: ${i * 2}%;
                    animation: fall ${Math.random() * 3 + 2}s linear infinite;
                `;
                column.textContent = chars.charAt(Math.floor(Math.random() * chars.length));
                matrix.appendChild(column);
            }
            
            document.body.appendChild(matrix);
        }

        // Adicionar CSS para animação da Matrix
        const style = document.createElement('style');
        style.textContent = `
            @keyframes fall {
                to { transform: translateY(100vh); }
            }
        `;
        document.head.appendChild(style);
        
        // Inicializar efeito Matrix
        createMatrixEffect();
    </script>
</body>
</html>