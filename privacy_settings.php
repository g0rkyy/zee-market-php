<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/tor_system.php';
require_once 'includes/pgp_system.php';
require_once 'includes/two_factor_auth.php';

// Verificar login
verificarLogin();

$user_id = $_SESSION['user_id'];
$username = $_SESSION['user_name'];

// Inicializar sistemas
$torSystem = new ZeeMarketTor($conn);
$pgpSystem = new ZeeMarketPGP($conn);
$twoFA = new TwoFactorAuth($conn);

// Análise de privacidade atual
$privacyAnalysis = $torSystem->analyzePrivacyLevel($user_id);
$hasPGPKeys = $pgpSystem->userHasPgpKey($user_id);
$has2FA = $twoFA->isUserTwoFAEnabled($user_id);

// Processar ações POST
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'generate_pgp':
            $result = $pgpSystem->generateUserKeyPair(
                $user_id,
                $username,
                $_SESSION['email'] ?? $username . '@zeemarket.onion',
                $_POST['passphrase']
            );
            if ($result['success']) {
                $message = "Chaves PGP geradas com sucesso!";
                $_SESSION['pgp_public_key'] = $result['public_key'];
                $hasPGPKeys = true;
            } else {
                $error = $result['error'];
            }
            break;
            
        case 'test_tor':
            $torStatus = $torSystem->checkTorStatus();
            $message = "Status TOR: " . ($torStatus['running'] ? "Ativo" : "Inativo");
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurações de Privacidade - ZeeMarket</title>
    <link href="assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: #1a1a1a;
            color: #e0e0e0;
        }
        .privacy-card {
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .feature-active {
            border-left: 3px solid #28a745;
        }
        .feature-inactive {
            border-left: 3px solid #dc3545;
        }
        .privacy-score-big {
            font-size: 3rem;
            font-weight: bold;
        }
        .recommendation {
            background: rgba(255,193,7,0.1);
            border: 1px solid #ffc107;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .code-display {
            background: #000;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <?php include 'includes/header.php'; ?>
    
    <div class="container mt-4">
        <h2 class="mb-4"><i class="fas fa-shield-alt"></i> Configurações de Privacidade</h2>
        
        <?php if ($message): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <?= htmlspecialchars($message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?= htmlspecialchars($error) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <!-- Score de Privacidade -->
        <div class="privacy-card text-center">
            <h4>Seu Score de Privacidade</h4>
            <div class="privacy-score-big text-<?= $privacyAnalysis['privacy_score'] >= 60 ? 'success' : 'warning' ?>">
                <?= $privacyAnalysis['privacy_score'] ?>/100
            </div>
            <p class="text-muted">Nível: <?= $privacyAnalysis['level'] ?></p>
            <div class="progress" style="height: 20px;">
                <div class="progress-bar bg-<?= $privacyAnalysis['privacy_score'] >= 60 ? 'success' : 'warning' ?>" 
                     style="width: <?= $privacyAnalysis['privacy_score'] ?>%"></div>
            </div>
        </div>
        
        <!-- Recomendações -->
        <?php if (!empty($privacyAnalysis['recommendations'])): ?>
        <div class="privacy-card">
            <h4><i class="fas fa-lightbulb"></i> Recomendações</h4>
            <?php foreach ($privacyAnalysis['recommendations'] as $rec): ?>
                <div class="recommendation">
                    <i class="fas fa-arrow-right"></i> <?= htmlspecialchars($rec) ?>
                </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        
        <div class="row">
            <!-- TOR Configuration -->
            <div class="col-md-6">
                <div class="privacy-card <?= $privacyAnalysis['tor_usage']['is_tor'] ? 'feature-active' : 'feature-inactive' ?>">
                    <h4><i class="fas fa-user-secret"></i> Navegador TOR</h4>
                    
                    <?php if ($privacyAnalysis['tor_usage']['is_tor']): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> Você está usando TOR!
                            <br>Confiança: <?= $privacyAnalysis['tor_usage']['confidence'] ?>%
                        </div>
                    <?php else: ?>
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> TOR não detectado
                        </div>
                        
                        <h6>Como usar TOR:</h6>
                        <ol>
                            <li>Baixe o Tor Browser em <a href="https://torproject.org" target="_blank">torproject.org</a></li>
                            <li>Instale e abra o navegador</li>
                            <li>Acesse nosso endereço .onion:</li>
                        </ol>
                        
                        <?php 
                        $onionAddress = $torSystem->getOnionAddress();
                        if ($onionAddress): 
                        ?>
                        <div class="code-display">
                            <?= htmlspecialchars($onionAddress) ?>
                        </div>
                        <button class="btn btn-sm btn-secondary mt-2" onclick="copyToClipboard('<?= $onionAddress ?>')">
                            <i class="fas fa-copy"></i> Copiar
                        </button>
                        <?php endif; ?>
                    <?php endif; ?>
                    
                    <form method="POST" class="mt-3">
                        <input type="hidden" name="action" value="test_tor">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-sync"></i> Testar Conexão TOR
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- PGP Configuration -->
            <div class="col-md-6">
                <div class="privacy-card <?= $hasPGPKeys ? 'feature-active' : 'feature-inactive' ?>">
                    <h4><i class="fas fa-key"></i> Chaves PGP</h4>
                    
                    <?php if ($hasPGPKeys): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> PGP configurado!
                        </div>
                        
                        <?php if (isset($_SESSION['pgp_public_key'])): ?>
                        <h6>Sua chave pública:</h6>
                        <div class="code-display">
                            <?= htmlspecialchars($_SESSION['pgp_public_key']) ?>
                        </div>
                        <button class="btn btn-sm btn-secondary mt-2" 
                                onclick="copyToClipboard('<?= htmlspecialchars($_SESSION['pgp_public_key']) ?>')">
                            <i class="fas fa-copy"></i> Copiar Chave Pública
                        </button>
                        <?php endif; ?>
                        
                    <?php else: ?>
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> PGP não configurado
                        </div>
                        
                        <p>O PGP permite criptografar mensagens e assinar transações.</p>
                        
                        <form method="POST" id="pgp-form">
                            <input type="hidden" name="action" value="generate_pgp">
                            <div class="mb-3">
                                <label class="form-label">Senha para proteger sua chave:</label>
                                <input type="password" class="form-control" name="passphrase" required 
                                       minlength="8" placeholder="Mínimo 8 caracteres">
                                <small class="text-muted">Guarde esta senha com segurança!</small>
                            </div>
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-shield-alt"></i> Gerar Chaves PGP
                            </button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Bitcoin Mixing -->
        <div class="privacy-card">
            <h4><i class="fas fa-random"></i> Bitcoin Mixing</h4>
            <div class="row">
                <div class="col-md-6">
                    <p>O mixing torna suas transações Bitcoin mais privadas.</p>
                    <ul>
                        <li>Quebra o link entre endereços</li>
                        <li>Aumenta anonimato</li>
                        <li>Taxa: 1-2%</li>
                    </ul>
                    <?php if ($privacyAnalysis['mixing_history'] > 0): ?>
                        <div class="alert alert-info">
                            Você já usou mixing <?= $privacyAnalysis['mixing_history'] ?> vez(es).
                        </div>
                    <?php endif; ?>
                </div>
                <div class="col-md-6">
                    <a href="bitcoin_mixer.php" class="btn btn-warning">
                        <i class="fas fa-random"></i> Acessar Mixer
                    </a>
                </div>
            </div>
        </div>
        
        <!-- 2FA Status -->
        <div class="privacy-card">
            <h4><i class="fas fa-mobile-alt"></i> Autenticação de Dois Fatores (2FA)</h4>
            <?php if ($has2FA): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> 2FA está ativo!
                </div>
                <a href="painel_usuario.php" class="btn btn-secondary">Gerenciar 2FA</a>
            <?php else: ?>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i> 2FA não está ativo
                </div>
                <p>Proteja sua conta com autenticação de dois fatores.</p>
                <a href="painel_usuario.php" class="btn btn-primary">Ativar 2FA</a>
            <?php endif; ?>
        </div>
        
        <!-- Dicas Extras -->
        <div class="privacy-card">
            <h4><i class="fas fa-info-circle"></i> Dicas Extras de Privacidade</h4>
            <ul>
                <li>Use endereços Bitcoin diferentes para cada transação</li>
                <li>Evite reutilizar senhas</li>
                <li>Não compartilhe informações pessoais em mensagens</li>
                <li>Sempre verifique assinaturas PGP em mensagens importantes</li>
                <li>Use VPN além do TOR para máxima privacidade</li>
            </ul>
        </div>
    </div>
    
    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Copiado para a área de transferência!');
        }).catch(() => {
            // Fallback para navegadores antigos
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert('Copiado!');
        });
    }
    
    // Validação do formulário PGP
    document.getElementById('pgp-form')?.addEventListener('submit', function(e) {
        const passphrase = this.passphrase.value;
        if (passphrase.length < 8) {
            e.preventDefault();
            alert('A senha deve ter pelo menos 8 caracteres!');
        }
    });
    </script>
</body>
</html>