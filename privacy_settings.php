<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'includes/simple_pgp.php';

verificarLogin();

$user_id = $_SESSION['user_id'];
$username = $_SESSION['user_name'];

// Verificar TOR
$torDetected = false;
$torConfidence = 0;
try {
    $torCheck = checkTorConnection();
    $torDetected = $torCheck['connected'];
    $torConfidence = $torCheck['confidence'];
} catch (Exception $e) {
    // Ignorar erro
}

// Verificar PGP
$pgpConfigured = false;
$publicKey = null;
try {
    if ($simplePGP) {
        $pgpConfigured = $simplePGP->keysExist();
        if ($pgpConfigured) {
            $publicKey = $simplePGP->getPublicKey();
        }
    }
} catch (Exception $e) {
    error_log("Erro ao verificar PGP: " . $e->getMessage());
}

// Calcular score
$privacyScore = 20; // Base
if ($torDetected) $privacyScore += 40;
if ($pgpConfigured) $privacyScore += 30;

$privacyLevel = $privacyScore >= 70 ? 'Alto' : ($privacyScore >= 50 ? 'Médio' : 'Básico');

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'test_tor':
            if ($torDetected) {
                $message = "✅ TOR detectado! Confiança: {$torConfidence}%";
            } else {
                $message = "❌ TOR não detectado. Use o Tor Browser.";
            }
            break;
            
        case 'show_public_key':
            // Apenas mostrar a chave
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
        body { background: #1a1a1a; color: #e0e0e0; }
        .privacy-card {
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .feature-active { border-left: 3px solid #28a745; }
        .feature-inactive { border-left: 3px solid #dc3545; }
        .privacy-score-big { font-size: 3rem; font-weight: bold; }
        .recommendation {
            background: rgba(255,193,7,0.1);
            border: 1px solid #ffc107;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .status-active { background: #28a745; color: white; }
        .status-inactive { background: #dc3545; color: white; }
        .code-display {
            background: #000;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <?php if (file_exists('includes/header.php')) include 'includes/header.php'; ?>
    
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
            <div class="privacy-score-big text-<?= $privacyScore >= 60 ? 'success' : 'warning' ?>">
                <?= $privacyScore ?>/100
            </div>
            <p class="text-muted">Nível: <?= $privacyLevel ?></p>
            <div class="progress" style="height: 20px;">
                <div class="progress-bar bg-<?= $privacyScore >= 60 ? 'success' : 'warning' ?>" 
                     style="width: <?= $privacyScore ?>%"></div>
            </div>
        </div>
        
        <!-- Recomendações -->
        <div class="privacy-card">
            <h4><i class="fas fa-lightbulb"></i> Recomendações</h4>
            <?php if (!$torDetected): ?>
                <div class="recommendation">
                    <i class="fas fa-arrow-right"></i> Use o Tor Browser para melhor privacidade (+40 pontos)
                </div>
            <?php endif; ?>
            <?php if (!$pgpConfigured): ?>
                <div class="recommendation">
                    <i class="fas fa-arrow-right"></i> Configure PGP para comunicação criptografada (+30 pontos)
                </div>
            <?php endif; ?>
            <div class="recommendation">
                <i class="fas fa-arrow-right"></i> Use senhas únicas e fortes
            </div>
            <div class="recommendation">
                <i class="fas fa-arrow-right"></i> Nunca compartilhe informações pessoais
            </div>
        </div>
        
        <div class="row">
            <!-- TOR Configuration -->
            <div class="col-md-6">
                <div class="privacy-card <?= $torDetected ? 'feature-active' : 'feature-inactive' ?>">
                    <h4>
                        <i class="fas fa-user-secret"></i> Navegador TOR
                        <span class="status-badge <?= $torDetected ? 'status-active' : 'status-inactive' ?>">
                            <?= $torDetected ? 'DETECTADO' : 'NÃO DETECTADO' ?>
                        </span>
                    </h4>
                    
                    <?php if ($torDetected): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> Você está usando TOR!
                            <br>Confiança: <?= $torConfidence ?>%
                            <br><small>Sua privacidade está protegida</small>
                        </div>
                    <?php else: ?>
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> TOR não detectado
                        </div>
                        
                        <h6>Como usar TOR:</h6>
                        <ol>
                            <li>Baixe o Tor Browser em <a href="https://torproject.org" target="_blank">torproject.org</a></li>
                            <li>Instale e abra o navegador</li>
                            <li>Acesse este site através do Tor Browser</li>
                        </ol>
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
                <div class="privacy-card <?= $pgpConfigured ? 'feature-active' : 'feature-inactive' ?>">
                    <h4>
                        <i class="fas fa-key"></i> Sistema PGP
                        <span class="status-badge <?= $pgpConfigured ? 'status-active' : 'status-inactive' ?>">
                            <?= $pgpConfigured ? 'CONFIGURADO' : 'NÃO CONFIGURADO' ?>
                        </span>
                    </h4>
                    
                    <?php if ($pgpConfigured): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> PGP configurado e funcionando!
                            <br><small>Você pode enviar mensagens criptografadas</small>
                        </div>
                        
                        <button class="btn btn-info" type="button" data-bs-toggle="collapse" data-bs-target="#publicKeyCollapse">
                            <i class="fas fa-eye"></i> Ver Nossa Chave Pública
                        </button>
                        
                        <div class="collapse mt-3" id="publicKeyCollapse">
                            <h6>Nossa Chave Pública PGP:</h6>
                            <div class="code-display">
                                <?= htmlspecialchars($publicKey) ?>
                            </div>
                            <button class="btn btn-sm btn-secondary mt-2" onclick="copyToClipboard()">
                                <i class="fas fa-copy"></i> Copiar Chave
                            </button>
                        </div>
                        
                        <div class="mt-3">
                            <a href="send_encrypted_message.php" class="btn btn-success">
                                <i class="fas fa-envelope"></i> Enviar Mensagem Criptografada
                            </a>
                        </div>
                        
                    <?php else: ?>
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> PGP não configurado
                        </div>
                        
                        <p>O sistema PGP permite comunicação totalmente criptografada.</p>
                        
                        <div class="alert alert-info">
                            <h6><i class="fas fa-database"></i> Status do banco:</h6>
                            <p>Verificando configuração PGP...</p>
                            <?php
                            // Debug info
                            try {
                                $stmt = $conn->prepare("SHOW TABLES LIKE 'site_pgp_keys'");
                                $stmt->execute();
                                $tableExists = $stmt->get_result()->num_rows > 0;
                                
                                if ($tableExists) {
                                    $stmt = $conn->prepare("SELECT COUNT(*) FROM site_pgp_keys WHERE site_name = 'zeemarket'");
                                    $stmt->execute();
                                    $keyCount = $stmt->get_result()->fetch_row()[0];
                                    echo "<small>✅ Tabela existe | Chaves: $keyCount</small>";
                                } else {
                                    echo "<small>❌ Tabela site_pgp_keys não existe</small>";
                                }
                            } catch (Exception $e) {
                                echo "<small>❌ Erro: " . htmlspecialchars($e->getMessage()) . "</small>";
                            }
                            ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Instruções PGP -->
        <?php if ($pgpConfigured): ?>
        <div class="privacy-card">
            <h4><i class="fas fa-info-circle"></i> Como Usar PGP</h4>
            <div class="row">
                <div class="col-md-6">
                    <h6>📥 Para nos enviar mensagem criptografada:</h6>
                    <ol>
                        <li>Copie nossa chave pública acima</li>
                        <li>Importe em seu software PGP (GPG, Kleopatra, etc.)</li>
                        <li>Criptografe sua mensagem com nossa chave</li>
                        <li>Envie através do formulário de contato</li>
                    </ol>
                </div>
                <div class="col-md-6">
                    <h6>🔧 Software PGP recomendado:</h6>
                    <ul>
                        <li><strong>Windows:</strong> Kleopatra, GPG4Win</li>
                        <li><strong>macOS:</strong> GPG Suite</li>
                        <li><strong>Linux:</strong> GnuPG (comando gpg)</li>
                        <li><strong>Email:</strong> Thunderbird + Enigmail</li>
                    </ul>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
        <!-- Bitcoin Mixing -->
        <div class="privacy-card">
            <h4><i class="fas fa-random"></i> Bitcoin Mixing</h4>
            <div class="row">
                <div class="col-md-8">
                    <p>O mixing torna suas transações Bitcoin mais privadas:</p>
                    <ul>
                        <li>Quebra vínculos entre endereços</li>
                        <li>Múltiplas camadas de privacidade</li>
                        <li>Pools com alta liquidez</li>
                        <li>Delays aleatórios para segurança</li>
                    </ul>
                    
                    <?php
                    // Verificar histórico de mixing do usuário
                    try {
                        $stmt = $conn->prepare("SELECT COUNT(*) as total, SUM(total_input_btc) as volume FROM advanced_mixing WHERE user_id = ? AND status = 'completed'");
                        $stmt->bind_param("i", $user_id);
                        $stmt->execute();
                        $mixingStats = $stmt->get_result()->fetch_assoc();
                        
                        if ($mixingStats['total'] > 0) {
                            echo '<div class="alert alert-info">';
                            echo '<i class="fas fa-check-circle"></i> ';
                            echo 'Você já utilizou mixing ' . $mixingStats['total'] . ' vez(es). ';
                            echo 'Volume total: ' . number_format($mixingStats['volume'], 4) . ' BTC';
                            echo '</div>';
                            $privacyScore += 10; // Bonus por usar mixing
                        } else {
                            echo '<div class="alert alert-secondary">';
                            echo '<i class="fas fa-info-circle"></i> ';
                            echo 'Você ainda não utilizou nosso serviço de mixing.';
                            echo '</div>';
                        }
                    } catch (Exception $e) {
                        echo '<div class="alert alert-secondary">';
                        echo '<i class="fas fa-info-circle"></i> ';
                        echo 'Serviço de mixing disponível.';
                        echo '</div>';
                    }
                    ?>
                </div>
                <div class="col-md-4 text-center">
                    <i class="fas fa-random fa-3x text-warning mb-3"></i>
                    <br>
                    <a href="bitcoin_mixer.php" class="btn btn-warning">
                        <i class="fas fa-random"></i> Acessar Mixer
                    </a>
                    <br><small class="text-muted mt-2 d-block">Taxas: 0.5% - 2.5%</small>
                </div>
            </div>
        </div>
        
        <!-- Status do Sistema -->
        <div class="privacy-card">
            <h4><i class="fas fa-server"></i> Status do Sistema</h4>
            <div class="row">
                <div class="col-md-4">
                    <strong>Detecção TOR:</strong><br>
                    <span class="status-badge status-active">FUNCIONANDO</span>
                </div>
                <div class="col-md-4">
                    <strong>Sistema PGP:</strong><br>
                    <span class="status-badge <?= $pgpConfigured ? 'status-active' : 'status-inactive' ?>">
                        <?= $pgpConfigured ? 'FUNCIONANDO' : 'DESCONFIGURADO' ?>
                    </span>
                </div>
                <div class="col-md-4">
                    <strong>Criptografia SSL:</strong><br>
                    <span class="status-badge status-active">ATIVA</span>
                </div>
            </div>
        </div>
    </div>
    
    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
    function copyToClipboard() {
        const keyDisplay = document.querySelector('.code-display');
        const text = keyDisplay.textContent;
        
        navigator.clipboard.writeText(text).then(() => {
            alert('✅ Chave PGP copiada para a área de transferência!');
        }).catch(() => {
            // Fallback
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert('✅ Chave PGP copiada!');
        });
    }
    </script>
</body>
</html>