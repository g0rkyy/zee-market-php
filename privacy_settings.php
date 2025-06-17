<?php
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
$username = $_SESSION['user_name'] ?? 'Usuário';

// ✅ VERIFICAR TOR COM TRATAMENTO DE ERRO
$torDetected = false;
$torConfidence = 0;
try {
    // Verificar se a função existe antes de chamar
    if (function_exists('checkTorConnection')) {
        $torCheck = checkTorConnection();
        $torDetected = $torCheck['connected'] ?? false;
        $torConfidence = $torCheck['confidence'] ?? 0;
    } else {
        // Detecção básica de TOR
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $torDetected = (strpos($userAgent, 'Firefox') !== false && 
                       strpos($userAgent, 'Chrome') === false &&
                       !empty($_SERVER['HTTP_ACCEPT_LANGUAGE']) &&
                       $_SERVER['HTTP_ACCEPT_LANGUAGE'] === 'en-US,en;q=0.5');
        $torConfidence = $torDetected ? 75 : 0;
    }
} catch (Exception $e) {
    error_log("Erro ao verificar TOR: " . $e->getMessage());
    $torDetected = false;
    $torConfidence = 0;
}

// ✅ VERIFICAR PGP COM TRATAMENTO DE ERRO
$pgpConfigured = false;
$publicKey = null;
try {
    // Verificar se existe arquivo de PGP e se a classe existe
    if (file_exists('includes/simple_pgp.php')) {
        require_once 'includes/simple_pgp.php';
        if (class_exists('SimplePGP')) {
            $simplePGP = new SimplePGP($conn);
            $pgpConfigured = $simplePGP->keysExist();
            if ($pgpConfigured) {
                $publicKey = $simplePGP->getPublicKey();
            }
        }
    }
    
    // Fallback: verificar diretamente no banco
    if (!$pgpConfigured) {
        $stmt_pgp = $conn->prepare("SHOW TABLES LIKE 'site_pgp_keys'");
        $stmt_pgp->execute();
        if ($stmt_pgp->get_result()->num_rows > 0) {
            $stmt_check = $conn->prepare("SELECT public_key FROM site_pgp_keys WHERE site_name = 'zeemarket' LIMIT 1");
            $stmt_check->execute();
            $result = $stmt_check->get_result();
            if ($result->num_rows > 0) {
                $pgpConfigured = true;
                $publicKey = $result->fetch_assoc()['public_key'];
            }
            $stmt_check->close();
        }
        $stmt_pgp->close();
    }
} catch (Exception $e) {
    error_log("Erro ao verificar PGP: " . $e->getMessage());
    $pgpConfigured = false;
    $publicKey = null;
}

// ✅ CALCULAR SCORE DE PRIVACIDADE
$privacyScore = 20; // Base
if ($torDetected) $privacyScore += 40;
if ($pgpConfigured) $privacyScore += 30;

// ✅ BONUS DE MIXING COM TRATAMENTO DE ERRO
$mixingCount = 0;
$mixingVolume = 0;
try {
    // Verificar se a tabela existe
    $stmt_check_table = $conn->prepare("SHOW TABLES LIKE 'advanced_mixing'");
    $stmt_check_table->execute();
    if ($stmt_check_table->get_result()->num_rows > 0) {
        $stmt_mixing = $conn->prepare("SELECT COUNT(*) as total, COALESCE(SUM(total_input_btc), 0) as volume FROM advanced_mixing WHERE user_id = ? AND status = 'completed'");
        $stmt_mixing->bind_param("i", $user_id);
        $stmt_mixing->execute();
        $mixing_stats = $stmt_mixing->get_result()->fetch_assoc();
        $mixingCount = (int)($mixing_stats['total'] ?? 0);
        $mixingVolume = (float)($mixing_stats['volume'] ?? 0);
        $stmt_mixing->close();
        
        if ($mixingCount > 0) {
            $privacyScore += 10;
        }
    }
    $stmt_check_table->close();
} catch (Exception $e) {
    error_log("Erro ao verificar mixing: " . $e->getMessage());
    $mixingCount = 0;
    $mixingVolume = 0;
}

$privacyScore = min($privacyScore, 100); // Limitar a 100
$privacyLevel = $privacyScore >= 80 ? 'Excelente' : ($privacyScore >= 60 ? 'Bom' : 'Básico');

$message = '';
$error = '';

// ✅ PROCESSAR AÇÕES POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar CSRF
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'test_tor':
                if ($torDetected) {
                    $message = "✅ TOR detectado! Confiança: " . $torConfidence . "%";
                } else {
                    $message = "❌ TOR não detectado. Use o Tor Browser para máxima segurança.";
                }
                break;
                
            case 'generate_pgp':
                try {
                    // Implementar geração de chaves PGP aqui
                    $message = "⚠️ Funcionalidade de geração PGP em desenvolvimento.";
                } catch (Exception $e) {
                    $error = "Erro ao gerar chaves PGP: " . $e->getMessage();
                }
                break;
                
            default:
                $error = "Ação inválida.";
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
    <title>Configurações de Privacidade - ZeeMarket</title>
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
            max-width: 1200px;
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
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }
        
        .page-subtitle {
            font-size: 1.2rem;
            color: var(--text-secondary);
        }
        
        .privacy-score-card {
            text-align: center;
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 2px solid var(--glass-border);
            border-radius: 25px;
            padding: 3rem;
            margin-bottom: 3rem;
            position: relative;
            overflow: hidden;
        }
        
        .privacy-score-card::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: linear-gradient(135deg, var(--primary), var(--secondary), var(--accent));
            border-radius: 25px;
            z-index: -1;
        }
        
        .score-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            margin: 0 auto 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            font-weight: 800;
            position: relative;
            background: conic-gradient(from 0deg, var(--primary) 0%, var(--primary-light) 50%, transparent 50%);
            padding: 8px;
        }
        
        .score-inner {
            width: 100%;
            height: 100%;
            background: var(--bg-secondary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
        }
        
        .score-value {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .score-label {
            font-size: 1rem;
            color: var(--text-muted);
            margin-top: 0.5rem;
        }
        
        .privacy-level {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        
        .privacy-level.excellent { color: var(--success); }
        .privacy-level.good { color: var(--accent); }
        .privacy-level.basic { color: var(--warning); }
        
        .progress-modern {
            height: 12px;
            background: rgba(255,255,255,0.1);
            border-radius: 6px;
            overflow: hidden;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .progress-bar-modern {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--primary-light));
            border-radius: 6px;
            transition: width 0.6s ease;
            position: relative;
            overflow: hidden;
        }
        
        .progress-bar-modern::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            animation: shimmer 2s ease-in-out infinite;
        }
        
        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .feature-card {
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 2rem;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            border-radius: 20px 20px 0 0;
        }
        
        .feature-card.active::before {
            background: linear-gradient(90deg, var(--success), #14B8A6);
        }
        
        .feature-card.inactive::before {
            background: linear-gradient(90deg, var(--danger), #F87171);
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-xl);
        }
        
        .feature-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
        }
        
        .feature-title {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .feature-icon {
            width: 50px;
            height: 50px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }
        
        .feature-icon.tor {
            background: linear-gradient(135deg, #7B2CBF, #9D4EDD);
            color: white;
        }
        
        .feature-icon.pgp {
            background: linear-gradient(135deg, var(--accent), #FBBF24);
            color: white;
        }
        
        .feature-icon.mixing {
            background: linear-gradient(135deg, var(--info), #60A5FA);
            color: white;
        }
        
        .status-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-active {
            background: linear-gradient(135deg, var(--success), #14B8A6);
            color: white;
        }
        
        .status-inactive {
            background: linear-gradient(135deg, var(--danger), #F87171);
            color: white;
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
        
        .btn-modern:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
            color: white;
        }
        
        .recommendations-card {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid var(--accent);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .recommendation-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            margin-bottom: 1rem;
            transition: all 0.3s ease;
        }
        
        .recommendation-item:hover {
            background: rgba(255,255,255,0.1);
            transform: translateX(5px);
        }
        
        .recommendation-item:last-child {
            margin-bottom: 0;
        }
        
        .code-display {
            background: #000;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
            font-size: 0.875rem;
            white-space: pre-wrap;
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
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .stat-item {
            text-align: center;
            padding: 1.5rem;
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary-light);
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-muted);
            font-size: 0.875rem;
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
        
        @media (max-width: 768px) {
            .main-container {
                padding: 1rem;
            }
            
            .feature-grid {
                grid-template-columns: 1fr;
            }
            
            .page-title {
                font-size: 2rem;
            }
            
            .score-circle {
                width: 150px;
                height: 150px;
            }
            
            .score-value {
                font-size: 2.5rem;
            }
        }
    </style>
</head>
<body>
    <a href="dashboard.php" class="nav-btn">
        <i class="bi bi-arrow-left"></i> Voltar ao Dashboard
    </a>

    <div class="main-container">
        <div class="page-header">
            <h1 class="page-title">
                <i class="bi bi-shield-lock"></i> Configurações de Privacidade
            </h1>
            <p class="page-subtitle">Gerencie suas configurações de segurança e anonimato</p>
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

        <!-- Privacy Score Card -->
        <div class="privacy-score-card">
            <div class="score-circle">
                <div class="score-inner">
                    <div class="score-value"><?= htmlspecialchars($privacyScore, ENT_QUOTES, 'UTF-8') ?></div>
                    <div class="score-label">/100</div>
                </div>
            </div>
            
            <h3 class="privacy-level <?= strtolower($privacyLevel) ?>">
                Nível: <?= htmlspecialchars($privacyLevel, ENT_QUOTES, 'UTF-8') ?>
            </h3>
            
            <div class="progress-modern">
                <div class="progress-bar-modern" style="width: <?= htmlspecialchars($privacyScore, ENT_QUOTES, 'UTF-8') ?>%;"></div>
            </div>
        </div>

        <!-- Recommendations -->
        <?php if ($privacyScore < 80): ?>
        <div class="recommendations-card">
            <h4 style="color: var(--accent); margin-bottom: 1.5rem;">
                <i class="bi bi-lightbulb"></i> Recomendações para Melhorar
            </h4>
            
            <?php if (!$torDetected): ?>
            <div class="recommendation-item">
                <i class="bi bi-shield-shaded" style="color: var(--primary); font-size: 1.25rem;"></i>
                <div>
                    <strong>Use o Tor Browser</strong><br>
                    <small>Melhora significativamente sua privacidade (+40 pontos)</small>
                </div>
            </div>
            <?php endif; ?>
            
            <?php if (!$pgpConfigured): ?>
            <div class="recommendation-item">
                <i class="bi bi-key" style="color: var(--accent); font-size: 1.25rem;"></i>
                <div>
                    <strong>Configure PGP</strong><br>
                    <small>Habilita comunicação criptografada (+30 pontos)</small>
                </div>
            </div>
            <?php endif; ?>
            
            <?php if ($mixingCount === 0): ?>
            <div class="recommendation-item">
                <i class="bi bi-shuffle" style="color: var(--info); font-size: 1.25rem;"></i>
                <div>
                    <strong>Use Bitcoin Mixing</strong><br>
                    <small>Aumenta anonimato das transações (+10 pontos)</small>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Feature Grid -->
        <div class="feature-grid">
            <!-- TOR Card -->
            <div class="feature-card <?= $torDetected ? 'active' : 'inactive' ?>">
                <div class="feature-header">
                    <div class="feature-title">
                        <div class="feature-icon tor">
                            <i class="bi bi-shield-shaded"></i>
                        </div>
                        <div>
                            <h4>Navegador TOR</h4>
                            <small style="color: var(--text-muted);">Navegação anônima</small>
                        </div>
                    </div>
                    <span class="status-badge <?= $torDetected ? 'status-active' : 'status-inactive' ?>">
                        <?= $torDetected ? 'DETECTADO' : 'NÃO DETECTADO' ?>
                    </span>
                </div>
                
                <?php if ($torDetected): ?>
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle"></i> <strong>Você está usando TOR!</strong><br>
                        Confiança: <?= htmlspecialchars($torConfidence, ENT_QUOTES, 'UTF-8') ?>%<br>
                        <small>Sua privacidade está protegida</small>
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i> <strong>TOR não detectado</strong><br>
                        <small>Recomendamos usar o Tor Browser</small>
                    </div>
                    
                    <h6 style="margin: 1.5rem 0 1rem 0;">Como usar TOR:</h6>
                    <ol style="margin-left: 1.5rem; color: var(--text-secondary);">
                        <li>Baixe o Tor Browser em <a href="https://torproject.org" target="_blank" style="color: var(--primary-light);">torproject.org</a></li>
                        <li>Instale e abra o navegador</li>
                        <li>Acesse este site através do Tor Browser</li>
                    </ol>
                <?php endif; ?>
                
                <form method="POST" style="margin-top: 1.5rem;">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="test_tor">
                    <button type="submit" class="btn-modern btn-primary">
                        <i class="bi bi-arrow-clockwise"></i> Testar Conexão TOR
                    </button>
                </form>
            </div>

            <!-- PGP Card -->
            <div class="feature-card <?= $pgpConfigured ? 'active' : 'inactive' ?>">
                <div class="feature-header">
                    <div class="feature-title">
                        <div class="feature-icon pgp">
                            <i class="bi bi-key"></i>
                        </div>
                        <div>
                            <h4>Sistema PGP</h4>
                            <small style="color: var(--text-muted);">Criptografia de ponta a ponta</small>
                        </div>
                    </div>
                    <span class="status-badge <?= $pgpConfigured ? 'status-active' : 'status-inactive' ?>">
                        <?= $pgpConfigured ? 'CONFIGURADO' : 'NÃO CONFIGURADO' ?>
                    </span>
                </div>
                
                <?php if ($pgpConfigured): ?>
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle"></i> <strong>PGP configurado e funcionando!</strong><br>
                        <small>Você pode enviar mensagens criptografadas</small>
                    </div>
                    
                    <button class="btn-modern btn-info" type="button" data-bs-toggle="collapse" data-bs-target="#publicKeyCollapse">
                        <i class="bi bi-eye"></i> Ver Nossa Chave Pública
                    </button>
                    
                    <div class="collapse mt-3" id="publicKeyCollapse">
                        <h6>Nossa Chave Pública PGP:</h6>
                        <div class="code-display" id="pgpKeyText">
                            <?= htmlspecialchars($publicKey ?? 'Chave não disponível', ENT_QUOTES, 'UTF-8') ?>
                        </div>
                        <button class="btn-modern btn-success mt-2" onclick="copyToClipboard('pgpKeyText')">
                            <i class="bi bi-copy"></i> Copiar Chave
                        </button>
                    </div>
                    
                    <div style="margin-top: 1.5rem;">
                        <a href="send_encrypted_message.php" class="btn-modern btn-success">
                            <i class="bi bi-envelope-lock"></i> Enviar Mensagem Criptografada
                        </a>
                    </div>
                    
                <?php else: ?>
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i> <strong>PGP não configurado</strong><br>
                        <small>Configure para comunicação segura</small>
                    </div>
                    
                    <p style="color: var(--text-secondary); margin: 1.5rem 0;">
                        O sistema PGP permite comunicação totalmente criptografada.
                    </p>
                    
                    <div class="alert alert-info">
                        <h6><i class="bi bi-database"></i> Status do sistema:</h6>
                        <?php
                        try {
                            $stmt_check = $conn->prepare("SHOW TABLES LIKE 'site_pgp_keys'");
                            $stmt_check->execute();
                            if ($stmt_check->get_result()->num_rows > 0) {
                                $stmt_count = $conn->prepare("SELECT COUNT(*) FROM site_pgp_keys WHERE site_name = 'zeemarket'");
                                $stmt_count->execute();
                                $keyCount = $stmt_count->get_result()->fetch_row()[0];
                                echo "<small style='color: var(--success);'>✅ Tabela 'site_pgp_keys' existe | Chaves: " . htmlspecialchars($keyCount, ENT_QUOTES, 'UTF-8') . "</small>";
                                $stmt_count->close();
                            } else {
                                echo "<small style='color: var(--danger);'>❌ Tabela 'site_pgp_keys' não existe</small>";
                            }
                            $stmt_check->close();
                        } catch (Exception $e) {
                            echo "<small style='color: var(--danger);'>❌ Erro: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</small>";
                        }
                        ?>
                    </div>
                    
                    <form method="POST" style="margin-top: 1.5rem;">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                        <input type="hidden" name="action" value="generate_pgp">
                        <button type="submit" class="btn-modern btn-warning">
                            <i class="bi bi-gear"></i> Configurar PGP
                        </button>
                    </form>
                <?php endif; ?>
            </div>

            <!-- Mixing Card -->
            <div class="feature-card <?= $mixingCount > 0 ? 'active' : 'inactive' ?>">
                <div class="feature-header">
                    <div class="feature-title">
                        <div class="feature-icon mixing">
                            <i class="bi bi-shuffle"></i>
                        </div>
                        <div>
                            <h4>Bitcoin Mixing</h4>
                            <small style="color: var(--text-muted);">Anonimização de transações</small>
                        </div>
                    </div>
                    <span class="status-badge <?= $mixingCount > 0 ? 'status-active' : 'status-inactive' ?>">
                        <?= $mixingCount > 0 ? 'USADO' : 'NUNCA USADO' ?>
                    </span>
                </div>
                
                <div style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                    <p>O mixing torna suas transações Bitcoin mais privadas:</p>
                    <ul style="margin-left: 1.5rem; margin-top: 1rem;">
                        <li>Quebra vínculos entre endereços</li>
                        <li>Múltiplas camadas de privacidade</li>
                        <li>Pools com alta liquidez</li>
                        <li>Delays aleatórios para segurança</li>
                    </ul>
                </div>
                
                <?php if ($mixingCount > 0): ?>
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle"></i> <strong>Você já utilizou mixing <?= htmlspecialchars($mixingCount, ENT_QUOTES, 'UTF-8') ?> vez(es)</strong><br>
                        Volume total: <?= htmlspecialchars(number_format($mixingVolume, 4), ENT_QUOTES, 'UTF-8') ?> BTC
                    </div>
                <?php else: ?>
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> <strong>Você ainda não utilizou nosso serviço de mixing</strong><br>
                        <small>Recomendado para máxima privacidade</small>
                    </div>
                <?php endif; ?>
                
                <div style="text-align: center; margin-top: 1.5rem;">
                    <a href="bitcoin_mixer.php" class="btn-modern btn-warning">
                        <i class="bi bi-shuffle"></i> Acessar Mixer
                    </a>
                    <br><small style="color: var(--text-muted); margin-top: 0.5rem; display: block;">Taxas: 0.5% - 2.5%</small>
                </div>
            </div>
        </div>

        <!-- PGP Usage Instructions -->
        <?php if ($pgpConfigured): ?>
        <div class="glass-card">
            <h4><i class="bi bi-info-circle"></i> Como Usar PGP</h4>
            <div class="row">
                <div class="col-md-6">
                    <h6 style="color: var(--primary-light); margin-bottom: 1rem;">📥 Para nos enviar mensagem criptografada:</h6>
                    <ol style="margin-left: 1.5rem; color: var(--text-secondary);">
                        <li>Copie nossa chave pública acima</li>
                        <li>Importe em seu software PGP (GPG, Kleopatra, etc.)</li>
                        <li>Criptografe sua mensagem com nossa chave</li>
                        <li>Envie através do formulário de contato</li>
                    </ol>
                </div>
                <div class="col-md-6">
                    <h6 style="color: var(--accent); margin-bottom: 1rem;">🔧 Software PGP recomendado:</h6>
                    <ul style="margin-left: 1.5rem; color: var(--text-secondary);">
                        <li><strong>Windows:</strong> Kleopatra, GPG4Win</li>
                        <li><strong>macOS:</strong> GPG Suite</li>
                        <li><strong>Linux:</strong> GnuPG (comando gpg)</li>
                        <li><strong>Email:</strong> Thunderbird + Enigmail</li>
                    </ul>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- System Status -->
        <div class="glass-card">
            <h4><i class="bi bi-server"></i> Status do Sistema</h4>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--success);">✓</div>
                    <div class="stat-label">Detecção TOR</div>
                    <small style="color: var(--success);">FUNCIONANDO</small>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: <?= $pgpConfigured ? 'var(--success)' : 'var(--danger)' ?>;">
                        <?= $pgpConfigured ? '✓' : '✗' ?>
                    </div>
                    <div class="stat-label">Sistema PGP</div>
                    <small style="color: <?= $pgpConfigured ? 'var(--success)' : 'var(--danger)' ?>;">
                        <?= $pgpConfigured ? 'FUNCIONANDO' : 'DESCONFIGURADO' ?>
                    </small>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--success);">✓</div>
                    <div class="stat-label">Criptografia SSL</div>
                    <small style="color: var(--success);">ATIVA</small>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--info);"><?= htmlspecialchars($mixingCount, ENT_QUOTES, 'UTF-8') ?></div>
                    <div class="stat-label">Mixing Usado</div>
                    <small style="color: var(--text-muted);">TRANSAÇÕES</small>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="glass-card">
            <h4><i class="bi bi-lightning"></i> Ações Rápidas</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1.5rem;">
                <a href="dashboard.php" class="btn-modern btn-primary">
                    <i class="bi bi-house"></i> Voltar ao Dashboard
                </a>
                <a href="painel_usuario.php" class="btn-modern btn-info">
                    <i class="bi bi-shield-check"></i> Configurar 2FA
                </a>
                <a href="alterar_senha.php" class="btn-modern btn-warning">
                    <i class="bi bi-key"></i> Alterar Senha
                </a>
                <?php if (!$torDetected): ?>
                <a href="https://torproject.org" target="_blank" class="btn-modern btn-success">
                    <i class="bi bi-download"></i> Baixar Tor Browser
                </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ✅ FUNÇÃO SEGURA PARA COPIAR TEXTO
        function copyToClipboard(elementId) {
            const textElement = document.getElementById(elementId);
            if (!textElement) {
                showAlert('error', 'Elemento não encontrado');
                return;
            }

            const text = textElement.textContent || textElement.innerText;
            
            navigator.clipboard.writeText(text.trim()).then(() => {
                showAlert('success', 'Copiado para a área de transferência!');
            }).catch(() => {
                // Fallback para navegadores antigos
                try {
                    const range = document.createRange();
                    range.selectNode(textElement);
                    window.getSelection().removeAllRanges();
                    window.getSelection().addRange(range);
                    document.execCommand('copy');
                    window.getSelection().removeAllRanges();
                    showAlert('success', 'Copiado para a área de transferência!');
                } catch (err) {
                    showAlert('error', 'Erro ao copiar. Por favor, copie manualmente.');
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

        // ✅ ANIMAÇÃO DA BARRA DE PROGRESSO
        document.addEventListener('DOMContentLoaded', function() {
            const progressBar = document.querySelector('.progress-bar-modern');
            if (progressBar) {
                const targetWidth = progressBar.style.width;
                progressBar.style.width = '0%';
                setTimeout(() => {
                    progressBar.style.width = targetWidth;
                }, 500);
            }

            // Auto-fechar alertas
            setTimeout(() => {
                document.querySelectorAll('.alert').forEach(alert => {
                    const bsAlert = bootstrap.Alert.getInstance(alert);
                    if (bsAlert) {
                        bsAlert.close();
                    }
                });
            }, 5000);

            console.log('✅ Privacy Settings carregado com sucesso!');
        });

        // ✅ VERIFICAÇÃO PERIÓDICA DE TOR (OPCIONAL)
        function checkTorPeriodically() {
            // Verificar indicadores básicos de TOR
            const userAgent = navigator.userAgent;
            const isTorLike = userAgent.includes('Firefox') && 
                             !userAgent.includes('Chrome') && 
                             navigator.language === 'en-US';
            
            if (isTorLike && !document.querySelector('.status-active')) {
                console.log('🔍 Possível uso de TOR detectado - considere atualizar a página');
            }
        }

        // Verificar TOR a cada 30 segundos (opcional)
        setInterval(checkTorPeriodically, 30000);
    </script>
</body>
</html>