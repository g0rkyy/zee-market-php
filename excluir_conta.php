<?php
/**
 * PÁGINA DE EXCLUSÃO DE CONTA
 * Versão corrigida com design moderno e segurança avançada
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'includes/config.php';
require_once 'includes/functions.php';

// ✅ VERIFICAR LOGIN COM FUNÇÃO CORRETA
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// ✅ GERAR TOKEN CSRF SEGURO
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$erro = '';
$user_id = $_SESSION['user_id'];
$user_name = $_SESSION['user_name'] ?? 'Usuário';

// ✅ PROCESSAR EXCLUSÃO COM SEGURANÇA MÁXIMA
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar CSRF
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("Tentativa de CSRF na exclusão de conta - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - User ID: " . $user_id);
        die("🛡️ ERRO DE SEGURANÇA: Token CSRF inválido. Operação bloqueada por segurança.");
    }

    // ✅ VALIDAR ENTRADAS
    $senha_confirmacao = trim($_POST['senha_confirmacao'] ?? '');
    $confirmacao_texto = trim($_POST['confirmacao_texto'] ?? '');
    $motivo_exclusao = trim($_POST['motivo_exclusao'] ?? 'Não informado');

    // Validações rigorosas para exclusão
    if (empty($senha_confirmacao)) {
        $erro = "Digite sua senha para confirmar a exclusão.";
    } elseif (strtoupper($confirmacao_texto) !== 'EXCLUIR') {
        $erro = "Digite 'EXCLUIR' (em maiúsculas) para confirmar que deseja apagar sua conta.";
    } else {
        try {
            // ✅ VERIFICAR SENHA DO USUÁRIO
            $stmt = $conn->prepare("SELECT password, email FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();

            if (!$user || !password_verify($senha_confirmacao, $user['password'])) {
                $erro = "Senha incorreta. Exclusão cancelada por segurança.";
                // Log de tentativa suspeita
                error_log("Tentativa de exclusão com senha incorreta - User ID: $user_id - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            } else {
                // ✅ INICIAR TRANSAÇÃO PARA EXCLUSÃO SEGURA
                $conn->begin_transaction();
                
                try {
                    // 1. Log da exclusão para auditoria (ANTES de excluir)
                    $user_email = $user['email'];
                    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
                    
                    // 2. Criar tabela de log se não existir
                    $conn->query("CREATE TABLE IF NOT EXISTS account_deletions (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        email VARCHAR(255) NOT NULL,
                        user_name VARCHAR(255) NOT NULL,
                        reason TEXT,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )");

                    // 3. Salvar log da exclusão
                    $stmt_log = $conn->prepare("INSERT INTO account_deletions (user_id, email, user_name, reason, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)");
                    $stmt_log->bind_param("isssss", $user_id, $user_email, $user_name, $motivo_exclusao, $ip_address, $user_agent);
                    $stmt_log->execute();
                    $stmt_log->close();

                    // 4. Remover dados relacionados (verificar se tabelas existem)
                    $tabelas_relacionadas = [
                        'feedback' => 'email',
                        'btc_transactions' => 'user_id',
                        'user_sessions' => 'user_id',
                        'user_access_logs' => 'user_id',
                        'encrypted_messages' => 'user_id',
                        'bitcoin_mixing' => 'input_address',
                        'advanced_mixing' => 'user_id'
                    ];

                    foreach ($tabelas_relacionadas as $tabela => $campo) {
                        try {
                            // Verificar se tabela existe
                            $stmt_check = $conn->prepare("SHOW TABLES LIKE ?");
                            $stmt_check->bind_param("s", $tabela);
                            $stmt_check->execute();
                            
                            if ($stmt_check->get_result()->num_rows > 0) {
                                if ($campo === 'email') {
                                    $stmt_del = $conn->prepare("DELETE FROM $tabela WHERE $campo = ?");
                                    $stmt_del->bind_param("s", $user_email);
                                } elseif ($campo === 'input_address') {
                                    // Para tabela bitcoin_mixing, usar endereço BTC do usuário
                                    $stmt_btc = $conn->prepare("SELECT btc_wallet FROM users WHERE id = ?");
                                    $stmt_btc->bind_param("i", $user_id);
                                    $stmt_btc->execute();
                                    $btc_result = $stmt_btc->get_result()->fetch_assoc();
                                    $stmt_btc->close();
                                    
                                    if ($btc_result && !empty($btc_result['btc_wallet'])) {
                                        $stmt_del = $conn->prepare("DELETE FROM $tabela WHERE $campo = ?");
                                        $stmt_del->bind_param("s", $btc_result['btc_wallet']);
                                    } else {
                                        continue;
                                    }
                                } else {
                                    $stmt_del = $conn->prepare("DELETE FROM $tabela WHERE $campo = ?");
                                    $stmt_del->bind_param("i", $user_id);
                                }
                                $stmt_del->execute();
                                $stmt_del->close();
                            }
                            $stmt_check->close();
                        } catch (Exception $e) {
                            // Continuar mesmo se houver erro em uma tabela específica
                            error_log("Erro ao limpar tabela $tabela: " . $e->getMessage());
                        }
                    }
                    
                    // 5. REMOVER O USUÁRIO (AÇÃO FINAL)
                    $stmt_user = $conn->prepare("DELETE FROM users WHERE id = ?");
                    $stmt_user->bind_param("i", $user_id);
                    
                    if ($stmt_user->execute()) {
                        $stmt_user->close();
                        
                        // ✅ COMMIT DA TRANSAÇÃO
                        $conn->commit();
                        
                        // Log final de sucesso
                        error_log("Conta excluída com sucesso - User ID: $user_id - Email: $user_email - IP: $ip_address");
                        
                        // ✅ DESTRUIR SESSÃO E REDIRECIONAR
                        session_destroy();
                        header("Location: index.php?msg=conta_excluida");
                        exit();
                    } else {
                        throw new Exception("Erro ao excluir usuário da base de dados");
                    }
                    
                } catch (Exception $e) {
                    // ✅ ROLLBACK EM CASO DE ERRO
                    $conn->rollback();
                    error_log("Erro na exclusão de conta - User ID: $user_id - Erro: " . $e->getMessage());
                    $erro = "Erro interno. Sua conta não foi excluída. Tente novamente ou entre em contato com o suporte.";
                }
            }
        } catch (Exception $e) {
            error_log("Exceção na exclusão de conta - User ID: $user_id - Erro: " . $e->getMessage());
            $erro = "Erro interno no sistema. Operação cancelada por segurança.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeeMarket - Excluir Conta</title>
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {
            --primary: #8B5CF6;
            --danger: #EF4444;
            --danger-dark: #DC2626;
            --warning: #F59E0B;
            --success: #10B981;
            --info: #3B82F6;
            
            --bg-primary: #0F0F0F;
            --bg-secondary: #1A1A1A;
            --bg-tertiary: #262626;
            --bg-danger: #1F1111;
            
            --text-primary: #FFFFFF;
            --text-secondary: #D1D5DB;
            --text-muted: #9CA3AF;
            --text-danger: #FCA5A5;
            
            --border: #374151;
            --border-danger: #B91C1C;
            
            --glass: rgba(255, 255, 255, 0.05);
            --glass-danger: rgba(239, 68, 68, 0.1);
            --glass-border: rgba(255, 255, 255, 0.1);
            
            --shadow-sm: 0 2px 4px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.5);
            --shadow-xl: 0 16px 48px rgba(0, 0, 0, 0.6);
            --shadow-danger: 0 8px 24px rgba(239, 68, 68, 0.3);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, #2D1B16 50%, var(--bg-danger) 100%);
            color: var(--text-primary);
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }
        
        /* Animated danger background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(239, 68, 68, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(220, 38, 38, 0.06) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(185, 28, 28, 0.04) 0%, transparent 50%);
            z-index: -1;
        }
        
        .main-container {
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1;
        }
        
        .danger-card {
            background: var(--glass-danger);
            backdrop-filter: blur(20px);
            border: 2px solid var(--border-danger);
            border-radius: 20px;
            box-shadow: var(--shadow-danger);
            position: relative;
            overflow: hidden;
            animation: dangerPulse 3s ease-in-out infinite;
        }
        
        @keyframes dangerPulse {
            0%, 100% { box-shadow: var(--shadow-danger); }
            50% { box-shadow: 0 8px 32px rgba(239, 68, 68, 0.5); }
        }
        
        .danger-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--danger), var(--danger-dark), var(--danger));
            border-radius: 20px 20px 0 0;
        }
        
        .danger-header {
            background: rgba(239, 68, 68, 0.15);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-danger);
            padding: 2rem;
            text-align: center;
            position: relative;
        }
        
        .danger-title {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--danger), #FF6B6B);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
        }
        
        .danger-subtitle {
            font-size: 1.2rem;
            color: var(--text-danger);
            font-weight: 500;
        }
        
        .danger-body {
            padding: 2rem;
        }
        
        .warning-zone {
            background: rgba(185, 28, 28, 0.1);
            border: 2px solid var(--danger);
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
            position: relative;
            overflow: hidden;
        }
        
        .warning-zone::before {
            content: '⚠️';
            position: absolute;
            top: -10px;
            right: -10px;
            font-size: 3rem;
            opacity: 0.1;
            animation: warningFloat 2s ease-in-out infinite alternate;
        }
        
        @keyframes warningFloat {
            0% { transform: translateY(0px) rotate(0deg); }
            100% { transform: translateY(-10px) rotate(5deg); }
        }
        
        .warning-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--danger);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .consequences-list {
            list-style: none;
            padding: 0;
        }
        
        .consequences-list li {
            padding: 0.75rem 0;
            border-bottom: 1px solid rgba(239, 68, 68, 0.2);
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: all 0.3s ease;
        }
        
        .consequences-list li:hover {
            background: rgba(239, 68, 68, 0.05);
            transform: translateX(5px);
        }
        
        .consequences-list li:last-child {
            border-bottom: none;
        }
        
        .consequences-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--danger), var(--danger-dark));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            flex-shrink: 0;
        }
        
        .form-control {
            background: rgba(255,255,255,0.05);
            border: 2px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            padding: 1rem 1.25rem;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            background: rgba(255,255,255,0.08);
            border-color: var(--danger);
            box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.15);
            color: var(--text-primary);
        }
        
        .form-control::placeholder {
            color: var(--text-muted);
        }
        
        .form-control.valid {
            border-color: var(--success);
            box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);
        }
        
        .form-control.invalid {
            border-color: var(--danger);
            box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.2);
        }
        
        .btn-modern {
            padding: 1rem 2rem;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            position: relative;
            overflow: hidden;
            text-transform: uppercase;
            letter-spacing: 0.5px;
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
            width: 300px;
            height: 300px;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), var(--danger-dark));
            color: white;
            box-shadow: var(--shadow-danger);
        }
        
        .btn-danger:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 32px rgba(239, 68, 68, 0.4);
            color: white;
        }
        
        .btn-danger:disabled {
            background: rgba(107, 114, 128, 0.3);
            color: var(--text-muted);
            cursor: not-allowed;
            box-shadow: none;
        }
        
        .btn-danger:disabled:hover {
            transform: none;
            box-shadow: none;
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success), #14B8A6);
            color: white;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        
        .btn-success:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 24px rgba(16, 185, 129, 0.4);
            color: white;
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
            background: var(--success);
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
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
        
        .alert-danger {
            background: rgba(239, 68, 68, 0.15);
            color: var(--text-danger);
            border-color: var(--danger);
        }
        
        .security-badge {
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, var(--danger), var(--danger-dark));
            color: white;
            padding: 0.75rem 1.25rem;
            border-radius: 25px;
            font-size: 0.875rem;
            font-weight: 600;
            z-index: 9999;
            box-shadow: var(--shadow-lg);
            animation: securityPulse 2s ease-in-out infinite;
        }
        
        @keyframes securityPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .progress-steps {
            display: flex;
            justify-content: space-between;
            margin: 2rem 0;
            padding: 0 1rem;
        }
        
        .step {
            display: flex;
            flex-direction: column;
            align-items: center;
            flex: 1;
            position: relative;
        }
        
        .step::after {
            content: '';
            position: absolute;
            top: 1.5rem;
            left: 50%;
            width: 100%;
            height: 2px;
            background: var(--border);
            z-index: -1;
        }
        
        .step:last-child::after {
            display: none;
        }
        
        .step-number {
            width: 3rem;
            height: 3rem;
            background: var(--border);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-bottom: 0.5rem;
            transition: all 0.3s ease;
        }
        
        .step-number.active {
            background: linear-gradient(135deg, var(--danger), var(--danger-dark));
            color: white;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }
        
        .step-label {
            font-size: 0.875rem;
            color: var(--text-muted);
            text-align: center;
        }
        
        .countdown {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--danger);
            text-align: center;
            margin: 1rem 0;
        }
        
        @media (max-width: 768px) {
            .main-container {
                padding: 1rem;
            }
            
            .danger-title {
                font-size: 2rem;
            }
            
            .progress-steps {
                flex-direction: column;
                gap: 1rem;
            }
            
            .step::after {
                display: none;
            }
        }
    </style>
</head>
<body>
    <a href="dashboard.php" class="nav-btn">
        <i class="bi bi-arrow-left"></i> Voltar ao Dashboard
    </a>

    <div class="security-badge">
        🛡️ ZONA DE PERIGO
    </div>

    <div class="main-container">
        <div class="danger-card">
            <div class="danger-header">
                <h1 class="danger-title">
                    <i class="bi bi-exclamation-triangle"></i> EXCLUIR CONTA
                </h1>
                <p class="danger-subtitle">Esta ação é irreversível e permanente</p>
            </div>
            
            <div class="danger-body">
                <?php if (!empty($erro)): ?>
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($erro, ENT_QUOTES, 'UTF-8') ?>
                    </div>
                <?php endif; ?>

                <!-- Progress Steps -->
                <div class="progress-steps">
                    <div class="step">
                        <div class="step-number" id="step1">1</div>
                        <div class="step-label">Confirmar Senha</div>
                    </div>
                    <div class="step">
                        <div class="step-number" id="step2">2</div>
                        <div class="step-label">Digite "EXCLUIR"</div>
                    </div>
                    <div class="step">
                        <div class="step-number" id="step3">3</div>
                        <div class="step-label">Confirmação Final</div>
                    </div>
                </div>

                <!-- Warning Zone -->
                <div class="warning-zone">
                    <div class="warning-title">
                        <i class="bi bi-exclamation-triangle"></i>
                        ATENÇÃO: Esta ação é irreversível!
                    </div>
                    <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                        <strong>Ao excluir sua conta permanentemente:</strong>
                    </p>
                    
                    <ul class="consequences-list">
                        <li>
                            <div class="consequences-icon">🗑️</div>
                            <div>
                                <strong>Todos os seus dados serão permanentemente apagados</strong><br>
                                <small style="color: var(--text-muted);">Incluindo perfil, configurações e histórico</small>
                            </div>
                        </li>
                        <li>
                            <div class="consequences-icon">💰</div>
                            <div>
                                <strong>Seu histórico de transações será perdido</strong><br>
                                <small style="color: var(--text-muted);">Bitcoin, Ethereum, Monero e outras criptomoedas</small>
                            </div>
                        </li>
                        <li>
                            <div class="consequences-icon">🔒</div>
                            <div>
                                <strong>Não será possível recuperar esta conta</strong><br>
                                <small style="color: var(--text-muted);">Nenhum backup ou restauração será possível</small>
                            </div>
                        </li>
                        <li>
                            <div class="consequences-icon">🚫</div>
                            <div>
                                <strong>Você perderá acesso a todos os serviços</strong><br>
                                <small style="color: var(--text-muted);">ZeeMarket, PGP, Mixing e ferramentas de privacidade</small>
                            </div>
                        </li>
                    </ul>
                </div>

                <!-- Deletion Form -->
                <form method="POST" id="deletionForm" onsubmit="return confirmarExclusao()">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    
                    <div class="mb-4">
                        <label for="senha_confirmacao" class="form-label" style="font-weight: 600; color: var(--text-primary);">
                            <i class="bi bi-key"></i> Digite sua senha para confirmar:
                        </label>
                        <input type="password" id="senha_confirmacao" name="senha_confirmacao" 
                               class="form-control" required placeholder="Sua senha atual"
                               autocomplete="current-password">
                    </div>
                    
                    <div class="mb-4">
                        <label for="confirmacao_texto" class="form-label" style="font-weight: 600; color: var(--text-primary);">
                            <i class="bi bi-type"></i> Digite "EXCLUIR" (em maiúsculas) para confirmar:
                        </label>
                        <input type="text" id="confirmacao_texto" name="confirmacao_texto" 
                               class="form-control" required placeholder="Digite: EXCLUIR"
                               autocomplete="off">
                    </div>
                    
                    <div class="mb-4">
                        <label for="motivo_exclusao" class="form-label" style="font-weight: 600; color: var(--text-primary);">
                            <i class="bi bi-chat-text"></i> Motivo da exclusão (opcional):
                        </label>
                        <select name="motivo_exclusao" id="motivo_exclusao" class="form-control">
                            <option value="Não informado">Prefiro não informar</option>
                            <option value="Não uso mais">Não uso mais o serviço</option>
                            <option value="Problemas de segurança">Preocupações com segurança</option>
                            <option value="Interface complexa">Interface muito complexa</option>
                            <option value="Falta de recursos">Falta de recursos que preciso</option>
                            <option value="Problemas técnicos">Problemas técnicos recorrentes</option>
                            <option value="Mudança de plataforma">Mudando para outra plataforma</option>
                            <option value="Questões de privacidade">Questões de privacidade</option>
                            <option value="Outro">Outro motivo</option>
                        </select>
                    </div>
                    
                    <!-- Countdown Timer -->
                    <div class="countdown" id="countdown" style="display: none;">
                        Exclusão em: <span id="timer">10</span> segundos
                    </div>
                    
                    <div style="display: grid; gap: 1rem; margin-top: 2rem;">
                        <button type="submit" class="btn-modern btn-danger" id="deleteBtn" disabled>
                            <i class="bi bi-trash"></i> EXCLUIR MINHA CONTA PERMANENTEMENTE
                        </button>
                        <a href="dashboard.php" class="btn-modern btn-success">
                            <i class="bi bi-shield-check"></i> Cancelar - Manter Minha Conta
                        </a>
                    </div>
                </form>

                <!-- Additional Security Info -->
                <div style="margin-top: 3rem; padding-top: 2rem; border-top: 1px solid var(--border);">
                    <h5 style="color: var(--text-primary); margin-bottom: 1rem;">
                        <i class="bi bi-info-circle"></i> Informações de Segurança
                    </h5>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
                        <div style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 12px;">
                            <strong style="color: var(--info);">📊 Dados Coletados:</strong><br>
                            <small style="color: var(--text-muted);">
                                Log da exclusão será mantido por 90 dias para auditoria de segurança
                            </small>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 12px;">
                            <strong style="color: var(--warning);">🔐 Dados Sensíveis:</strong><br>
                            <small style="color: var(--text-muted);">
                                Senhas e chaves privadas são imediatamente apagadas
                            </small>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 12px;">
                            <strong style="color: var(--success);">♻️ Recuperação:</strong><br>
                            <small style="color: var(--text-muted);">
                                Nenhuma recuperação possível após confirmação
                            </small>
                        </div>
                    </div>
                </div>

                <!-- Alternative Options -->
                <div style="margin-top: 2rem; padding: 1.5rem; background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success); border-radius: 12px;">
                    <h6 style="color: var(--success); margin-bottom: 1rem;">
                        <i class="bi bi-lightbulb"></i> Alternativas à Exclusão
                    </h6>
                    <div style="color: var(--text-secondary);">
                        <p style="margin-bottom: 1rem;">Antes de excluir, considere estas opções:</p>
                        <ul style="margin-left: 1.5rem;">
                            <li><strong>Alterar senha:</strong> Se há preocupações de segurança</li>
                            <li><strong>Configurar 2FA:</strong> Para melhor proteção</li>
                            <li><strong>Limpar histórico:</strong> Manter conta mas remover dados</li>
                            <li><strong>Desativar temporariamente:</strong> Pausa sem perder dados</li>
                        </ul>
                        <div style="margin-top: 1rem;">
                            <a href="alterar_senha.php" class="btn-modern" style="background: var(--success); color: white; padding: 0.5rem 1rem; text-decoration: none; font-size: 0.875rem;">
                                <i class="bi bi-key"></i> Alterar Senha
                            </a>
                            <a href="painel_usuario.php" class="btn-modern" style="background: var(--info); color: white; padding: 0.5rem 1rem; text-decoration: none; font-size: 0.875rem; margin-left: 0.5rem;">
                                <i class="bi bi-shield"></i> Configurar 2FA
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ✅ VARIÁVEIS GLOBAIS
        let currentStep = 1;
        let passwordValid = false;
        let textValid = false;
        let countdownActive = false;

        // ✅ FUNÇÃO DE CONFIRMAÇÃO FINAL
        function confirmarExclusao() {
            if (countdownActive) {
                return false;
            }

            const confirmacao = document.getElementById('confirmacao_texto').value;
            
            if (confirmacao !== 'EXCLUIR') {
                showAlert('error', 'Você deve digitar "EXCLUIR" para confirmar a exclusão da conta.');
                return false;
            }
            
            // Iniciar countdown
            startCountdown();
            return false; // Impedir submit imediato
        }

        // ✅ COUNTDOWN DE SEGURANÇA
        function startCountdown() {
            const countdownEl = document.getElementById('countdown');
            const timerEl = document.getElementById('timer');
            const deleteBtn = document.getElementById('deleteBtn');
            
            countdownActive = true;
            countdownEl.style.display = 'block';
            deleteBtn.disabled = true;
            deleteBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> AGUARDE...';
            
            let timeLeft = 10;
            timerEl.textContent = timeLeft;
            
            const countdownInterval = setInterval(() => {
                timeLeft--;
                timerEl.textContent = timeLeft;
                
                if (timeLeft <= 0) {
                    clearInterval(countdownInterval);
                    
                    // Confirmação final
                    const finalConfirm = confirm(
                        '🚨 ÚLTIMA CHANCE! 🚨\n\n' +
                        'Você tem CERTEZA ABSOLUTA de que deseja excluir sua conta?\n\n' +
                        '• Esta ação é IRREVERSÍVEL\n' +
                        '• Todos os seus dados serão PERDIDOS PARA SEMPRE\n' +
                        '• Não há como desfazer esta operação\n' +
                        '• Você perderá acesso a todas as funcionalidades\n\n' +
                        'Clique OK apenas se tiver CERTEZA TOTAL.\n' +
                        'Clique Cancelar para manter sua conta segura.'
                    );
                    
                    if (finalConfirm) {
                        // Submeter formulário real
                        deleteBtn.innerHTML = '<i class="bi bi-trash"></i> EXCLUINDO...';
                        document.getElementById('deletionForm').submit();
                    } else {
                        // Cancelar operação
                        countdownActive = false;
                        countdownEl.style.display = 'none';
                        deleteBtn.disabled = true;
                        deleteBtn.innerHTML = '<i class="bi bi-trash"></i> EXCLUIR MINHA CONTA PERMANENTEMENTE';
                        showAlert('success', 'Operação cancelada. Sua conta está segura.');
                        updateStepProgress();
                    }
                }
            }, 1000);
        }

        // ✅ VALIDAÇÃO EM TEMPO REAL
        document.getElementById('senha_confirmacao').addEventListener('input', function() {
            const senha = this.value;
            
            if (senha.length >= 8) {
                this.classList.remove('invalid');
                this.classList.add('valid');
                passwordValid = true;
                updateStepProgress();
            } else {
                this.classList.remove('valid');
                this.classList.add('invalid');
                passwordValid = false;
                updateStepProgress();
            }
        });
        
        document.getElementById('confirmacao_texto').addEventListener('input', function() {
            const texto = this.value;
            const deleteBtn = document.getElementById('deleteBtn');
            
            if (texto === 'EXCLUIR') {
                this.classList.remove('invalid');
                this.classList.add('valid');
                textValid = true;
                updateStepProgress();
            } else {
                this.classList.remove('valid');
                this.classList.add('invalid');
                textValid = false;
                deleteBtn.disabled = true;
                updateStepProgress();
            }
        });

        // ✅ ATUALIZAR PROGRESSO DOS STEPS
        function updateStepProgress() {
            const step1 = document.getElementById('step1');
            const step2 = document.getElementById('step2');
            const step3 = document.getElementById('step3');
            const deleteBtn = document.getElementById('deleteBtn');
            
            // Reset all steps
            [step1, step2, step3].forEach(step => step.classList.remove('active'));
            
            if (passwordValid) {
                step1.classList.add('active');
                currentStep = Math.max(currentStep, 2);
            }
            
            if (passwordValid && textValid) {
                step1.classList.add('active');
                step2.classList.add('active');
                currentStep = 3;
                deleteBtn.disabled = false;
            } else {
                deleteBtn.disabled = true;
            }
        }

        // ✅ FUNÇÃO PARA MOSTRAR ALERTAS
        function showAlert(type, message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type}`;
            alertDiv.style.cssText = `
                position: fixed;
                top: 80px;
                right: 20px;
                z-index: 9999;
                min-width: 300px;
                max-width: 400px;
            `;
            alertDiv.innerHTML = `
                <i class="bi bi-${type === 'error' ? 'exclamation-triangle' : 'check-circle'}"></i> 
                ${message.replace(/[<>]/g, '')}
            `;
            
            document.body.appendChild(alertDiv);
            
            // Auto-remover após 5 segundos
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        }

        // ✅ PREVENÇÃO DE SAÍDA ACIDENTAL
        window.addEventListener('beforeunload', function(e) {
            if (passwordValid || textValid) {
                const message = 'Você tem dados não salvos. Tem certeza que deseja sair?';
                e.returnValue = message;
                return message;
            }
        });

        // ✅ INICIALIZAÇÃO
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-focar no primeiro campo
            document.getElementById('senha_confirmacao').focus();

            // Inicializar estado dos botões
            updateStepProgress();

            // Auto-fechar alertas existentes
            setTimeout(() => {
                document.querySelectorAll('.alert').forEach(alert => {
                    if (alert.style.position !== 'fixed') {
                        alert.remove();
                    }
                });
            }, 5000);

            console.log('✅ Delete Account page carregado com sucesso!');
        });

        // ✅ ATALHOS DE TECLADO
        document.addEventListener('keydown', function(e) {
            // ESC para cancelar
            if (e.key === 'Escape') {
                if (confirm('Cancelar processo de exclusão?')) {
                    window.location.href = 'dashboard.php';
                }
            }
            
            // Ctrl+Enter para avançar (apenas se válido)
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (passwordValid && textValid && !countdownActive) {
                    e.preventDefault();
                    confirmarExclusao();
                }
            }
        });

        // ✅ VALIDAÇÃO ADICIONAL DE SEGURANÇA
        document.getElementById('deletionForm').addEventListener('submit', function(e) {
            // Verificações finais de segurança
            const senha = document.getElementById('senha_confirmacao').value;
            const confirmacao = document.getElementById('confirmacao_texto').value;
            
            if (senha.length < 3) {
                e.preventDefault();
                showAlert('error', 'Senha muito curta para ser válida.');
                return false;
            }
            
            if (confirmacao !== 'EXCLUIR') {
                e.preventDefault();
                showAlert('error', 'Confirmação incorreta. Digite "EXCLUIR" exatamente.');
                return false;
            }
            
            // Log da tentativa (para auditoria)
            console.log('Tentativa de exclusão de conta iniciada');
        });

        // ✅ ANIMAÇÃO DE ENTRADA
        document.addEventListener('DOMContentLoaded', function() {
            const card = document.querySelector('.danger-card');
            card.style.opacity = '0';
            card.style.transform = 'translateY(50px)';
            
            setTimeout(() => {
                card.style.transition = 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, 100);
        });

        // ✅ DETECTAR PASTE SUSPEITO
        document.getElementById('confirmacao_texto').addEventListener('paste', function(e) {
            e.preventDefault();
            showAlert('error', 'Cole não é permitido. Digite manualmente "EXCLUIR" para confirmar.');
        });

        // ✅ MONITORAR TENTATIVAS SUSPEITAS
        let tentativas = 0;
        document.getElementById('deletionForm').addEventListener('submit', function(e) {
            tentativas++;
            if (tentativas > 3) {
                e.preventDefault();
                showAlert('error', 'Muitas tentativas. Aguarde 60 segundos antes de tentar novamente.');
                setTimeout(() => { tentativas = 0; }, 60000);
                return false;
            }
        });
    </script>
</body>
</html>