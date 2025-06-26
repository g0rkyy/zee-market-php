<?php 
/**
 * FEEDBACK SYSTEM - VERSÃO FINAL CORRIGIDA
 * Compatível com a estrutura existente da tabela
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ✅ INICIALIZAR SESSÃO SEGURA
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'includes/functions.php';
require_once 'includes/config.php';

// ✅ VERIFICAR CONEXÃO COM BANCO
if (!$conn) {
    error_log("❌ ERRO DE CONEXÃO DB - feedback.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    die("Erro na conexão com o banco de dados. Tente novamente mais tarde.");
}

// ✅ CORRIGIR ESTRUTURA DA TABELA SE NECESSÁRIO
try {
    // Verificar se as colunas ip_address e user_agent existem
    $columns_check = $conn->query("SHOW COLUMNS FROM feedback LIKE 'ip_address'");
    if ($columns_check->num_rows == 0) {
        // Adicionar colunas que faltam
        $conn->query("ALTER TABLE feedback ADD COLUMN ip_address VARCHAR(45) DEFAULT NULL");
        $conn->query("ALTER TABLE feedback ADD COLUMN user_agent TEXT DEFAULT NULL");
        $conn->query("ALTER TABLE feedback ADD INDEX idx_ip_address (ip_address)");
        error_log("✅ Colunas ip_address e user_agent adicionadas à tabela feedback");
    }
    
    // Verificar se email tem tamanho suficiente
    $email_check = $conn->query("SHOW COLUMNS FROM feedback WHERE Field = 'email'");
    if ($email_check) {
        $email_info = $email_check->fetch_assoc();
        if (strpos($email_info['Type'], 'varchar(100)') !== false) {
            $conn->query("ALTER TABLE feedback MODIFY COLUMN email VARCHAR(255)");
            error_log("✅ Coluna email expandida para VARCHAR(255)");
        }
    }
    
} catch (Exception $e) {
    error_log("Erro ao corrigir estrutura da tabela: " . $e->getMessage());
}

// ✅ GERAR TOKEN CSRF SE NÃO EXISTIR
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$mensagem_sucesso = '';
$erro_formulario = '';

// ✅ PROCESSAR FORMULÁRIO COM PROTEÇÃO CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 🛡️ VALIDAÇÃO CSRF OBRIGATÓRIA
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("🚨 CSRF ATTACK - feedback.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $erro_formulario = "🛡️ ERRO DE SEGURANÇA: Token CSRF inválido. Operação bloqueada por segurança.";
        $_POST = array();
    } else {
        // ✅ SANITIZAÇÃO E VALIDAÇÃO
        $nome = trim($_POST['name'] ?? '');
        $email_input = trim($_POST['email'] ?? '');
        $feedback = trim($_POST['feedback'] ?? '');
        $rating = isset($_POST['rating']) ? (int)$_POST['rating'] : 0;

        // Sanitização adicional para prevenir XSS
        $nome = htmlspecialchars($nome, ENT_QUOTES, 'UTF-8');
        $email_input = htmlspecialchars($email_input, ENT_QUOTES, 'UTF-8');
        $feedback = htmlspecialchars($feedback, ENT_QUOTES, 'UTF-8');

        // Validação de email
        $email = filter_var($email_input, FILTER_VALIDATE_EMAIL);

        // ✅ VALIDAÇÕES
        $erros = [];

        if (empty($nome)) {
            $erros[] = "Nome é obrigatório";
        } elseif (strlen($nome) < 2) {
            $erros[] = "Nome deve ter pelo menos 2 caracteres";
        } elseif (strlen($nome) > 100) {
            $erros[] = "Nome muito longo (máximo 100 caracteres)";
        }

        if (!$email) {
            $erros[] = "Email inválido";
        } elseif (strlen($email) > 255) {
            $erros[] = "Email muito longo";
        }

        if (empty($feedback)) {
            $erros[] = "Feedback é obrigatório";
        } elseif (strlen($feedback) < 10) {
            $erros[] = "Feedback deve ter pelo menos 10 caracteres";
        } elseif (strlen($feedback) > 2000) {
            $erros[] = "Feedback muito longo (máximo 2000 caracteres)";
        }

        if ($rating < 1 || $rating > 5) {
            $erros[] = "Rating deve ser entre 1 e 5";
        }

        // ✅ VERIFICAÇÃO ANTI-SPAM
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        try {
            $stmt_spam = $conn->prepare("SELECT COUNT(*) as count FROM feedback WHERE ip_address = ? AND data_envio > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
            if ($stmt_spam) {
                $stmt_spam->bind_param("s", $ip_address);
                $stmt_spam->execute();
                $spam_result = $stmt_spam->get_result()->fetch_assoc();
                $stmt_spam->close();
                
                if ($spam_result['count'] > 0) {
                    $erros[] = "Aguarde 5 minutos antes de enviar outro feedback";
                }
            }
        } catch (Exception $e) {
            error_log("Erro ao verificar spam: " . $e->getMessage());
        }

        // ✅ DETECTAR CONTEÚDO SUSPEITO
        $suspicious_patterns = [
            '/\b(viagra|cialis|casino|poker)\b/i',
            '/\b(buy now|click here|free money)\b/i',
            '/<script|javascript:|onclick=/i',
            '/\b(http:\/\/|https:\/\/|www\.)/i'
        ];
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $feedback) || preg_match($pattern, $nome)) {
                $erros[] = "Conteúdo não permitido detectado";
                error_log("🚨 CONTEÚDO SUSPEITO - feedback.php - IP: $ip_address - Nome: $nome");
                break;
            }
        }

        if (!empty($erros)) {
            $erro_formulario = implode(". ", $erros) . ".";
        } else {
            // ✅ INSERÇÃO SEGURA NO BANCO
            try {
                $stmt = $conn->prepare("INSERT INTO feedback (nome, email, feedback, rating, ip_address, user_agent, data_envio) VALUES (?, ?, ?, ?, ?, ?, NOW())");
                
                if (!$stmt) {
                    throw new Exception("Erro na preparação da query: " . $conn->error);
                }
                
                $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 500);
                
                $stmt->bind_param("sssiss", $nome, $email, $feedback, $rating, $ip_address, $user_agent);
                
                if ($stmt->execute()) {
                    if ($stmt->affected_rows > 0) {
                        error_log("✅ FEEDBACK ENVIADO - Nome: $nome - Email: $email - Rating: $rating - IP: $ip_address");
                        
                        $mensagem_sucesso = "✅ Feedback enviado com sucesso! Obrigado pela sua contribuição.";
                        
                        // Regenerar token CSRF
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                        
                        // Limpar POST
                        $_POST = array();
                    } else {
                        throw new Exception("Nenhuma linha foi inserida");
                    }
                } else {
                    throw new Exception("Erro na execução: " . $stmt->error);
                }
                
                $stmt->close();
                
            } catch (Exception $e) {
                error_log("❌ ERRO AO INSERIR FEEDBACK - IP: $ip_address - Erro: " . $e->getMessage());
                $erro_formulario = "❌ Erro interno ao enviar feedback. Tente novamente.";
            }
        }
    }
}

// ✅ CONFIGURAÇÃO DE PAGINAÇÃO
$itens_por_pagina = 5;
$pagina_atual = isset($_GET['pagina']) ? (int)$_GET['pagina'] : 1;
if ($pagina_atual < 1) $pagina_atual = 1;
if ($pagina_atual > 1000) $pagina_atual = 1000;

$offset = ($pagina_atual - 1) * $itens_por_pagina;

// ✅ CONTAR TOTAL DE FEEDBACKS
$total_feedbacks = 0;
try {
    $count_stmt = $conn->prepare("SELECT COUNT(*) as total FROM feedback");
    if ($count_stmt) {
        $count_stmt->execute();
        $count_result = $count_stmt->get_result();
        if ($count_result) {
            $total_feedbacks = $count_result->fetch_assoc()['total'];
        }
        $count_stmt->close();
    }
} catch (Exception $e) {
    error_log("Erro ao contar feedbacks: " . $e->getMessage());
}

$total_paginas = $total_feedbacks > 0 ? ceil($total_feedbacks / $itens_por_pagina) : 1;

if ($pagina_atual > $total_paginas && $total_paginas > 0) {
    $pagina_atual = $total_paginas;
    $offset = ($pagina_atual - 1) * $itens_por_pagina;
}

// ✅ BUSCAR FEEDBACKS
$feedbacks = [];
try {
    $query = "SELECT nome, feedback, rating, data_envio FROM feedback ORDER BY data_envio DESC LIMIT ?, ?";
    $stmt = $conn->prepare($query);
    if ($stmt) {
        $stmt->bind_param("ii", $offset, $itens_por_pagina);
        $stmt->execute();
        $resultados = $stmt->get_result();
        if ($resultados) {
            $feedbacks = $resultados->fetch_all(MYSQLI_ASSOC);
        }
        $stmt->close();
    }
} catch (Exception $e) {
    error_log("Erro ao buscar feedbacks: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="ZeeMarket - Sistema de Feedback Seguro">
    <meta name="robots" content="index, follow">
    <title>ZeeMarket - Feedback</title>
    <link rel="icon" href="images/capsule.png" type="image/x-icon">
    
    <!-- CSS -->
    <link rel="stylesheet" href="assets/css/feedback.css?v=<?= time() ?>">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    
    <!-- Security Headers -->
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
</head>
<body>
    <div id="feedback-container" class="">
        <h1 class="text-center color-title">
            <i class="bi bi-chat-heart"></i> Feedback - Chat
        </h1>
        
        <!-- ALERTAS -->
        <?php if (!empty($mensagem_sucesso)): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle"></i> <?= $mensagem_sucesso ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($erro_formulario)): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle"></i> <?= $erro_formulario ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>
        
        <!-- NAVEGAÇÃO -->
        <div id="nav-container">
            <ul class="nav navbar justify-content-center">
                <li class="nav-item"><a class="nav-link c-link-yellow" href="index.php"><i class="bi bi-house"></i> Home</a></li>
                <li class="nav-item"><a class="nav-link" href="FAQ.html"><i class="bi bi-question-circle"></i> FAQ</a></li>
                <li class="nav-item"><a class="nav-link" href="signup.php"><i class="bi bi-person-plus"></i> SignUp</a></li>
                <li class="nav-item"><a class="nav-link" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a></li>
                <li class="nav-item"><a class="nav-link active" href="feedback.php"><i class="bi bi-chat-heart"></i> Feedback</a></li>
            </ul>
        </div>

        <!-- FORMULÁRIO -->
        <form id="feedback-form" method="POST" novalidate>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            
            <div class="mb-3">
                <label for="name" class="form-label form-name-color">
                    <i class="bi bi-person"></i> Nome *
                </label>
                <input type="text" 
                       class="form-control form-bg-color" 
                       id="name" 
                       name="name" 
                       required 
                       maxlength="100"
                       placeholder="Seu nome" 
                       value="<?= htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                       autocomplete="name">
                <div class="form-text">Mínimo 2 caracteres, máximo 100</div>
            </div>
            
            <div class="mb-3">
                <label for="email" class="form-label form-name-color">
                    <i class="bi bi-envelope"></i> Email *
                </label>
                <input type="email" 
                       class="form-control form-bg-color" 
                       id="email" 
                       name="email" 
                       required 
                       maxlength="255"
                       placeholder="seu.email@exemplo.com" 
                       value="<?= htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                       autocomplete="email">
                <div class="form-text">Será usado apenas para resposta se necessário</div>
            </div>
            
            <div class="mb-3">
                <label for="feedback" class="form-label form-name-color">
                    <i class="bi bi-chat-text"></i> Seu Feedback *
                </label>
                <textarea class="form-control form-bg-color" 
                          id="feedback" 
                          name="feedback" 
                          rows="5" 
                          required 
                          maxlength="2000"
                          placeholder="Compartilhe sua experiência, sugestões ou críticas construtivas..."><?= htmlspecialchars($_POST['feedback'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
                <div class="form-text">Mínimo 10 caracteres, máximo 2000. <span id="char-count">0</span>/2000</div>
            </div>
            
            <div class="mb-3">
                <label for="rating" class="form-label form-name-color">
                    <i class="bi bi-star"></i> Avaliação *
                </label>
                <select class="form-select" id="rating" name="rating" required>
                    <option value="" disabled <?= !isset($_POST['rating']) ? 'selected' : '' ?>>Selecione uma avaliação</option>
                    <option value="1" <?= (isset($_POST['rating']) && $_POST['rating'] == 1) ? 'selected' : '' ?>>⭐ 1 - Ruim</option>
                    <option value="2" <?= (isset($_POST['rating']) && $_POST['rating'] == 2) ? 'selected' : '' ?>>⭐⭐ 2 - Regular</option>
                    <option value="3" <?= (isset($_POST['rating']) && $_POST['rating'] == 3) ? 'selected' : '' ?>>⭐⭐⭐ 3 - Bom</option>
                    <option value="4" <?= (isset($_POST['rating']) && $_POST['rating'] == 4) ? 'selected' : '' ?>>⭐⭐⭐⭐ 4 - Muito Bom</option>
                    <option value="5" <?= (isset($_POST['rating']) && $_POST['rating'] == 5) ? 'selected' : '' ?>>⭐⭐⭐⭐⭐ 5 - Excelente</option>
                </select>
            </div>
            
            <div class="mb-3">
                <div class="alert alert-info">
                    <small>
                        <i class="bi bi-shield-check"></i> 
                        <strong>Segurança:</strong> Este formulário é protegido contra spam e ataques. 
                        Seu IP e dados são registrados para fins de segurança.
                    </small>
                </div>
            </div>
            
            <div class="mb-3">
                <button id="button-submit" type="submit" class="btn btn-primary">
                    <i class="bi bi-send"></i> Enviar Feedback
                </button>
                <button type="reset" class="btn btn-secondary ms-2">
                    <i class="bi bi-arrow-clockwise"></i> Limpar
                </button>
            </div>
        </form>
    </div>

    <!-- LISTA DE FEEDBACKS -->
    <div class="mt-5" id="lista-feedbacks">
        <h2 class="text-center color-title">
            <i class="bi bi-chat-dots"></i> Feedbacks Recentes
        </h2>
        
        <?php if (empty($feedbacks)): ?>
            <div class="text-center">
                <div class="alert alert-info">
                    <i class="bi bi-info-circle"></i> Nenhum feedback ainda. Seja o primeiro a compartilhar sua experiência!
                </div>
            </div>
        <?php else: ?>
            <!-- Mensagem da equipe -->
            <div class="list-group-item mb-3" style="background-color: #0a120f; border-left: 4px solid #e1f845;">
                <div class="d-flex justify-content-between">
                    <h5 style="color: #dfbc78;">
                        <i class="bi bi-shield-check"></i> Equipe ZeeMarket
                    </h5>
                    <div class="text-warning">⭐⭐⭐⭐⭐</div>
                </div>
                <p class="mb-1" style="color: #ffdfa1;">
                    🎉 <strong>Bem-vindo ao nosso espaço de feedback!</strong><br>
                    É uma enorme honra receber vocês aqui! Deixe aqui seu feedback para que possamos dar continuidade ao 
                    projeto ZeeMarket e torná-lo ainda melhor. Sua opinião é muito importante para nós!<br>
                    🛡️ <em>Todos os feedbacks são moderados para garantir qualidade e segurança.</em>
                </p>
                <small class="text-muted" style="color: #b0b0b0;">
                    <i class="bi bi-pin"></i> Mensagem Fixa da Equipe
                </small>
            </div>
            
            <!-- Lista de feedbacks -->
            <div class="list-group">
                <?php foreach ($feedbacks as $fb): ?>
                    <div class="list-group-item mb-3">
                        <div class="d-flex justify-content-between">
                            <h5>
                                <i class="bi bi-person-circle"></i> 
                                <?= htmlspecialchars($fb['nome'], ENT_QUOTES, 'UTF-8') ?>
                            </h5>
                            <div class="text-warning">
                                <?= str_repeat('⭐', $fb['rating']) . str_repeat('☆', 5 - $fb['rating']) ?>
                            </div>
                        </div>
                        <p class="mb-1">
                            <?= nl2br(htmlspecialchars($fb['feedback'], ENT_QUOTES, 'UTF-8')) ?>
                        </p>
                        <small class="text-muted">
                            <i class="bi bi-calendar"></i> 
                            <?= date('d/m/Y H:i', strtotime($fb['data_envio'])) ?>
                        </small>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- PAGINAÇÃO -->
            <?php if ($total_paginas > 1): ?>
                <nav class="mt-4">
                    <ul class="pagination justify-content-center">
                        <?php if ($pagina_atual > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?pagina=<?= $pagina_atual - 1 ?>">
                                    <i class="bi bi-chevron-left"></i> Anterior
                                </a>
                            </li>
                        <?php endif; ?>

                        <?php 
                        $inicio = max(1, $pagina_atual - 2);
                        $fim = min($total_paginas, $pagina_atual + 2);
                        
                        for ($i = $inicio; $i <= $fim; $i++): 
                        ?>
                            <li class="page-item <?= $i == $pagina_atual ? 'active' : '' ?>">
                                <a class="page-link" href="?pagina=<?= $i ?>"><?= $i ?></a>
                            </li>
                        <?php endfor; ?>

                        <?php if ($pagina_atual < $total_paginas): ?>
                            <li class="page-item">
                                <a class="page-link" href="?pagina=<?= $pagina_atual + 1 ?>">
                                    Próxima <i class="bi bi-chevron-right"></i>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                    
                    <div class="text-center mt-2">
                        <small class="text-muted">
                            Página <?= $pagina_atual ?> de <?= $total_paginas ?> 
                            (<?= $total_feedbacks ?> feedbacks no total)
                        </small>
                    </div>
                </nav>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- SCRIPTS -->
    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const feedback = document.getElementById('feedback');
            const charCount = document.getElementById('char-count');
            
            if (feedback && charCount) {
                function updateCharCount() {
                    const count = feedback.value.length;
                    charCount.textContent = count;
                    
                    if (count > 1800) {
                        charCount.style.color = '#dc3545';
                    } else if (count > 1500) {
                        charCount.style.color = '#fd7e14';
                    } else {
                        charCount.style.color = '#6c757d';
                    }
                }
                
                feedback.addEventListener('input', updateCharCount);
                updateCharCount();
            }
            
            // Auto-hide alerts
            setTimeout(function() {
                document.querySelectorAll('.alert-success').forEach(function(alert) {
                    alert.style.transition = 'opacity 0.5s';
                    alert.style.opacity = '0';
                    setTimeout(() => alert.remove(), 500);
                });
            }, 5000);
            
            console.log('✅ Feedback system loaded successfully!');
        });
    </script>
</body>
</html>