<?php 
require_once 'includes/functions.php';
require_once 'includes/config.php';
// Verifica se a conexão foi estabelecida
if (!$conn) {
    die("Erro na conexão com o banco de dados: " . mysqli_connect_error());
}

$mensagem_sucesso = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $feedback = htmlspecialchars($_POST['feedback']);
    $rating = (int)$_POST['rating'];

    if (!$email || $rating < 1 || $rating > 5) {
        die("Dados inválidos");
    }

    try {
        // Verifica se a tabela existe
        $table_check = $conn->query("SHOW TABLES LIKE 'feedback'");
        if ($table_check->num_rows == 0) {
            die("A tabela feedback não existe no banco de dados");
        }

        $stmt = $conn->prepare("INSERT INTO feedback (nome, email, feedback, rating) VALUES (?, ?, ?, ?)");
        if (!$stmt) {
            die("Erro na preparação da query: " . $conn->error);
        }
        
        $stmt->bind_param("sssi", $nome, $email, $feedback, $rating);
        
        if ($stmt->execute()) {
            $mensagem_sucesso = "Feedback enviado com sucesso!";
            // Limpa as variáveis para limpar o formulário
            $nome = $email = $feedback = '';
            $rating = null;
        } else {
            die("Erro ao enviar feedback: " . $stmt->error);
        }
    } catch (Exception $e) {
        die("Erro no banco de dados: " . $e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>ZeeMarket - Feedback</title>
    <link rel="icon" href="images/capsule.png" type="image/x-icon">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="ZeeMarket - Feedback">
    <link rel="stylesheet" href="assets/css/feedback.css?v=<?= time() ?>">
    <link rel="stylesheet" href="assets/css/bootstrap.css">
    <link rel="stylesheet" href="assets/bootstrap-icons/font/bootstrap-icons.css">
</head>
<body>
    <div id="feedback-container" class="">
        <h1 class="text-center color-title">Feedback - Chat</h1>
        
        <?php if (!empty($mensagem_sucesso)): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?php echo $mensagem_sucesso; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>
        
        <div id="nav-container">
            <ul class="nav navbar justify-content-center">
                <li class="nav-item"><a class="nav-link c-link-yellow" href="index.php">Home</a></li>
                <li class="nav-item"><a class="nav-link" href="FAQ.html">FAQ</a></li>
                <li class="nav-item"><a class="nav-link" href="signup.php">SignUp</a></li>
                <li class="nav-item"><a class="nav-link" href="login.php">Login</a></li>
                <li class="nav-item"><a class="nav-link active" href="feedback.php">Feedback</a></li>
            </ul>
        </div>

            <?php
    // Configuração da paginação
    $itens_por_pagina = 5; // Itens por página
    $pagina_atual = isset($_GET['pagina']) ? (int)$_GET['pagina'] : 1;
    $offset = ($pagina_atual - 1) * $itens_por_pagina;

    // Busca os feedbacks no BD
    $query = "SELECT nome, feedback, rating, data_envio FROM feedback ORDER BY data_envio DESC LIMIT ?, ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ii", $offset, $itens_por_pagina);
    $stmt->execute();
    $resultados = $stmt->get_result();
    $feedbacks = $resultados->fetch_all(MYSQLI_ASSOC);

    // Conta o total de feedbacks para a paginação
    $total_feedbacks = $conn->query("SELECT COUNT(*) FROM feedback")->fetch_row()[0];
    $total_paginas = ceil($total_feedbacks / $itens_por_pagina);
    ?>

    <!-- Formulário de Feedback -->
        <form id="feedback-form" method="post">
            <div class="mb-3">
                <label for="name" class="form-label form-name-color">Name</label>
                <input type="text" class="form-control form-bg-color" id="name" name="name" required 
                       placeholder="Enter your name" value="<?php echo isset($nome) ? $nome : ''; ?>">
            </div>
            <div class="mb-3">
                <label for="email" class="form-label form-name-color">Email</label>
                <input type="email" class="form-control form-bg-color" id="email" name="email" required 
                       placeholder="Enter your email" value="<?php echo isset($email) ? $email : ''; ?>">
            </div>
            <div class="mb-3">
                <label for="feedback" class="form-label form-name-color">Feedback</label>
                <textarea class="form-control form-bg-color" id="feedback" name="feedback" rows="5" required 
                          placeholder="Enter your feedback"><?php echo isset($feedback) ? $feedback : ''; ?></textarea>
            </div>
            <div class="mb-3">
                <label for="rating" class="form-label form-name-color">Rating</label>
                <select class="form-select" id="rating" name="rating" required>
                    <option value="" disabled <?php echo !isset($rating) ? 'selected' : ''; ?>>Select a rating</option>
                    <option value="1" <?php echo (isset($rating) && $rating == 1) ? 'selected' : ''; ?>>1 - Poor</option>
                    <option value="2" <?php echo (isset($rating) && $rating == 2) ? 'selected' : ''; ?>>2 - Fair</option>
                    <option value="3" <?php echo (isset($rating) && $rating == 3) ? 'selected' : ''; ?>>3 - Good</option>
                    <option value="4" <?php echo (isset($rating) && $rating == 4) ? 'selected' : ''; ?>>4 - Very Good</option>
                    <option value="5" <?php echo (isset($rating) && $rating == 5) ? 'selected' : ''; ?>>5 - Excellent</option>
                </select>
            </div>
            <div class="mb-3">
                <button id="button-submit" type="submit" class="btn btn-primary">Submit</button>
            </div>
        </form>
    </div>
    <!-- Seção de Feedbacks -->
<div class="mt-5" id="lista-feedbacks">
    <h2 class="text-center color-title">Feedbacks Recentes</h2>
    
    <?php if (empty($feedbacks)): ?>
        <p class="text-center text-muted">Nenhum feedback ainda. Seja o primeiro!</p>
    <?php else: ?>
        <!-- Msg fixed -->
        <div class="list-group-item mb-3" style="background-color: #0a120f; border-left: 4px solid #e1f845;">
            <div class="d-flex justify-content-between">
                <h5 style="color: #dfbc78;">Equipe ZeeMarket</h5>
                <div class="text-warning">
                    Equipe ZeeMarket - Bem-vindo ao nosso espaço de feedback!
                </div>
            </div>
            <p class="mb-1" style="color: #ffdfa1;">
                É uma enorme honra receber vocês aqui! Deixe aqui seu feedback para que possamos dar continuidade ao 
                projeto ZeeMarket e torná-lo ainda melhor. Sua opinião é muito importante para nós! 
            </p>
            <small class="text-muted" style="color: #b0b0b0;">
                 Mensagem Fixa
            </small>
            <!-- final fixed msg -->
        </div>
        <div class="list-group">
            <?php foreach ($feedbacks as $fb): ?>
                <div class="list-group-item mb-3">
                    <div class="d-flex justify-content-between">
                        <h5><?= htmlspecialchars($fb['nome']) ?></h5>
                        <div class="text-warning">
                            <?= str_repeat('★', $fb['rating']) . str_repeat('☆', 5 - $fb['rating']) ?>
                        </div>
                    </div>
                    <p class="mb-1"><?= nl2br(htmlspecialchars($fb['feedback'])) ?></p>
                    <small class="text-muted">
                        <?= date('d/m/Y H:i', strtotime($fb['data_envio'])) ?>
                    </small>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Paginação -->
        <nav class="mt-4">
            <ul class="pagination justify-content-center">
                <?php if ($pagina_atual > 1): ?>
                    <li class="page-item">
                        <a class="page-link" href="?pagina=<?= $pagina_atual - 1 ?>">Anterior</a>
                    </li>
                <?php endif; ?>

                <?php for ($i = 1; $i <= $total_paginas; $i++): ?>
                    <li class="page-item <?= $i == $pagina_atual ? 'active' : '' ?>">
                        <a class="page-link" href="?pagina=<?= $i ?>"><?= $i ?></a>
                    </li>
                <?php endfor; ?>

                <?php if ($pagina_atual < $total_paginas): ?>
                    <li class="page-item">
                        <a class="page-link" href="?pagina=<?= $pagina_atual + 1 ?>">Próxima</a>
                    </li>
                <?php endif; ?>
            </ul>
        </nav>
    <?php endif; ?>
</div>

    <script src="assets/js/bootstrap.bundle.min.js"></script>
</body>
</html>