<?php
session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Verifica autenticação e permissão
if (!isset($_SESSION['vendedor_id'])) {
    header("Location: ../vendedores.php");
    exit();
}

$erro = '';

// Função para obter cotações de criptomoedas
function getCryptoRates() {
    $url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum&vs_currencies=usd";
    $response = file_get_contents($url);
    return json_decode($response, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome = trim($_POST['nome']);
    $descricao = trim($_POST['descricao']);
    $preco = (float)$_POST['preco'];
    $vendedor_id = $_SESSION['vendedor_id'];
    $criptomoedas = isset($_POST['criptomoedas']) ? $_POST['criptomoedas'] : [];

    // Validações básicas
    if (empty($nome) || empty($preco)) {
        $erro = "Nome e preço são obrigatórios!";
    } elseif ($preco <= 0) {
        $erro = "Preço deve ser maior que zero!";
    } elseif (!isset($_FILES['imagem']['error']) || $_FILES['imagem']['error'] !== UPLOAD_ERR_OK) {
        $erro = "Selecione uma imagem válida!";
    } elseif (empty($criptomoedas)) {
        $erro = "Selecione pelo menos uma criptomoeda!";
    } else {
        // Processamento seguro do upload
        $extensao = strtolower(pathinfo($_FILES['imagem']['name'], PATHINFO_EXTENSION));
        $extensoesPermitidas = ['jpg', 'jpeg', 'png', 'webp'];
        
        if (!in_array($extensao, $extensoesPermitidas)) {
            $erro = "Formato inválido! Use JPG, PNG ou WEBP.";
        } else {
            // Gera nome único para o arquivo
            $nomeImagem = uniqid('prod_') . '.' . $extensao;
            $caminhoImagem = '../assets/uploads/' . $nomeImagem;
            
            if (move_uploaded_file($_FILES['imagem']['tmp_name'], $caminhoImagem)) {
                // Obtém cotações atuais
                $rates = getCryptoRates();
                $preco_btc = $preco / $rates['bitcoin']['usd'];
                $preco_eth = $preco / $rates['ethereum']['usd'];
                $aceita_cripto = implode(',', $criptomoedas);

                // Insere no banco
                $stmt = $conn->prepare("INSERT INTO produtos (vendedor_id, nome, descricao, preco, preco_btc, preco_eth, aceita_cripto, imagem) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param("issddsss", $vendedor_id, $nome, $descricao, $preco, $preco_btc, $preco_eth, $aceita_cripto, $nomeImagem);
                
                if ($stmt->execute()) {
                    header("Location: painel_vendedor.php");
                    exit();
                } else {
                    $erro = "Erro ao cadastrar produto: " . $conn->error;
                    // Remove a imagem enviada em caso de falha no BD
                    @unlink($caminhoImagem);
                }
            } else {
                $erro = "Falha ao enviar imagem. Tente novamente!";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Cadastrar Produto - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 800px; }
        .form-control:focus { border-color: #ffc107; box-shadow: 0 0 0 0.25rem rgba(255, 193, 7, 0.25); }
        .crypto-badge {
            font-size: 0.8rem;
            margin-right: 5px;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="text-warning">Cadastrar Produto</h1>
            <a href="painel_vendedor.php" class="btn btn-outline-secondary">
                <i class="bi bi-arrow-left"></i> Voltar
            </a>
        </div>

        <?php if (!empty($erro)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($erro) ?></div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
            <div class="mb-3">
                <label class="form-label fw-bold">Nome do Produto*</label>
                <input type="text" name="nome" class="form-control" value="<?= isset($_POST['nome']) ? htmlspecialchars($_POST['nome']) : '' ?>" required>
            </div>
            
            <div class="mb-3">
                <label class="form-label fw-bold">Descrição</label>
                <textarea name="descricao" class="form-control" rows="3"><?= isset($_POST['descricao']) ? htmlspecialchars($_POST['descricao']) : '' ?></textarea>
            </div>
            
            <div class="mb-3">
                <label class="form-label fw-bold">Preço (R$)*</label>
                <input type="number" step="0.01" min="0.01" name="preco" class="form-control" 
                       value="<?= isset($_POST['preco']) ? htmlspecialchars($_POST['preco']) : '' ?>" required>
                <small class="text-muted">Os preços em criptomoedas serão calculados automaticamente</small>
            </div>
            
            <div class="mb-3">
                <label class="form-label fw-bold">Criptomoedas Aceitas*</label>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="BTC" id="crypto-btc" <?= (isset($_POST['criptomoedas']) && in_array('BTC', $_POST['criptomoedas'])) ? 'checked' : 'checked' ?>>
                    <label class="form-check-label" for="crypto-btc">
                        <span class="badge bg-warning text-dark crypto-badge">BTC</span> Bitcoin
                    </label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="ETH" id="crypto-eth" <?= (isset($_POST['criptomoedas']) && in_array('ETH', $_POST['criptomoedas'])) ? 'checked' : 'checked' ?>>
                    <label class="form-check-label" for="crypto-eth">
                        <span class="badge bg-primary crypto-badge">ETH</span> Ethereum
                    </label>
                </div>
                <small class="text-muted">Selecione pelo menos uma opção</small>
            </div>
            
            <div class="mb-4">
                <label class="form-label fw-bold">Imagem*</label>
                <input type="file" name="imagem" class="form-control" accept="image/jpeg, image/png, image/webp" required>
                <small class="text-muted">Formatos aceitos: JPG, PNG ou WEBP (Máx. 2MB)</small>
            </div>
            
            <div class="d-grid gap-2">
                <button type="submit" class="btn btn-warning btn-lg">
                    <i class="bi bi-check-circle"></i> Cadastrar Produto
                </button>
            </div>
        </form>
    </div>

    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <!-- Bootstrap JS -->
    <script src="../assets/js/bootstrap.bundle.min.js"></script>
</body>
</html>