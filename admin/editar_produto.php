<?php
session_start();
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Verifica autenticação
if (!isset($_SESSION['vendedor_id'])) {
    header("Location: ../vendedores.php");
    exit();
}

// Verifica se o ID do produto foi fornecido
if (!isset($_GET['id'])) {
    header("Location: painel_vendedor.php?erro=Produto não especificado");
    exit();
}

$produto_id = (int)$_GET['id'];
$erro = '';
$sucesso = '';

// Busca os dados atuais do produto
$stmt = $conn->prepare("SELECT * FROM produtos WHERE id = ? AND vendedor_id = ?");
$stmt->bind_param("ii", $produto_id, $_SESSION['vendedor_id']);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    header("Location: painel_vendedor.php?erro=Produto não encontrado");
    exit();
}

$produto = $result->fetch_assoc();

// Processa o formulário de atualização
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome = trim($_POST['nome']);
    $descricao = trim($_POST['descricao']);
    $preco = (float)$_POST['preco'];
    $criptomoedas = isset($_POST['criptomoedas']) ? $_POST['criptomoedas'] : [];
    
    // Validações
    if (empty($nome) || empty($preco)) {
        $erro = "Nome e preço são obrigatórios!";
    } elseif ($preco <= 0) {
        $erro = "O preço deve ser maior que zero!";
    } else {
        // Processa a imagem se for enviada
        $nome_imagem = $produto['imagem']; // Mantém a imagem atual por padrão
        
        if (isset($_FILES['imagem']['error']) && $_FILES['imagem']['error'] === UPLOAD_ERR_OK) {
            $extensao = strtolower(pathinfo($_FILES['imagem']['name'], PATHINFO_EXTENSION));
            $extensoes_validas = ['jpg', 'jpeg', 'png', 'webp'];
            
            if (in_array($extensao, $extensoes_validas)) {
                $nome_imagem = uniqid('prod_') . '.' . $extensao;
                $caminho_imagem = '../assets/uploads/' . $nome_imagem;
                
                if (!move_uploaded_file($_FILES['imagem']['tmp_name'], $caminho_imagem)) {
                    $erro = "Erro ao enviar a imagem. Tente novamente!";
                } else {
                    // Remove a imagem antiga se for diferente
                    if ($produto['imagem'] !== $nome_imagem && file_exists('../assets/uploads/' . $produto['imagem'])) {
                        unlink('../assets/uploads/' . $produto['imagem']);
                    }
                }
            } else {
                $erro = "Formato de imagem inválido! Use JPG, PNG ou WEBP.";
            }
        }
        
        // Atualiza no banco se não houver erros
        if (empty($erro)) {
            $aceita_cripto = implode(',', $criptomoedas);
            
            $stmt = $conn->prepare("UPDATE produtos SET 
                                  nome = ?, 
                                  descricao = ?, 
                                  preco = ?, 
                                  aceita_cripto = ?, 
                                  imagem = ?
                                  WHERE id = ? AND vendedor_id = ?");
            $stmt->bind_param("ssdssii", 
                             $nome, 
                             $descricao, 
                             $preco, 
                             $aceita_cripto, 
                             $nome_imagem, 
                             $produto_id, 
                             $_SESSION['vendedor_id']);
            
            if ($stmt->execute()) {
                $sucesso = "Produto atualizado com sucesso!";
                // Atualiza os dados locais para exibição
                $produto['nome'] = $nome;
                $produto['descricao'] = $descricao;
                $produto['preco'] = $preco;
                $produto['aceita_cripto'] = $aceita_cripto;
                $produto['imagem'] = $nome_imagem;
            } else {
                $erro = "Erro ao atualizar produto: " . $conn->error;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Editar Produto - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .edit-container {
            max-width: 800px;
            margin: 30px auto;
            padding: 25px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.1);
        }
        .preview-image {
            max-width: 200px;
            max-height: 200px;
            margin-top: 15px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="edit-container">
            <h2 class="mb-4"><i class="bi bi-pencil-square"></i> Editar Produto</h2>
            
            <?php if ($sucesso): ?>
                <div class="alert alert-success"><?= $sucesso ?></div>
            <?php endif; ?>
            
            <?php if ($erro): ?>
                <div class="alert alert-danger"><?= $erro ?></div>
            <?php endif; ?>
            
            <form method="POST" enctype="multipart/form-data">
                <div class="mb-3">
                    <label class="form-label">Nome do Produto*</label>
                    <input type="text" name="nome" class="form-control" value="<?= htmlspecialchars($produto['nome']) ?>" required>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">Descrição</label>
                    <textarea name="descricao" class="form-control" rows="4"><?= htmlspecialchars($produto['descricao']) ?></textarea>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">Preço (R$)*</label>
                    <input type="number" step="0.01" min="0.01" name="preco" class="form-control" 
                           value="<?= number_format($produto['preco'], 2, '.', '') ?>" required>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">Criptomoedas Aceitas*</label>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="BTC" id="btc"
                            <?= strpos($produto['aceita_cripto'], 'BTC') !== false ? 'checked' : '' ?>>
                        <label class="form-check-label" for="btc">
                            <span class="badge bg-warning text-dark">BTC</span> Bitcoin
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="ETH" id="eth"
                            <?= strpos($produto['aceita_cripto'], 'ETH') !== false ? 'checked' : '' ?>>
                        <label class="form-check-label" for="eth">
                            <span class="badge bg-primary">ETH</span> Ethereum
                        </label>
                    </div>
                </div>
                
                <div class="mb-4">
                    <label class="form-label">Imagem do Produto</label>
                    <input type="file" name="imagem" class="form-control" accept="image/jpeg, image/png, image/webp">
                    <?php if ($produto['imagem']): ?>
                        <div class="mt-2">
                            <p>Imagem atual:</p>
                            <img src="../assets/uploads/<?= htmlspecialchars($produto['imagem']) ?>" 
                                 class="preview-image" 
                                 alt="Preview">
                        </div>
                    <?php endif; ?>
                </div>
                
                <div class="d-flex justify-content-between">
                    <a href="painel_vendedor.php" class="btn btn-secondary">
                        <i class="bi bi-arrow-left"></i> Voltar
                    </a>
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-check-circle"></i> Salvar Alterações
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script src="../assets/js/bootstrap.bundle.min.js"></script>
    <script>
        // Preview da imagem antes de enviar
        document.querySelector('input[name="imagem"]').addEventListener('change', function(e) {
            const preview = document.querySelector('.preview-image');
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    if (!preview) {
                        const img = document.createElement('img');
                        img.src = e.target.result;
                        img.className = 'preview-image';
                        document.querySelector('input[name="imagem"]').after(img);
                    } else {
                        preview.src = e.target.result;
                    }
                }
                reader.readAsDataURL(this.files[0]);
            }
        });
    </script>
</body>
</html>