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
    $response = @file_get_contents($url);
    if ($response === false) {
        // Fallback em caso de erro da API
        return [
            'bitcoin' => ['usd' => 45000],
            'ethereum' => ['usd' => 2800]
        ];
    }
    return json_decode($response, true);
}

// ✅ FUNÇÃO DE VALIDAÇÃO SEGURA DE UPLOAD
function validarUploadSeguro($file) {
    $erros = [];
    
    // 1. Verificar se o arquivo foi enviado
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        $erros[] = "Erro no upload do arquivo";
        return $erros;
    }
    
    // 2. Verificar tamanho máximo (2MB)
    $maxSize = 2 * 1024 * 1024; // 2MB
    if ($file['size'] > $maxSize) {
        $erros[] = "Arquivo muito grande. Máximo 2MB permitido";
        return $erros;
    }
    
    // 3. Verificar extensão do arquivo
    $extensao = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $extensoesPermitidas = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
    
    if (!in_array($extensao, $extensoesPermitidas)) {
        $erros[] = "Formato inválido! Use apenas: " . implode(', ', $extensoesPermitidas);
        return $erros;
    }
    
    // 4. ✅ VERIFICAÇÃO MIME TYPE REAL
    $mimeType = mime_content_type($file['tmp_name']);
    $mimePermitidos = [
        'image/jpeg',
        'image/jpg', 
        'image/png',
        'image/webp',
        'image/gif'
    ];
    
    if (!in_array($mimeType, $mimePermitidos)) {
        $erros[] = "Tipo de arquivo não permitido. Apenas imagens reais são aceitas";
        return $erros;
    }
    
    // 5. ✅ VERIFICAÇÃO DE CONTEÚDO (MAGIC BYTES)
    $fileContent = file_get_contents($file['tmp_name'], false, null, 0, 512);
    
    // Verificar assinaturas de arquivo conhecidas
    $magicBytes = [
        'jpeg' => ['\xFF\xD8\xFF'],
        'png' => ['\x89\x50\x4E\x47'],
        'gif' => ['\x47\x49\x46'],
        'webp' => ['\x52\x49\x46\x46']
    ];
    
    $isValidImage = false;
    foreach ($magicBytes as $type => $signatures) {
        foreach ($signatures as $signature) {
            if (strpos($fileContent, $signature) === 0) {
                $isValidImage = true;
                break 2;
            }
        }
    }
    
    if (!$isValidImage) {
        $erros[] = "Arquivo não é uma imagem válida";
        return $erros;
    }
    
    // 6. ✅ VERIFICAR CONTEÚDO MALICIOSO
    $suspiciousPatterns = [
        '<?php',
        '<?=', 
        '<script',
        'eval(',
        'exec(',
        'system(',
        'shell_exec(',
        'passthru(',
        'base64_decode(',
        'gzinflate(',
        'str_rot13(',
        'fwrite(',
        'file_get_contents(',
        'file_put_contents('
    ];
    
    $fileContentLower = strtolower($fileContent);
    foreach ($suspiciousPatterns as $pattern) {
        if (strpos($fileContentLower, strtolower($pattern)) !== false) {
            $erros[] = "Conteúdo malicioso detectado no arquivo";
            return $erros;
        }
    }
    
    // 7. ✅ TENTAR ABRIR COMO IMAGEM (VALIDAÇÃO FINAL)
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        $erros[] = "Arquivo não pode ser processado como imagem";
        return $erros;
    }
    
    // Verificar dimensões mínimas/máximas
    if ($imageInfo[0] < 50 || $imageInfo[1] < 50) {
        $erros[] = "Imagem muito pequena. Mínimo 50x50 pixels";
        return $erros;
    }
    
    if ($imageInfo[0] > 5000 || $imageInfo[1] > 5000) {
        $erros[] = "Imagem muito grande. Máximo 5000x5000 pixels";
        return $erros;
    }
    
    return $erros; // Vazio = validação passou
}

// ✅ FUNÇÃO PARA GERAR NOME SEGURO DE ARQUIVO
function gerarNomeSeguro($extensao) {
    // Gerar nome único e seguro
    $timestamp = time();
    $random = bin2hex(random_bytes(8));
    $vendedor_id = (int)$_SESSION['vendedor_id'];
    
    // Nome no formato: prod_[vendedor]_[timestamp]_[random].[ext]
    return sprintf('prod_%d_%d_%s.%s', $vendedor_id, $timestamp, $random, $extensao);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome = trim($_POST['nome']);
    $descricao = trim($_POST['descricao']);
    $preco = (float)$_POST['preco'];
    $vendedor_id = (int)$_SESSION['vendedor_id'];
    $criptomoedas = isset($_POST['criptomoedas']) ? $_POST['criptomoedas'] : [];

    // Validações básicas
    if (empty($nome) || empty($preco)) {
        $erro = "Nome e preço são obrigatórios!";
    } elseif (strlen($nome) > 200) {
        $erro = "Nome do produto muito longo (máximo 200 caracteres)!";
    } elseif (strlen($descricao) > 2000) {
        $erro = "Descrição muito longa (máximo 2000 caracteres)!";
    } elseif ($preco <= 0 || $preco > 1000000) {
        $erro = "Preço deve estar entre R$ 0,01 e R$ 1.000.000,00!";
    } elseif (empty($criptomoedas)) {
        $erro = "Selecione pelo menos uma criptomoeda!";
    } elseif (!isset($_FILES['imagem'])) {
        $erro = "Selecione uma imagem para o produto!";
    } else {
        
        // ✅ VALIDAÇÃO SEGURA DE UPLOAD
        $errosUpload = validarUploadSeguro($_FILES['imagem']);
        
        if (!empty($errosUpload)) {
            $erro = implode('. ', $errosUpload);
        } else {
            
            // Obter extensão segura
            $extensao = strtolower(pathinfo($_FILES['imagem']['name'], PATHINFO_EXTENSION));
            
            // Gerar nome seguro para o arquivo
            $nomeImagem = gerarNomeSeguro($extensao);
            $caminhoImagem = '../assets/uploads/' . $nomeImagem;
            
            // ✅ CRIAR DIRETÓRIO SE NÃO EXISTIR (COM PERMISSÕES SEGURAS)
            $diretorioUploads = '../assets/uploads/';
            if (!is_dir($diretorioUploads)) {
                if (!mkdir($diretorioUploads, 0755, true)) {
                    $erro = "Erro ao criar diretório de uploads!";
                }
            }
            
            if (empty($erro)) {
                // Mover arquivo com verificação de segurança
                if (move_uploaded_file($_FILES['imagem']['tmp_name'], $caminhoImagem)) {
                    
                    // ✅ DEFINIR PERMISSÕES SEGURAS NO ARQUIVO
                    chmod($caminhoImagem, 0644);
                    
                    // ✅ CRIAR .htaccess NO DIRETÓRIO DE UPLOADS (PROTEÇÃO ADICIONAL)
                    $htaccessPath = $diretorioUploads . '.htaccess';
                    if (!file_exists($htaccessPath)) {
                        $htaccessContent = "# Proteção contra execução de scripts\n";
                        $htaccessContent .= "Options -ExecCGI\n";
                        $htaccessContent .= "AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi\n";
                        $htaccessContent .= "RemoveHandler .php .phtml .php3 .php4 .php5 .php6 .phps\n";
                        $htaccessContent .= "\n# Permitir apenas imagens\n";
                        $htaccessContent .= "<FilesMatch \"\\.(jpg|jpeg|png|gif|webp)$\">\n";
                        $htaccessContent .= "    Order Allow,Deny\n";
                        $htaccessContent .= "    Allow from all\n";
                        $htaccessContent .= "</FilesMatch>\n";
                        $htaccessContent .= "\n# Bloquear tudo que não for imagem\n";
                        $htaccessContent .= "<FilesMatch \"^(?!.*\\.(jpg|jpeg|png|gif|webp)$).*\">\n";
                        $htaccessContent .= "    Order Deny,Allow\n";
                        $htaccessContent .= "    Deny from all\n";
                        $htaccessContent .= "</FilesMatch>\n";
                        
                        @file_put_contents($htaccessPath, $htaccessContent);
                    }
                    
                    // Obtém cotações atuais
                    $rates = getCryptoRates();
                    $preco_btc = $rates ? ($preco / $rates['bitcoin']['usd']) : ($preco / 45000);
                    $preco_eth = $rates ? ($preco / $rates['ethereum']['usd']) : ($preco / 2800);
                    $aceita_cripto = implode(',', array_map('htmlspecialchars', $criptomoedas));

                    // ✅ INSERIR NO BANCO COM PREPARED STATEMENT
                    $stmt = $conn->prepare("INSERT INTO produtos (vendedor_id, nome, descricao, preco, preco_btc, preco_eth, aceita_cripto, imagem, data_cadastro) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())");
                    
                    if ($stmt === false) {
                        $erro = "Erro no sistema. Tente novamente.";
                        // Remover arquivo em caso de erro
                        @unlink($caminhoImagem);
                    } else {
                        $stmt->bind_param("issddsss", $vendedor_id, $nome, $descricao, $preco, $preco_btc, $preco_eth, $aceita_cripto, $nomeImagem);
                        
                        if ($stmt->execute()) {
                            $produto_id = $stmt->insert_id;
                            
                            // ✅ LOG DE SEGURANÇA
                            error_log("Produto cadastrado com sucesso - ID: {$produto_id} - Vendedor: {$vendedor_id} - Arquivo: {$nomeImagem}");
                            
                            // ✅ REGISTRAR NO LOG DE AUDITORIA
                            if (function_exists('logActivity')) {
                                logActivity($vendedor_id, 'product_created', [
                                    'produto_id' => $produto_id,
                                    'nome' => $nome,
                                    'preco' => $preco,
                                    'imagem' => $nomeImagem
                                ]);
                            }
                            
                            $stmt->close();
                            header("Location: painel_vendedor.php?sucesso=Produto cadastrado com sucesso!");
                            exit();
                        } else {
                            error_log("Erro SQL ao cadastrar produto - Vendedor: {$vendedor_id} - Erro: " . $stmt->error);
                            $erro = "Erro ao cadastrar produto: " . htmlspecialchars($stmt->error);
                            // Remover arquivo em caso de falha no BD
                            @unlink($caminhoImagem);
                            $stmt->close();
                        }
                    }
                } else {
                    $erro = "Falha ao salvar imagem. Verifique as permissões do servidor!";
                }
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
    <title>Cadastrar Produto - ZeeMarket</title>
    <link href="../assets/css/bootstrap.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 800px; }
        .form-control:focus { border-color: #ffc107; box-shadow: 0 0 0 0.25rem rgba(255, 193, 7, 0.25); }
        .crypto-badge {
            font-size: 0.8rem;
            margin-right: 5px;
        }
        .upload-info {
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 10px;
            margin-top: 5px;
        }
        .security-badge {
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="text-warning">
                <i class="bi bi-plus-circle"></i> Cadastrar Produto 
                <span class="security-badge">🛡️ ULTRA-SEGURO</span>
            </h1>
            <a href="painel_vendedor.php" class="btn btn-outline-secondary">
                <i class="bi bi-arrow-left"></i> Voltar
            </a>
        </div>

        <?php if (!empty($erro)): ?>
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($erro) ?>
            </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data" id="productForm">
            <div class="mb-3">
                <label class="form-label fw-bold">Nome do Produto*</label>
                <input type="text" name="nome" class="form-control" 
                       value="<?= isset($_POST['nome']) ? htmlspecialchars($_POST['nome']) : '' ?>" 
                       maxlength="200" required>
                <small class="text-muted">Máximo 200 caracteres</small>
            </div>
            
            <div class="mb-3">
                <label class="form-label fw-bold">Descrição</label>
                <textarea name="descricao" class="form-control" rows="3" 
                          maxlength="2000"><?= isset($_POST['descricao']) ? htmlspecialchars($_POST['descricao']) : '' ?></textarea>
                <small class="text-muted">Máximo 2000 caracteres</small>
            </div>
            
            <div class="mb-3">
                <label class="form-label fw-bold">Preço (R$)*</label>
                <input type="number" step="0.01" min="0.01" max="1000000" name="preco" class="form-control" 
                       value="<?= isset($_POST['preco']) ? htmlspecialchars($_POST['preco']) : '' ?>" required>
                <small class="text-muted">Entre R$ 0,01 e R$ 1.000.000,00. Os preços em criptomoedas serão calculados automaticamente</small>
            </div>
            
            <div class="mb-3">
                <label class="form-label fw-bold">Criptomoedas Aceitas*</label>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="BTC" id="crypto-btc" 
                           <?= (isset($_POST['criptomoedas']) && in_array('BTC', $_POST['criptomoedas'])) ? 'checked' : 'checked' ?>>
                    <label class="form-check-label" for="crypto-btc">
                        <span class="badge bg-warning text-dark crypto-badge">BTC</span> Bitcoin
                    </label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="ETH" id="crypto-eth" 
                           <?= (isset($_POST['criptomoedas']) && in_array('ETH', $_POST['criptomoedas'])) ? 'checked' : 'checked' ?>>
                    <label class="form-check-label" for="crypto-eth">
                        <span class="badge bg-primary crypto-badge">ETH</span> Ethereum
                    </label>
                </div>
                <small class="text-muted">Selecione pelo menos uma opção</small>
            </div>
            
            <div class="mb-4">
                <label class="form-label fw-bold">Imagem do Produto*</label>
                <input type="file" name="imagem" class="form-control" 
                       accept="image/jpeg,image/jpg,image/png,image/webp,image/gif" required id="imageInput">
                
                <div class="upload-info">
                    <h6><i class="bi bi-shield-check"></i> Validações de Segurança Ativas:</h6>
                    <ul class="mb-0 small">
                        <li>✅ Formatos: JPG, PNG, WEBP, GIF</li>
                        <li>✅ Tamanho máximo: 2MB</li>
                        <li>✅ Verificação MIME type real</li>
                        <li>✅ Análise de conteúdo malicioso</li>
                        <li>✅ Validação de magic bytes</li>
                        <li>✅ Dimensões: 50x50 a 5000x5000 pixels</li>
                    </ul>
                </div>
            </div>
            
            <div class="d-grid gap-2">
                <button type="submit" class="btn btn-warning btn-lg" id="submitBtn">
                    <i class="bi bi-check-circle"></i> Cadastrar Produto Seguro
                </button>
            </div>
        </form>
    </div>

    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <!-- Bootstrap JS -->
    <script src="../assets/js/bootstrap.bundle.min.js"></script>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const form = document.getElementById('productForm');
        const imageInput = document.getElementById('imageInput');
        const submitBtn = document.getElementById('submitBtn');
        
        // Validação em tempo real do arquivo
        imageInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (!file) return;
            
            const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
            const maxSize = 2 * 1024 * 1024; // 2MB
            
            let isValid = true;
            let message = '';
            
            // Verificar tipo
            if (!allowedTypes.includes(file.type)) {
                isValid = false;
                message += 'Formato não permitido. ';
            }
            
            // Verificar tamanho
            if (file.size > maxSize) {
                isValid = false;
                message += 'Arquivo muito grande (máx 2MB). ';
            }
            
            // Verificar nome do arquivo
            const fileName = file.name.toLowerCase();
            const suspiciousExtensions = ['.php', '.js', '.html', '.htm', '.asp', '.jsp', '.exe'];
            if (suspiciousExtensions.some(ext => fileName.includes(ext))) {
                isValid = false;
                message += 'Nome de arquivo suspeito. ';
            }
            
            if (!isValid) {
                alert('❌ Arquivo inválido: ' + message);
                imageInput.value = '';
                return;
            }
            
            // Preview da imagem (opcional)
            const reader = new FileReader();
            reader.onload = function(e) {
                // Aqui você poderia mostrar um preview
                console.log('✅ Arquivo carregado para preview');
            };
            reader.readAsDataURL(file);
        });
        
        // Validação final no submit
        form.addEventListener('submit', function(e) {
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processando...';
            submitBtn.disabled = true;
            
            // Timeout de segurança
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-check-circle"></i> Cadastrar Produto Seguro';
            }, 10000);
        });
        
        // Contador de caracteres
        const nomeInput = document.querySelector('input[name="nome"]');
        const descricaoInput = document.querySelector('textarea[name="descricao"]');
        
        nomeInput.addEventListener('input', function() {
            const remaining = 200 - this.value.length;
            const small = this.nextElementSibling;
            small.textContent = `${remaining} caracteres restantes`;
            small.className = remaining < 20 ? 'text-warning' : 'text-muted';
        });
        
        descricaoInput.addEventListener('input', function() {
            const remaining = 2000 - this.value.length;
            const small = this.nextElementSibling;
            small.textContent = `${remaining} caracteres restantes`;
            small.className = remaining < 100 ? 'text-warning' : 'text-muted';
        });
    });
    </script>
</body>
</html>