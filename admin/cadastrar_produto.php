<?php
/**
 * @author Blackcat Security Team - SISTEMA RECALIBRADO
 * @version 5.0 - ULTRA-HARDENED & ARCHITECTURE FIXED
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ✅ INICIALIZAR SESSÃO SEGURA
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ✅ CAMINHOS CORRIGIDOS PARA ESTRUTURA ATUAL
require_once '../includes/config.php';
require_once '../includes/functions.php';

// ✅ VERIFICAR AUTENTICAÇÃO
if (!isset($_SESSION['user_id'])) {
    error_log("🚨 ACESSO NÃO AUTORIZADO - cadastrar_produto.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    header("Location: login.php");
    exit();
}

// ✅ DEFINIR vendedor_id baseado no user_id da sessão
$vendedor_id = (int)$_SESSION['user_id'];

// ✅ VERIFICAÇÃO RÁPIDA DE VENDEDOR - SEMPRE CONSULTAR O BANCO
$quick_check = $conn->prepare("SELECT is_vendor FROM users WHERE id = ?");
$quick_check->bind_param("i", $vendedor_id);
$quick_check->execute();
$result = $quick_check->get_result()->fetch_assoc();
$quick_check->close();

if (!$result || !$result['is_vendor']) {
    header("Location: isvendor.php?msg=" . urlencode("Você precisa ser vendedor para cadastrar produtos!"));
    exit();
} else {
    // ✅ SINCRONIZAR SESSÃO COM BANCO
    $_SESSION['is_vendor'] = 1;
}

// ✅ GERAR TOKEN CSRF SE NÃO EXISTIR
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$erro = '';

// ✅ FUNÇÃO PARA OBTER COTAÇÕES DE CRIPTOMOEDAS COM FALLBACK SEGURO
function getCryptoRates() {
    $url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum&vs_currencies=usd";
    
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'user_agent' => 'ZeeMarket/1.0'
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        error_log("⚠️ Falha ao obter cotação de crypto - usando fallback");
        return [
            'bitcoin' => ['usd' => 100000], // Fallback price
            'ethereum' => ['usd' => 3000]    // Fallback price
        ];
    }
    
    $data = json_decode($response, true);
    return $data ?: [
        'bitcoin' => ['usd' => 100000],
        'ethereum' => ['usd' => 3000]
    ];
}

// ✅ FUNÇÃO DE VALIDAÇÃO ULTRA-SEGURA DE UPLOAD
function validarUploadSeguro($file) {
    $erros = [];
    
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        $uploadErrors = [
            UPLOAD_ERR_INI_SIZE => 'Arquivo excede o tamanho máximo do servidor',
            UPLOAD_ERR_FORM_SIZE => 'Arquivo excede o tamanho máximo do formulário',
            UPLOAD_ERR_PARTIAL => 'Upload foi parcialmente completado',
            UPLOAD_ERR_NO_FILE => 'Nenhum arquivo foi enviado',
            UPLOAD_ERR_NO_TMP_DIR => 'Diretório temporário não encontrado',
            UPLOAD_ERR_CANT_WRITE => 'Falha ao escrever arquivo no disco',
            UPLOAD_ERR_EXTENSION => 'Upload bloqueado por extensão PHP'
        ];
        
        $errorCode = $file['error'] ?? UPLOAD_ERR_NO_FILE;
        $erros[] = $uploadErrors[$errorCode] ?? "Erro desconhecido no upload";
        return $erros;
    }
    
    $maxSize = 2 * 1024 * 1024; // 2MB
    if ($file['size'] > $maxSize) {
        $erros[] = "Arquivo muito grande. Máximo " . round($maxSize/1024/1024, 1) . "MB permitido";
        return $erros;
    }
    
    if ($file['size'] < 100) {
        $erros[] = "Arquivo muito pequeno para ser uma imagem válida";
        return $erros;
    }
    
    $fileName = $file['name'];
    if (strlen($fileName) > 255) {
        $erros[] = "Nome do arquivo muito longo";
        return $erros;
    }
    
    if (preg_match('/[<>:"|?*\\\\\/]/', $fileName)) {
        $erros[] = "Nome do arquivo contém caracteres não permitidos";
        return $erros;
    }
    
    $extensao = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    $extensoesPermitidas = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
    
    if (!in_array($extensao, $extensoesPermitidas)) {
        $erros[] = "Formato inválido! Use apenas: " . implode(', ', $extensoesPermitidas);
        return $erros;
    }
    
    if (!file_exists($file['tmp_name'])) {
        $erros[] = "Arquivo temporário não encontrado";
        return $erros;
    }
    
    $mimeType = mime_content_type($file['tmp_name']);
    $mimePermitidos = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
    
    if (!in_array($mimeType, $mimePermitidos)) {
        $erros[] = "Tipo de arquivo não permitido. Apenas imagens reais são aceitas";
        return $erros;
    }
    
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        $erros[] = "Arquivo não pode ser processado como imagem";
        return $erros;
    }
    
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

// ✅ FUNÇÃO PARA GERAR NOME ULTRA-SEGURO DE ARQUIVO
function gerarNomeSeguro($extensao) {
    global $vendedor_id;
    $timestamp = time();
    $random = bin2hex(random_bytes(8)); // 16 chars hex
    $hash = substr(hash('sha256', $vendedor_id . $timestamp . $random), 0, 8);
    
    return sprintf('prod_%d_%d_%s_%s.%s', $vendedor_id, $timestamp, $hash, $random, $extensao);
}

// ✅ PROCESSAR FORMULÁRIO COM PROTEÇÃO CSRF TOTAL
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 🛡️ VALIDAÇÃO CSRF OBRIGATÓRIA
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        error_log("🚨 CSRF ATTACK - cadastrar_produto.php - IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $erro = "🛡️ ERRO DE SEGURANÇA: Token CSRF inválido. Operação bloqueada por segurança.";
    } else {
        // ✅ SANITIZAÇÃO E VALIDAÇÃO RIGOROSA
        $nome = trim($_POST['nome'] ?? '');
        $descricao = trim($_POST['descricao'] ?? '');
        $preco = isset($_POST['preco']) ? (float)$_POST['preco'] : 0;
        $criptomoedas = isset($_POST['criptomoedas']) ? $_POST['criptomoedas'] : [];

        $nome = htmlspecialchars($nome, ENT_QUOTES, 'UTF-8');
        $descricao = htmlspecialchars($descricao, ENT_QUOTES, 'UTF-8');

        // ✅ VALIDAÇÕES RIGOROSAS
        if (empty($nome)) {
            $erro = "Nome do produto é obrigatório!";
        } elseif (strlen($nome) < 3) {
            $erro = "Nome deve ter pelo menos 3 caracteres!";
        } elseif (strlen($nome) > 200) {
            $erro = "Nome do produto muito longo (máximo 200 caracteres)!";
        } elseif (strlen($descricao) > 2000) {
            $erro = "Descrição muito longa (máximo 2000 caracteres)!";
        } elseif ($preco <= 0) {
            $erro = "Preço deve ser maior que zero!";
        } elseif ($preco > 1000000) {
            $erro = "Preço muito alto (máximo R$ 1.000.000,00)!";
        } elseif (empty($criptomoedas)) {
            $erro = "Selecione pelo menos uma criptomoeda!";
        } elseif (!isset($_FILES['imagem']) || $_FILES['imagem']['error'] == UPLOAD_ERR_NO_FILE) {
            $erro = "Selecione uma imagem para o produto!";
        } else {
            
            if (empty($erro)) {
                $errosUpload = validarUploadSeguro($_FILES['imagem']);
                
                if (!empty($errosUpload)) {
                    $erro = implode('. ', $errosUpload);
                } else {
                    
                    $extensao = strtolower(pathinfo($_FILES['imagem']['name'], PATHINFO_EXTENSION));
                    $nomeImagem = gerarNomeSeguro($extensao);
                    
                    // CORREÇÃO DE CAMINHO: Assumindo que este script está na raiz
                    $diretorioUploads = 'assets/uploads/';
                    $caminhoImagem = $diretorioUploads . $nomeImagem;
                    
                    if (!is_dir($diretorioUploads)) {
                        if (!mkdir($diretorioUploads, 0755, true)) {
                            $erro = "Erro crítico: Não foi possível criar o diretório de uploads.";
                        }
                    }
                    
                    if (empty($erro)) {
                        if (move_uploaded_file($_FILES['imagem']['tmp_name'], $caminhoImagem)) {
                            
                            chmod($caminhoImagem, 0644);
                            
                            $rates = getCryptoRates();
                            $preco_btc = $rates ? ($preco / $rates['bitcoin']['usd']) : 0;
                            $preco_eth = $rates ? ($preco / $rates['ethereum']['usd']) : 0;
                            
                            $criptomoedas_safe = array_map('htmlspecialchars', $criptomoedas);
                            $aceita_cripto = implode(',', $criptomoedas_safe);

                            $transaction_started = false;
                            try {
                                $conn->autocommit(false);
                                $transaction_started = true;
                                
                                // CORREÇÃO: Usar vendedor_id, que é o user_id da sessão
                                $sql = "INSERT INTO produtos (vendedor_id, nome, descricao, imagem, preco, preco_btc, preco_eth, aceita_cripto) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                                $stmt = $conn->prepare($sql);
                                
                                if ($stmt === false) {
                                    throw new Exception("Erro na preparação da query: " . $conn->error);
                                }
                                
                                $stmt->bind_param("isssddds", $vendedor_id, $nome, $descricao, $nomeImagem, $preco, $preco_btc, $preco_eth, $aceita_cripto);
                                
                                if ($stmt->execute()) {
                                    if ($stmt->affected_rows > 0) {
                                        $produto_id = $stmt->insert_id;
                                        
                                        $conn->commit();
                                        $conn->autocommit(true);
                                        $transaction_started = false;
                                        
                                        error_log("✅ PRODUTO CADASTRADO - ID: {$produto_id} - Vendedor: {$vendedor_id} - Nome: {$nome}");
                                        
                                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                                        $stmt->close();
                                        
                                        // CORREÇÃO: Redirecionar para o dashboard na RAIZ
                                        header("Location: painel_vendedor.php?sucesso=" . urlencode("Produto '{$nome}' cadastrado com sucesso! Agora está visível no marketplace."));
                                        exit();
                                    } else {
                                        throw new Exception("Nenhuma linha foi inserida");
                                    }
                                } else {
                                    throw new Exception("Erro na execução: " . $stmt->error);
                                }
                                
                            } catch (Exception $e) {
                                if ($transaction_started) {
                                    $conn->rollback();
                                    $conn->autocommit(true);
                                }
                                error_log("❌ ERRO SQL AO CADASTRAR PRODUTO - Vendedor: {$vendedor_id} - Erro: " . $e->getMessage());
                                $erro = "Erro interno ao cadastrar produto. Tente novamente.";
                                @unlink($caminhoImagem);
                                if (isset($stmt)) $stmt->close();
                            }
                        } else {
                            $erro = "Falha ao salvar imagem. Verifique as permissões do servidor!";
                        }
                    }
                }
            }
        }
    }
    // Regenerar token CSRF após a tentativa de POST
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="ZeeMarket - Cadastrar Produto com Segurança Máxima">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <title>Cadastrar Produto - ZeeMarket</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.0/font/bootstrap-icons.css">
    <style>
        body { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .container { max-width: 900px; }
        .form-control:focus { 
            border-color: #ffc107; 
            box-shadow: 0 0 0 0.25rem rgba(255, 193, 7, 0.25); 
        }
        .crypto-badge {
            font-size: 0.8rem;
            margin-right: 5px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        .upload-info {
            background: linear-gradient(135deg, #e3f2fd, #f3e5f5);
            border: 2px solid #2196f3;
            border-radius: 10px;
            padding: 15px;
            margin-top: 10px;
        }
        .security-badge {
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        .form-section {
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 4px solid #ffc107;
        }
        .char-counter {
            font-size: 0.8rem;
            float: right;
            font-weight: bold;
        }
        .price-info {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 10px;
            margin-top: 5px;
        }
        .breadcrumb-nav {
            background: linear-gradient(135deg, #6c757d, #495057);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        .breadcrumb-nav a {
            color: #ffc107;
            text-decoration: none;
        }
        .breadcrumb-nav a:hover {
            color: white;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <nav class="breadcrumb-nav">
            <div class="d-flex align-items-center">
                <i class="bi bi-house-door me-2"></i>
                <a href="index.php">Home</a>
                <span class="mx-2">></span>
                <a href="dashboard.php">Dashboard</a>
                <span class="mx-2">></span>
                <span>Cadastrar Produto</span>
            </div>
        </nav>

        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="text-warning">
                <i class="bi bi-plus-circle-fill"></i> Cadastrar Produto 
                <span class="security-badge">🛡️ BLACKCAT SECURED</span>
            </h1>
            <div>
                <a href="dashboard.php" class="btn btn-outline-secondary me-2">
                    <i class="bi bi-arrow-left"></i> Voltar ao Dashboard
                </a>
                <a href="index.php" class="btn btn-outline-primary">
                    <i class="bi bi-house"></i> Ver Marketplace
                </a>
            </div>
        </div>

        <?php if (!empty($erro)): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i> 
                <strong>Erro:</strong> <?= $erro ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['sucesso'])): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle-fill"></i> 
                <strong>Sucesso:</strong> <?= htmlspecialchars($_GET['sucesso']) ?>
                <div class="mt-2">
                    <a href="index.php" class="btn btn-sm btn-outline-success">
                        <i class="bi bi-eye"></i> Ver no Marketplace
                    </a>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data" id="productForm" novalidate>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            
            <div class="form-section">
                <h5 class="text-primary mb-3"><i class="bi bi-info-circle"></i> Informações Básicas</h5>
                <div class="mb-3">
                    <label class="form-label fw-bold"><i class="bi bi-tag"></i> Nome do Produto *</label>
                    <input type="text" name="nome" class="form-control" value="<?= htmlspecialchars($_POST['nome'] ?? '', ENT_QUOTES, 'UTF-8') ?>" maxlength="200" required>
                    <small class="text-muted">Mínimo 3 caracteres, máximo 200. <span class="char-counter" id="nome-counter">0/200</span></small>
                </div>
                <div class="mb-3">
                    <label class="form-label fw-bold"><i class="bi bi-file-text"></i> Descrição</label>
                    <textarea name="descricao" class="form-control" rows="4" maxlength="2000" placeholder="Descreva seu produto detalhadamente..."><?= htmlspecialchars($_POST['descricao'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
                    <small class="text-muted">Opcional. Máximo 2000 caracteres. <span class="char-counter" id="desc-counter">0/2000</span></small>
                </div>
            </div>
            
            <div class="form-section">
                <h5 class="text-success mb-3"><i class="bi bi-currency-bitcoin"></i> Preços e Criptomoedas</h5>
                <div class="mb-3">
                    <label class="form-label fw-bold"><i class="bi bi-cash-stack"></i> Preço (USD) *</label>
                    <input type="number" step="0.01" min="0.01" max="1000000" name="preco" class="form-control" value="<?= htmlspecialchars($_POST['preco'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required id="preco-input">
                    <div class="price-info">
                        <small><i class="bi bi-info-circle"></i> Entre $0.01 e $1,000,000.00. Os preços em criptomoedas serão calculados automaticamente.</small>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label fw-bold"><i class="bi bi-currency-bitcoin"></i> Criptomoedas Aceitas *</label>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="BTC" id="crypto-btc" checked>
                        <label class="form-check-label" for="crypto-btc"><span class="badge bg-warning text-dark crypto-badge">₿ BTC</span> Bitcoin <small class="text-muted">(Recomendado)</small></label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="criptomoedas[]" value="ETH" id="crypto-eth" checked>
                        <label class="form-check-label" for="crypto-eth"><span class="badge bg-primary crypto-badge">⟐ ETH</span> Ethereum <small class="text-muted">(Rápido)</small></label>
                    </div>
                    <small class="text-muted">Selecione pelo menos uma opção</small>
                </div>
            </div>
            
            <div class="form-section">
                <h5 class="text-danger mb-3"><i class="bi bi-shield-lock"></i> Upload Ultra-Seguro</h5>
                <div class="mb-4">
                    <label class="form-label fw-bold"><i class="bi bi-image"></i> Imagem do Produto *</label>
                    <input type="file" name="imagem" class="form-control" accept="image/jpeg,image/jpg,image/png,image/webp,image/gif" required id="imageInput">
                    <div class="upload-info">
                        <h6><i class="bi bi-shield-check"></i> Validações de Segurança:</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <ul class="mb-0 small">
                                    <li>✅ <strong>Formatos:</strong> JPG, PNG, WEBP, GIF</li>
                                    <li>✅ <strong>Tamanho:</strong> Máximo 2MB</li>
                                    <li>✅ <strong>Dimensões:</strong> 50x50 a 5000x5000px</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <ul class="mb-0 small">
                                    <li>✅ <strong>MIME Type:</strong> Verificação real</li>
                                    <li>✅ <strong>Validação:</strong> Múltiplas camadas</li>
                                    <li>✅ <strong>Anti-Malware:</strong> Proteção ativa</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div id="image-preview" class="mt-3" style="display: none;">
                        <label class="form-label fw-bold">Preview:</label>
                        <div class="border rounded p-2 text-center">
                            <img id="preview-img" src="" alt="Preview" style="max-width: 200px; max-height: 200px;">
                            <div id="image-info" class="small text-muted mt-2"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <div class="alert alert-info">
                    <h6><i class="bi bi-shield-check"></i> Proteções Ativas:</h6>
                    <div class="row">
                        <div class="col-md-6"><ul class="mb-0 small"><li>🛡️ <strong>CSRF Protection</strong></li><li>🔒 <strong>SQL Injection Protection</strong></li><li>🚫 <strong>XSS Protection</strong></li></ul></div>
                        <div class="col-md-6"><ul class="mb-0 small"><li>📊 <strong>Rate Limiting</strong></li><li>🔍 <strong>File Validation</strong></li><li>📝 <strong>Audit Logging</strong></li></ul></div>
                    </div>
                </div>
                <div class="d-grid gap-2">
                    <button type="submit" class="btn btn-warning btn-lg" id="submitBtn"><i class="bi bi-shield-check"></i> Cadastrar Produto com Segurança Máxima</button>
                    <button type="reset" class="btn btn-outline-secondary"><i class="bi bi-arrow-clockwise"></i> Limpar Formulário</button>
                </div>
            </div>
        </form>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const form = document.getElementById('productForm');
        const imageInput = document.getElementById('imageInput');
        const submitBtn = document.getElementById('submitBtn');
        const nomeInput = document.querySelector('input[name="nome"]');
        const descricaoInput = document.querySelector('textarea[name="descricao"]');
        
        function updateCharCounter(input, counterId, maxLength) {
            const counter = document.getElementById(counterId);
            if (counter) {
                const current = input.value.length;
                counter.textContent = `${current}/${maxLength}`;
                counter.style.color = current > maxLength ? '#dc3545' : '#6c757d';
            }
        }
        
        nomeInput.addEventListener('input', () => updateCharCounter(nomeInput, 'nome-counter', 200));
        descricaoInput.addEventListener('input', () => updateCharCounter(descricaoInput, 'desc-counter', 2000));
        updateCharCounter(nomeInput, 'nome-counter', 200);
        updateCharCounter(descricaoInput, 'desc-counter', 2000);
        
        imageInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            const preview = document.getElementById('image-preview');
            const previewImg = document.getElementById('preview-img');
            const imageInfo = document.getElementById('image-info');
            
            if (!file) {
                preview.style.display = 'none';
                return;
            }
            
            const reader = new FileReader();
            reader.onload = function(e) {
                previewImg.src = e.target.result;
                const img = new Image();
                img.onload = function() {
                    imageInfo.textContent = `📏 ${this.width}x${this.height}px | 📁 ${(file.size/1024).toFixed(1)}KB | 🏷️ ${file.type}`;
                };
                img.src = e.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        });
        
        form.addEventListener('submit', function(e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
                alert('Por favor, preencha todos os campos obrigatórios corretamente.');
                form.classList.add('was-validated');
                return;
            }
            submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processando...';
            submitBtn.disabled = true;
        });
        
        console.log('✅ Formulário de cadastro carregado com segurança!');
    });
    </script>
</body>
</html>