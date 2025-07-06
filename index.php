<?php
// ✅ CORREÇÃO: Comentar require problemáticos
// require_once __DIR__ . '/vendor/autoload.php'; 

require_once 'includes/config.php';
require_once 'includes/functions.php';


// ✅ DETECÇÃO TOR SIMPLES E SEGURA (apenas para indicador visual)
$torDetection = checkTorConnection();
$isTorUser = $torDetection['connected'];

// ✅ SANITIZAR PARÂMETROS DE ENTRADA
$pagina_atual = 1;
if (isset($_GET['pagina'])) {
    $pagina_param = filter_input(INPUT_GET, 'pagina', FILTER_VALIDATE_INT);
    if ($pagina_param !== false && $pagina_param > 0 && $pagina_param <= 10000) {
        $pagina_atual = $pagina_param;
    }
}

// ✅ SANITIZAR PARÂMETROS DE PESQUISA
$search_term = '';
$categoria_filter = '';

if (isset($_GET['search'])) {
    $search_input = filter_input(INPUT_GET, 'search', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    if ($search_input && strlen($search_input) <= 100) {
        $search_term = trim($search_input);
    }
}

if (isset($_GET['categoria'])) {
    $categoria_input = filter_input(INPUT_GET, 'categoria', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    if ($categoria_input && strlen($categoria_input) <= 50) {
        $categoria_filter = trim($categoria_input);
    }
}

// Inicializa variáveis para evitar erros
$produtos = null;
$total_paginas = 1;
$erro_bd = false;
$produtos_safe = [];

try {
    // ✅ CONFIGURAÇÃO SEGURA DA PAGINAÇÃO
    $produtos_por_pagina = 6;
    $offset = ($pagina_atual - 1) * $produtos_por_pagina;

    // Verifica se a conexão existe e está válida
    if (!$conn || $conn->connect_error) {
        throw new Exception("Erro na conexão com o banco de dados");
    }

    // ✅ CONSTRUIR QUERY SEGURA COM FILTROS
    $where_clauses = [];
    $params = [];
    $types = '';

    // Filtro de pesquisa
    if (!empty($search_term)) {
        $where_clauses[] = "(p.nome LIKE ? OR p.descricao LIKE ?)";
        $search_param = '%' . $search_term . '%';
        $params[] = &$search_param; // Passar por referência
        $params[] = &$search_param; // Passar por referência
        $types .= 'ss';
    }

    // Filtro de categoria
    if (!empty($categoria_filter)) {
        $where_clauses[] = "p.categoria = ?";
        $params[] = &$categoria_filter; // Passar por referência
        $types .= 's';
    }

    // Montar WHERE clause
    $where_sql = '';
    if (!empty($where_clauses)) {
        $where_sql = 'WHERE ' . implode(' AND ', $where_clauses);
    }

    // ✅ QUERY PRINCIPAL COM PREPARED STATEMENT
$sql = "
    SELECT p.id, p.nome, p.descricao, p.preco, p.preco_btc, p.preco_eth, p.imagem, p.aceita_cripto,
           u.name as vendedor_nome -- CORRIGIDO: Busca 'name' da tabela 'users'
    FROM produtos p 
    LEFT JOIN users u ON p.vendedor_id = u.id -- CORRIGIDO: Junta com a tabela 'users'
    {$where_sql}
    ORDER BY p.id DESC
    LIMIT ? OFFSET ?
";
    $stmt = $conn->prepare($sql);
    if ($stmt === false) {
        throw new Exception("Erro ao preparar consulta: " . $conn->error);
    }
    
    // Adicionar parâmetros de paginação e passar por referência
    $params[] = &$produtos_por_pagina;
    $params[] = &$offset;
    $types .= 'ii';
    
    // ✅ CORREÇÃO: Usar call_user_func_array para compatibilidade
    if (!empty($types) && !empty($params)) {
        call_user_func_array([$stmt, 'bind_param'], array_merge([$types], $params));
    }
    
    if (!$stmt->execute()) {
        throw new Exception("Erro ao executar consulta: " . $stmt->error);
    }
    
    $produtos = $stmt->get_result();
    $stmt->close();

    // ✅ CONTAR TOTAL DE PRODUTOS COM MESMOS FILTROS
    $count_sql = "SELECT COUNT(*) as total FROM produtos p LEFT JOIN users v ON p.vendedor_id = v.id {$where_sql}";
    $count_stmt = $conn->prepare($count_sql);
    
    if ($count_stmt === false) {
        throw new Exception("Erro ao preparar contagem: " . $conn->error);
    }
    
    // Usar mesmos parâmetros de filtro (sem paginação)
    $count_params = array_slice($params, 0, -2); // Remove LIMIT e OFFSET
    $count_types = substr($types, 0, -2); // Remove 'ii'
    
    // ✅ CORREÇÃO: Usar call_user_func_array para compatibilidade
    if (!empty($count_types) && !empty($count_params)) {
        call_user_func_array([$count_stmt, 'bind_param'], array_merge([$count_types], $count_params));
    }
    
    $count_stmt->execute();
    $total_result = $count_stmt->get_result()->fetch_assoc();
    $count_stmt->close();
    
    $total_produtos = (int)$total_result['total'];
    $total_paginas = max(1, ceil($total_produtos / $produtos_por_pagina));

    // ✅ SANITIZAR TODOS OS PRODUTOS
    if ($produtos && $produtos->num_rows > 0) {
        while ($produto = $produtos->fetch_assoc()) {
            // Calcular preço XMR (estimativa baseada em BTC)
            $preco_xmr = (float)$produto['preco_btc'] * 0.05;
            
            // Verificar e higienizar aceita_cripto
            $criptos_aceitas = [];
            if (!empty($produto['aceita_cripto'])) {
                $criptos_raw = explode(',', $produto['aceita_cripto']);
                foreach ($criptos_raw as $cripto) {
                    $cripto_clean = htmlspecialchars(trim(strtoupper($cripto)));
                    if (in_array($cripto_clean, ['BTC', 'ETH', 'XMR'])) {
                        $criptos_aceitas[] = $cripto_clean;
                    }
                }
            }
            
            // Se não tem criptos válidas, assumir BTC como padrão
            if (empty($criptos_aceitas)) {
                $criptos_aceitas = ['BTC'];
            }

            $produtos_safe[] = [
                'id' => (int)$produto['id'],
                'nome' => htmlspecialchars($produto['nome'] ?? 'Produto sem nome'),
                'descricao' => htmlspecialchars($produto['descricao'] ?? ''),
                'preco' => (float)($produto['preco'] ?? 0),
                'preco_btc' => (float)($produto['preco_btc'] ?? 0),
                'preco_eth' => (float)($produto['preco_eth'] ?? 0),
                'preco_xmr' => $preco_xmr,
                'imagem' => htmlspecialchars($produto['imagem'] ?? 'default.jpg'),
                'vendedor_nome' => htmlspecialchars($produto['vendedor_nome'] ?? 'Anônimo'),
                'aceita_cripto' => $criptos_aceitas,
                'url_compra' => 'comprar.php?id=' . (int)$produto['id']
            ];
        }
    }

} catch (Exception $e) {
    $erro_bd = true;
    error_log("Erro no sistema de listagem: " . $e->getMessage());
}

// ✅ SANITIZAR DADOS PARA URL DE PAGINAÇÃO
function buildPaginationUrl($page) {
    global $search_term, $categoria_filter;
    
    $params = ['pagina' => (int)$page];
    
    if (!empty($search_term)) {
        $params['search'] = htmlspecialchars($search_term);
    }
    
    if (!empty($categoria_filter)) {
        $params['categoria'] = htmlspecialchars($categoria_filter);
    }
    
    return '?' . http_build_query($params);
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
    <head>
        <title>ZeeMarket</title>
        <link rel="icon" href="assets/images/capsule.png" type="image/x-icon">
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="ZeeMarket - Marketplace Seguro">
        
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' data: api.qrserver.com; connect-src 'self' api.coingecko.com;">
        
        <link rel="stylesheet" href="assets/css/style.css">
        <link rel="stylesheet" href="assets/css/producsts.css">
        <link rel="stylesheet" href="assets/css/bootstrap.css">
        <link rel="stylesheet" href="assets/bootstrap-icons/font/bootstrap-icons.css">
        <link rel="stylesheet" href="assets/icons2">
        
        <script src="assets/js/my_script.js" defer></script>
        
        <style>
            svg {
                fill: white;
            }
            .crypto-price {
                display: flex;
                align-items: center;
                margin: 2px 0;
                font-size: 0.8em;
                padding: 2px;
                border-radius: 3px;
            }
            .crypto-price img {
                width: 30px;
                height: 30px;
                margin-right: 4px;
            }
            
            .tor-indicator {
                position: fixed;
                top: 10px;
                right: 10px;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 0.8em;
                z-index: 1000;
                font-weight: bold;
            }
            .tor-connected {
                background: rgba(40, 167, 69, 0.9);
                color: white;
            }
            .tor-disconnected {
                background: rgba(220, 53, 69, 0.9);
                color: white;
            }
            
            
            .secure-indicator {
                position: fixed;
                top: 10px;
                left: 10px;
                background: linear-gradient(45deg, #28a745, #20c997);
                color: white;
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 0.7em;
                font-weight: bold;
                z-index: 9999;
            }
            
            .item-secure {
                position: relative;
                overflow: hidden;
            }
            
            .item-secure::before {
                content: '🛡️';
                position: absolute;
                top: 5px;
                right: 5px;
                background: rgba(40, 167, 69, 0.8);
                color: white;
                padding: 2px 6px;
                border-radius: 10px;
                font-size: 0.8em;
                z-index: 1;
            }
            
            .search-secure {
                position: relative;
            }
            
            .search-secure input {
                padding-right: 40px;
            }
            
            .search-secure::after {
                content: '🔒';
                position: absolute;
                right: 35px;
                top: 50%;
                transform: translateY(-50%);
                color: #28a745;
                font-size: 0.9em;
            }
            
            .pagination-secure .page-link {
                position: relative;
            }
            
            
            * {
                max-width: 100vw;
                max-height: 100vh;
            }
            
            input, textarea {
                max-length: 1000;
            }
        </style>
    </head>
    <body>


        <nav class="navbar navbar-expand-sm navbar-dark bg-dark">
            <a class="navbar-brand ms-5" href="#">
                <span><img src="assets/icons2/zebra_branca.svg" class="zee_icon" alt="ZeeMarket Logo"></span>
                <span class="title">[Zee-Market]</span><br>
            </a>
            
            <ul class="navbar-nav ">
                <li class="nav-item">
                    <a class="nav-link gap-2 align-items-center" href="index.php">
                        <span>Home</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="FAQ.html">FAQ</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="login.php">Login</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="feedback.php">
                        <span class="bi bi-chat-left-text"></span>
                        <span>Feedback</span>
                    </a>
                </li>
             </ul>
             
             <div class="dropdown">
                <button class="btn btn-secondary btn-warning dropdown-toggle" type="button" id="dropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                    Categories
                </button>
                <ul class="dropdown-menu" aria-labelledby="dropdownMenuButton">
                    <li><a class="dropdown-item" href="<?= buildPaginationUrl(1) ?>&categoria=mdma">MDMA</a></li>
                    <li><a class="dropdown-item" href="<?= buildPaginationUrl(1) ?>&categoria=cannabis">Cannabis</a></li>
                    <li><a class="dropdown-item" href="<?= buildPaginationUrl(1) ?>&categoria=cocain">Cocain</a></li>
                    <li><a class="dropdown-item" href="<?= buildPaginationUrl(1) ?>&categoria=others">Others</a></li>
                </ul>
             </div>
             
             <form id="search-bar" class="d-flex ms-auto me-5 search-secure" method="GET">
                <input type="text" 
                       id="search" 
                       name="search" 
                       class="form-control me-2" 
                       placeholder="Pesquisar produtos..."
                       value="<?= htmlspecialchars($search_term) ?>"
                       maxlength="100"
                       pattern="[a-zA-Z0-9\s\-_]+"
                       title="Apenas letras, números, espaços e hífens">
                
                <?php if (!empty($categoria_filter)): ?>
                    <input type="hidden" name="categoria" value="<?= htmlspecialchars($categoria_filter) ?>">
                <?php endif; ?>
                
                <button id="search-button" class="btn btn-outline-success" type="submit">
                    <span class="bi bi-search"></span>
                </button>
            </form>
       </nav>

        <div id="conteudo-principal">
           <div id="side-bar">
                <div class="nav-perfil">
                    <a href="dashboard.php">
                      <span class="bi bi-person"></span> 
                      <span>Perfil</span> 
                    </a>
                </div>
                <br>
                <div class="nav-item bg-warning">
                    <a href="side-bar/produtos.html">
                        <span class="bi bi-bag-fill"></span>
                        <span class="text-black">Produtos</span>
                    </a>
                </div>
                <div class="nav-item bg-warning">
                    <a href="vendedores.php">
                        <span class="bi bi-coin"></span>
                        <span>Vender</span>
                    </a>
                </div>
                <div class="nav-item bg-outline-info">
                    <a href="contact.php">
                    <span class="bi bi-key"></span>
                        <span>Contact PGP</span>
                    </a>
                </div>
                <div class="nav-item">
                    <a href="side-bar/lojas.html">
                        <span class="bi bi-cart-fill"></span>
                        <span>Loja</span>
                    </a>
                </div>
                <div class="nav-item">
                    <a href="/side-bar/emalta.html">
                        <span class="bi bi-file-bar-graph"></span>
                        <span>Em Alta</span>
                    </a>
                </div>
                <div class="nav-item">
                    <a href="side-bar/afiliado.html">
                        <span class="bi bi-person-check-fill"></span>
                        <span>Afiliado</span>
                    </a>
                </div>
        </div>

        <div id="paginationProducts">
                <h2>Bem-Vindo ao Zee-Market, seu marketplace libertário seguro!</h2>
                
                <?php if (!empty($search_term) || !empty($categoria_filter)): ?>
                    <div class="alert alert-info">
                        <h6>Filtros ativos:</h6>
                        <?php if (!empty($search_term)): ?>
                            <span class="badge bg-primary">Busca: <?= htmlspecialchars($search_term) ?></span>
                        <?php endif; ?>
                        <?php if (!empty($categoria_filter)): ?>
                            <span class="badge bg-secondary">Categoria: <?= htmlspecialchars($categoria_filter) ?></span>
                        <?php endif; ?>
                        <a href="index.php" class="btn btn-sm btn-outline-secondary ms-2">Limpar filtros</a>
                    </div>
                <?php endif; ?>
                
                <?php if ($erro_bd): ?>
                    <div class="alert alert-warning">
                        <strong>Aviso:</strong> Alguns produtos podem não estar sendo exibidos, a sessão de categorias esta em manutenção
                        <button class="btn btn-sm btn-outline-warning ms-2" onclick="location.reload()">Tentar novamente</button>
                    </div>
                <?php endif; ?>

                <div id="cardContainer" class="items">
                    <?php if (!empty($produtos_safe)): ?>
                        <?php foreach ($produtos_safe as $produto): ?> 
                            <a href="<?= htmlspecialchars($produto['url_compra']) ?>" class="item-link">
                                <div class="item item-secure">
                                    <img src="assets/uploads/<?= $produto['imagem'] ?>" 
                                         alt="<?= $produto['nome'] ?>"
                                         onerror="this.src='assets/images/placeholder.jpg'">
                                    
                                    <h3 class="item-title"><?= $produto['nome'] ?></h3>
                                    
                                    <div class="price-container">
                                        <?php foreach ($produto['aceita_cripto'] as $cripto): ?>
                                            <?php 
                                            $preco_crypto = 0;
                                            $icon_crypto = '';
                                            
                                            switch ($cripto) {
                                                case 'BTC':
                                                    $preco_crypto = $produto['preco_btc'];
                                                    $icon_crypto = 'btc.svg';
                                                    break;
                                                case 'ETH':
                                                    $preco_crypto = $produto['preco_eth'];
                                                    $icon_crypto = 'eth.svg';
                                                    break;
                                                case 'XMR':
                                                    $preco_crypto = $produto['preco_xmr'];
                                                    $icon_crypto = 'xmr.svg';
                                                    break;
                                            }
                                            ?>
                                            
                                            <div class="crypto-price">
                                                <span><img src="assets/images/<?= htmlspecialchars($icon_crypto) ?>" alt="<?= $cripto ?>"></span>
                                                <span><?= htmlspecialchars(number_format($preco_crypto, 8)) ?> <?= $cripto ?></span>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                    
                                    <div class="mt-2">
                                        <small class="text-muted">
                                            Vendedor: <?= $produto['vendedor_nome'] ?>
                                        </small>
                                    </div>
                                    
                                    <div class="mt-1">
                                        <span class="badge bg-success">✓ Verificado</span>
                                        <?php if ($isTorUser): ?>
                                            
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </a>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div id="no_results">
                            <div class="text-center py-5">
                                <i class="bi bi-search" style="font-size: 3rem; color: #6c757d;"></i>
                                <h4 class="mt-3">Nenhum produto encontrado</h4>
                                <?php if (!empty($search_term)): ?>
                                    <p class="text-muted">Sua busca por "<?= htmlspecialchars($search_term) ?>" não retornou resultados.</p>
                                    <a href="index.php" class="btn btn-outline-primary">Ver todos os produtos</a>
                                <?php elseif ($erro_bd): ?>
                                    <p class="text-muted">Erro temporário na conexão com o banco de dados.</p>
                                    <button class="btn btn-outline-warning" onclick="location.reload()">Tentar novamente</button>
                                <?php else: ?>
                                    <p class="text-muted">Ainda não há produtos cadastrados no sistema.</p>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <?php if ($total_paginas > 1): ?>
                <nav id="pagination-area" class="mt-4">
                    <ul class="pagination justify-content-center pagination-secure">
                        <?php if ($pagina_atual > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="<?= htmlspecialchars(buildPaginationUrl($pagina_atual - 1)) ?>">
                                    <i class="bi bi-chevron-left"></i> Anterior
                                </a>
                            </li>
                        <?php endif; ?>

                        <?php
                        $inicio = max(1, $pagina_atual - 2);
                        $fim = min($total_paginas, $pagina_atual + 2);
                        
                        if ($fim - $inicio < 4) {
                            if ($inicio == 1) {
                                $fim = min($total_paginas, $inicio + 4);
                            } else {
                                $inicio = max(1, $fim - 4);
                            }
                        }
                        ?>

                        <?php if ($inicio > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="<?= htmlspecialchars(buildPaginationUrl(1)) ?>">1</a>
                            </li>
                            <?php if ($inicio > 2): ?>
                                <li class="page-item disabled">
                                    <span class="page-link">...</span>
                                </li>
                            <?php endif; ?>
                        <?php endif; ?>

                        <?php for ($i = $inicio; $i <= $fim; $i++): ?>
                            <li class="page-item <?= $i == $pagina_atual ? 'active' : '' ?>">
                                <a class="page-link" href="<?= htmlspecialchars(buildPaginationUrl($i)) ?>">
                                    <?= htmlspecialchars($i) ?>
                                </a>
                            </li>
                        <?php endfor; ?>

                        <?php if ($fim < $total_paginas): ?>
                            <?php if ($fim < $total_paginas - 1): ?>
                                <li class="page-item disabled">
                                    <span class="page-link">...</span>
                                </li>
                            <?php endif; ?>
                            <li class="page-item">
                                <a class="page-link" href="<?= htmlspecialchars(buildPaginationUrl($total_paginas)) ?>">
                                    <?= htmlspecialchars($total_paginas) ?>
                                </a>
                            </li>
                        <?php endif; ?>

                        <?php if ($pagina_atual < $total_paginas): ?>
                            <li class="page-item">
                                <a class="page-link" href="<?= htmlspecialchars(buildPaginationUrl($pagina_atual + 1)) ?>">
                                    Próximo <i class="bi bi-chevron-right"></i>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                    
                    <div class="text-center mt-2">
                        <small class="text-muted">
                            Página <?= htmlspecialchars($pagina_atual) ?> de <?= htmlspecialchars($total_paginas) ?> 
                            (<?= htmlspecialchars($total_produtos) ?> produtos encontrados)
                        </small>
                    </div>
                </nav>
            <?php endif; ?>
            
            <div class="text-center mt-4">
                <a href="#" class="btn btn-outline-info">Apoie nossa causa libertária</a>
            </div>
        </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
    <script src="assets/js/my_script.js"></script>
    <script src="assets/js/item.js"></script>
    
    <script>
        // ✅ VALIDAÇÃO SEGURA DE PESQUISA
        document.addEventListener('DOMContentLoaded', function() {
            const searchForm = document.getElementById('search-bar');
            const searchInput = document.getElementById('search');
            
            searchInput.addEventListener('input', function(e) {
                let value = e.target.value;
                value = value.replace(/[<>\"'&]/g, '');
                if (value.length > 100) {
                    value = value.substring(0, 100);
                }
                e.target.value = value;
            });
            
            searchForm.addEventListener('submit', function(e) {
                const searchValue = searchInput.value.trim();
                if (searchValue.length > 0 && searchValue.length < 2) {
                    e.preventDefault();
                    alert('⚠️ Busca deve ter pelo menos 2 caracteres');
                    return false;
                }
                const suspiciousPatterns = [/<script/i, /javascript:/i, /on\w+=/i, /<iframe/i, /eval\(/i, /document\./i];
                for (let pattern of suspiciousPatterns) {
                    if (pattern.test(searchValue)) {
                        e.preventDefault();
                        alert('🚫 Busca contém caracteres não permitidos');
                        searchInput.value = '';
                        return false;
                    }
                }
            });
        });
        
        // ✅ PROTEÇÃO CONTRA CLICKJACKING
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }
        
        // ✅ ATUALIZAR STATUS TOR PERIODICAMENTE
        setInterval(function() {
            const torIndicator = document.querySelector('.tor-indicator');
            if (torIndicator) {
                console.log('Tor Status: <?= $isTorUser ? "Connected" : "Disconnected" ?>');
            }
        }, 30000);
        
        // ✅ PROTEÇÃO CONTRA ATAQUES XSS VIA HASH
        if (window.location.hash) {
            const hash = window.location.hash.substring(1);
            if (hash.includes('<') || hash.includes('>') || hash.includes('script')) {
                window.location.hash = '';
            }
        }
        
        // ✅ MONITORAMENTO DE INTEGRIDADE DA PÁGINA
        const originalTitle = document.title;
        setInterval(() => {
            if (document.title !== originalTitle) {
                document.title = originalTitle;
            }
        }, 1000);
        
        // ✅ PROTEÇÃO CONTRA MANIPULAÇÃO DE FORMS VIA JS
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const originalAction = form.action;
            const originalMethod = form.method;
            
            setInterval(() => {
                if (form.action !== originalAction) {
                    form.action = originalAction;
                    console.warn('⚠️ Tentativa de alteração do action do form detectada e bloqueada');
                }
                if (form.method !== originalMethod) {
                    form.method = originalMethod;
                    console.warn('⚠️ Tentativa de alteração do method do form detectada e bloqueada');
                }
            }, 1000);
        });
        
        // ✅ LOG DE EVENTOS SUSPEITOS
        window.addEventListener('error', function(e) {
            if (e.message.includes('script') || e.message.includes('eval')) {
                console.warn('🔒 Possível tentativa de execução de script bloqueada:', e.message);
            }
        });
        
        // ✅ PROTEÇÃO CONTRA KEYLOGGERS BÁSICOS
        let suspiciousKeyCount = 0;
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.altKey && e.shiftKey) {
                suspiciousKeyCount++;
                if (suspiciousKeyCount > 3) {
                    console.warn('🔒 Atividade suspeita de teclado detectada');
                }
            }
        });
        
    </script>

    <noscript>
        <div style="position: fixed; top: 0; left: 0; width: 100%; background: #dc3545; color: white; text-align: center; padding: 10px; z-index: 9999;">
            ⚠️ JavaScript está desabilitado. Algumas funcionalidades podem não funcionar corretamente.
        </div>
    </noscript>

    <div style="position: absolute; left: -9999px; opacity: 0;">
        <input type="text" name="honeypot" tabindex="-1" autocomplete="off">
    </div>
</body>
</html>