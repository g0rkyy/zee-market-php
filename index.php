<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Inicializa variáveis para evitar erros
$produtos = null;
$total_paginas = 1;
$erro_bd = false;

try {
    // Configuração da paginação
    $pagina_atual = isset($_GET['pagina']) ? (int)$_GET['pagina'] : 1;
    $produtos_por_pagina = 6;
    $offset = ($pagina_atual - 1) * $produtos_por_pagina;

    // Verifica se a conexão existe e está válida
    if (!$conn || $conn->connect_error) {
        throw new Exception("Erro na conexão com o banco de dados");
    }

    // Busca produtos com preços em cripto
    $stmt = $conn->prepare("
        SELECT p.*, v.nome as vendedor_nome,
        p.preco_btc,
        p.preco_eth,
        (p.preco_btc * 0.05) as preco_xmr
        FROM produtos p 
        LEFT JOIN vendedores v ON p.vendedor_id = v.id 
        LIMIT ? OFFSET ?
    ");
    
    $stmt->bind_param("ii", $produtos_por_pagina, $offset);
    if (!$stmt->execute()) {
        throw new Exception("Erro ao executar consulta: " . $stmt->error);
    }
    
    $produtos = $stmt->get_result();

    // Calcula total de páginas
    $total_produtos = $conn->query("SELECT COUNT(*) FROM produtos");
    if ($total_produtos) {
        $total_paginas = ceil($total_produtos->fetch_row()[0] / $produtos_por_pagina);
    }

} catch (Exception $e) {
    $erro_bd = true;
    error_log("Erro no sistema: " . $e->getMessage());
}
?>
<!DOCTYPE html>
    <head>
        <title>ZeeMarket</title>
        <link rel="icon" href="assets/images/capsule.png" type="image/x-icon">
        <!--  META AREA: UTF-8  -->
        <meta charset="utf-8">
        <!--  META AREA: VIEWPORT  -->
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <!--  META AREA: DESCRIPTION  -->
        <meta name="description" content="ZeeMarket">
        <!--  CSS AREA  -->
        <link rel="stylesheet" href="assets/css/style.css">
        <link rel="stylesheet" href="assets/css/producsts.css">
        <link rel="stylesheet" href="assets/css/bootstrap.css">
        <link rel="stylesheet" href="assets/bootstrap-icons/font/bootstrap-icons.css">
        <link rel="stylesheet" href="assets/icons2">
        <!--  JS AREA  
        <script src="js/search.js" defer></script>
        <script src="/js/auth.js" defer></script> -->
        <script src="assets/js/my_script.js" defer></script>
        <script src="assets/js/item.js" defer></script>
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
        
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-sm navbar-dark bg-dark">
            <!-- Brand/logo -->
            <a class="navbar-brand ms-5" href="#">
                <span><img src="assets/icons2/zebra_branca.svg" class="zee_icon" alt=""></span>
                <span class="title">[Zee-Market]</span><br>

            </a>
            <!-- Navegação -->
             <ul class="navbar-nav ">
                <li class="nav-item">
                    <a class="nav-link gap-2 align-items-center" href="index.html">
                    
                    <span>Home</span>
                </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="FAQ.html">FAQ</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="signup.php">Signup</a>
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
                <li class="nav-item">
                    <a class="nav-link" href="security.php">
                        <span class="bi bi-shield-lock"></span>
                        <span>Segurança</span>
                    </a>
                    <li class="nav-item">
                        <a class="nav-link" href="vendedores.php">
                            <span>Vender</span>
             </ul>
             <div class="dropdown">
                <button class="btn btn-secondary btn-warning dropdown-toggle" type="button" id="dropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                    Categories
                </button>
                <ul class="dropdown-menu" aria-labelledby="dropdownMenuButton">
                    <li><a class="dropdown-item" href="#">Category 1</a></li>
                    <li><a class="dropdown-item" href="#">Category 2</a></li>
                    <li><a class="dropdown-item" href="#">Category 3</a></li>
                    <li><a class="dropdown-item" href="#">Category 4</a></li>
                </ul>
             </div>
             <!-- Search bar -->
                <form id="search-bar" class="d-flex ms-auto me-5">
                    <input type="text" id="search" class="form-control me-2" placeholder="Pesquisar">
                    <button id="search-button" class="btn btn-outline-success" type="button">
                        <span class="bi bi-search"></span>
                    </button>
       </nav>


        <!--  AREA DE ALERTAS 
<div class="alert-overlay">
    
    <div class="alert alert-warning alert-dismissible fade show mb-0 rounded-0" role="alert">
      <strong>Atenção!</strong> O site ainda esta em construção, algumas funcionalidades podem não funcionar corretamente.
      <br>Estamos trabalhando para melhorar a experiência de compra e venda.
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>
    
    <div class="alert alert-warning alert-dismissible fade show rounded-0" role="alert">
      <strong>Atenção!</strong> O site não esta bem otimizado para dispositivos moveis, 
      utilize um computador para uma melhor experiência.
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>
    <div class="alert alert-success alert-dismissible fade show rounded-0" role="alert">
      <strong>Atenção!</strong> Use VPN para utilizar e fazer compras, para que sua
      experiência seja individual e o mais segura possível.
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>

    </div>
  </div> -->
        <!--  AREA DE PERFIL  -->
        <div id="conteudo-principal">
           <div id="side-bar">
                <div class="nav-perfil">
                    <a href="dashboard.php">
                      <span class="bi bi-person"></span> 
                      <span>Perfil</span> 
                    </a>
                </div>
                <br>
                <!--  AREA DE NAVEGAÇÃO-LATERAL  -->
                <div class="nav-item bg-warning">
                    <a href="side-bar/produtos.html">
                        <span class="bi bi-bag-fill"></span>
                        <span class="text-black">Produtos</span>
                    </a>
                </div>
                <div class="nav-item">
                    <a href="side-bar/vendedores.html">
                        <span class="bi bi-coin"></span>
                        <span>Vendedores</span>
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

        <!-- AREA DE PAGINAÇÃO -->
        <div id="paginationProducts">
                <h2>Bem-Vindo ao Zee-Market, seu site libertário predileto!</h2>
                <div id="cardContainer" class="items">
                    <?php if ($produtos && $produtos->num_rows > 0): ?>
                        <?php while ($produto = $produtos->fetch_assoc()): ?> 
                            <a href="comprar.php?id=<?= $produto['id'] ?>" class="item-link">
                                <div class="item">
                                    <img src="assets/uploads/<?= htmlspecialchars($produto['imagem']) ?>" 
                                         alt="<?= htmlspecialchars($produto['nome']) ?>">
                                    <h3 class="item-title"><?= htmlspecialchars($produto['nome']) ?></h3>
                                    
                                    <div class="price-container">
                                        <div class="crypto-price">
                                            <span><img src="assets/images/btc.svg"></span>
                                            <span><?= number_format($produto['preco_btc'], 8) ?> BTC</span>
                                        </div>
                                        
                                        <div class="crypto-price">
                                        <span><img src="assets/images/eth.svg"></span>
                                            <span><?= number_format($produto['preco_eth'], 8) ?> ETH</span>
                                        </div>
                                        
                                        <div class="crypto-price">
                                        <span><img src="assets/images/xmr.svg"></span>
                                            <span><?= number_format($produto['preco_xmr'], 8) ?> XMR</span>
                                        </div>
                                    </div>
                                                                        <div class="mt-2">
                                        <small class="text-muted">
                                            Vendedor: <?= htmlspecialchars($produto['vendedor_nome'] ?? 'Anônimo') ?>
                                        </small>
                                    </div>
                                </div>
                            </a>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <div id="no_results">
                            <p>Nenhum produto encontrado</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>  

            <!-- Paginação Dinâmica -->
            <?php if ($total_paginas > 1): ?>
                <nav id="pagination-area">
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
                                <a class="page-link" href="?pagina=<?= $pagina_atual + 1 ?>">Próximo</a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
            
            <div>
                <a href="">Apoie a nossa causa</a>
            </div>
        </div>
    </div>

    <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
    <script src="assets/js/my_script.js" defer></script>
    <script src="assets/js/item.js" defer></script>
</body>
</html>