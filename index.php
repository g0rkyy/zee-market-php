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
            <nav id="pagination-area">
                 <ul class="pagination justify-content-center">
                     <li class="page-item">
                         <a class="page-link" href="#">Anterior</a>
                     </li>
                     <li class="page-item">
                         <a class="page-link" href="#">1</a>
                     </li>
                     <li class="page-item">
                         <a class="page-link" href="#">2</a>
                     </li>
                     <li class="page-item">
                         <a class="page-link" href="#">3</a>
                     </li>
                     <li class="page-item">
                         <a class="page-link" href="#">4</a>
                     </li>
                     <li class="page-item">
                         <a class="page-link" href="#">5</a>
                     </li>
                     <li class="page-item">
                         <a class="page-link" href="#">Próximo</a>
                     </li>
                 </ul>
              </nav>
                 
             <!--  AREA DE PRODUTOS -->
             <div id="cardContainer" class="items">
                 <div onclick="esgotado()" class="item">
                     <img src="assets/images/MDMA.jpg" alt="Produto 1">
                     <h3 class="item-title">Produto 1</h3>
                     <p class="preco">R$ 100,00</p>
                 </div>
                 <div class="item">
                     <img src="assets/images/PILLmd.jpg" alt="Produto 2">
                     <h3 class="item-title">Produto 2</h3>
                     <p class="preco">R$ 150,00</p>
                 </div>
                 <div class="item">
                     <img src="assets/images/PILLS.jpg" alt="Produto 3">
                     <h3 class="item-title">Produto 3</h3>
                     <p class="preco">R$ 200,00</p>
                 </div>
                 <div class="item">
                     <img src="assets/images/MDMA.jpg" alt="Produto 4">
                     <h3 class="item-title">Produto 1</h3>
                     <p class="preco">R$ 100,00</p>
                 </div>
                 <div class="item">
                     <img src="assets/images/PILLmd.jpg" alt="Produto 5">
                     <h3 class="item-title">Produto 2</h3>
                     <p class="preco">R$ 150,00</p>
                 </div>
                 <div class="item">
                     <img src="assets/images/PILLS.jpg" alt="Produto 6">
                     <h3 class="item-title">Produto 3</h3>
                     <p class="preco">R$ 200,00</p>
                 </div> 
                 <div id="no_results">
                    <p>Nenhum resultado encontrado</p>
                 </div>
         </div>
         <div>
             <a href="">Apoie a nossa causa</a>
         </div>
        </div>
        <!-- JS do Bootstrap -->
        <script src="assets/bootstrap5/js/bootstrap.bundle.js"></script>
    </body>

</html>