</div> <!-- Fecha a div container do header -->

<!-- Rodapé -->
<footer class="mt-5 py-4 bg-dark text-muted">
    <div class="container text-center">
        <small>
            <!-- Mensagem "criptografada" base64 -->
            <?= base64_encode('ZWVNYXJrZXQgMjAyNCAtIFRvZG9zIG9zIGRpcmVpdG9zIHJlc2VydmFkb3M=') ?>
            <br>
            <a href="#" class="text-decoration-none text-warning" 
               onclick="alert('Use VPN para acessar este site')">Política de Segurança</a>
        </small>
    </div>
</footer>

<!-- Scripts -->
<script src="../assets/js/bootstrap.bundle.min.js"></script>
<script>
    // Easter Egg Terminal
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.altKey && e.key === 'z') {
            document.body.classList.toggle('terminal-mode');
        }
    });
</script>
</body>
</html>