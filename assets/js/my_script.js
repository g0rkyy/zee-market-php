function esgotado(){
    alert("Produto esgotado!");
}
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.altKey && e.key === 'z') {
        document.body.classList.toggle('terminal-mode');
    }
});
