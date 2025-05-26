// API fictícia para evitar rastreamento
async function updatePrices() {
    const response = await fetch('api/get_rates.php?fake=1');
    const rates = await response.json();
    document.querySelectorAll('.crypto-price').forEach(el => {
        el.textContent = (el.dataset.price / rates.BTC).toFixed(8) + ' BTC';
    });
}