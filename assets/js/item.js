let searchInput = document.getElementById('search');
searchInput.addEventListener('input', (event) => {
    const value = formString(event.target.value);

    const items = document.querySelectorAll('.items .item')
    const noResults = document.getElementById('no_results');

    let hasResults = false;

    items.forEach(item => {
    const itemTitle = item.querySelector('.item-title').textContent;

    if(formString(itemTitle).indexOf(value) !== -1){
        item.style.display = '';
        hasResults = true
    }else{
        item.style.display = 'none';
    }
    })
    if(hasResults){
        noResults.style.display = '';
    }else {
        noResults.style.display = 'block';
    }
});

function formString(value) {
    return value
    .toLowerCase()
    .trim()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
}