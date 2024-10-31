// Search functionality
document.querySelector('.search-box').addEventListener('input', function() {
    const query = this.value;
    if (query) {
        fetch(`/search?query=${query}`)
            .then(response => response.json())
            .then(data => {
                const productList = document.getElementById('product-listings');
                productList.innerHTML = ''; // Clear previous results
                if (data.products.length > 0) {
                    data.products.forEach(product => {
                        productList.innerHTML += `
                            <div class="product">
                                <img src="${product.product_picture}" alt="${product.product_name}">
                                <h3>${product.product_name}</h3>
                                <p class="current-price">$${product.current_price}</p>
                                ${product.previous_price ? `<p class="previous-price">Was: ${product.previous_price} AED</p>` : ''}
                                <p class="stock-status">${product.in_stock ? 'In Stock' : 'Out of Stock'}</p>
                                ${product.flash_sale ? '<p class="flash-sale">Flash Sale!</p>' : ''}
                                <p class="date-added">Added on: ${product.date_added}</p>
                            </div>`;
                    });
                } else {
                    productList.innerHTML = '<p>No products found for your search.</p>';
                }
            })
            .catch(error => console.error('Error fetching search results:', error));
    } else {
        window.location.reload(); // Reload if search is empty
    }
});

// GIF rotation functionality
const gifs = [
    "static/uploads/gif1.gif",
    "static/uploads/gif2.gif",
    "static/uploads/gif3.gif",
    "static/uploads/gif4.gif",
    "static/uploads/gif5.gif",
    "static/uploads/gif6.gif",
    "static/uploads/gif7.gif",
    "static/uploads/gif8.gif",
    "static/uploads/gif9.gif",
    "static/uploads/gif10.gif",
    "static/uploads/gif11.gif",
    "static/uploads/gif12.gif",
];

const duration = 5000; // 5 seconds per GIF
let currentGifIndex = 0;

function changeGif() {
    const bannerGif = document.getElementById('banner-gif');
    currentGifIndex = (currentGifIndex + 1) % gifs.length;
    bannerGif.src = gifs[currentGifIndex];
}

// Change GIF every `duration` milliseconds
setInterval(changeGif, duration);
