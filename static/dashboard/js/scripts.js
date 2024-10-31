/*!
    * Start Bootstrap - SB Admin v7.0.7 (https://startbootstrap.com/template/sb-admin)
    * Copyright 2013-2023 Start Bootstrap
    * Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-sb-admin/blob/master/LICENSE)
    */
    // 
// Scripts
// 

window.addEventListener('DOMContentLoaded', event => {

    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        // Uncomment Below to persist sidebar toggle between refreshes
        // if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
        //     document.body.classList.toggle('sb-sidenav-toggled');
        // }
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

});


            document.addEventListener('DOMContentLoaded', function() {
                // Search functionality
                const searchInput = document.querySelector('input[placeholder="Search for..."]');
                const tableRows = document.querySelectorAll('tbody tr');

                searchInput.addEventListener('input', function(e) {
                    const searchTerm = e.target.value.toLowerCase();

                    tableRows.forEach(row => {
                        const text = row.textContent.toLowerCase();
                        row.style.display = text.includes(searchTerm) ? '' : 'none';
                    });
                });

                // Sort functionality
                const tableHeaders = document.querySelectorAll('th');
                
                tableHeaders.forEach(header => {
                    header.addEventListener('click', function() {
                        const index = Array.from(header.parentElement.children).indexOf(header);
                        const isAscending = header.classList.contains('sort-asc');
                        
                        // Remove sort classes from all headers
                        tableHeaders.forEach(h => {
                            h.classList.remove('sort-asc', 'sort-desc');
                        });
                        
                        // Add sort class to clicked header
                        header.classList.add(isAscending ? 'sort-desc' : 'sort-asc');
                        
                        // Sort the rows
                        const rows = Array.from(document.querySelectorAll('tbody tr'));
                        rows.sort((a, b) => {
                            const aValue = a.children[index].textContent;
                            const bValue = b.children[index].textContent;
                            
                            if (isAscending) {
                                return bValue.localeCompare(aValue);
                            } else {
                                return aValue.localeCompare(bValue);
                            }
                        });
                        
                        // Reinsert the sorted rows
                        const tbody = document.querySelector('tbody');
                        rows.forEach(row => tbody.appendChild(row));
                    });
                });
            });
       
