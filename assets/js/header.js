
    // Profile dropdown toggle logic (moved from index to header.php)
    const profileIcon = document.getElementById('profileIcon');
    const dropdownArrow = document.getElementById('dropdownArrow');
    const profileDropdown = document.getElementById('profileDropdown');

    function toggleDropdown(event) {
        event.stopPropagation(); // Prevent document click from immediately closing it
        if (profileDropdown) {
            profileDropdown.classList.toggle('open');
        }
    }
    // Check if elements exist before adding event listeners to prevent errors
    if (profileIcon) {
        profileIcon.addEventListener('click', toggleDropdown);
    }
    if (dropdownArrow) { // This will still exist but without an arrow character
        dropdownArrow.addEventListener('click', toggleDropdown);
    }

    document.addEventListener('click', function(event) {
        // Close dropdown if click outside
        if (profileDropdown && !profileDropdown.contains(event.target) && profileDropdown.classList.contains('open')) {
            profileDropdown.classList.remove('open');
        }
    });
    