// manage_accounts.js - JavaScript functionality for manage accounts page
document.addEventListener('DOMContentLoaded', function() {
    // Edit button functionality
    document.querySelectorAll('.edit-btn').forEach(function(button) {
        button.addEventListener('click', function() {
            const row = this.closest('tr');
            const userID = row.querySelector('[data-label="User ID"]').textContent.trim();
            const fullName = row.querySelector('[data-label="Name"]').textContent.trim();
            let nameParts = fullName.split(" ");
            const firstname = nameParts[0] || "";
            const lastname = (nameParts.length > 1) ? nameParts[nameParts.length - 1] : "";
            // Handle middle name correctly, in case it's multi-word or absent
            let middlename = "";
            if (nameParts.length > 2) {
                // All parts between first and last are middle name
                middlename = nameParts.slice(1, nameParts.length - 1).join(" ");
            }

            const username = row.querySelector('[data-label="Username"]').textContent.trim();
            const role = row.querySelector('[data-label="Role"]').textContent.trim();
            const office = row.querySelector('[data-label="Office"]').textContent.trim();
            const position = row.querySelector('[data-label="Position"]').textContent.trim();
            
            // Populate the form fields
            document.getElementById('editUserID').value = userID;
            document.getElementById('editFirstname').value = firstname;
            document.getElementById('editMiddlename').value = middlename;
            document.getElementById('editLastname').value = lastname;
            document.getElementById('editUsername').value = username;
            document.getElementById('editPassword').value = ""; // Always clear password field for security
            document.getElementById('editAdmin').checked = (role === "Admin");
            document.getElementById('editPosition').value = position;
            
            // Set the selected option for the office dropdown
            const editOfficeSelect = document.getElementById('editOffice');
            let foundOffice = false;
            for (let i = 0; i < editOfficeSelect.options.length; i++) {
                if (editOfficeSelect.options[i].value === office) {
                    editOfficeSelect.selectedIndex = i;
                    foundOffice = true;
                    break;
                }
            }
            if (!foundOffice && office) {
                // If the office from the table row isn't in the dropdown, add it as a new option
                // This handles cases where office data in table might not perfectly match dropdown options
                let newOption = new Option(office, office, true, true);
                editOfficeSelect.add(newOption);
            }
            
            // Display the modal
            document.getElementById('editModal').style.display = 'flex'; // Use 'flex' to show the flex container
        });
    });
    
    // Delete button functionality
    let currentDeleteUserID = null;
    document.querySelectorAll('.account-delete-btn').forEach(function(button) {
        button.addEventListener('click', function() {
            currentDeleteUserID = this.dataset.id;
            document.getElementById('deleteConfirmModal').style.display = 'flex'; // Use 'flex' to show the flex container
        });
    });
    
    // Confirm delete button
    document.getElementById('confirmDeleteBtn').addEventListener('click', function() {
        if (currentDeleteUserID) {
            window.location.href = `manage_accounts.php?delete=${currentDeleteUserID}`;
        }
        document.getElementById('deleteConfirmModal').style.display = 'none';
    });
    
    // Cancel delete button
    document.getElementById('cancelDeleteBtn').addEventListener('click', function() {
        document.getElementById('deleteConfirmModal').style.display = 'none';
        currentDeleteUserID = null;
    });
    
    // Close buttons
    document.getElementById('editClose').addEventListener('click', function() {
        document.getElementById('editModal').style.display = 'none';
    });
    
    document.getElementById('deleteClose').addEventListener('click', function() {
        document.getElementById('deleteConfirmModal').style.display = 'none';
        currentDeleteUserID = null;
    });
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        const editModal = document.getElementById('editModal');
        const deleteConfirmModal = document.getElementById('deleteConfirmModal');
        
        if (event.target === editModal) {
            editModal.style.display = 'none';
        }
        if (event.target === deleteConfirmModal) {
            deleteConfirmModal.style.display = 'none';
            currentDeleteUserID = null;
        }
    });
});
