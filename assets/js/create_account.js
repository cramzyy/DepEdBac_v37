// create_account.js - JavaScript functionality for create account page
document.addEventListener('DOMContentLoaded', function() {
    // Add form submission loading state
    const createAccountForm = document.getElementById('createAccountForm');
    if (createAccountForm) {
        createAccountForm.addEventListener('submit', function() {
            const submitBtn = document.getElementById('submitBtn');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Account...';
            }
        });
    }

    // Add smooth focus transitions
    document.querySelectorAll('.form-control').forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
    });

    // Add form validation feedback
    document.querySelectorAll('input[required], select[required]').forEach(field => {
        field.addEventListener('invalid', function() {
            this.style.borderColor = '#e53e3e';
            this.style.boxShadow = '0 0 0 3px rgba(229, 62, 62, 0.1)';
        });
        
        field.addEventListener('input', function() {
            if (this.validity.valid) {
                this.style.borderColor = '#48bb78';
                this.style.boxShadow = '0 0 0 3px rgba(72, 187, 120, 0.1)';
            } else {
                this.style.borderColor = '#e2e8f0';
                this.style.boxShadow = 'none';
            }
        });
    });
});
