// edit_project.js - JavaScript functionality for edit project page
document.addEventListener('DOMContentLoaded', function() {
    // Highlight the current active stage for better visibility
    const highlightActiveStage = function() {
        const firstUnsubmittedStageName = window.firstUnsubmittedStageName;
        if (firstUnsubmittedStageName) {
            document.querySelectorAll(`tr[data-stage="${firstUnsubmittedStageName}"]`).forEach(row => {
                row.style.backgroundColor = '#f8f9fa';
                row.style.boxShadow = '0 0 5px rgba(0,0,0,0.1)';
            });

            document.querySelectorAll(`.stage-card h4`).forEach(heading => {
                if (heading.textContent === firstUnsubmittedStageName) {
                    heading.closest('.stage-card').style.backgroundColor = '#f8f9fa';
                    heading.closest('.stage-card').style.boxShadow = '0 0 8px rgba(0,0,0,0.15)';
                }
            });
        }
    };

    highlightActiveStage();

    // Add tooltips for better usability
    const addTooltip = function(element, text) {
        element.title = text;
        element.style.cursor = 'help';
    };

    document.querySelectorAll('th').forEach(th => {
        if (th.textContent === 'Created') {
            addTooltip(th, 'When the document was created');
        } else if (th.textContent === 'Approved') {
            addTooltip(th, 'When the document was approved');
        } else if (th.textContent === 'Office') {
            addTooltip(th, 'Office responsible for this stage');
        }
    });

    // Toast notification handler
    const showToast = function() {
        var toast = document.getElementById('toast-success');
        if (toast) {
            toast.style.display = 'block';
            setTimeout(function() {
                toast.style.opacity = '0';
                setTimeout(function() { 
                    toast.style.display = 'none'; 
                }, 600);
            }, 2500);
        }
    };

    // Check if we need to show toast
    if (window.showSuccessToast) {
        showToast();
    }
});



// Add these functions to your edit_project.js file

let currentStageToSubmit = null;

// Show submit stage modal - simplified version
function showSubmitModal(stageName) {
    const safeStage = stageName.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '_');
    
    // Look for inputs (desktop and mobile)
    let approvedAtInput = document.getElementById(`approvedAt_${safeStage}`) || 
                         document.getElementById(`mobile_approvedAt_${safeStage}`);
    
    // Fallback: search in mobile cards by stage name
    if (!approvedAtInput) {
        const mobileCards = document.querySelectorAll('.mobile-stage-card');
        for (const card of mobileCards) {
            const cardTitle = card.querySelector('.mobile-stage-card-title');
            if (cardTitle && cardTitle.textContent.trim() === stageName) {
                approvedAtInput = card.querySelector('input[type="datetime-local"]');
                if (approvedAtInput) break;
            }
        }
    }
    
    if (!approvedAtInput) {
        alert('Could not find the "Date Approved" field. Please try again.');
        return;
    }
    
    // Check if input is disabled
    if (approvedAtInput.disabled) {
        alert('This stage has already been submitted.');
        return;
    }
    
    // Auto-fill empty datetime inputs with current time
    if (!approvedAtInput.value || approvedAtInput.value.trim() === '') {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        approvedAtInput.value = `${year}-${month}-${day}T${hours}:${minutes}`;
    }
    
    // Store the stage name for later submission
    currentStageToSubmit = stageName;
    
    // Update modal text and show
    document.getElementById('submitStageNameText').textContent = stageName;
    document.getElementById('submitModal').style.display = 'block';
}

// Close submit stage modal
function closeSubmitModal() {
    document.getElementById('submitModal').style.display = 'none';
    currentStageToSubmit = null;
}

// Confirm stage submission - simplified version
function confirmSubmitStage() {
    if (!currentStageToSubmit) {
        console.error('No stage selected for submission');
        return;
    }
    
    const safeStage = currentStageToSubmit.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '_');
    
    // Look for inputs (desktop and mobile)
    let approvedAtInput = document.getElementById(`approvedAt_${safeStage}`) || 
                         document.getElementById(`mobile_approvedAt_${safeStage}`);
    let remarkInput = document.getElementById(`remark_${safeStage}`) || 
                     document.getElementById(`mobile_remark_${safeStage}`);
    
    // Fallback: search in mobile cards by stage name
    if (!approvedAtInput || !remarkInput) {
        const mobileCards = document.querySelectorAll('.mobile-stage-card');
        for (const card of mobileCards) {
            const cardTitle = card.querySelector('.mobile-stage-card-title');
            if (cardTitle && cardTitle.textContent.trim() === currentStageToSubmit) {
                if (!approvedAtInput) {
                    approvedAtInput = card.querySelector('input[type="datetime-local"]');
                }
                if (!remarkInput) {
                    remarkInput = card.querySelector('input[type="text"]');
                }
                break;
            }
        }
    }
    
    if (!approvedAtInput) {
        alert('Could not find the "Date Approved" field.');
        closeSubmitModal();
        return;
    }
    
    if (approvedAtInput.disabled) {
        alert('This stage has already been submitted.');
        closeSubmitModal();
        return;
    }
    
    // Auto-fill empty datetime inputs with current time
    if (!approvedAtInput.value || approvedAtInput.value.trim() === '') {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        approvedAtInput.value = `${year}-${month}-${day}T${hours}:${minutes}`;
    }
    
    // Create a form and submit it
    const form = document.createElement('form');
    form.method = 'POST';
    form.style.display = 'none';
    
    // Add form fields
    const stageNameInput = document.createElement('input');
    stageNameInput.type = 'hidden';
    stageNameInput.name = 'stageName';
    stageNameInput.value = currentStageToSubmit;
    form.appendChild(stageNameInput);
    
    const approvedAtHidden = document.createElement('input');
    approvedAtHidden.type = 'hidden';
    approvedAtHidden.name = 'approvedAt';
    approvedAtHidden.value = approvedAtInput.value;
    form.appendChild(approvedAtHidden);
    
    const remarkHidden = document.createElement('input');
    remarkHidden.type = 'hidden';
    remarkHidden.name = 'remark';
    remarkHidden.value = remarkInput ? remarkInput.value : '';
    form.appendChild(remarkHidden);
    
    const submitInput = document.createElement('input');
    submitInput.type = 'hidden';
    submitInput.name = 'submit_stage';
    submitInput.value = '1';
    form.appendChild(submitInput);
    
    // Add form to document and submit
    document.body.appendChild(form);
    form.submit();
    
    closeSubmitModal();
}

// Show stage creation modal
function showStageModal() {
    const dropdown = document.getElementById('stageDropdown');
    const selectedStage = dropdown.value;
    
    if (!selectedStage) {
        alert('Please select a stage to create.');
        return;
    }
    
    document.getElementById('stageNameText').textContent = selectedStage;
    document.getElementById('stageModal').style.display = 'block';
}

// Close stage creation modal
function closeStageModal() {
    document.getElementById('stageModal').style.display = 'none';
}

// Confirm stage creation
function confirmCreateStage() {
    const dropdown = document.getElementById('stageDropdown');
    const selectedStage = dropdown.value;
    
    if (selectedStage) {
        // Set the hidden input and submit the form
        document.getElementById('create_stage_hidden').value = '1';
        document.getElementById('stageDropdownForm').submit();
    }
    
    closeStageModal();
}

// Close modals when clicking outside
window.onclick = function(event) {
    const stageModal = document.getElementById('stageModal');
    const submitModal = document.getElementById('submitModal');
    const deleteModal = document.getElementById('deleteModal');
    const statusModal = document.getElementById('statusModal');
    
    if (event.target === stageModal) {
        closeStageModal();
    }
    if (event.target === submitModal) {
        closeSubmitModal();
    }
    if (event.target === deleteModal) {
        closeDeleteModal();
    }
    if (event.target === statusModal) {
        closeStatusModal();
    }
}

// Add ESC key support for modals
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeStageModal();
        closeSubmitModal();
        closeDeleteModal();
        closeStatusModal();
    }
});

// Show success toast if needed
document.addEventListener('DOMContentLoaded', function() {
    if (window.showSuccessToast) {
        const toast = document.getElementById('toast-success');
        if (toast) {
            toast.style.display = 'block';
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => {
                    toast.style.display = 'none';
                    toast.style.opacity = '1';
                }, 600);
            }, 3000);
        }
    }
    
    // Highlight the current active stage for better visibility
    const highlightActiveStage = function() {
        const firstUnsubmittedStageName = window.firstUnsubmittedStageName;
        if (firstUnsubmittedStageName) {
            document.querySelectorAll(`tr[data-stage="${firstUnsubmittedStageName}"]`).forEach(row => {
                row.style.backgroundColor = '#f8f9fa';
                row.style.boxShadow = '0 0 5px rgba(0,0,0,0.1)';
            });

            document.querySelectorAll(`.stage-card h4`).forEach(heading => {
                if (heading.textContent === firstUnsubmittedStageName) {
                    heading.closest('.stage-card').style.backgroundColor = '#f8f9fa';
                    heading.closest('.stage-card').style.boxShadow = '0 0 8px rgba(0,0,0,0.15)';
                }
            });
        }
    };

    highlightActiveStage();
});

// Delete stage functionality
let currentStageToDelete = null;

// Show delete stage modal
function showDeleteModal(stageName) {
    currentStageToDelete = stageName;
    document.getElementById('deleteStageNameText').textContent = stageName;
    document.getElementById('deleteModal').style.display = 'block';
}

// Close delete stage modal
function closeDeleteModal() {
    document.getElementById('deleteModal').style.display = 'none';
    currentStageToDelete = null;
}

// Confirm stage deletion
function confirmDeleteStage() {
    if (!currentStageToDelete) {
        console.error('No stage selected for deletion');
        return;
    }
    
    // Create a form and submit it
    const form = document.createElement('form');
    form.method = 'POST';
    form.style.display = 'none';
    
    // Add form fields
    const stageNameInput = document.createElement('input');
    stageNameInput.type = 'hidden';
    stageNameInput.name = 'stageName';
    stageNameInput.value = currentStageToDelete;
    form.appendChild(stageNameInput);
    
    const deleteInput = document.createElement('input');
    deleteInput.type = 'hidden';
    deleteInput.name = 'delete_stage';
    deleteInput.value = '1';
    form.appendChild(deleteInput);
    
    // Add form to document and submit
    document.body.appendChild(form);
    form.submit();
    
    closeDeleteModal();
}

// Project Status Change Modal Functions
let pendingStatusChange = '';

function showStatusModal(newStatus) {
    pendingStatusChange = newStatus;
    const statusText = newStatus === 'finished' ? 'Finished' : 'In Progress';
    document.getElementById('newStatusText').textContent = statusText;
    document.getElementById('statusModal').style.display = 'block';
}

function closeStatusModal() {
    document.getElementById('statusModal').style.display = 'none';
    pendingStatusChange = '';
}

function confirmStatusChange() {
    if (!pendingStatusChange) return;
    
    // Create form to submit status change
    const form = document.createElement('form');
    form.method = 'post';
    form.action = window.location.href;
    
    // Add project status input
    const statusInput = document.createElement('input');
    statusInput.type = 'hidden';
    statusInput.name = 'update_project_status';
    statusInput.value = pendingStatusChange;
    form.appendChild(statusInput);
    
    // Add form to document and submit
    document.body.appendChild(form);
    form.submit();
    
    closeStatusModal();
}