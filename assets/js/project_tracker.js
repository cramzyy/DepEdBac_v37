// Project Tracker JavaScript Functions

// Delete Project Modal Functions
let currentProjectToDelete = null;

function showDeleteProjectModal(projectName, projectID) {
    currentProjectToDelete = projectID;
    document.getElementById('deleteProjectModal').style.display = 'block';
}

function closeDeleteProjectModal() {
    document.getElementById('deleteProjectModal').style.display = 'none';
    currentProjectToDelete = null;
}

function confirmDeleteProject() {
    if (!currentProjectToDelete) {
        console.error('No project selected for deletion');
        return;
    }
    
    // Redirect to the delete URL
    window.location.href = `index.php?deleteProject=${currentProjectToDelete}`;
}

// Close modal when clicking outside
window.onclick = function(event) {
    const deleteModal = document.getElementById('deleteProjectModal');
    if (event.target === deleteModal) {
        closeDeleteProjectModal();
    }
}

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeDeleteProjectModal();
    }
});
