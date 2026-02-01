// Category Management Functions

async function addParentCategory() {
    const name = document.getElementById('newParentName').value.trim();
    const color = document.getElementById('newParentColor').value;
    
    if (!name) {
        showAlert('Please enter a category name', 5000, { title: 'Error', type: 'error' });
        return;
    }
    
    try {
        const response = await fetch('/addParentCategory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, color })
        });
        
        const data = await response.json();
        
        if (!data.error) {
            showAlert('Parent category created successfully!', 3000, { title: 'Success', type: 'success' });
            setTimeout(() => location.reload(), 3000);
        } else {
            showAlert('Error: ' + (data.error || 'Failed to create category'), 5000, { title: 'Error', type: 'error' });
        }
    } catch (error) {
        console.error('Error:', error);
        showAlert('Error creating category', 5000, { title: 'Error', type: 'error' });
    }
}

async function addSubcategory(parentCategory) {
    const inputId = 'newSub_' + parentCategory.replace(/\s+/g, '_');
    const subcategoryName = document.getElementById(inputId).value.trim();
    
    if (!subcategoryName) {
        showAlert('Please enter a subcategory name', 5000, { title: 'Error', type: 'error' });
        return;
    }
    
    try {
        const response = await fetch('/addSubcategory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ parentCategory, subcategoryName })
        });
        
        const data = await response.json();
        
        if (!data.error) {
            showAlert('Subcategory created successfully!', 3000, { title: 'Success', type: 'success' });
            setTimeout(() => location.reload(), 3000);
        } else {
            showAlert('Error: ' + (data.error || 'Failed to create subcategory'), 5000, { title: 'Error', type: 'error' });
        }
    } catch (error) {
        console.error('Error:', error);
        showAlert('Error creating subcategory', 5000, { title: 'Error', type: 'error' });
    }
}

async function renameParentCategory(oldName) {
    const newName = prompt('Enter new name for category:', oldName);
    
    if (!newName || newName === oldName) return;
    
    try {
        const response = await fetch('/renameParentCategory', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ oldName, newName })
        });
        
        const data = await response.json();
        
        if (!data.error) {
            showAlert('Category renamed successfully!', 3000, { title: 'Success', type: 'success' });
            setTimeout(() => location.reload(), 3000);
        } else {
            showAlert('Error: ' + (data.error || 'Failed to rename category'), 5000, { title: 'Error', type: 'error' });
        }
    } catch (error) {
        console.error('Error:', error);
        showAlert('Error renaming category', 5000, { title: 'Error', type: 'error' });
    }
}

async function renameSubcategory(parentCategory, oldName) {
    const newName = prompt('Enter new name for subcategory:', oldName);
    
    if (!newName || newName === oldName) return;
    
    showConfirm(
        `This will rename "${oldName}" to "${newName}" and update all Miis using this category.\n\nContinue?`,
        async () => {
            try {
                const response = await fetch('/renameSubcategory', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ parentCategory, oldName, newName })
                });
                
                const data = await response.json();
                
                if (!data.error) {
                    showAlert(`Subcategory renamed successfully!\n${data.updatedMiis} Miis were updated.`, 4000, { title: 'Success', type: 'success' });
                    setTimeout(() => location.reload(), 4000);
                } else {
                    showAlert('Error: ' + (data.error || 'Failed to rename subcategory'), 5000, { title: 'Error', type: 'error' });
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert('Error renaming subcategory', 5000, { title: 'Error', type: 'error' });
            }
        },
        null,
        { title: 'Confirm Rename' }
    );
}

async function deleteSubcategory(parentCategory, subcategoryName) {
    showConfirm(
        `Delete subcategory "${subcategoryName}"?\n\nThis will remove it from all Miis using it. This cannot be undone.`,
        async () => {
            try {
                const response = await fetch('/deleteSubcategory', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ parentCategory, subcategoryName })
                });
                
                const data = await response.json();
                
                if (!data.error) {
                    showAlert(`Subcategory deleted successfully!\n${data.updatedMiis} Miis were updated.`, 4000, { title: 'Success', type: 'success' });
                    setTimeout(() => location.reload(), 4000);
                } else {
                    showAlert('Error: ' + (data.error || 'Failed to delete subcategory'), 5000, { title: 'Error', type: 'error' });
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert('Error deleting subcategory', 5000, { title: 'Error', type: 'error' });
            }
        },
        null,
        { title: 'Confirm Delete', confirmText: 'Delete' }
    );
}

async function deleteParentCategory(name) {
    showConfirm(
        `Delete parent category "${name}" and ALL its subcategories?\n\nThis will remove all subcategories from all Miis. This cannot be undone.`,
        () => {
            showConfirm(
                `Are you ABSOLUTELY sure? This is a destructive action.`,
                async () => {
                    try {
                        const response = await fetch('/deleteParentCategory', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ name })
                        });
                        
                        const data = await response.json();
                        
                        if (!data.error) {
                            showAlert(`Parent category deleted successfully!\n${data.updatedMiis} Miis were updated.`, 4000, { title: 'Success', type: 'success' });
                            setTimeout(() => location.reload(), 4000);
                        } else {
                            showAlert('Error: ' + (data.error || 'Failed to delete category'), 5000, { title: 'Error', type: 'error' });
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        showAlert('Error deleting category', 5000, { title: 'Error', type: 'error' });
                    }
                },
                null,
                // TODO: warning icon?
                { title: 'Final Warning', confirmText: 'Yes, Delete Everything' }
            );
        },
        null,
        { title: 'Confirm Delete', confirmText: 'Continue' }
    );
}