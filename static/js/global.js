function likeMii(el,id,highlightedMii,mod){
	fetch("/voteMii?id="+id).then(d=>d.text()).then(d=>{
		// TODO: this hurts my eyes
		if(d==="Liked"){
			el.innerHTML=`<svg class="like" xmlns="http://www.w3.org/2000/svg" height="36px" viewBox="0 0 24 24" width="36px" fill="#000000"><path d="M0 0h24v24H0V0z" fill="none"/><path d="M13.35 20.13c-.76.69-1.93.69-2.69-.01l-.11-.1C5.3 15.27 1.87 12.16 2 8.28c.06-1.7.93-3.33 2.34-4.29 2.64-1.8 5.9-.96 7.66 1.1 1.76-2.06 5.02-2.91 7.66-1.1 1.41.96 2.28 2.59 2.34 4.29.14 3.88-3.3 6.99-8.55 11.76l-.1.09z"/></svg>`;
		}
		else if(d==="Unliked"){
			el.innerHTML=`<svg xmlns="http://www.w3.org/2000/svg" height="48" viewBox="0 96 960 960" width="36px" height="36px" class="like" viewBox="0 0 24 24" fill="#000000"><path d="m480 935-41-37q-105.768-97.121-174.884-167.561Q195 660 154 604.5T96.5 504Q80 459 80 413q0-90.155 60.5-150.577Q201 202 290 202q57 0 105.5 27t84.5 78q42-54 89-79.5T670 202q89 0 149.5 60.423Q880 322.845 880 413q0 46-16.5 91T806 604.5Q765 660 695.884 730.439 626.768 800.879 521 898l-41 37Zm0-79q101.236-92.995 166.618-159.498Q712 630 750.5 580t54-89.135q15.5-39.136 15.5-77.72Q820 347 778 304.5T670.225 262q-51.524 0-95.375 31.5Q531 325 504 382h-49q-26-56-69.85-88-43.851-32-95.375-32Q224 262 182 304.5t-42 108.816Q140 452 155.5 491.5t54 90Q248 632 314 698t166 158Zm0-297Z"/></svg>`;
		}
		if(mod&&(d==="Liked"||d==="Unliked")){
			el.innerHTML+=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 96 960 960" fill="#f00" class="trash" onclick="deleteMii('${id}')"><path d="M261 936q-24.75 0-42.375-17.625T201 876V306h-41v-60h188v-30h264v30h188v60h-41v570q0 24-18 42t-42 18H261Zm438-630H261v570h438V306ZM367 790h60V391h-60v399Zm166 0h60V391h-60v399ZM261 306v570-570Z"/></svg>`;
		}
	});
}

// Custom Modal System
let modalOverlay = null;

function createModalOverlay() {
    if (!modalOverlay) {
        modalOverlay = document.createElement('div');
        modalOverlay.className = 'custom-modal-overlay';
        document.body.appendChild(modalOverlay);
    }
    return modalOverlay;
}

function closeModal() {
    const overlay = document.querySelector('.custom-modal-overlay');
    if (overlay) {
        overlay.classList.remove('active');
        setTimeout(() => {
            overlay.innerHTML = '';
        }, 200);
    }
}

/**
 * Show a confirmation dialog with custom message
 * @param {string} message - The message to display
 * @param {Function} onConfirm - Callback function to run when user confirms
 * @param {Function} onCancel - Optional callback function to run when user cancels
 * @param {Object} options - Optional configuration
 * @param {string} options.title - Modal title (default: "Confirm")
 * @param {string} options.confirmText - Confirm button text (default: "Confirm")
 * @param {string} options.cancelText - Cancel button text (default: "Cancel")
 */
function showConfirm(message, onConfirm, onCancel = null, options = {}) {
    const overlay = createModalOverlay();
    
    const title = options.title || 'Confirm';
    const confirmText = options.confirmText || 'Confirm';
    const cancelText = options.cancelText || 'Cancel';
    
    // Create modal structure using DOM methods
    const modal = document.createElement('div');
    modal.className = 'custom-modal';
    
    // Header
    const header = document.createElement('div');
    header.className = 'custom-modal-header';
    
    const titleEl = document.createElement('h3');
    titleEl.textContent = title;
    
    const closeBtnObj = document.createElement('button');
    closeBtnObj.className = 'custom-modal-close';
    closeBtnObj.setAttribute('aria-label', 'Close');
    closeBtnObj.innerHTML = '&times;';
    
    header.appendChild(titleEl);
    header.appendChild(closeBtnObj);
    
    // Body
    const body = document.createElement('div');
    body.className = 'custom-modal-body';
    body.textContent = message;
    
    // Footer
    const footer = document.createElement('div');
    footer.className = 'custom-modal-footer';
    
    const cancelBtnObj = document.createElement('button');
    cancelBtnObj.className = 'custom-modal-btn custom-modal-btn-secondary';
    cancelBtnObj.setAttribute('data-action', 'cancel');
    cancelBtnObj.textContent = cancelText;
    
    const confirmBtnObj = document.createElement('button');
    confirmBtnObj.className = 'custom-modal-btn custom-modal-btn-primary';
    confirmBtnObj.setAttribute('data-action', 'confirm');
    confirmBtnObj.textContent = confirmText;
    
    footer.appendChild(cancelBtnObj);
    footer.appendChild(confirmBtnObj);
    
    // Assemble modal
    modal.appendChild(header);
    modal.appendChild(body);
    modal.appendChild(footer);
    
    overlay.innerHTML = '';
    overlay.appendChild(modal);
    
    const closeBtn = overlay.querySelector('.custom-modal-close');
    const confirmBtn = overlay.querySelector('[data-action="confirm"]');
    const cancelBtn = overlay.querySelector('[data-action="cancel"]');
    
    const handleClose = () => {
        closeModal();
        if (onCancel) onCancel();
    };
    
    const handleConfirm = () => {
        closeModal();
        if (onConfirm) onConfirm();
    };
    
    closeBtn.addEventListener('click', handleClose);
    cancelBtn.addEventListener('click', handleClose);
    confirmBtn.addEventListener('click', handleConfirm);
    
    // Close on overlay click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) handleClose();
    });
    
    // Close on Escape key
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            handleClose();
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);
    
    // Show modal
    setTimeout(() => overlay.classList.add('active'), 10);
    confirmBtn.focus();
}

/**
 * Show an alert dialog with auto-dismiss
 * @param {string} message - The message to display
 * @param {number} duration - Duration in milliseconds before auto-dismiss (default: 5000)
 * @param {Object} options - Optional configuration
 * @param {string} options.title - Modal title (default: "Notice")
 * @param {string} options.type - Alert type: 'info', 'success', 'error' (default: 'info')
 */
function showAlert(message, duration = 5000, options = {}) {
    const overlay = createModalOverlay();
    
    const title = options.title || 'Notice';
    const type = options.type || 'info';
    
    overlay.className = 'custom-modal-overlay custom-modal-alert';
    overlay.innerHTML = `
        <div class="custom-modal">
            <div class="custom-modal-header">
                <h3>${title}</h3>
                <button class="custom-modal-close" aria-label="Close">&times;</button>
            </div>
            <div class="custom-modal-body">${message}</div>
            <div class="custom-modal-timer" style="animation-duration: ${duration}ms;"></div>
        </div>
    `;
    
    const closeBtn = overlay.querySelector('.custom-modal-close');
    
    const handleClose = () => {
        closeModal();
        if (autoCloseTimeout) clearTimeout(autoCloseTimeout);
    };
    
    closeBtn.addEventListener('click', handleClose);
    
    // Close on overlay click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) handleClose();
    });
    
    // Close on Escape key
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            handleClose();
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);
    
    // Show modal
    setTimeout(() => overlay.classList.add('active'), 10);
    
    // Auto-close after duration
    const autoCloseTimeout = setTimeout(() => {
        handleClose();
    }, duration);
}

function deleteMii(id){
	showConfirm("Are you sure you want to delete this Mii?", () => {
		fetch("/deleteMii?id="+id).then(d=>d.json()).then(d=>{
			if(d.error){
				const errorDiv = document.getElementById('delete-error-message');
				if (errorDiv) {
					errorDiv.textContent = d.error;
					errorDiv.className = 'form-message error';
					errorDiv.style.display = 'block';
				} else {
					// Ideally not used
					showAlert(d.error, 5000, { title: 'Error', type: 'error' });
				}
			}
			else{
				document.getElementById(id).remove();
			}
		});
	});
}
function highlightedMiiChange(){
    fetch("/changeHighlightedMii", {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: JSON.stringify({ id: document.getElementById("highlightedMiiID").value })
	}).then(d=>d.json()).then(d=>{
        if(!d.error){
            location.reload();
        }
        else{
            showAlert(d.error, 5000, { title: 'Error', type: 'error' });
        }
    });
}

/**
 * Standardized form submission handler
 * @param {Event} e - The form submit event
 * @param {string} url - The endpoint URL to submit to
 * @param {string} loadingText - Text to display on submit button during loading
 * @param {string} errorDivId - ID of the div to display error/success messages
 * @param {Object} options - Additional options
 * @param {Object} options.headers - Custom headers (default: none for FormData)
 * @param {Function} options.bodyFormatter - Function to format FormData before sending
 * @param {Function} options.onSuccess - Custom success handler (result, messageDiv, response)
 * @param {boolean} options.handleFileDownload - Whether this endpoint returns a file download
* @param {String} options.next - Where to go instead of response.redirect
 */
async function handleFormSubmit(e, url, loadingText, errorDivId, options = {}) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const submitBtn = form.querySelector('input[type="submit"], button[type="submit"]');
    const originalText = submitBtn.value || submitBtn.textContent;
    const messageDiv = document.getElementById(errorDivId);
    
    // Clear any previous messages
    messageDiv.style.display = 'none';
    messageDiv.textContent = '';
    messageDiv.className = 'form-message';
    
    // Update button state
    if (submitBtn.tagName === 'INPUT') {
        submitBtn.value = loadingText;
    } else {
        submitBtn.textContent = loadingText;
    }
    submitBtn.disabled = true;
    
    try {
        const fetchOptions = {
            method: 'POST',
            body: options.bodyFormatter ? options.bodyFormatter(formData) : formData
        };
        
        if (options.headers) {
            fetchOptions.headers = options.headers;
        }
        
        const response = await fetch(url, fetchOptions);
        
        // Handle file downloads
        if (options.handleFileDownload) {
            const contentType = response.headers.get('content-type');
            const contentDisposition = response.headers.get('content-disposition');
            
            if (contentDisposition && contentDisposition.includes('attachment')) {
                const blob = await response.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                const filename = contentDisposition.split('filename=')[1].replace(/"/g, '');
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(downloadUrl);
                document.body.removeChild(a);
                
                // Reset button
                if (submitBtn.tagName === 'INPUT') {
                    submitBtn.value = originalText;
                } else {
                    submitBtn.textContent = originalText;
                }
                submitBtn.disabled = false;
                return;
            }
        }
        
        const result = await response.json();
        
        if (result.error) {
            messageDiv.textContent = result.error;
            messageDiv.className = 'form-message error';
            messageDiv.style.display = 'block';
        } else {
            // Success
            if (options.onSuccess) {
                options.onSuccess(result, messageDiv, response);
            } else if (result.redirect) {
                window.location.href = options?.next || result.redirect;
            } else if (result.message) {
                messageDiv.textContent = result.message;
                messageDiv.className = 'form-message success';
                messageDiv.style.display = 'block';
            }
        }
    } catch (error) {
        console.error('Form submission error:', error);
        messageDiv.textContent = 'An error occurred. Please try again.';
        messageDiv.className = 'form-message error';
        messageDiv.style.display = 'block';
    } finally {
        // Reset button if not redirecting
        if (submitBtn.tagName === 'INPUT') {
            submitBtn.value = originalText;
        } else {
            submitBtn.textContent = originalText;
        }
        submitBtn.disabled = false;
    }
}