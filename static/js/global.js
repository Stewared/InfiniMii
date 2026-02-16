function likeMii(el,id,highlightedMii,mod){
    fetch("/voteMii?id="+encodeURIComponent(id), { method: 'POST' }).then(d=>d.text()).then(d=>{
        let parsed;
        try { parsed = JSON.parse(d); } catch (e) {}
        if (parsed?.error) {
            if (typeof showAlert === 'function') showAlert(parsed.error, 5000, { title: 'Error', type: 'error' });
            return;
        }

        const icon = el.querySelector('.like-icon');
        const countEl = el.querySelector('.vote-count');
        const currentCount = countEl ? parseInt(countEl.textContent) || 0 : 0;
        const likedSvg = `<svg class="like-icon liked" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M0 0h24v24H0V0z" fill="none"/><path d="M13.35 20.13c-.76.69-1.93.69-2.69-.01l-.11-.1C5.3 15.27 1.87 12.16 2 8.28c.06-1.7.93-3.33 2.34-4.29 2.64-1.8 5.9-.96 7.66 1.1 1.76-2.06 5.02-2.91 7.66-1.1 1.41.96 2.28 2.59 2.34 4.29.14 3.88-3.3 6.99-8.55 11.76l-.1.09z"/></svg>`;
        const unlikedSvg = `<svg xmlns="http://www.w3.org/2000/svg" class="like-icon" viewBox="0 96 960 960" fill="currentColor"><path d="m480 935-41-37q-105.768-97.121-174.884-167.561Q195 660 154 604.5T96.5 504Q80 459 80 413q0-90.155 60.5-150.577Q201 202 290 202q57 0 105.5 27t84.5 78q42-54 89-79.5T670 202q89 0 149.5 60.423Q880 322.845 880 413q0 46-16.5 91T806 604.5Q765 660 695.884 730.439 626.768 800.879 521 898l-41 37Zm0-79q101.236-92.995 166.618-159.498Q712 630 750.5 580t54-89.135q15.5-39.136 15.5-77.72Q820 347 778 304.5T670.225 262q-51.524 0-95.375 31.5Q531 325 504 382h-49q-26-56-69.85-88-43.851-32-95.375-32Q224 262 182 304.5t-42 108.816Q140 452 155.5 491.5t54 90Q248 632 314 698t166 158Zm0-297Z"/></svg>`;

        if(d==="Liked"){
            if (icon) icon.outerHTML = likedSvg;
            if (countEl) countEl.textContent = currentCount + 1;
        }
        else if(d==="Unliked"){
            if (icon) icon.outerHTML = unlikedSvg;
            if (countEl) countEl.textContent = Math.max(0, currentCount - 1);
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

const INSTRUCTION_CONSOLE_OPTIONS = [
    { value: 'DS', label: 'Nintendo DS' },
    { value: 'WII', label: 'Wii' },
    { value: '3DS', label: 'Nintendo 3DS' },
    { value: 'WIIU', label: 'Wii U' },
    { value: 'SWITCH', label: 'Nintendo Switch' },
    { value: 'SWITCH2', label: 'Nintendo Switch 2' }
];

function flattenInstructionEntries(instructions, prefix = '') {
    if (!instructions || typeof instructions !== 'object') return [];

    const entries = [];
    for (const [key, value] of Object.entries(instructions)) {
        const nextPrefix = prefix ? `${prefix}.${key}` : key;
        if (!value) continue;

        if (typeof value === 'string') {
            entries.push({
                key: nextPrefix,
                label: nextPrefix
                    .split('.')
                    .map(part => part.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()))
                    .join(' > ')
                    .trim(),
                text: value
            });
            continue;
        }

        if (typeof value === 'object') {
            entries.push(...flattenInstructionEntries(value, nextPrefix));
        }
    }

    return entries;
}

window.showMiiInstructionsModal = function(loader, options = {}) {
    if (typeof loader !== 'function') {
        throw new Error('showMiiInstructionsModal requires a loader callback');
    }

    const overlay = createModalOverlay();
    overlay.className = 'custom-modal-overlay custom-modal-instructions';

    const defaultConsole = String(options.defaultConsole || '3DS').toUpperCase();
    const title = options.title || 'Recreation Instructions';

    const modal = document.createElement('div');
    modal.className = 'custom-modal';

    const header = document.createElement('div');
    header.className = 'custom-modal-header';
    header.innerHTML = `
        <h3>${title}</h3>
        <button class="custom-modal-close" aria-label="Close">&times;</button>
    `;

    const body = document.createElement('div');
    body.className = 'custom-modal-body instructions-modal-body';

    const controls = document.createElement('div');
    controls.className = 'instructions-controls';

    const consoleGroup = document.createElement('label');
    consoleGroup.className = 'instructions-control-group';
    consoleGroup.innerHTML = `
        <span>Console</span>
        <select class="instructions-console-select">
            ${INSTRUCTION_CONSOLE_OPTIONS.map(opt => `<option value="${opt.value}"${opt.value === defaultConsole ? ' selected' : ''}>${opt.label}</option>`).join('')}
        </select>
    `;

    controls.appendChild(consoleGroup);

    const output = document.createElement('div');
    output.className = 'instructions-output';
    output.innerHTML = '<p class="instructions-status">Loading instructions...</p>';

    body.appendChild(controls);
    body.appendChild(output);

    const footer = document.createElement('div');
    footer.className = 'custom-modal-footer';
    footer.innerHTML = `
        <button class="custom-modal-btn custom-modal-btn-secondary" data-action="copy">Copy to Clipboard</button>
        <button class="custom-modal-btn custom-modal-btn-primary" data-action="close">Close</button>
    `;

    modal.appendChild(header);
    modal.appendChild(body);
    modal.appendChild(footer);
    overlay.innerHTML = '';
    overlay.appendChild(modal);

    const closeBtn = modal.querySelector('.custom-modal-close');
    const closeFooterBtn = modal.querySelector('[data-action="close"]');
    const copyBtn = modal.querySelector('[data-action="copy"]');
    const consoleSelect = modal.querySelector('.instructions-console-select');

    let latestPayload = null;
    let latestEntries = [];

    const handleClose = () => {
        closeModal();
        overlay.className = 'custom-modal-overlay';
        document.removeEventListener('keydown', handleEscape);
    };

    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            handleClose();
        }
    };

    const renderEntries = (entries) => {
        latestEntries = entries;
        if (!entries.length) {
            output.innerHTML = '<p class="instructions-status">All settings are at default values.</p>';
            return;
        }

        output.innerHTML = '';
        for (const entry of entries) {
            const row = document.createElement('div');
            row.className = 'instructions-entry';

            const label = document.createElement('span');
            label.className = 'instructions-entry-label';
            label.textContent = `${entry.label}:`;

            row.appendChild(label);
            row.appendChild(document.createTextNode(entry.text));
            output.appendChild(row);
        }
    };

    const loadInstructions = async () => {
        const selectedConsole = consoleSelect.value;
        output.innerHTML = '<p class="instructions-status">Loading instructions...</p>';

        try {
            const payload = await loader({
                consoleType: selectedConsole
            });

            if (!payload || payload.error) {
                throw new Error(payload?.error || 'Failed to load instructions');
            }

            latestPayload = payload;
            const entries = flattenInstructionEntries(payload.instructions);
            renderEntries(entries);
        } catch (error) {
            console.error('Error loading instructions:', error);
            output.innerHTML = '';
            const errorLine = document.createElement('p');
            errorLine.className = 'instructions-status instructions-status-error';
            errorLine.textContent = error.message || 'Failed to load instructions';
            output.appendChild(errorLine);
            latestPayload = null;
            latestEntries = [];
        }
    };

    closeBtn.addEventListener('click', handleClose);
    closeFooterBtn.addEventListener('click', handleClose);
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            handleClose();
        }
    });
    document.addEventListener('keydown', handleEscape);

    consoleSelect.addEventListener('change', loadInstructions);

    copyBtn.addEventListener('click', async () => {
        if (!latestEntries.length) {
            if (typeof showAlert === 'function') {
                showAlert('No instructions to copy yet.', 3000, { title: 'Notice', type: 'info' });
            }
            return;
        }

        const miiName = latestPayload?.miiName || options.miiName || 'Mii';
        const selectedConsole = latestPayload?.console || consoleSelect.value;
        const lines = latestEntries.map(entry => `${entry.label}: ${entry.text}`);
        const text = `Recreation Instructions for ${miiName} (${selectedConsole})\n\n${lines.join('\n')}`;

        try {
            await navigator.clipboard.writeText(text);
            if (typeof showAlert === 'function') {
                showAlert('Instructions copied to clipboard.', 3000, { title: 'Success', type: 'success' });
            }
        } catch (error) {
            console.error('Error copying instructions:', error);
            if (typeof showAlert === 'function') {
                showAlert('Failed to copy instructions.', 4000, { title: 'Error', type: 'error' });
            }
        }
    });

    setTimeout(() => overlay.classList.add('active'), 10);
    loadInstructions();
};

function bytesToHexString(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64String(bytes) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
}

async function readErrorMessageFromResponse(response) {
    try {
        const result = await response.json();
        if (result?.error) return result.error;
    } catch (e) { }
    return `Request failed (${response.status})`;
}

window.copyExportTextFromForm = async function(form, encoding = 'hex', options = {}) {
    try {
        if (!form || !(form instanceof HTMLFormElement)) {
            throw new Error('Copy source form is invalid.');
        }

        const method = String(options.method || form.method || 'GET').toUpperCase();
        let endpoint = options.url || form.action || '/exportMii';
        const formData = new FormData(form);
        const fetchOptions = { method };

        if (method === 'GET') {
            const params = new URLSearchParams();
            for (const [key, value] of formData.entries()) {
                if (typeof value === 'string') {
                    params.append(key, value);
                }
            }
            const query = params.toString();
            if (query) {
                endpoint += (endpoint.includes('?') ? '&' : '?') + query;
            }
        } else {
            fetchOptions.body = formData;
        }

        const response = await fetch(endpoint, fetchOptions);
        const contentDisposition = response.headers.get('content-disposition') || '';
        const isFileResponse = contentDisposition.includes('attachment');

        if (!response.ok || !isFileResponse) {
            const errorMessage = await readErrorMessageFromResponse(response);
            throw new Error(errorMessage);
        }

        const bytes = new Uint8Array(await response.arrayBuffer());
        const normalizedEncoding = String(encoding).toLowerCase();
        const text = normalizedEncoding === 'base64'
            ? bytesToBase64String(bytes)
            : bytesToHexString(bytes);

        await navigator.clipboard.writeText(text);
        if (typeof showAlert === 'function') {
            const label = normalizedEncoding === 'base64' ? 'Base64' : 'Hex';
            showAlert(`${label} copied to clipboard.`, 2500, { title: 'Success', type: 'success' });
        }

        return text;
    } catch (error) {
        if (typeof showAlert === 'function') {
            showAlert(error.message || 'Failed to copy export data.', 5000, { title: 'Error', type: 'error' });
        }
        return null;
    }
};

function initMobileSideDrawers() {
    if (window.__infinimiiMobileDrawersInit) return;

    const leftDrawer = document.getElementById('leftSidebarDrawer');
    const rightDrawer = document.getElementById('featuredMiisDrawer');
    const drawerById = {};

    if (leftDrawer?.id) drawerById[leftDrawer.id] = leftDrawer;
    if (rightDrawer?.id) drawerById[rightDrawer.id] = rightDrawer;

    const toggles = Array.from(document.querySelectorAll('.mobile-drawer-toggle[data-drawer-target]'))
        .filter((btn) => {
            const target = btn.getAttribute('data-drawer-target') || '';
            return Boolean(drawerById[target]);
        });

    if (!Object.keys(drawerById).length || !toggles.length) {
        return;
    }

    window.__infinimiiMobileDrawersInit = true;

    const mobileQuery = window.matchMedia('(max-width: 992px)');
    const EDGE_TRIGGER_PX = 28;
    const SWIPE_TRIGGER_PX = 66;

    const overlay = document.createElement('div');
    overlay.className = 'mobile-drawer-overlay';
    document.body.appendChild(overlay);

    let swipeState = null;

    function getDrawerSide(drawer) {
        if (!drawer) return null;
        return drawer.classList.contains('mobile-drawer-right') ? 'right' : 'left';
    }

    function syncToggleState(drawerId, isOpen) {
        toggles.forEach((btn) => {
            if (btn.getAttribute('data-drawer-target') !== drawerId) return;
            btn.setAttribute('aria-expanded', String(isOpen));
            btn.classList.toggle('is-open', isOpen);
        });
    }

    function clearBodyDrawerClasses() {
        document.body.classList.remove(
            'mobile-drawer-overlay-visible',
            'mobile-drawer-lock',
            'mobile-drawer-left-open',
            'mobile-drawer-right-open'
        );
    }

    function getOpenDrawer() {
        return Object.values(drawerById).find((drawer) => drawer.classList.contains('mobile-drawer-open')) || null;
    }

    function closeAllDrawers() {
        Object.values(drawerById).forEach((drawer) => {
            drawer.classList.remove('mobile-drawer-open');
            syncToggleState(drawer.id, false);
        });
        clearBodyDrawerClasses();
    }

    function openDrawerById(drawerId) {
        if (!mobileQuery.matches) return;
        const drawer = drawerById[drawerId];
        if (!drawer) return;

        closeAllDrawers();
        drawer.classList.add('mobile-drawer-open');
        syncToggleState(drawer.id, true);

        document.body.classList.add('mobile-drawer-overlay-visible', 'mobile-drawer-lock');
        const side = getDrawerSide(drawer);
        if (side === 'left') {
            document.body.classList.add('mobile-drawer-left-open');
        } else if (side === 'right') {
            document.body.classList.add('mobile-drawer-right-open');
        }
    }

    function toggleDrawerById(drawerId) {
        if (!mobileQuery.matches) return;
        const drawer = drawerById[drawerId];
        if (!drawer) return;

        if (drawer.classList.contains('mobile-drawer-open')) {
            closeAllDrawers();
            return;
        }

        openDrawerById(drawerId);
    }

    function openDrawerFromSide(side) {
        if (side === 'left' && leftDrawer?.id) {
            openDrawerById(leftDrawer.id);
            return;
        }

        if (side === 'right' && rightDrawer?.id) {
            openDrawerById(rightDrawer.id);
        }
    }

    toggles.forEach((btn) => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-drawer-target');
            if (!target) return;
            toggleDrawerById(target);
        });
    });

    overlay.addEventListener('click', closeAllDrawers);

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeAllDrawers();
        }
    });

    const onViewportChange = () => {
        if (!mobileQuery.matches) {
            closeAllDrawers();
        }
    };

    if (typeof mobileQuery.addEventListener === 'function') {
        mobileQuery.addEventListener('change', onViewportChange);
    } else if (typeof mobileQuery.addListener === 'function') {
        mobileQuery.addListener(onViewportChange);
    }

    function onTouchStart(event) {
        if (!mobileQuery.matches || event.touches.length !== 1) return;

        const touch = event.touches[0];
        const x = touch.clientX;
        const y = touch.clientY;
        const openDrawer = getOpenDrawer();

        if (openDrawer) {
            if (openDrawer.contains(event.target)) {
                swipeState = {
                    mode: 'close',
                    side: getDrawerSide(openDrawer),
                    startX: x,
                    startY: y
                };
            } else {
                swipeState = null;
            }
            return;
        }

        if (leftDrawer && x <= EDGE_TRIGGER_PX) {
            swipeState = { mode: 'open', side: 'left', startX: x, startY: y };
            return;
        }

        if (rightDrawer && x >= (window.innerWidth - EDGE_TRIGGER_PX)) {
            swipeState = { mode: 'open', side: 'right', startX: x, startY: y };
            return;
        }

        swipeState = null;
    }

    function onTouchMove(event) {
        if (!swipeState || !mobileQuery.matches || event.touches.length !== 1) return;

        const touch = event.touches[0];
        const dx = touch.clientX - swipeState.startX;
        const dy = touch.clientY - swipeState.startY;

        if (Math.abs(dy) > (Math.abs(dx) + 16)) {
            swipeState = null;
            return;
        }

        if (swipeState.mode === 'open') {
            if (swipeState.side === 'left' && dx > SWIPE_TRIGGER_PX) {
                openDrawerFromSide('left');
                swipeState = null;
                return;
            }

            if (swipeState.side === 'right' && dx < (-SWIPE_TRIGGER_PX)) {
                openDrawerFromSide('right');
                swipeState = null;
            }
            return;
        }

        if (swipeState.mode === 'close') {
            if (swipeState.side === 'left' && dx < (-SWIPE_TRIGGER_PX)) {
                closeAllDrawers();
                swipeState = null;
                return;
            }

            if (swipeState.side === 'right' && dx > SWIPE_TRIGGER_PX) {
                closeAllDrawers();
                swipeState = null;
            }
        }
    }

    function onTouchEnd() {
        swipeState = null;
    }

    document.addEventListener('touchstart', onTouchStart, { passive: true });
    document.addEventListener('touchmove', onTouchMove, { passive: true });
    document.addEventListener('touchend', onTouchEnd, { passive: true });
    document.addEventListener('touchcancel', onTouchEnd, { passive: true });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMobileSideDrawers);
} else {
    initMobileSideDrawers();
}
