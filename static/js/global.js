function setLikeButtonVisualState(button, liked, locked = false) {
    if (!button) return;
    button.classList.toggle('is-liked', Boolean(liked));
    button.classList.toggle('is-unliked', !liked);
    button.classList.toggle('is-like-locked', Boolean(locked));
    button.dataset.liked = liked ? 'true' : 'false';
    button.dataset.likeLocked = locked ? 'true' : 'false';
    button.setAttribute('aria-pressed', liked ? 'true' : 'false');

    const label = locked
        ? 'You permanently like Miis you upload'
        : (liked ? 'Unlike this Mii' : 'Like this Mii');
    button.setAttribute('aria-label', label);
}

function getLikeButtonsForMii(miiId, fallbackButton = null) {
    const normalizedMiiId = String(miiId || '');
    if (!normalizedMiiId) return fallbackButton ? [fallbackButton] : [];

    const buttons = Array.from(document.querySelectorAll('.like-button'))
        .filter((candidate) => candidate?.dataset?.miiId === normalizedMiiId);

    return buttons.length > 0 ? buttons : (fallbackButton ? [fallbackButton] : []);
}

function getLikeButtonVoteCount(buttons) {
    for (const button of buttons) {
        const countEl = button?.querySelector?.('.vote-count');
        if (!countEl) continue;

        const schemaCount = countEl.querySelector?.('[itemprop="userInteractionCount"]');
        const schemaValue = parseInt(schemaCount?.getAttribute?.('content') || '', 10);
        if (!Number.isNaN(schemaValue)) return schemaValue;

        const parsedCount = parseInt(countEl.textContent, 10);
        if (!Number.isNaN(parsedCount)) return parsedCount;
    }

    return 0;
}

function setLikeButtonVoteCount(buttons, nextCount) {
    buttons.forEach((button) => {
        const countEl = button?.querySelector?.('.vote-count');
        if (!countEl) return;

        const nextText = String(nextCount);
        const schemaCount = countEl.querySelector?.('[itemprop="userInteractionCount"]');
        if (schemaCount) {
            schemaCount.setAttribute('content', nextText);
        }

        const visibleTextNode = Array.from(countEl.childNodes || [])
            .find((node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim().length > 0);

        if (visibleTextNode) {
            visibleTextNode.textContent = nextText;
            return;
        }

        countEl.appendChild(document.createTextNode(nextText));
    });
}

function likeMii(el,id,highlightedMii,mod){
    const button = el?.closest?.('.like-button') || el;
    const syncedButtons = getLikeButtonsForMii(id, button);

    fetch("/voteMii?id="+encodeURIComponent(id), { method: 'POST' }).then(async (response) => {
        if (response.redirected) {
            window.location.href = "/login?next=" + encodeURIComponent(
                window.location.pathname + window.location.search + window.location.hash
            );
            return null;
        }

        return response.text();
    }).then(d=>{
        if (d === null) return;

        let parsed;
        try { parsed = JSON.parse(d); } catch (e) {}
        if (parsed?.error) {
            if (typeof showAlert === 'function') showAlert(parsed.error, 5000, { title: 'Error', type: 'error' });
            return;
        }

        const currentCount = getLikeButtonVoteCount(syncedButtons);

        if(d==="Liked"){
            syncedButtons.forEach((candidate) => setLikeButtonVisualState(candidate, true, false));
            setLikeButtonVoteCount(syncedButtons, currentCount + 1);
            return;
        }
        if(d==="Unliked"){
            syncedButtons.forEach((candidate) => setLikeButtonVisualState(candidate, false, false));
            setLikeButtonVoteCount(syncedButtons, Math.max(0, currentCount - 1));
            return;
        }
        if(d==="UnlikedSeeded"){
            syncedButtons.forEach((candidate) => setLikeButtonVisualState(candidate, false, false));
            setLikeButtonVoteCount(syncedButtons, 1);
            return;
        }
        if (d === "LockedLiked") {
            syncedButtons.forEach((candidate) => setLikeButtonVisualState(candidate, true, true));
            setLikeButtonVoteCount(syncedButtons, Math.max(1, currentCount));
            return;
        }
    }).catch(() => {
        if (typeof showAlert === 'function') showAlert('Failed to update like', 5000, { title: 'Error', type: 'error' });
    });
}

function initializeHomepagePreviewRows() {
    const categories = Array.from(document.querySelectorAll('[data-home-preview-row]'));
    if (categories.length === 0) return;

    let frameId = 0;

    const syncCategory = (category) => {
        const cards = Array.from(category.querySelectorAll('.mii-card'));
        if (cards.length === 0) return;

        cards.forEach((card) => {
            card.hidden = false;
        });

        const firstRowTop = cards[0].offsetTop;
        const firstWrappedCardIndex = cards.findIndex((card) => Math.abs(card.offsetTop - firstRowTop) > 1);
        const firstRowCount = firstWrappedCardIndex === -1 ? cards.length : firstWrappedCardIndex;
        const cardsToShow = firstRowCount === 1
            ? Math.min(cards.length, 5)
            : Math.min(cards.length, firstRowCount < 5 ? firstRowCount * 2 : firstRowCount);

        cards.forEach((card, index) => {
            card.hidden = index >= cardsToShow;
        });
    };

    const syncAllCategories = () => {
        frameId = 0;
        categories.forEach(syncCategory);
    };

    const requestSync = () => {
        if (frameId) {
            cancelAnimationFrame(frameId);
        }

        frameId = requestAnimationFrame(syncAllCategories);
    };

    requestSync();
    window.addEventListener('load', requestSync, { once: true });
    window.addEventListener('resize', requestSync, { passive: true });

    if ('ResizeObserver' in window) {
        const observedWidths = new WeakMap();
        const observer = new ResizeObserver((entries) => {
            const widthChanged = entries.some((entry) => {
                const nextWidth = Math.round(entry.contentRect.width);
                const previousWidth = observedWidths.get(entry.target);
                observedWidths.set(entry.target, nextWidth);
                return typeof previousWidth === 'undefined' || previousWidth !== nextWidth;
            });

            if (widthChanged) {
                requestSync();
            }
        });

        categories.forEach((category) => {
            observedWidths.set(category, Math.round(category.getBoundingClientRect().width));
            observer.observe(category);
        });

        window.__homepagePreviewResizeObserver = observer;
    }
}

function initializeMiiCardImageLoading() {
    const cardImages = Array.from(document.querySelectorAll('.mii-card > a > img, .private-mii-card > a > img'));
    if (cardImages.length === 0) return;

    const markLoaded = (img) => {
        const link = img.closest('a');
        if (!link) return;
        link.classList.remove('mii-image-is-loading');
        link.classList.add('mii-image-is-loaded');
    };

    cardImages.forEach((img) => {
        const link = img.closest('a');
        if (!link) return;

        if (!img.getAttribute('decoding')) {
            img.setAttribute('decoding', 'async');
        }

        if (img.complete && img.naturalWidth > 0) {
            markLoaded(img);
            return;
        }

        link.classList.add('mii-image-is-loading');
        img.addEventListener('load', () => markLoaded(img), { once: true });
        img.addEventListener('error', () => {
            link.classList.remove('mii-image-is-loading');
        }, { once: true });
    });
}

function initializePageFeatures() {
    initializeHomepagePreviewRows();
    initializeMiiCardImageLoading();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializePageFeatures, { once: true });
} else {
    initializePageFeatures();
}

// Custom Modal System
let modalOverlay = null;

function createModalOverlay() {
    // Always create a fresh overlay so stale timers/listeners cannot
    // interfere with newly opened modals.
    if (modalOverlay && modalOverlay.parentNode) {
        modalOverlay.parentNode.removeChild(modalOverlay);
    }

    modalOverlay = document.createElement('div');
    modalOverlay.className = 'custom-modal-overlay';
    document.body.appendChild(modalOverlay);

    return modalOverlay;
}

function closeModal(overlay = null) {
    const targetOverlay = overlay && overlay.classList
        ? overlay
        : document.querySelector('.custom-modal-overlay');
    if (!targetOverlay) return;

    targetOverlay.classList.remove('active');
    const cleanupId = (targetOverlay.__cleanupId || 0) + 1;
    targetOverlay.__cleanupId = cleanupId;

    setTimeout(() => {
        if (targetOverlay.__cleanupId !== cleanupId) return;
        if (targetOverlay.classList.contains('active')) return;

        if (targetOverlay.parentNode) {
            targetOverlay.parentNode.removeChild(targetOverlay);
        }

        if (modalOverlay === targetOverlay) {
            modalOverlay = null;
        }
    }, 200);
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
        closeModal(overlay);
        if (onCancel) onCancel();
    };
    
    const handleConfirm = () => {
        closeModal(overlay);
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
    overlay.innerHTML = '';

    const modal = document.createElement('div');
    modal.className = 'custom-modal';

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

    const body = document.createElement('div');
    body.className = 'custom-modal-body';
    body.textContent = typeof message === 'string' ? message : String(message ?? '');

    const timer = document.createElement('div');
    timer.className = 'custom-modal-timer';
    timer.style.animationDuration = `${duration}ms`;

    modal.appendChild(header);
    modal.appendChild(body);
    modal.appendChild(timer);
    overlay.appendChild(modal);
    
    const closeBtn = overlay.querySelector('.custom-modal-close');
    
    const handleClose = () => {
        closeModal(overlay);
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
		fetch("/deleteMii", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id })
        }).then(d=>d.json()).then(d=>{
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
				const miiEl = document.getElementById(id);
				if (miiEl) {
                    miiEl.remove();
                } else if (d.redirect) {
                    window.location.href = d.redirect;
                }
			}
		}).catch(() => {
            showAlert('Failed to delete Mii', 5000, { title: 'Error', type: 'error' });
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

function getSafeClientRedirectTarget(target, fallback = '/') {
    const fallbackPath = (typeof fallback === 'string' && fallback.startsWith('/')) ? fallback : '/';
    const candidate = typeof target === 'string' ? target.trim() : '';

    if (!candidate) return fallbackPath;

    try {
        const resolved = new URL(candidate, window.location.origin);
        if (resolved.origin !== window.location.origin) return fallbackPath;
        if (!resolved.pathname.startsWith('/')) return fallbackPath;
        return `${resolved.pathname}${resolved.search}${resolved.hash}` || fallbackPath;
    } catch {
        return fallbackPath;
    }
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

    const setMessage = (content = '', type = '', html = '') => {
        if (!messageDiv) return;
        messageDiv.className = type ? `form-message ${type}` : 'form-message';
        messageDiv.style.display = content || html ? 'block' : 'none';
        if (html) {
            messageDiv.innerHTML = html;
            return;
        }
        messageDiv.textContent = content;
    };
    
    // Clear any previous messages
    setMessage('', '');
    
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
            setMessage(result.error, 'error', result.errorHtml || '');
        } else {
            // Success
            if (options.onSuccess) {
                options.onSuccess(result, messageDiv, response);
            } else if (result.redirect) {
                window.location.href = getSafeClientRedirectTarget(options?.next || result.redirect, '/');
            } else if (result.message) {
                setMessage(result.message, 'success', result.messageHtml || '');
            }
        }
    } catch (error) {
        console.error('Form submission error:', error);
        setMessage('An error occurred. Please try again.', 'error');
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
        closeModal(overlay);
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

function getNarrowHeaderViewportWidth() {
    const viewportWidths = [
        window.innerWidth,
        document.documentElement?.clientWidth,
        window.visualViewport?.width
    ].filter((width) => Number.isFinite(width) && width > 0);

    return viewportWidths.length > 0 ? Math.min(...viewportWidths) : window.innerWidth;
}

function updateMobileAccountHeaderSpace(header, account) {
    if (!header?.classList?.contains('site-header-with-account')) return false;

    const narrowViewportWidth = getNarrowHeaderViewportWidth();
    const isNarrowHeader = window.matchMedia('(max-width: 992px)').matches || narrowViewportWidth <= 992;
    if (!isNarrowHeader) {
        header.classList.remove('site-header-positioned');
        header.style.removeProperty('--mobile-account-reserved-width');
        return false;
    }

    if (!account) return false;

    const accountStyles = window.getComputedStyle(account);
    if (accountStyles.display === 'none' || accountStyles.visibility === 'hidden') return false;

    const accountRect = account.getBoundingClientRect();
    const viewportRight = Math.min(
        ...[
            document.documentElement?.clientWidth,
            window.innerWidth,
            window.visualViewport?.width
        ].filter((width) => Number.isFinite(width) && width > 0)
    );
    const minimumGap = 12;
    const reservedWidth = Math.max(0, viewportRight - accountRect.left + minimumGap);

    header.style.setProperty('--mobile-account-reserved-width', `${Math.ceil(reservedWidth)}px`);
    header.classList.add('site-header-positioned');
    return true;
}

function updateHeaderBannerShift() {
    const header = document.querySelector('.site-header') || document.querySelector('header');
    const bannerLink = header?.querySelector?.('.site-banner-link');
    const bannerImage = bannerLink?.querySelector?.('.site-banner-image') || header?.querySelector?.('.site-banner-image');
    const account = document.querySelector('.account');

    if (!bannerLink || !bannerImage) return;

    bannerLink.style.setProperty('--banner-shift-x', '0px');
    if (updateMobileAccountHeaderSpace(header, account)) return;

    const narrowViewportWidth = getNarrowHeaderViewportWidth();
    const isNarrowHeader = window.matchMedia('(max-width: 992px)').matches || narrowViewportWidth <= 992;
    if (!header || !account || !isNarrowHeader) return;
    if (header.classList.contains('site-header-with-account')) return;

    const accountStyles = window.getComputedStyle(account);
    if (accountStyles.display === 'none' || accountStyles.visibility === 'hidden') return;

    const headerRect = header.getBoundingClientRect();
    const bannerRect = bannerImage.getBoundingClientRect();
    const accountRect = account.getBoundingClientRect();
    const minimumGap = 12;
    const viewportRight = Math.min(
        ...[
            headerRect.right,
            document.documentElement?.clientWidth,
            window.innerWidth,
            window.visualViewport?.width
        ].filter((width) => Number.isFinite(width) && width > 0)
    );
    const visibleLeft = Math.max(0, headerRect.left) + minimumGap;

    const verticalOverlap = Math.min(headerRect.bottom, accountRect.bottom) - Math.max(headerRect.top, accountRect.top);
    if (verticalOverlap <= 0) return;

    const accountAvoidLeft = Math.min(accountRect.left, viewportRight);
    const horizontalOverlap = bannerRect.right - (accountAvoidLeft - minimumGap);
    if (horizontalOverlap <= 0) return;

    const maxShift = Math.max(0, bannerRect.left - visibleLeft);
    const shift = Math.min(Math.ceil(horizontalOverlap), Math.ceil(maxShift));
    if (shift <= 0) return;

    bannerLink.style.setProperty('--banner-shift-x', `${-shift}px`);
}

function initHeaderBannerShift() {
    if (window.__infinimiiHeaderBannerShiftInitialized) return;

    const header = document.querySelector('.site-header') || document.querySelector('header');
    const bannerLink = header?.querySelector?.('.site-banner-link');
    const bannerImage = bannerLink?.querySelector?.('.site-banner-image') || header?.querySelector?.('.site-banner-image');
    const account = document.querySelector('.account');

    if (!header || !bannerLink || !bannerImage) return;
    window.__infinimiiHeaderBannerShiftInitialized = true;

    let frameId = null;
    let resizeObserver = null;
    const scheduleUpdate = () => {
        if (frameId !== null) cancelAnimationFrame(frameId);
        frameId = requestAnimationFrame(() => {
            frameId = null;
            updateHeaderBannerShift();
        });
    };

    scheduleUpdate();
    if (header.classList.contains('site-header-with-account') && !account && 'MutationObserver' in window) {
        const accountObserver = new MutationObserver(() => {
            const nextAccount = document.querySelector('.account');
            if (!nextAccount) return;

            accountObserver.disconnect();
            if (resizeObserver) {
                resizeObserver.observe(nextAccount);
            }
            scheduleUpdate();
        });

        accountObserver.observe(document.documentElement, { childList: true, subtree: true });
    }

    window.addEventListener('resize', scheduleUpdate, { passive: true });
    window.addEventListener('orientationchange', scheduleUpdate, { passive: true });
    window.addEventListener('pageshow', scheduleUpdate);
    window.addEventListener('load', scheduleUpdate);
    window.visualViewport?.addEventListener('resize', scheduleUpdate, { passive: true });

    if (!bannerImage.complete) {
        bannerImage.addEventListener('load', scheduleUpdate, { once: true });
    }

    if (document.fonts?.ready) {
        document.fonts.ready.then(scheduleUpdate).catch(() => { });
    }

    if ('ResizeObserver' in window) {
        resizeObserver = new ResizeObserver(scheduleUpdate);
        resizeObserver.observe(header);
        resizeObserver.observe(bannerLink);
        resizeObserver.observe(bannerImage);
        if (account) {
            resizeObserver.observe(account);
        }
    }
}

if (document.querySelector('.site-header')) {
    initHeaderBannerShift();
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeaderBannerShift, { once: true });
} else {
    initHeaderBannerShift();
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

async function waitForDocumentFocus(timeoutMs = 350) {
    if (typeof document === 'undefined') return false;
    if (document.hasFocus()) return true;

    try {
        if (typeof window !== 'undefined' && typeof window.focus === 'function') {
            window.focus();
        }
    } catch (e) { }

    const startedAt = Date.now();
    while ((Date.now() - startedAt) < timeoutMs) {
        await new Promise((resolve) => setTimeout(resolve, 25));
        if (document.hasFocus()) return true;
    }

    return document.hasFocus();
}

function fallbackCopyTextToClipboard(text) {
    if (typeof document === 'undefined') return false;
    if (!document.body) return false;

    const textarea = document.createElement('textarea');
    textarea.value = String(text ?? '');
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '-9999px';
    textarea.style.left = '-9999px';
    textarea.style.opacity = '0';
    textarea.style.pointerEvents = 'none';

    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);

    let copied = false;
    try {
        copied = document.execCommand('copy');
    } catch (e) {
        copied = false;
    } finally {
        textarea.remove();
    }

    return copied;
}

async function copyTextToClipboard(text) {
    const normalized = String(text ?? '');
    const hasClipboardApi =
        typeof navigator !== 'undefined' &&
        navigator.clipboard &&
        typeof navigator.clipboard.writeText === 'function';

    if (hasClipboardApi) {
        try {
            await waitForDocumentFocus();
            await navigator.clipboard.writeText(normalized);
            return true;
        } catch (error) {
            if (fallbackCopyTextToClipboard(normalized)) {
                return true;
            }
            throw error;
        }
    }

    if (fallbackCopyTextToClipboard(normalized)) {
        return true;
    }

    throw new Error('Clipboard API unavailable and fallback copy failed.');
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

        let resolvedEncoding = encoding;
        let resolvedOptions = options;

        // Backward/defensive support: allow passing options as second arg.
        if (resolvedEncoding && typeof resolvedEncoding === 'object' && !Array.isArray(resolvedEncoding)) {
            resolvedOptions = resolvedEncoding;
            resolvedEncoding = resolvedOptions.encoding || 'hex';
        }

        const normalizedEncoding = String(resolvedEncoding || '').trim().toLowerCase();
        if (normalizedEncoding !== 'hex' && normalizedEncoding !== 'base64') {
            throw new Error(`Invalid copy encoding: ${resolvedEncoding}`);
        }

        const method = String(resolvedOptions.method || form.method || 'GET').toUpperCase();
        let endpoint = resolvedOptions.url || form.action || '/exportMii';
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
        const text = normalizedEncoding === 'base64'
            ? bytesToBase64String(bytes)
            : bytesToHexString(bytes);

        await copyTextToClipboard(text);
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

window.copyExportHexFromForm = async function(form, options = {}) {
    return window.copyExportTextFromForm(form, 'hex', options);
};

window.copyExportBase64FromForm = async function(form, options = {}) {
    return window.copyExportTextFromForm(form, 'base64', options);
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
