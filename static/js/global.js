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

function getGridCards(container) {
    return Array.from(container.querySelectorAll('.mii-card'));
}

function getCardsPerRow(container, cards) {
    if (!Array.isArray(cards) || cards.length === 0) return 0;

    try {
        const computedStyle = window.getComputedStyle(container);
        const displayValue = String(computedStyle.display || '').toLowerCase();
        if (displayValue.includes('grid')) {
            const templateColumns = String(computedStyle.gridTemplateColumns || '').trim();
            if (templateColumns && templateColumns !== 'none') {
                const columnCount = templateColumns.split(/\s+/).filter(Boolean).length;
                if (columnCount > 0) {
                    return Math.min(cards.length, columnCount);
                }
            }
        }
    } catch (e) {
        // Fall back to layout-based detection below.
    }

    const firstRowTop = cards[0].offsetTop;
    const firstWrappedCardIndex = cards.findIndex((card) => Math.abs(card.offsetTop - firstRowTop) > 1);
    return firstWrappedCardIndex === -1 ? cards.length : firstWrappedCardIndex;
}

function buildStartPaginationUrl(startOffset) {
    const normalizedStart = Number.isFinite(Number(startOffset)) && Number(startOffset) > 0
        ? Math.floor(Number(startOffset))
        : 0;

    try {
        const url = new URL(window.location.href);
        url.searchParams.delete('page');
        if (normalizedStart > 0) {
            url.searchParams.set('start', String(normalizedStart));
        } else {
            url.searchParams.delete('start');
        }
        return url.toString();
    } catch (e) {
        const existingSearch = String(window.location.search || '').replace(/^\?/, '');
        const queryParts = existingSearch ? existingSearch.split('&').filter(Boolean) : [];
        let hasStart = false;

        const nextQueryParts = queryParts.reduce((parts, part) => {
            const equalsIndex = part.indexOf('=');
            const rawKey = equalsIndex === -1 ? part : part.slice(0, equalsIndex);
            const key = decodeURIComponent(rawKey || '');

            if (key === 'page') {
                return parts;
            }

            if (key !== 'start') {
                parts.push(part);
                return parts;
            }

            hasStart = true;
            if (normalizedStart > 0) {
                parts.push(`start=${encodeURIComponent(String(normalizedStart))}`);
            }
            return parts;
        }, []);

        if (!hasStart && normalizedStart > 0) {
            nextQueryParts.push(`start=${encodeURIComponent(String(normalizedStart))}`);
        }

        const queryString = nextQueryParts.join('&');
        return `${window.location.pathname}${queryString ? `?${queryString}` : ''}${window.location.hash || ''}`;
    }
}

function initializeHomepagePreviewRows() {
    const categories = Array.from(document.querySelectorAll('[data-home-preview-row]'));
    if (categories.length === 0) return;

    let frameId = 0;

    const syncCategory = (category) => {
        const cards = getGridCards(category);
        if (cards.length === 0) return;

        cards.forEach((card) => {
            card.hidden = false;
        });

        const firstRowCount = getCardsPerRow(category, cards);
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

function initializeFullRowBrowseGrids() {
    const grids = Array.from(document.querySelectorAll('[data-full-row-grid]'));
    if (grids.length === 0) return;

    let frameId = 0;

    const setPaginationLinkState = (link, isEnabled, href) => {
        if (!link) return;

        if (isEnabled && href) {
            link.setAttribute('href', href);
            link.removeAttribute('aria-disabled');
            link.removeAttribute('tabindex');
            return;
        }

        link.removeAttribute('href');
        link.setAttribute('aria-disabled', 'true');
        link.setAttribute('tabindex', '-1');
    };

    const syncGrid = (grid) => {
        const cards = getGridCards(grid);
        if (cards.length === 0) return;

        cards.forEach((card) => {
            card.hidden = false;
        });

        const cardsPerRow = getCardsPerRow(grid, cards);
        if (!cardsPerRow) return;

        const start = Number.parseInt(grid.dataset.fullRowStart || '', 10);
        const total = Number.parseInt(grid.dataset.fullRowTotal || '', 10);
        const requestLimit = Number.parseInt(grid.dataset.fullRowRequestLimit || '', 10);
        const baseCount = Number.parseInt(grid.dataset.fullRowBaseCount || '', 10);
        const allowPartialLastRow = grid.dataset.fullRowAllowPartialLast === '1';
        const safeStart = Number.isFinite(start) && start > 0 ? start : 0;
        const safeTotal = Number.isFinite(total) && total >= 0 ? total : cards.length;
        const safeRequestLimit = Number.isFinite(requestLimit) && requestLimit > 0 ? requestLimit : cards.length;
        const safeBaseCount = Number.isFinite(baseCount) && baseCount > 0 ? baseCount : Math.min(16, safeRequestLimit);
        const totalRemaining = Math.max(0, safeTotal - safeStart);
        const maxVisibleAvailable = Math.min(cards.length, totalRemaining || cards.length);
        const fullPageSize = (() => {
            const computed = Math.ceil(Math.max(safeBaseCount, cardsPerRow) / cardsPerRow) * cardsPerRow;
            return Math.min(safeRequestLimit, Math.max(cardsPerRow, computed));
        })();
        const isLastPage = allowPartialLastRow && totalRemaining <= fullPageSize;
        const visibleCount = isLastPage
            ? maxVisibleAvailable
            : Math.min(maxVisibleAvailable, fullPageSize);

        cards.forEach((card, index) => {
            card.hidden = index >= visibleCount;
        });

        const controls = grid.id
            ? document.querySelector(`[data-full-row-controls-for="${grid.id}"]`)
            : null;
        if (!controls) return;

        const paginationInfo = controls.querySelector('.pagination-info');
        const pageButton = controls.querySelector('.pagination-current-page');
        const pageInput = controls.querySelector('.pagination-page-input');
        const totalPagesEl = controls.querySelector('[data-pagination-total-pages]');
        const totalEl = controls.querySelector('[data-pagination-total]');
        const prevLink = controls.querySelector('[data-pagination-prev]');
        const nextLink = controls.querySelector('[data-pagination-next]');
        const randomVisibleCountEl = controls.querySelector('[data-random-visible-count]');
        const totalPages = fullPageSize > 0 ? Math.max(1, Math.ceil(safeTotal / fullPageSize)) : 1;
        const currentPage = Math.min(totalPages, fullPageSize > 0 ? Math.floor(safeStart / fullPageSize) + 1 : 1);
        const hasPrevious = safeStart > 0;
        const previousStart = Math.max(0, safeStart - fullPageSize);
        const nextStart = safeStart + visibleCount;
        const hasNext = nextStart < safeTotal;

        if (paginationInfo) {
            paginationInfo.dataset.currentPage = String(currentPage);
            paginationInfo.dataset.totalPages = String(totalPages);
            paginationInfo.dataset.pageSize = String(fullPageSize);
            paginationInfo.dataset.start = String(safeStart);
            paginationInfo.dataset.totalItems = String(safeTotal);
        }
        if (pageButton) {
            pageButton.textContent = String(currentPage);
        }
        if (pageInput) {
            pageInput.value = String(currentPage);
            pageInput.max = String(totalPages);
        }
        if (totalPagesEl) {
            totalPagesEl.textContent = String(totalPages);
        }
        if (totalEl) {
            totalEl.textContent = String(safeTotal);
        }
        if (randomVisibleCountEl) {
            randomVisibleCountEl.textContent = String(visibleCount);
        }
        if (prevLink) {
            setPaginationLinkState(prevLink, hasPrevious, buildStartPaginationUrl(previousStart));
        }
        if (nextLink) {
            setPaginationLinkState(nextLink, hasNext, buildStartPaginationUrl(nextStart));
        }
    };

    const syncAllGrids = () => {
        frameId = 0;
        grids.forEach(syncGrid);
    };

    const requestSync = () => {
        if (frameId) {
            cancelAnimationFrame(frameId);
        }

        frameId = requestAnimationFrame(syncAllGrids);
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

        grids.forEach((grid) => {
            observedWidths.set(grid, Math.round(grid.getBoundingClientRect().width));
            observer.observe(grid);
        });

        window.__fullRowBrowseResizeObserver = observer;
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

function initializeTagBoundaryMarquees() {
    const trackSelector = [
        '.mii-card-tag .tag-marquee-content',
        '.mii-tag-badge .tag-marquee-content',
        '.mii-chip .tag-marquee-content',
        '.tag-filter-option .tag-marquee-content'
    ].join(', ');
    const chipSelector = '.mii-card-tag, .mii-tag-badge, .mii-chip, .tag-filter-option';
    let frameId = 0;
    let followUpFrameId = 0;

    const measureTrackContentWidth = (track) => {
        const label = track.textContent || '';
        if (!label.trim()) return 0;

        const computedStyles = window.getComputedStyle(track);
        const canvas = window.__tagBoundaryMarqueeMeasureCanvas
            || (window.__tagBoundaryMarqueeMeasureCanvas = document.createElement('canvas'));
        const context = canvas.getContext('2d');

        if (!context) {
            return track.scrollWidth;
        }

        const font = computedStyles.font && computedStyles.font !== ''
            ? computedStyles.font
            : [
                computedStyles.fontStyle,
                computedStyles.fontVariant,
                computedStyles.fontWeight,
                computedStyles.fontStretch,
                computedStyles.fontSize,
                computedStyles.fontFamily
            ].filter(Boolean).join(' ');

        context.font = font;

        let measuredWidth = context.measureText(label).width;
        const letterSpacing = Number.parseFloat(computedStyles.letterSpacing);
        if (Number.isFinite(letterSpacing) && letterSpacing !== 0) {
            measuredWidth += letterSpacing * Math.max(0, label.length - 1);
        }

        return measuredWidth || track.scrollWidth;
    };

    const syncTrack = (track) => {
        const chip = track.closest(chipSelector);
        if (!chip) return;

        chip.classList.remove('is-tag-marqueeing');
        track.style.removeProperty('--tag-marquee-distance');
        track.style.removeProperty('--tag-marquee-duration');

        const rect = chip.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return;

        const visibleWidth = track.getBoundingClientRect().width;
        if (visibleWidth <= 0) return;

        const contentWidth = measureTrackContentWidth(track);
        const overflowDistance = Math.ceil(contentWidth - visibleWidth);
        if (overflowDistance <= 1) return;

        const duration = Math.min(16, Math.max(6, 4 + overflowDistance / 16));
        track.style.setProperty('--tag-marquee-distance', `${overflowDistance}px`);
        track.style.setProperty('--tag-marquee-duration', `${duration.toFixed(2)}s`);
        chip.classList.add('is-tag-marqueeing');

        if (!chip.getAttribute('title')) {
            const label = track.textContent.trim();
            if (label) {
                chip.setAttribute('title', label);
            }
        }
    };

    const syncAll = () => {
        frameId = 0;
        followUpFrameId = 0;
        document.querySelectorAll(trackSelector).forEach(syncTrack);
    };

    const requestSync = () => {
        if (frameId) {
            cancelAnimationFrame(frameId);
        }
        if (followUpFrameId) {
            cancelAnimationFrame(followUpFrameId);
        }

        frameId = requestAnimationFrame(() => {
            frameId = 0;
            followUpFrameId = requestAnimationFrame(syncAll);
        });
    };

    requestSync();
    window.addEventListener('load', requestSync, { once: true });
    window.addEventListener('resize', requestSync, { passive: true });
    window.addEventListener('orientationchange', requestSync, { passive: true });
    window.addEventListener('pageshow', requestSync, { passive: true });

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', requestSync, { passive: true });
    }

    if (document.fonts && typeof document.fonts.ready?.then === 'function') {
        document.fonts.ready.then(requestSync).catch(() => {});
    }

    if ('ResizeObserver' in window) {
        const resizeObserver = new ResizeObserver(requestSync);
        document.querySelectorAll(chipSelector).forEach((chip) => resizeObserver.observe(chip));
        window.__tagBoundaryMarqueeResizeObserver = resizeObserver;
    }

    if ('MutationObserver' in window) {
        const mutationObserver = new MutationObserver(requestSync);
        mutationObserver.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true
        });
        window.__tagBoundaryMarqueeMutationObserver = mutationObserver;
    }

    window.refreshTagBoundaryMarquees = requestSync;
}

function initializePageFeatures() {
    initializeHomepagePreviewRows();
    initializeFullRowBrowseGrids();
    initializeMiiCardImageLoading();
    initializeTagBoundaryMarquees();
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

const USER_ERROR_SCROLL_SELECTOR = [
    '.form-message.error',
    '.error-message.active',
    '.upload-category-state-error',
    '.instructions-status-error',
    '[data-type="error"]',
    '.log-area .error'
].join(', ');
const userErrorScrollSignatures = new WeakMap();

function isVisibleUserErrorElement(element) {
    if (!element || !element.isConnected || element.hidden) return false;
    if (!String(element.textContent || '').trim()) return false;

    const style = window.getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden') return false;

    return element.getClientRects().length > 0;
}

function getUserErrorScrollTarget(element) {
    return element.closest?.('.log-area') || element;
}

function scrollToUserError(element, options = {}) {
    const errorElement = typeof element === 'string'
        ? (document.getElementById(element) || document.querySelector(element))
        : element;
    if (!errorElement?.scrollIntoView) return;

    requestAnimationFrame(() => {
        if (!options.force && !isVisibleUserErrorElement(errorElement)) return;

        const scrollTarget = getUserErrorScrollTarget(errorElement);
        try {
            scrollTarget.scrollIntoView({
                behavior: options.behavior || 'smooth',
                block: options.block || 'center',
                inline: 'nearest'
            });
        } catch (e) {
            scrollTarget.scrollIntoView();
        }
    });
}

function maybeScrollToShownUserError(element) {
    if (!element?.matches?.(USER_ERROR_SCROLL_SELECTOR)) return;
    if (!isVisibleUserErrorElement(element)) return;

    const signature = [
        String(element.textContent || '').trim(),
        element.className || '',
        element.hidden ? 'hidden' : 'visible',
        element.getAttribute('style') || '',
        element.dataset?.type || ''
    ].join('|');

    if (userErrorScrollSignatures.get(element) === signature) return;
    userErrorScrollSignatures.set(element, signature);
    scrollToUserError(element);
}

function scanUserErrors(root = document) {
    if (!root) return;

    if (root.nodeType === Node.ELEMENT_NODE && root.matches?.(USER_ERROR_SCROLL_SELECTOR)) {
        maybeScrollToShownUserError(root);
    }

    root.querySelectorAll?.(USER_ERROR_SCROLL_SELECTOR).forEach(maybeScrollToShownUserError);
}

function installUserErrorScrollObserver() {
    if (window.__infinimiiUserErrorScrollObserver || !window.MutationObserver) return;

    const observer = new MutationObserver((mutations) => {
        const roots = new Set();

        mutations.forEach((mutation) => {
            if (mutation.type === 'characterData') {
                if (mutation.target.parentElement) roots.add(mutation.target.parentElement);
                return;
            }

            if (mutation.type === 'attributes') {
                roots.add(mutation.target);
                return;
            }

            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    roots.add(node);
                }
            });
        });

        if (roots.size === 0) return;
        requestAnimationFrame(() => roots.forEach(scanUserErrors));
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        characterData: true,
        attributes: true,
        attributeFilter: ['class', 'style', 'hidden', 'data-type']
    });

    window.__infinimiiUserErrorScrollObserver = observer;
}

window.scrollToUserError = scrollToUserError;
window.maybeScrollToShownUserError = maybeScrollToShownUserError;
installUserErrorScrollObserver();

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => scanUserErrors(document), { once: true });
} else {
    scanUserErrors(document);
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
					scrollToUserError(errorDiv);
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
    const submitter = e.submitter && e.submitter.form === form ? e.submitter : null;
    let formData;
    try {
        formData = submitter ? new FormData(form, submitter) : new FormData(form);
    } catch {
        formData = new FormData(form);
        if (submitter?.name && !formData.has(submitter.name)) {
            formData.append(submitter.name, submitter.value || '');
        }
    }
    const submitBtn = submitter?.matches?.('input[type="submit"], button[type="submit"]')
        ? submitter
        : form.querySelector('input[type="submit"], button[type="submit"]');
    const getButtonText = (button) => button?.tagName === 'INPUT'
        ? button.value
        : (button?.textContent || '');
    const setButtonText = (button, text) => {
        if (!button) return;
        if (button.tagName === 'INPUT') {
            button.value = text;
        } else {
            button.textContent = text;
        }
    };
    const originalText = getButtonText(submitBtn);
    const messageDiv = document.getElementById(errorDivId);

    const setMessage = (content = '', type = '', html = '') => {
        if (!messageDiv) return;
        messageDiv.className = type ? `form-message ${type}` : 'form-message';
        messageDiv.style.display = content || html ? 'block' : 'none';
        if (html) {
            messageDiv.innerHTML = html;
        } else {
            messageDiv.textContent = content;
        }
        if (type === 'error' && (content || html)) {
            scrollToUserError(messageDiv);
        }
    };
    
    // Clear any previous messages
    setMessage('', '');
    
    // Update button state
    setButtonText(submitBtn, loadingText);
    if (submitBtn) {
        submitBtn.disabled = true;
    }
    
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
                setButtonText(submitBtn, originalText);
                if (submitBtn) {
                    submitBtn.disabled = false;
                }
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
        setButtonText(submitBtn, originalText);
        if (submitBtn) {
            submitBtn.disabled = false;
        }
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
            scrollToUserError(errorLine);
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
