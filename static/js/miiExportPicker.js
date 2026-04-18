(() => {
    function initMiiExportPicker() {
        const form = document.getElementById('miiExportForm');
        if (!form) return;

        const formatInput = form.querySelector('input[name="format"]');
        const qrConsoleInput = form.querySelector('[data-export-qr-console-input]');
        const selectionKeyInput = form.querySelector('[data-export-selection-key]');
        const pickerRoot = form.querySelector('[data-export-picker]');
        const pickerToggle = form.querySelector('[data-export-picker-toggle]');
        const pickerMenu = form.querySelector('.export-format-menu');
        const formatList = form.querySelector('.export-format-list');
        const searchWrap = form.querySelector('.export-format-search-wrap');
        const searchResultsList = form.querySelector('[data-export-search-results]');
        const selectedLabel = form.querySelector('[data-export-selected-label]');
        const actionButtons = Array.from(form.querySelectorAll('[data-export-action]'));
        const optionButtons = Array.from(form.querySelectorAll('.export-format-option[data-export-value]'));
        const quickOptionButtons = Array.from(form.querySelectorAll('.export-format-option-quick[data-export-value]'));
        const flyoutTrigger = form.querySelector('[data-export-flyout-trigger]');
        const flyoutPanel = form.querySelector('[data-export-flyout-panel]');
        const flyoutBackButton = form.querySelector('[data-export-flyout-back]');
        const searchInput = form.querySelector('[data-export-search]');
        const noResults = form.querySelector('[data-export-no-results]');
        const cardRoot = form.closest('.mii-id-card');

        if (!formatInput || !pickerRoot || !pickerToggle || !pickerMenu || !formatList) return;

        const normalizeSearch = (value) => String(value || '').trim().toLowerCase();
        const viewportPadding = 8;
        let openMenuOverflowGap = 0;

        const isMobileViewport = () => {
            return window.matchMedia('(max-width: 768px)').matches;
        };

        const isPrintableKey = (event) => {
            return event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey;
        };

        const isTextEntryTarget = (target) => {
            if (!(target instanceof HTMLElement)) return false;
            if (target.isContentEditable) return true;
            if (target instanceof HTMLInputElement) return true;
            if (target instanceof HTMLTextAreaElement) return true;
            return false;
        };

        const getOptionSearchFields = (button) => {
            const value = normalizeSearch(button.dataset.exportValue || '');
            const label = normalizeSearch(button.dataset.exportLabel || '');
            const display = normalizeSearch(button.dataset.exportDisplay || '');
            const combined = `${value} ${display} ${label}`.trim();

            return { value, label, display, combined };
        };

        const isSearchBoundaryCharacter = (char) => {
            return char === ' '
                || char === '-'
                || char === '_'
                || char === '/'
                || char === '('
                || char === ')'
                || char === '['
                || char === ']'
                || char === '.'
                || char === ',';
        };

        const getSubsequenceScore = (text, query) => {
            if (!text || !query) {
                return null;
            }

            let queryIndex = 0;
            let score = 0;
            let consecutiveMatches = 0;

            for (let i = 0; i < text.length && queryIndex < query.length; i += 1) {
                if (text[i] !== query[queryIndex]) {
                    consecutiveMatches = 0;
                    continue;
                }

                score += 6;
                if (i === 0 || isSearchBoundaryCharacter(text[i - 1])) {
                    score += 3;
                }
                if (consecutiveMatches > 0) {
                    score += 4;
                }

                consecutiveMatches += 1;
                queryIndex += 1;
            }

            if (queryIndex !== query.length) {
                return null;
            }

            return score - Math.max(0, text.length - query.length) * 0.12;
        };

        const getFieldMatchScore = (field, query, weight) => {
            if (!field) {
                return null;
            }

            if (field === query) {
                return weight + 1200;
            }

            if (field.startsWith(query)) {
                return weight + 900 - (field.length - query.length) * 0.4;
            }

            const includesAt = field.indexOf(query);
            if (includesAt >= 0) {
                return weight + 600 - includesAt * 0.6;
            }

            const subsequenceScore = getSubsequenceScore(field, query);
            if (subsequenceScore === null) {
                return null;
            }

            return weight + subsequenceScore;
        };

        const getSearchRank = (button, rawQuery) => {
            const query = normalizeSearch(rawQuery);
            if (!query) {
                return null;
            }

            const { value, label, display, combined } = getOptionSearchFields(button);
            const scores = [
                getFieldMatchScore(value, query, 400),
                getFieldMatchScore(display, query, 320),
                getFieldMatchScore(label, query, 260),
                getFieldMatchScore(combined, query, 120)
            ].filter((score) => Number.isFinite(score));

            if (scores.length === 0) {
                return null;
            }

            return Math.max(...scores);
        };

        const getRankedSearchMatches = (query) => {
            return optionButtons
                .map((button, index) => ({
                    button,
                    index,
                    rank: getSearchRank(button, query)
                }))
                .filter((entry) => Number.isFinite(entry.rank))
                .sort((a, b) => b.rank - a.rank || a.index - b.index)
                .map((entry) => entry.button);
        };

        const getVisibleOptions = () => {
            const hasSearchQuery = normalizeSearch(searchInput?.value || '').length > 0;

            if (hasSearchQuery) {
                if (searchResultsList && !searchResultsList.hidden) {
                    return Array.from(searchResultsList.querySelectorAll('.export-format-option[data-export-value]'));
                }
                return [];
            }

            return Array.from(
                form.querySelectorAll(
                    '.export-format-list .export-format-option[data-export-value], .export-format-flyout-panel:not([hidden]) .export-format-option[data-export-value]'
                )
            );
        };

        const syncMobileLayoutMeasurements = () => {
            if (!searchWrap || pickerMenu.hidden || !isMobileViewport()) return;

            const measuredSearchWrapHeight = Math.ceil(searchWrap.getBoundingClientRect().height);
            if (Number.isFinite(measuredSearchWrapHeight) && measuredSearchWrapHeight > 0) {
                pickerMenu.style.setProperty('--export-search-wrap-height', `${measuredSearchWrapHeight}px`);
            }
        };

        const updateCardOverflowGap = () => {
            if (!cardRoot) return;

            if (pickerMenu.hidden) {
                openMenuOverflowGap = 0;
                cardRoot.style.setProperty('--export-menu-overflow-gap', '0px');
                return;
            }

            let maxBottom = pickerMenu.getBoundingClientRect().bottom;
            if (flyoutPanel && !flyoutPanel.hidden) {
                maxBottom = Math.max(maxBottom, flyoutPanel.getBoundingClientRect().bottom);
            }

            const cardBottom = cardRoot.getBoundingClientRect().bottom;
            const extraGap = Math.max(0, Math.ceil(maxBottom - cardBottom + 8));
            openMenuOverflowGap = Math.max(openMenuOverflowGap, extraGap);

            cardRoot.style.setProperty('--export-menu-overflow-gap', `${openMenuOverflowGap}px`);
        };

        const positionFlyoutPanel = () => {
            if (!flyoutPanel || !flyoutTrigger || flyoutPanel.hidden) return;
            if (pickerMenu.classList.contains('is-mobile-flyout-open')) {
                updateCardOverflowGap();
                return;
            }

            const triggerRect = flyoutTrigger.getBoundingClientRect();
            const menuRect = pickerMenu.getBoundingClientRect();

            flyoutPanel.style.setProperty('--flyout-top', '0px');
            flyoutPanel.style.setProperty('--flyout-offset-y', '0px');
            flyoutPanel.classList.remove('is-align-left');

            let panelRect = flyoutPanel.getBoundingClientRect();

            const preferredTop = Math.round((triggerRect.bottom - menuRect.top) - panelRect.height + 1);
            flyoutPanel.style.setProperty('--flyout-top', `${preferredTop}px`);
            panelRect = flyoutPanel.getBoundingClientRect();

            if (panelRect.right > window.innerWidth - viewportPadding) {
                flyoutPanel.classList.add('is-align-left');
                panelRect = flyoutPanel.getBoundingClientRect();
            }

            let offsetY = 0;
            const bottomOverflow = panelRect.bottom - (window.innerHeight - viewportPadding);
            if (bottomOverflow > 0) {
                offsetY -= bottomOverflow;
            }

            const topOverflow = viewportPadding - (panelRect.top + offsetY);
            if (topOverflow > 0) {
                offsetY += topOverflow;
            }

            flyoutPanel.style.setProperty('--flyout-offset-y', `${Math.round(offsetY)}px`);
            updateCardOverflowGap();
        };

        const closeFlyout = ({ force = false } = {}) => {
            if (!flyoutPanel || !flyoutTrigger) return;

            if (!force && searchInput && String(searchInput.value || '').trim()) {
                return;
            }

            pickerMenu.classList.remove('is-mobile-flyout-open');
            flyoutPanel.hidden = true;
            flyoutTrigger.setAttribute('aria-expanded', 'false');
            flyoutPanel.classList.remove('is-align-left');
            flyoutPanel.style.setProperty('--flyout-offset-y', '0px');
            flyoutPanel.style.setProperty('--flyout-top', '0px');
            updateCardOverflowGap();
        };

        const openFlyout = () => {
            if (!flyoutPanel || !flyoutTrigger) return;
            if (searchInput && String(searchInput.value || '').trim()) return;

            if (isMobileViewport()) {
                syncMobileLayoutMeasurements();
                flyoutPanel.hidden = false;
                flyoutTrigger.setAttribute('aria-expanded', 'true');
                pickerMenu.classList.add('is-mobile-flyout-open');
                updateCardOverflowGap();
                return;
            }

            flyoutPanel.hidden = false;
            flyoutTrigger.setAttribute('aria-expanded', 'true');
            positionFlyoutPanel();
        };

        const updateActionState = () => {
            const selectedValue = String(formatInput.value || '').trim();
            const selectedKey = String(selectionKeyInput?.value || '').trim();
            const hasSelection = selectedValue.length > 0;
            let selectedDisplay = selectedValue;

            form.classList.toggle('has-export-format', hasSelection);
            actionButtons.forEach((button) => {
                button.disabled = !hasSelection;
            });

            optionButtons.forEach((button) => {
                const buttonKey = String(button.dataset.exportKey || button.dataset.exportValue || '').trim();
                const isSelected = hasSelection && buttonKey === selectedKey;
                button.classList.toggle('is-selected', isSelected);
                button.setAttribute('aria-pressed', isSelected ? 'true' : 'false');

                if (isSelected) {
                    selectedDisplay = String(
                        button.dataset.exportDisplay ||
                        button.dataset.exportLabel ||
                        button.dataset.exportValue ||
                        selectedValue
                    ).trim();
                }
            });

            if (selectedLabel) {
                selectedLabel.textContent = hasSelection ? selectedDisplay : 'Select format';
            }
        };

        const clearSearchResults = () => {
            if (!searchResultsList) return;
            searchResultsList.innerHTML = '';
            searchResultsList.hidden = true;
        };

        const applySearchFilter = (rawQuery = searchInput?.value || '') => {
            const query = normalizeSearch(rawQuery);
            const isSearching = query.length > 0;

            if (!isSearching) {
                clearSearchResults();
                formatList.hidden = false;
                if (flyoutTrigger) {
                    flyoutTrigger.hidden = false;
                }
                if (noResults) {
                    noResults.hidden = true;
                }
                closeFlyout({ force: true });
                updateCardOverflowGap();
                return;
            }

            const matches = getRankedSearchMatches(query);

            if (searchResultsList) {
                searchResultsList.innerHTML = '';

                matches.forEach((button) => {
                    const resultButton = button.cloneNode(true);
                    resultButton.classList.remove('is-selected', 'export-format-option-quick', 'export-format-option-other');
                    resultButton.classList.add('export-format-option-search');
                    resultButton.addEventListener('click', () => {
                        applyFormatSelection(
                            resultButton.dataset.exportValue,
                            resultButton.dataset.exportKey,
                            resultButton.dataset.exportQrConsole
                        );
                    });
                    searchResultsList.appendChild(resultButton);
                });

                searchResultsList.hidden = matches.length === 0;
                searchResultsList.scrollTop = 0;
            }

            formatList.hidden = true;
            if (flyoutTrigger) {
                flyoutTrigger.hidden = true;
            }
            closeFlyout({ force: true });

            if (noResults) {
                noResults.hidden = matches.length > 0;
            }

            updateCardOverflowGap();
        };

        const resetSearchFilter = () => {
            if (searchInput) {
                searchInput.value = '';
            }
            applySearchFilter('');
        };

        const closePicker = (restoreFocus = false) => {
            pickerMenu.hidden = true;
            pickerToggle.setAttribute('aria-expanded', 'false');
            pickerRoot.classList.remove('is-open');
            closeFlyout({ force: true });
            resetSearchFilter();
            updateCardOverflowGap();

            if (restoreFocus) {
                pickerToggle.focus();
            }
        };

        const openPicker = (focusSearchInput = false) => {
            openMenuOverflowGap = 0;
            pickerMenu.hidden = false;
            syncMobileLayoutMeasurements();
            pickerToggle.setAttribute('aria-expanded', 'true');
            pickerRoot.classList.add('is-open');
            applySearchFilter(searchInput?.value || '');

            if (focusSearchInput && searchInput) {
                searchInput.focus();
                searchInput.select();
            }

            updateCardOverflowGap();
        };

        const applyFormatSelection = (value, selectionKey, qrConsoleValue) => {
            const nextValue = String(value || '').trim();
            if (!nextValue) return;

            formatInput.value = nextValue;

            if (selectionKeyInput) {
                selectionKeyInput.value = String(selectionKey || nextValue).trim();
            }

            if (qrConsoleInput) {
                const normalizedConsole = String(qrConsoleValue || '').trim().toUpperCase();
                qrConsoleInput.value = nextValue.toLowerCase() === 'qr' && normalizedConsole === 'WIIU'
                    ? 'WIIU'
                    : '3DS';
            }

            updateActionState();
            closePicker();
        };

        pickerToggle.addEventListener('click', () => {
            if (pickerMenu.hidden) {
                openPicker();
                return;
            }
            closePicker();
        });

        pickerToggle.addEventListener('keydown', (event) => {
            if (event.key === 'ArrowDown') {
                event.preventDefault();
                openPicker(true);
                const firstVisibleOption = getVisibleOptions()[0];
                firstVisibleOption?.focus();
                return;
            }

            if (isPrintableKey(event)) {
                event.preventDefault();
                openPicker(true);
                if (searchInput) {
                    searchInput.value = `${searchInput.value || ''}${event.key}`;
                    applySearchFilter(searchInput.value);
                }
            }
        });

        optionButtons.forEach((button) => {
            button.addEventListener('click', () => {
                applyFormatSelection(
                    button.dataset.exportValue,
                    button.dataset.exportKey,
                    button.dataset.exportQrConsole
                );
            });
        });

        if (flyoutTrigger && flyoutPanel) {
            flyoutTrigger.addEventListener('mouseenter', () => {
                if (isMobileViewport()) return;
                openFlyout();
            });

            flyoutTrigger.addEventListener('focus', () => {
                if (isMobileViewport()) return;
                openFlyout();
            });

            flyoutTrigger.addEventListener('click', (event) => {
                event.preventDefault();

                if (searchInput && String(searchInput.value || '').trim()) {
                    return;
                }

                if (flyoutPanel.hidden || isMobileViewport()) {
                    openFlyout();
                    return;
                }
                closeFlyout();
            });

            flyoutTrigger.addEventListener('keydown', (event) => {
                if (event.key === 'ArrowRight' || event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    openFlyout();
                    if (!isMobileViewport()) {
                        const firstFlyoutOption = flyoutPanel.querySelector('.export-format-option-other');
                        firstFlyoutOption?.focus();
                    }
                    return;
                }

                if (event.key === 'ArrowLeft' || event.key === 'Escape') {
                    event.preventDefault();
                    closeFlyout();
                }
            });

            flyoutPanel.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    closeFlyout();
                    flyoutTrigger.focus();
                }
            });

            quickOptionButtons.forEach((button) => {
                button.addEventListener('mouseenter', () => {
                    if (isMobileViewport()) return;
                    closeFlyout();
                });
                button.addEventListener('focus', () => {
                    if (isMobileViewport()) return;
                    closeFlyout();
                });
            });

            flyoutBackButton?.addEventListener('click', (event) => {
                event.preventDefault();
                event.stopPropagation();
                pickerMenu.classList.remove('is-mobile-flyout-open');
                flyoutTrigger.focus();
                updateCardOverflowGap();
            });
        }

        if (searchInput) {
            searchInput.addEventListener('input', () => {
                applySearchFilter(searchInput.value);
            });

            searchInput.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    if (searchInput.value) {
                        searchInput.value = '';
                        applySearchFilter('');
                    } else {
                        closePicker(true);
                    }
                    return;
                }

                if (event.key === 'ArrowDown') {
                    event.preventDefault();
                    const firstVisibleOption = getVisibleOptions()[0];
                    firstVisibleOption?.focus();
                    return;
                }

                if (event.key === 'Enter') {
                    const visibleOptions = getVisibleOptions();
                    if (visibleOptions.length === 1) {
                        event.preventDefault();
                        applyFormatSelection(
                            visibleOptions[0].dataset.exportValue,
                            visibleOptions[0].dataset.exportKey,
                            visibleOptions[0].dataset.exportQrConsole
                        );
                    }
                }
            });
        }

        form.addEventListener('submit', (event) => {
            if (String(formatInput.value || '').trim()) {
                return;
            }

            event.preventDefault();
            openPicker(true);
            if (typeof showAlert === 'function') {
                showAlert('Choose an export format first.', 3500, { title: 'Format Required' });
            }
        });

        document.addEventListener('click', (event) => {
            if (!(event.target instanceof Node)) return;
            if (!pickerRoot.contains(event.target)) {
                closePicker();
            }
        });

        document.addEventListener('keydown', (event) => {
            if (!pickerMenu.hidden && isPrintableKey(event) && searchInput && !isTextEntryTarget(event.target)) {
                event.preventDefault();
                searchInput.focus();
                searchInput.value = `${searchInput.value || ''}${event.key}`;
                applySearchFilter(searchInput.value);
                return;
            }

            if (event.key === 'Escape' && !pickerMenu.hidden) {
                closePicker(true);
            }
        });

        window.addEventListener('resize', () => {
            syncMobileLayoutMeasurements();

            if (!pickerMenu.hidden && flyoutPanel && !flyoutPanel.hidden) {
                if (isMobileViewport()) {
                    closeFlyout({ force: true });
                    return;
                }

                positionFlyoutPanel();
                return;
            }

            updateCardOverflowGap();
        }, { passive: true });

        if (selectionKeyInput && !selectionKeyInput.value) {
            selectionKeyInput.value = '';
        }

        updateActionState();
        updateCardOverflowGap();
    }

    window.initMiiExportPicker = initMiiExportPicker;
})();
