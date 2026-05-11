(() => {
    const dashboardForm = document.getElementById('miiDashboardForm');
    const dashboardResults = document.getElementById('dashboardResults');
    const dashboardMiiName = document.getElementById('dashboardMiiName');
    const dashboardCreatedOn = document.getElementById('dashboardCreatedOn');
    const dashboardRender = document.getElementById('dashboardRender');
    const dashboardFullBodyRender = document.getElementById('dashboardFullBodyRender');
    const dashboardQr = document.getElementById('dashboardQr');
    const dashboardQrLink = document.getElementById('dashboardQrLink');
    const dashboardQrPreview = document.getElementById('dashboardQrPreview');
    const dashboardInfoGrid = document.getElementById('dashboardInfoGrid');
    const dashboardTomodachiCard = document.getElementById('dashboardTomodachiCard');
    const dashboardTomodachiGrid = document.getElementById('dashboardTomodachiGrid');
    const dashboardJsonOutput = document.getElementById('dashboardJsonOutput');
    const dashboardApplyJsonBtn = document.getElementById('dashboardApplyJsonBtn');
    const dashboardJsonDownloadBtn = document.getElementById('dashboardJsonDownloadBtn');
    const dashboardSaveJsonBtn = document.getElementById('dashboardSaveJsonBtn');
    const dashboardMiiFile = document.getElementById('dashboardMiiFile');
    const dashboardMiiId = document.getElementById('dashboardMiiId');
    const dashboardMiiData = document.getElementById('dashboardMiiData');
    const dashboardDownloadBtn = document.getElementById('dashboardDownloadBtn');
    const dashboardUploadBtn = document.getElementById('dashboardUploadBtn');
    const dashboardInstructionsBtn = document.getElementById('dashboardInstructionsBtn');
    const dashboardKidomaticBtn = document.getElementById('dashboardKidomaticBtn');
    const dashboardUploadForm = document.getElementById('dashboardUploadForm');
    const dashboardUploadMiiData = document.getElementById('dashboardUploadMiiData');
    const dashboardKidomaticResults = document.getElementById('dashboardKidomaticResults');
    const dashboardKidomaticGrid = document.getElementById('dashboardKidomaticGrid');
    const exportModal = document.getElementById('dashboardExportModal');
    const exportModalClose = document.getElementById('dashboardExportModalClose');
    const exportLabel = document.getElementById('dashboardExportLabel');
    const exportFormat = document.getElementById('dashboardExportFormat');
    const exportSpecial = document.getElementById('dashboardExportSpecial');
    const exportQrConsole = document.getElementById('dashboardExportQrConsole');
    const exportMessage = document.getElementById('dashboardExportMessage');
    const exportDownloadBtn = document.getElementById('dashboardExportDownloadBtn');
    const exportCopyHexBtn = document.getElementById('dashboardExportCopyHexBtn');
    const exportCopyBase64Btn = document.getElementById('dashboardExportCopyBase64Btn');
    const dashboardConfig = window.miiDashboardConfig || {};

    const STAGE_EXPORT_META_FIELDS = new Set(['stageIndex', 'stageLabel', 'renderDataUri', 'heightMeasurements', 'weightMeasurements']);
    let dashboardState = null;
    let activeExportMii = null;
    let activeExportLabel = 'Mii';
    let activeExportUsesEditedJson = true;
    let lastAnalyzeError = '';

    function clonePlain(value) {
        if (typeof structuredClone === 'function') {
            return structuredClone(value);
        }
        return JSON.parse(JSON.stringify(value));
    }

    function setInlineMessage(elementId, message, type = 'error') {
        const element = document.getElementById(elementId);
        if (!element) return;
        element.className = message ? `form-message ${type}` : 'form-message';
        element.style.display = message ? 'block' : 'none';
        element.textContent = message || '';
    }

    function setExportMessage(message, type = 'error') {
        if (!exportMessage) return;
        exportMessage.className = message ? `form-message ${type}` : 'form-message';
        exportMessage.style.display = message ? 'block' : 'none';
        exportMessage.textContent = message || '';
    }

    function getDashboardJsonText() {
        if (!dashboardJsonOutput) return '';
        return typeof dashboardJsonOutput.value === 'string'
            ? dashboardJsonOutput.value
            : dashboardJsonOutput.textContent || '';
    }

    function setDashboardJsonText(value) {
        if (!dashboardJsonOutput) return;
        const nextValue = typeof value === 'string' ? value : JSON.stringify(value || {}, null, 2);
        if (typeof dashboardJsonOutput.value === 'string') {
            dashboardJsonOutput.value = nextValue;
            return;
        }
        dashboardJsonOutput.textContent = nextValue;
    }

    function getEditedDashboardMii({ showError = true, messageId = 'dashboardMessage' } = {}) {
        const rawJson = getDashboardJsonText().trim();
        if (!rawJson) {
            if (dashboardState?.mii) return clonePlain(dashboardState.mii);
            if (showError) setInlineMessage(messageId, 'Decode a Mii before using this action.', 'error');
            return null;
        }

        try {
            return JSON.parse(rawJson);
        } catch (error) {
            if (showError) {
                setInlineMessage(messageId, `The edited MiiJS JSON is not valid JSON: ${error.message}`, 'error');
            }
            return null;
        }
    }

    function getAppliedDashboardMii({ showError = true, messageId = 'dashboardMessage' } = {}) {
        if (dashboardState?.mii) return clonePlain(dashboardState.mii);
        if (showError) setInlineMessage(messageId, 'Apply or decode a Mii before using this action.', 'error');
        return null;
    }

    function syncUploadMiiDataFromAppliedJson() {
        const appliedMii = getAppliedDashboardMii({ showError: false });
        if (dashboardUploadMiiData && appliedMii) {
            dashboardUploadMiiData.value = JSON.stringify(appliedMii);
        }
    }

    function clearDashboardDecodeInputs() {
        if (dashboardMiiFile) dashboardMiiFile.value = '';
        if (dashboardMiiId) dashboardMiiId.value = '';
        if (dashboardMiiData) dashboardMiiData.value = '';
    }

    function hasTomodachiData(mii) {
        const tl = mii?.tl;
        if (tl === null || tl === undefined) return false;
        if (typeof tl !== 'object') return true;
        return Object.keys(tl).length > 0;
    }

    function getDefaultQrConsoleForMii(mii) {
        return hasTomodachiData(mii) ? 'TOMODACHI' : '3DS';
    }

    function dataUriToBlob(dataUri) {
        const [metadata, data] = String(dataUri || '').split(',');
        if (!metadata || !data) return null;
        const mimeMatch = metadata.match(/^data:([^;]+)/i);
        const mimeType = mimeMatch?.[1] || 'image/png';
        const binary = atob(data);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
            bytes[index] = binary.charCodeAt(index);
        }
        return new Blob([bytes], { type: mimeType });
    }

    function openDataUriImage(dataUri) {
        if (!String(dataUri || '').startsWith('data:image/')) return false;
        const imageWindow = window.open('', '_blank', 'noopener');
        const blob = dataUriToBlob(dataUri);
        if (!blob) return false;
        const objectUrl = window.URL.createObjectURL(blob);
        if (imageWindow) {
            imageWindow.location.href = objectUrl;
        } else {
            window.location.href = objectUrl;
        }
        window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 60000);
        return true;
    }

    function asFiniteNumber(value, fallback = 0) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : fallback;
    }

    function formatHeight(heightMeasurements) {
        const feet = asFiniteNumber(heightMeasurements?.feet);
        const inches = asFiniteNumber(heightMeasurements?.inches);
        const centimeters = asFiniteNumber(heightMeasurements?.centimeters);
        return `${feet}' ${inches.toFixed(0)}" (${centimeters.toFixed(1)} cm)`;
    }

    function formatWeight(weightMeasurements) {
        const pounds = asFiniteNumber(weightMeasurements?.pounds);
        const kilograms = asFiniteNumber(weightMeasurements?.kilograms);
        return `${pounds.toFixed(1)} lbs (${kilograms.toFixed(1)} kg)`;
    }

    function buildStatRow(label, value) {
        const row = document.createElement('p');
        row.className = 'child-stage-stat';

        const labelEl = document.createElement('span');
        labelEl.className = 'child-stage-stat-label';
        labelEl.textContent = `${label}:`;

        const valueEl = document.createElement('span');
        valueEl.className = 'child-stage-stat-value';
        valueEl.textContent = value;

        row.appendChild(labelEl);
        row.appendChild(valueEl);
        return row;
    }

    function buildExportableStage(stage) {
        if (!stage || typeof stage !== 'object') return null;
        const cloned = clonePlain(stage);
        for (const field of STAGE_EXPORT_META_FIELDS) {
            delete cloned[field];
        }
        return cloned;
    }

    function renderInfoRows(rows) {
        if (!dashboardInfoGrid) return;
        dashboardInfoGrid.innerHTML = '';

        (rows || []).forEach((row) => {
            const item = document.createElement('div');
            item.className = 'dashboard-info-item';

            const label = document.createElement('span');
            label.className = 'dashboard-info-label';
            label.textContent = row.label || '';

            const value = document.createElement('span');
            value.className = 'dashboard-info-value';
            value.textContent = row.value || 'Not Set';

            item.appendChild(label);
            item.appendChild(value);
            dashboardInfoGrid.appendChild(item);
        });
    }

    function renderTomodachiRows(rows) {
        if (!dashboardTomodachiCard || !dashboardTomodachiGrid) return;
        dashboardTomodachiGrid.innerHTML = '';

        const hasRows = Array.isArray(rows) && rows.length > 0;
        dashboardTomodachiCard.hidden = !hasRows;
        if (!hasRows) return;

        rows.forEach((row) => {
            const item = document.createElement('div');
            item.className = 'dashboard-info-item';

            const label = document.createElement('span');
            label.className = 'dashboard-info-label';
            label.textContent = row.label || '';

            const value = document.createElement('span');
            value.className = 'dashboard-info-value';
            value.textContent = row.value || 'Not Set';

            item.appendChild(label);
            item.appendChild(value);
            dashboardTomodachiGrid.appendChild(item);
        });
    }

    function normalizeQrConsole(consoleType) {
        const normalized = String(consoleType || '').trim().toUpperCase().replace(/[\s_-]+/g, '');
        if (['TOMODACHI', 'TOMODACHILIFE', 'TL', 'TLE'].includes(normalized)) return 'TOMODACHI';
        return normalized === 'WIIU' ? 'WIIU' : '3DS';
    }

    function setDashboardQrConsole(consoleType) {
        if (!dashboardState) return;
        const normalized = normalizeQrConsole(consoleType);
        const src = normalized === 'TOMODACHI'
            ? dashboardState.qrTomodachiDataUri
            : (normalized === 'WIIU' ? dashboardState.qrWiiuDataUri : dashboardState.qr3dsDataUri);
        if (!src) return;

        if (dashboardQrPreview) {
            dashboardQrPreview.classList.toggle('is-qr-3ds', normalized === '3DS');
            dashboardQrPreview.classList.toggle('is-qr-wiiu', normalized === 'WIIU');
            dashboardQrPreview.classList.toggle('is-qr-tomodachi', normalized === 'TOMODACHI');
        }
        if (dashboardQr) {
            dashboardQr.classList.add('is-switching');
            dashboardQr.src = src;
            const qrLabel = normalized === 'TOMODACHI' ? 'Tomodachi Life' : (normalized === 'WIIU' ? 'Wii U' : '3DS');
            dashboardQr.alt = `${dashboardState.miiName || 'Decoded Mii'} ${qrLabel} QR code`;
            dashboardQr.dataset.qrConsole = normalized;
        }
        if (dashboardQrLink) {
            dashboardQrLink.href = src;
        }

        document.querySelectorAll('[data-qr-tab]').forEach((tab) => {
            const isActive = normalizeQrConsole(tab.dataset.qrTab) === normalized;
            tab.classList.toggle('is-active', isActive);
            tab.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });
    }

    function renderDashboard(result, options = {}) {
        dashboardState = result;
        activeExportMii = result.mii;
        activeExportLabel = result.miiName || 'Mii';

        if (dashboardMiiName) dashboardMiiName.textContent = result.miiName || 'Decoded Mii';
        if (dashboardCreatedOn) {
            dashboardCreatedOn.textContent = result.createdOn ? `Created On: ${result.createdOn}` : '';
        }
        if (dashboardRender) {
            dashboardRender.src = result.renderDataUri || '';
            dashboardRender.alt = `${result.miiName || 'Decoded Mii'} render`;
        }
        if (dashboardFullBodyRender) {
            dashboardFullBodyRender.src = result.fullBodyRenderDataUri || '';
            dashboardFullBodyRender.alt = `${result.miiName || 'Decoded Mii'} full body render`;
        }
        if (dashboardJsonOutput) {
            setDashboardJsonText(result.miiJson || JSON.stringify(result.mii || {}, null, 2));
        }
        if (dashboardUploadMiiData) {
            dashboardUploadMiiData.value = result.miiData || JSON.stringify(result.mii || {});
        }
        if (dashboardMiiId && result.sourceMiiId) {
            dashboardMiiId.value = result.sourceMiiId;
        }
        if (dashboardQrPreview) {
            dashboardQrPreview.dataset.qr3dsSrc = result.qr3dsDataUri || '';
            dashboardQrPreview.dataset.qrWiiuSrc = result.qrWiiuDataUri || '';
            dashboardQrPreview.dataset.qrTomodachiSrc = result.qrTomodachiDataUri || '';
            dashboardQrPreview.classList.toggle('has-tomodachi-qr', Boolean(result.qrTomodachiDataUri));
        }

        renderInfoRows(result.infoRows || []);
        renderTomodachiRows(result.tomodachiRows || []);
        document.querySelectorAll('[data-qr-tab="TOMODACHI"]').forEach((tab) => {
            tab.hidden = !result.qrTomodachiDataUri;
        });
        setDashboardQrConsole('3DS');
        if (dashboardSaveJsonBtn) {
            dashboardSaveJsonBtn.hidden = !(dashboardConfig.isAdmin && result.sourceMiiId);
        }
        if (options.clearInputs !== false) {
            clearDashboardDecodeInputs();
        }

        if (dashboardKidomaticResults) dashboardKidomaticResults.hidden = true;
        if (dashboardKidomaticGrid) dashboardKidomaticGrid.innerHTML = '';
        if (dashboardUploadForm) dashboardUploadForm.hidden = true;
        if (dashboardResults) {
            dashboardResults.hidden = false;
            if (!options.skipScroll) {
                dashboardResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    }

    function parseFilename(contentDisposition, fallbackName = 'mii', fallbackExtension = 'bin') {
        if (typeof contentDisposition === 'string' && contentDisposition) {
            const utfMatch = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
            if (utfMatch?.[1]) {
                try {
                    return decodeURIComponent(utfMatch[1]);
                } catch (e) { }
            }

            const basicMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
            if (basicMatch?.[1]) {
                return basicMatch[1];
            }
        }

        return `${fallbackName}.${fallbackExtension}`;
    }

    async function readExportError(response) {
        const fallback = `Export failed (${response?.status || 'unknown status'}).`;
        if (!response) return fallback;
        const contentType = response.headers.get('content-type') || '';

        if (contentType.includes('application/json')) {
            try {
                const payload = await response.json();
                if (payload?.error) return payload.error;
            } catch (e) { }
        }

        try {
            const text = (await response.text()).trim();
            if (text) return text;
        } catch (e) { }

        return fallback;
    }

    function setExportBusy(isBusy, activeButton = null, loadingLabel = '') {
        [exportDownloadBtn, exportCopyHexBtn, exportCopyBase64Btn].forEach((button) => {
            if (!button) return;
            if (!button.dataset.originalText) {
                button.dataset.originalText = button.textContent;
            }
            button.disabled = isBusy;
            button.textContent = isBusy && button === activeButton ? loadingLabel : button.dataset.originalText;
        });
    }

    function openExportModal(mii, label = 'Mii', options = {}) {
        if (!exportModal) return;
        const useEditedJson = options.useEditedJson !== undefined ? Boolean(options.useEditedJson) : false;
        if (!useEditedJson && !mii) return;
        activeExportMii = mii;
        activeExportLabel = label;
        activeExportUsesEditedJson = useEditedJson;
        if (exportLabel) exportLabel.textContent = label;
        if (exportFormat) exportFormat.value = '';
        if (exportQrConsole) {
            const defaultMii = useEditedJson ? dashboardState?.mii : mii;
            exportQrConsole.value = getDefaultQrConsoleForMii(defaultMii);
        }
        setExportMessage('');
        exportModal.hidden = false;
        requestAnimationFrame(() => exportModal.classList.add('active'));
    }

    function closeExportModal() {
        if (!exportModal) return;
        exportModal.classList.remove('active');
        setTimeout(() => {
            if (!exportModal.classList.contains('active')) {
                exportModal.hidden = true;
            }
        }, 200);
    }

    async function requestExport() {
        const requestedFormat = String(exportFormat?.value || '').trim();
        const format = requestedFormat || 'qr';
        const miiForExport = activeExportUsesEditedJson
            ? getAppliedDashboardMii({ showError: false })
            : activeExportMii;
        if (!miiForExport) {
            throw new Error(activeExportUsesEditedJson
                ? 'Apply or decode a Mii before exporting.'
                : 'No Mii selected for export.');
        }

        const response = await fetch('/convertMii', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                miiData: miiForExport,
                format,
                special: Boolean(exportSpecial?.checked),
                qrConsole: requestedFormat
                    ? (exportQrConsole?.value || getDefaultQrConsoleForMii(miiForExport))
                    : getDefaultQrConsoleForMii(miiForExport)
            })
        });

        const contentDisposition = response.headers.get('content-disposition') || '';
        const isAttachment = contentDisposition.includes('attachment');
        if (!response.ok || !isAttachment) {
            throw new Error(await readExportError(response));
        }

        return { response, contentDisposition, format };
    }

    async function runExport(action, button) {
        setExportMessage('');
        setExportBusy(true, button, action === 'download' ? 'Downloading...' : 'Copying...');

        try {
            const { response, contentDisposition, format } = await requestExport();

            if (action === 'download') {
                const blob = await response.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const anchor = document.createElement('a');
                anchor.href = downloadUrl;
                anchor.download = parseFilename(
                    contentDisposition,
                    activeExportLabel.replace(/\s+/g, '_').toLowerCase() || 'mii',
                    format.replace(/[^a-z0-9]+/gi, '') || 'bin'
                );
                document.body.appendChild(anchor);
                anchor.click();
                document.body.removeChild(anchor);
                window.URL.revokeObjectURL(downloadUrl);
                setExportMessage('Download started successfully.', 'success');
                return;
            }

            const bytes = new Uint8Array(await response.arrayBuffer());
            const isBase64 = action === 'copyBase64';
            const exportText = isBase64 ? bytesToBase64String(bytes) : bytesToHexString(bytes);
            await copyTextToClipboard(exportText);
            setExportMessage(`${isBase64 ? 'Base64' : 'Hex'} copied to clipboard.`, 'success');
        } catch (error) {
            setExportMessage(error.message || 'Failed to export Mii.', 'error');
        } finally {
            setExportBusy(false);
        }
    }

    function renderKidomaticStages(children) {
        if (!dashboardKidomaticGrid || !dashboardKidomaticResults) return;
        dashboardKidomaticGrid.innerHTML = '';

        children.forEach((stage, index) => {
            const stageCard = document.createElement('article');
            stageCard.className = 'child-stage-card';

            const stageHeader = document.createElement('h4');
            stageHeader.textContent = stage.stageLabel || `Stage ${index + 1}`;

            const stageHeaderRow = document.createElement('div');
            stageHeaderRow.className = 'child-stage-header-row';

            const stageDownloadButton = document.createElement('button');
            stageDownloadButton.type = 'button';
            stageDownloadButton.className = 'child-stage-download-trigger';
            stageDownloadButton.setAttribute('aria-label', `Export ${stageHeader.textContent}`);
            stageDownloadButton.setAttribute('title', 'Download and copy options');
            stageDownloadButton.innerHTML = dashboardConfig.downloadIconSvg || 'Download';
            stageDownloadButton.addEventListener('click', () => {
                openExportModal(buildExportableStage(stage), stageHeader.textContent, { useEditedJson: false });
            });

            stageHeaderRow.appendChild(stageHeader);
            stageHeaderRow.appendChild(stageDownloadButton);

            const stageImage = document.createElement('img');
            stageImage.src = stage.renderDataUri;
            stageImage.alt = `${stage?.meta?.name || 'Kidomatic Mii'} - ${stageHeader.textContent}`;
            stageImage.loading = 'lazy';

            const statsWrap = document.createElement('div');
            statsWrap.className = 'child-stage-stats';

            const name = stage?.meta?.name || 'Unknown';
            const miiHeight = asFiniteNumber(stage?.general?.height);
            const miiWeight = asFiniteNumber(stage?.general?.weight);

            statsWrap.appendChild(buildStatRow('Name', name));
            statsWrap.appendChild(buildStatRow('Mii Height', `${miiHeight}`));
            statsWrap.appendChild(buildStatRow('Mii Weight', `${miiWeight}`));
            statsWrap.appendChild(buildStatRow('Height (Real)', formatHeight(stage.heightMeasurements)));
            statsWrap.appendChild(buildStatRow('Weight (Real)', formatWeight(stage.weightMeasurements)));

            stageCard.appendChild(stageHeaderRow);
            stageCard.appendChild(stageImage);
            stageCard.appendChild(statsWrap);
            dashboardKidomaticGrid.appendChild(stageCard);
        });

        dashboardKidomaticResults.hidden = false;
        dashboardKidomaticResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    async function runKidomatic(messageId = 'dashboardActionMessage') {
        if (!dashboardState?.mii) {
            setInlineMessage(messageId, 'Decode a Mii before running Kidomatic.', 'error');
            return;
        }
        const appliedMii = getAppliedDashboardMii({ messageId });
        if (!appliedMii) return;

        const originalHtml = dashboardKidomaticBtn?.innerHTML || 'Kidomatic';
        if (dashboardKidomaticBtn) {
            dashboardKidomaticBtn.disabled = true;
            dashboardKidomaticBtn.textContent = 'Running...';
        }
        setInlineMessage(messageId, '', '');

        try {
            const response = await fetch('/makeMiiKidomatic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ miiData: appliedMii })
            });
            const result = await response.json();
            if (result.error) {
                throw new Error(result.error);
            }

            const children = Array.isArray(result.children) ? result.children : [];
            if (!children.length) {
                throw new Error('No Kidomatic stages were returned.');
            }

            renderKidomaticStages(children);
            setInlineMessage(messageId, `Generated ${children.length} Kidomatic stages.`, 'success');
        } catch (error) {
            setInlineMessage(messageId, error.message || 'Failed to run Kidomatic.', 'error');
        } finally {
            if (dashboardKidomaticBtn) {
                dashboardKidomaticBtn.disabled = false;
                dashboardKidomaticBtn.innerHTML = originalHtml;
            }
        }
    }

    async function analyzeDashboardPayload(payload, {
        loadingMessage = 'Decoding...',
        autoKidomatic = false,
        successMessage = '',
        preserveSourceMiiId = false,
        skipScroll = false,
        clearInputs = true,
        messageId = 'dashboardMessage'
    } = {}) {
        lastAnalyzeError = '';
        setInlineMessage(messageId, loadingMessage, 'info');

        try {
            const response = await fetch('/miiDashboard/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const result = await response.json();
            if (result.error) {
                throw new Error(result.error);
            }

            if (preserveSourceMiiId && dashboardState?.sourceMiiId && !result.sourceMiiId) {
                result.sourceMiiId = dashboardState.sourceMiiId;
            }

            renderDashboard(result, { skipScroll, clearInputs });
            setInlineMessage(messageId, successMessage || result.message || 'Mii decoded successfully.', 'success');

            if (autoKidomatic) {
                await runKidomatic('dashboardActionMessage');
            }
            return result;
        } catch (error) {
            lastAnalyzeError = error.message || 'Failed to decode Mii.';
            setInlineMessage(messageId, lastAnalyzeError, 'error');
            return null;
        }
    }

    async function applyJsonEdits() {
        const editedMii = getEditedDashboardMii({ messageId: 'dashboardJsonMessage' });
        if (!editedMii) return;
        const previousState = dashboardState ? clonePlain(dashboardState) : null;
        const previousJson = previousState?.miiJson || getDashboardJsonText();
        const originalText = dashboardApplyJsonBtn?.textContent || 'Apply JSON Edits';
        if (dashboardApplyJsonBtn) {
            dashboardApplyJsonBtn.disabled = true;
            dashboardApplyJsonBtn.textContent = 'Applying...';
        }

        const result = await analyzeDashboardPayload(
            { miiData: editedMii },
            {
                loadingMessage: 'Applying JSON edits...',
                successMessage: 'JSON edits applied.',
                preserveSourceMiiId: true,
                skipScroll: true,
                clearInputs: false,
                messageId: 'dashboardJsonMessage'
            }
        );

        if (!result && previousState) {
            renderDashboard(previousState, { skipScroll: true, clearInputs: false });
            setDashboardJsonText(previousJson);
            setInlineMessage(
                'dashboardJsonMessage',
                `JSON edits could not be applied, so the previous dashboard state was restored. ${lastAnalyzeError}`.trim(),
                'error'
            );
        }

        if (dashboardApplyJsonBtn) {
            dashboardApplyJsonBtn.disabled = false;
            dashboardApplyJsonBtn.textContent = result ? 'Applied' : originalText;
            if (result) {
                window.setTimeout(() => {
                    if (dashboardApplyJsonBtn) dashboardApplyJsonBtn.textContent = originalText;
                }, 1400);
            }
        }
    }

    async function saveJsonEdits() {
        if (!dashboardState?.sourceMiiId) {
            setInlineMessage('dashboardJsonMessage', 'Open a Mii from an InfiniMii Mii ID before saving JSON back to the site.', 'error');
            return;
        }

        const editedMii = getEditedDashboardMii({ messageId: 'dashboardJsonMessage' });
        if (!editedMii) return;

        const originalText = dashboardSaveJsonBtn?.textContent || 'Save';
        if (dashboardSaveJsonBtn) {
            dashboardSaveJsonBtn.disabled = true;
            dashboardSaveJsonBtn.textContent = 'Saving...';
        }
        const checkedResult = await analyzeDashboardPayload(
            { miiData: editedMii },
            {
                loadingMessage: 'Checking JSON before save...',
                successMessage: 'JSON decoded. Saving...',
                preserveSourceMiiId: true,
                skipScroll: true,
                clearInputs: false,
                messageId: 'dashboardJsonMessage'
            }
        );

        if (!checkedResult) {
            if (dashboardSaveJsonBtn) {
                dashboardSaveJsonBtn.disabled = false;
                dashboardSaveJsonBtn.textContent = originalText;
            }
            return;
        }

        try {
            const response = await fetch('/miiDashboard/saveJson', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    miiId: dashboardState.sourceMiiId,
                    miiData: checkedResult.mii
                })
            });
            const result = await response.json();
            if (result.error) {
                throw new Error(result.error);
            }

            renderDashboard(result, { skipScroll: true, clearInputs: false });
            setInlineMessage('dashboardJsonMessage', result.message || 'Mii JSON saved.', 'success');
        } catch (error) {
            setInlineMessage('dashboardJsonMessage', error.message || 'Failed to save Mii JSON.', 'error');
        } finally {
            if (dashboardSaveJsonBtn) {
                dashboardSaveJsonBtn.disabled = false;
                dashboardSaveJsonBtn.textContent = originalText;
            }
        }
    }

    function getInitialDashboardRequest() {
        const params = new URLSearchParams(window.location.search);
        const miiId = (params.get('id') || params.get('miiId') || '').trim();
        const miiData = (params.get('miiData') || params.get('data') || '').trim();
        const kidomaticValue = (params.get('kidomatic') || '').trim().toLowerCase();
        const autoKidomatic = params.has('kidomatic') && (!kidomaticValue || ['1', 'true', 'yes', 'run'].includes(kidomaticValue));

        if (miiId) {
            if (dashboardMiiId) dashboardMiiId.value = miiId;
            return { payload: { miiId }, autoKidomatic };
        }

        if (miiData) {
            if (dashboardMiiData) dashboardMiiData.value = miiData;
            return { payload: { miiData }, autoKidomatic };
        }

        return { payload: null, autoKidomatic };
    }

    dashboardForm?.addEventListener('submit', (event) => {
        handleFormSubmit(event, '/miiDashboard/analyze', 'Decoding...', 'dashboardMessage', {
            onSuccess: (result, messageDiv) => {
                renderDashboard(result);
                if (messageDiv) {
                    messageDiv.textContent = result.message || 'Mii decoded successfully.';
                    messageDiv.className = 'form-message success';
                    messageDiv.style.display = 'block';
                }
            }
        });
    });

    dashboardUploadForm?.addEventListener('submit', (event) => {
        syncUploadMiiDataFromAppliedJson();
        handleFormSubmit(event, '/uploadMii', 'Uploading...', 'dashboardUploadMessage');
    });

    dashboardDownloadBtn?.addEventListener('click', () => {
        if (!dashboardState?.mii) return;
        openExportModal(null, `${dashboardState.miiName || 'Mii'} (applied JSON)`, { useEditedJson: true });
    });

    dashboardJsonDownloadBtn?.addEventListener('click', () => {
        if (!dashboardState?.mii) return;
        openExportModal(null, `${dashboardState.miiName || 'Mii'} (applied JSON)`, { useEditedJson: true });
    });

    dashboardUploadBtn?.addEventListener('click', () => {
        if (!dashboardUploadForm) return;
        dashboardUploadForm.hidden = false;
        setInlineMessage('dashboardActionMessage', 'Upload options opened below.', 'success');
        dashboardUploadForm.scrollIntoView({ behavior: 'smooth', block: 'start' });
        document.getElementById('dashboardUploadDesc')?.focus();
    });

    dashboardInstructionsBtn?.addEventListener('click', () => {
        if (!dashboardState?.mii) {
            setInlineMessage('dashboardActionMessage', 'Decode a Mii before opening instructions.', 'error');
            return;
        }
        const appliedMii = getAppliedDashboardMii({ messageId: 'dashboardActionMessage' });
        if (!appliedMii) return;

        showMiiInstructionsModal(async ({ consoleType }) => {
            const response = await fetch('/getInstructions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    miiData: appliedMii,
                    console: consoleType
                })
            });
            return await response.json();
        }, {
            title: 'Recreation Instructions',
            defaultConsole: '3DS',
            miiName: dashboardState.miiName || 'Mii'
        });
    });

    dashboardKidomaticBtn?.addEventListener('click', () => runKidomatic('dashboardActionMessage'));
    dashboardApplyJsonBtn?.addEventListener('click', applyJsonEdits);
    dashboardSaveJsonBtn?.addEventListener('click', saveJsonEdits);

    document.querySelectorAll('[data-qr-tab]').forEach((tab) => {
        tab.addEventListener('click', () => setDashboardQrConsole(tab.dataset.qrTab));
    });

    dashboardQrLink?.addEventListener('click', (event) => {
        const qrSrc = dashboardQr?.src || dashboardQrLink.href;
        if (openDataUriImage(qrSrc)) {
            event.preventDefault();
        }
    });

    dashboardQr?.addEventListener('load', () => {
        dashboardQr.classList.remove('is-switching');
        dashboardQr.classList.add('is-loaded');
    });

    exportModalClose?.addEventListener('click', closeExportModal);
    exportModal?.addEventListener('click', (event) => {
        if (event.target === exportModal) {
            closeExportModal();
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && exportModal && !exportModal.hidden) {
            closeExportModal();
        }
    });

    exportDownloadBtn?.addEventListener('click', () => runExport('download', exportDownloadBtn));
    exportCopyHexBtn?.addEventListener('click', () => runExport('copyHex', exportCopyHexBtn));
    exportCopyBase64Btn?.addEventListener('click', () => runExport('copyBase64', exportCopyBase64Btn));

    const initialRequest = getInitialDashboardRequest();
    if (initialRequest.payload) {
        analyzeDashboardPayload(initialRequest.payload, {
            loadingMessage: 'Loading Mii...',
            autoKidomatic: initialRequest.autoKidomatic
        });
    }
})();
