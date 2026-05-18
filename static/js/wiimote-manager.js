import { WiimoteMiiManager, MiiSlot, constants } from './wiimote-lib.js';

const WIIMOTE_MANAGER_BUILD = '2026-02-16-cache-bust-3';
window.__WIIMOTE_MANAGER_BUILD = WIIMOTE_MANAGER_BUILD;
console.info('[wiimote-manager] build', WIIMOTE_MANAGER_BUILD);

// Initialize manager
const manager = new WiimoteMiiManager();
let selectedSlot = null;
let currentSlots = [];

// Check API support
const hasHID = !!navigator.hid;

if (!hasHID) {
    document.getElementById('browserWarning').style.display = 'block';
    document.getElementById('connectBtn').disabled = true;
}

// Initialize empty slots display
renderEmptySlots();

function renderEmptySlots() {
    const grid = document.getElementById('miiGrid');
    grid.innerHTML = '';
    for (let i = 0; i < 10; i++) {
        const slot = document.createElement('div');
        slot.className = 'mii-slot empty';
        slot.innerHTML = `
            <div class="mii-avatar">
                <div class="loading">❓</div>
            </div>
            <div class="mii-name">Slot ${i + 1}</div>
            <div class="mii-info">Empty</div>
        `;
        slot.onclick = () => selectSlot(i);
        grid.appendChild(slot);
    }
}

function log(message, type = 'normal') {
    const logArea = document.getElementById('logArea');
    const p = document.createElement('p');
    p.className = type;
    p.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logArea.appendChild(p);
    logArea.scrollTop = logArea.scrollHeight;
    if (type === 'error' && typeof window.scrollToUserError === 'function') {
        window.scrollToUserError(p);
    }
}

function updateStatus(connected) {
    const indicator = document.getElementById('statusIndicator');
    const text = document.getElementById('statusText');
    const typeDisplay = document.getElementById('connectionType');
    const selected = selectedSlot !== null ? currentSlots[selectedSlot] : null;
    
    if (connected) {
        indicator.classList.add('connected');
        const info = manager.getConnectionInfo();
        text.textContent = 'Connected to Wii Remote';
        
        if (info.type === 'WebHID') {
            typeDisplay.textContent = `${info.type} - ${info.variant || 'Unknown'}`;
        }
    } else {
        indicator.classList.remove('connected');
        text.textContent = 'Not connected';
        typeDisplay.textContent = '';
    }
    
    // Update button states
    document.getElementById('connectBtn').disabled = connected;
    document.getElementById('disconnectBtn').disabled = !connected;
    document.getElementById('readAllBtn').disabled = !connected;
    document.getElementById('exportBtn').disabled = !connected || !selected || selected.isEmpty || selected.readError;
    document.getElementById('copyHexBtn').disabled = !connected || !selected || selected.isEmpty || selected.readError;
    document.getElementById('copyBase64Btn').disabled = !connected || !selected || selected.isEmpty || selected.readError;
    document.getElementById('instructionsBtn').disabled = !connected || !selected || selected.isEmpty || selected.readError;
    document.getElementById('importBtn').disabled = !connected || selectedSlot === null;
    document.getElementById('clearBtn').disabled = !connected || selectedSlot === null;
}

window.connectWiimote = async function() {
    try {
        log('Requesting Wii Remote connection via WebHID...', 'info');
        await manager.hid.connectWebHID();
        manager.hid.isConnected = true;
        updateStatus(true);
        log('Connected successfully via WebHID!', 'success');
        log(`Device: ${manager.getConnectionInfo().variant}`, 'info');
    } catch (error) {
        log(`Connection failed: ${error.message}`, 'error');
    }
};

window.disconnectWiimote = async function() {
    try {
        await manager.disconnect();
        updateStatus(false);
        renderEmptySlots();
        currentSlots = [];
        selectedSlot = null;
        log('Disconnected', 'info');
    } catch (error) {
        log(`Disconnect error: ${error.message}`, 'error');
    }
};

window.readAllSlots = async function() {
    try {
        log('Reading all Mii slots...', 'info');
        const slots = await manager.readAllSlots();
        currentSlots = slots;
        await renderSlots(slots);
        const failedReads = slots.filter(s => s.readError);
        if (failedReads.length > 0) {
            log(`Read completed with ${failedReads.length} slot error(s). Failed slots were left empty.`, 'error');
        }
        log(`Read ${slots.filter(s => !s.isEmpty).length} Miis`, 'success');
    } catch (error) {
        log(`Read error: ${error.message}`, 'error');
    }
};

async function renderSlots(slots) {
    const grid = document.getElementById('miiGrid');
    grid.innerHTML = '';

    for (let index = 0; index < slots.length; index++) {
        const slot = slots[index];
        const div = document.createElement('div');
        div.className = `mii-slot ${slot.isEmpty ? 'empty' : ''} ${selectedSlot === index ? 'selected' : ''}`;

        if (slot.readError) {
            div.innerHTML = `
                <div class="mii-avatar">
                    <div class="loading">!</div>
                </div>
                <div class="mii-name">Slot ${index + 1}</div>
                <div class="mii-info">Read failed</div>
            `;
        } else if (slot.isEmpty) {
            div.innerHTML = `
                <div class="mii-avatar">
                    <div class="loading">?</div>
                </div>
                <div class="mii-name">Slot ${index + 1}</div>
                <div class="mii-info">Empty</div>
            `;
        } else {
            div.innerHTML = `
                <div class="mii-avatar">
                    <div class="loading">...</div>
                </div>
                <div class="mii-name">${slot.name || 'Loading...'}</div>
                <div class="mii-info">Rendering...</div>
            `;

            const avatarEl = div.querySelector('.mii-avatar');
            const nameEl = div.querySelector('.mii-name');
            const infoEl = div.querySelector('.mii-info');
            const imageUrl = `/render?miiData=${encodeURIComponent(slot.toBase64())}`;

            const img = document.createElement('img');
            img.alt = slot.name || 'Mii';
            img.onload = () => {
                nameEl.textContent = slot.name || 'Unknown';
                infoEl.textContent = `ID: ${slot.miiId?.toUpperCase() || 'N/A'}`;
            };
            img.onerror = () => {
                log(`Failed to render Mii in slot ${index + 1}`, 'error');
                avatarEl.innerHTML = '<div class="loading">:)</div>';
                nameEl.textContent = slot.name || 'Unknown';
                infoEl.textContent = 'Render failed';
            };
            img.src = imageUrl;

            avatarEl.innerHTML = '';
            avatarEl.appendChild(img);
        }

        div.onclick = () => selectSlot(index);
        grid.appendChild(div);
    }
}

function selectSlot(index) {
    selectedSlot = index;
    
    // Update visual selection
    document.querySelectorAll('.mii-slot').forEach((el, i) => {
        el.classList.toggle('selected', i === index);
    });
    
    // Update button states
    const slot = currentSlots[index];
    
    document.getElementById('exportBtn').disabled = !slot || slot.isEmpty || !!slot.readError;
    document.getElementById('copyHexBtn').disabled = !slot || slot.isEmpty || !!slot.readError;
    document.getElementById('copyBase64Btn').disabled = !slot || slot.isEmpty || !!slot.readError;
    document.getElementById('instructionsBtn').disabled = !slot || slot.isEmpty || !!slot.readError;
    document.getElementById('importBtn').disabled = !manager.hid.isConnected;
    document.getElementById('clearBtn').disabled = !manager.hid.isConnected || !slot || slot.isEmpty;
    
    log(`Selected slot ${index + 1}`, 'info');
}

window.exportSelected = function() {
    if (selectedSlot === null) return;
    
    const slot = currentSlots[selectedSlot];
    if (!slot || slot.isEmpty || slot.readError) {
        log('Cannot export empty slot', 'error');
        return;
    }

    const fallbackName = `wiimote_slot_${selectedSlot + 1}`;
    const safeBaseName = (slot.name || fallbackName)
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')
        .trim()
        .replace(/\s+/g, '_')
        .slice(0, 64) || fallbackName;
    const fileName = `${safeBaseName}.rcd`;

    const blob = new Blob([slot.toBytes()], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    log(`Downloaded ${fileName}`, 'success');
};

window.showSelectedInstructions = function() {
    if (selectedSlot === null) {
        log('Please select a slot first', 'error');
        return;
    }

    const slot = currentSlots[selectedSlot];
    if (!slot || slot.isEmpty || slot.readError) {
        log('Cannot generate instructions for this slot', 'error');
        return;
    }

    if (typeof window.showMiiInstructionsModal !== 'function') {
        log('Instructions modal is unavailable on this page', 'error');
        return;
    }

    const miiDataBase64 = slot.toBase64();
    window.showMiiInstructionsModal(async ({ consoleType }) => {
        const requestData = new FormData();
        requestData.append('miiData', miiDataBase64);
        requestData.append('console', consoleType);

        const response = await fetch('/getInstructions', {
            method: 'POST',
            body: requestData
        });
        return await response.json();
    }, {
        title: `Recreation Instructions (Slot ${selectedSlot + 1})`,
        defaultConsole: '3DS',
        miiName: slot.name || `Slot ${selectedSlot + 1}`
    });
};

window.showImportModal = function() {
    if (selectedSlot === null) {
        log('Please select a slot first', 'error');
        return;
    }

    document.getElementById('importMiiId').value = '';
    document.getElementById('importRcdFile').value = '';
    const rawInput = document.getElementById('importRawMiiData');
    if (rawInput) rawInput.value = '';

    document.getElementById('importModal').classList.add('active');
};

window.importMii = async function() {
    try {
        if (selectedSlot === null) {
            log('Please select a slot first', 'error');
            return;
        }

        const formData = new FormData();
        const selectedFile = document.getElementById('importRcdFile')?.files?.[0] || null;
        const miiId = document.getElementById('importMiiId')?.value?.trim() || '';
        const rawMiiData = document.getElementById('importRawMiiData')?.value?.trim() || '';

        if (selectedFile) formData.append('miiFile', selectedFile);
        if (miiId) formData.append('miiId', miiId);
        if (rawMiiData) formData.append('miiData', rawMiiData);

        let detectedSource = '';
        if (selectedFile) detectedSource = 'rcd file';
        else if (miiId) detectedSource = 'Mii ID';
        else if (rawMiiData) detectedSource = 'raw data';

        if (!detectedSource) {
            log('Provide at least one source: .rcd file, Mii ID, or raw base64/hex data', 'error');
            return;
        }

        log(`Preparing import from ${detectedSource}...`, 'info');
        const response = await fetch('/api/wiimote/importData', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (!response.ok || result.error) {
            throw new Error(result.error || `Import source failed (${response.status})`);
        }

        const miiSlot = MiiSlot.fromBase64(selectedSlot, result.miiData);
        if (miiSlot.data.length !== constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT) {
            throw new Error(`Invalid Wii slot data size: ${miiSlot.data.length}`);
        }

        await manager.writeSlot(selectedSlot, miiSlot);
        
        log(`Imported "${result.name || miiSlot.name || 'Mii'}" to slot ${selectedSlot + 1}`, 'success');
        window.closeModal('importModal');
        
        // Refresh slots
        await window.readAllSlots();
    } catch (error) {
        log(`Import error: ${error.message}`, 'error');
    }
};

window.clearSelected = async function() {
    if (selectedSlot === null) return;
    
    const slot = currentSlots[selectedSlot];
    if (!slot || slot.isEmpty) {
        log('Slot is already empty', 'info');
        return;
    }
    
    if (!confirm(`Are you sure you want to clear "${slot.name}" from slot ${selectedSlot + 1}?`)) {
        return;
    }
    
    try {
        await manager.clearSlot(selectedSlot);
        log(`Cleared slot ${selectedSlot + 1}`, 'success');
        
        // Refresh slots
        await window.readAllSlots();
    } catch (error) {
        log(`Clear error: ${error.message}`, 'error');
    }
};

window.closeModal = function(modalId) {
    document.getElementById(modalId).classList.remove('active');
};

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
}

async function copySelectedSlotData(encoding) {
    if (selectedSlot === null) {
        log('Please select a slot first', 'error');
        return;
    }

    const slot = currentSlots[selectedSlot];
    if (!slot || slot.isEmpty || slot.readError) {
        log('Cannot copy data from this slot', 'error');
        return;
    }

    const bytes = slot.toBytes();
    const text = encoding === 'base64' ? bytesToBase64(bytes) : bytesToHex(bytes);

    try {
        await navigator.clipboard.writeText(text);
        log(`Copied ${encoding.toUpperCase()} for slot ${selectedSlot + 1}`, 'success');
    } catch (error) {
        log(`Failed to copy ${encoding.toUpperCase()}: ${error.message}`, 'error');
    }
}

window.copySelectedHex = async function() {
    await copySelectedSlotData('hex');
};

window.copySelectedBase64 = async function() {
    await copySelectedSlotData('base64');
};

// Close modals when clicking outside
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
        }
    });
});

