import { WiimoteMiiManager, MiiSlot, constants } from './wiimote-lib.js';

const WIIMOTE_MANAGER_BUILD = '2026-02-16-cache-bust-1';
window.__WIIMOTE_MANAGER_BUILD = WIIMOTE_MANAGER_BUILD;
console.info('[wiimote-manager] build', WIIMOTE_MANAGER_BUILD);

// Initialize manager
const manager = new WiimoteMiiManager();
let selectedSlot = null;
let currentSlots = [];
let currentImportSource = 'studio';

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
}

function updateStatus(connected) {
    const indicator = document.getElementById('statusIndicator');
    const text = document.getElementById('statusText');
    const typeDisplay = document.getElementById('connectionType');
    
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
    
    document.getElementById('exportBtn').disabled = !slot || slot.isEmpty;
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

window.showImportModal = function() {
    if (selectedSlot === null) {
        log('Please select a slot first', 'error');
        return;
    }

    document.getElementById('importStudioCode').value = '';
    document.getElementById('importMiiId').value = '';
    document.getElementById('importRcdFile').value = '';

    const defaultSource = document.querySelector('input[name="importSource"][value="studio"]');
    if (defaultSource) {
        defaultSource.checked = true;
    }
    window.setImportSource('studio');

    document.getElementById('importModal').classList.add('active');
};

window.setImportSource = function(source) {
    currentImportSource = source;

    document.querySelectorAll('.import-source-panel').forEach(panel => {
        panel.classList.remove('active');
    });

    if (source === 'studio') {
        document.getElementById('importSourceStudio').classList.add('active');
    } else if (source === 'miiId') {
        document.getElementById('importSourceMiiId').classList.add('active');
    } else if (source === 'rcd') {
        document.getElementById('importSourceRcd').classList.add('active');
    }
};

window.importMii = async function() {
    try {
        if (selectedSlot === null) {
            log('Please select a slot first', 'error');
            return;
        }

        const source = document.querySelector('input[name="importSource"]:checked')?.value || currentImportSource;
        const formData = new FormData();
        formData.append('source', source);

        if (source === 'studio') {
            const studioCode = document.getElementById('importStudioCode').value.trim();
            if (!studioCode) {
                log('Please paste a Studio code first', 'error');
                return;
            }
            formData.append('studioCode', studioCode);
        } else if (source === 'miiId') {
            const miiId = document.getElementById('importMiiId').value.trim();
            if (!miiId) {
                log('Please paste a Mii ID first', 'error');
                return;
            }
            formData.append('miiId', miiId);
        } else if (source === 'rcd') {
            const fileInput = document.getElementById('importRcdFile');
            const file = fileInput?.files?.[0];
            if (!file) {
                log('Please choose a .rcd file first', 'error');
                return;
            }
            formData.append('miiFile', file);
        } else {
            log('Invalid import source selected', 'error');
            return;
        }

        log(`Preparing import from ${source} source...`, 'info');
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

// Close modals when clicking outside
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
        }
    });
});

