import { WiimoteMiiManager, MiiSlot } from './wiimote-lib.js';

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
        
        if (slot.isEmpty) {
            div.innerHTML = `
                <div class="mii-avatar">
                    <div class="loading">❓</div>
                </div>
                <div class="mii-name">Slot ${index + 1}</div>
                <div class="mii-info">Empty</div>
            `;
        } else {
            // Show loading state initially
            div.innerHTML = `
                <div class="mii-avatar">
                    <div class="loading">⏳</div>
                </div>
                <div class="mii-name">${slot.name || 'Loading...'}</div>
                <div class="mii-info">Rendering...</div>
            `;
            
            // Render Mii image via server endpoint
            try {
                const miiData = slot.toBase64();
                const response = await fetch('/api/renderMii', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ miiData })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const imageUrl = URL.createObjectURL(blob);
                    
                    div.innerHTML = `
                        <div class="mii-avatar">
                            <img src="${imageUrl}" alt="${slot.name || 'Mii'}">
                        </div>
                        <div class="mii-name">${slot.name || 'Unknown'}</div>
                        <div class="mii-info">ID: ${slot.miiId?.toString(16)?.toUpperCase() || 'N/A'}</div>
                    `;
                } else {
                    throw new Error('Failed to render Mii');
                }
            } catch (error) {
                log(`Failed to render Mii in slot ${index + 1}: ${error.message}`, 'error');
                div.innerHTML = `
                    <div class="mii-avatar">
                        <div class="loading">😊</div>
                    </div>
                    <div class="mii-name">${slot.name || 'Unknown'}</div>
                    <div class="mii-info">Render failed</div>
                `;
            }
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
    if (!slot || slot.isEmpty) {
        log('Cannot export empty slot', 'error');
        return;
    }
    
    const data = {
        name: slot.name,
        slot: selectedSlot,
        data: slot.toBase64()
    };
    
    document.getElementById('exportData').value = JSON.stringify(data, null, 2);
    document.getElementById('exportModal').classList.add('active');
    log(`Exported Mii "${slot.name}"`, 'success');
};

window.copyExportData = function() {
    const textarea = document.getElementById('exportData');
    textarea.select();
    document.execCommand('copy');
    log('Copied to clipboard!', 'success');
};

window.showImportModal = function() {
    if (selectedSlot === null) {
        log('Please select a slot first', 'error');
        return;
    }
    document.getElementById('importData').value = '';
    document.getElementById('importModal').classList.add('active');
};

window.importMii = async function() {
    try {
        const dataStr = document.getElementById('importData').value.trim();
        let miiData;
        
        try {
            // Try parsing as JSON
            const json = JSON.parse(dataStr);
            miiData = json.data || json;
        } catch {
            // Assume it's raw base64
            miiData = dataStr;
        }
        
        const miiSlot = MiiSlot.fromBase64(selectedSlot, miiData);
        await manager.writeSlot(selectedSlot, miiSlot);
        
        log(`Imported Mii to slot ${selectedSlot + 1}`, 'success');
        closeModal('importModal');
        
        // Refresh slots
        await readAllSlots();
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
        await readAllSlots();
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
