/**
 * WiimoteMiiExtractJS - Browser-based Wii Remote Mii Extraction Library
 * Enhanced version with support for multiple Wii Remote variants
 * 
 * This library allows reading and writing Mii data from paired Wii Remotes
 * using the WebHID API with fallback to Web Bluetooth.
 * 
 * Based on WiimoteDataManagementLibrary v0.9.2
 * @license MIT
 */

import * as constants from './constants.js';
import { calculateCRC16, verifyCRC16 } from './crc16.js';

// Wii Remote variant identifiers
const WIIMOTE_VARIANTS = {
    // Original Wii Remote (RVL-CNT-01)
    ORIGINAL: {
        vendorId: 0x057E,
        productId: 0x0306,
        name: 'RVL-CNT-01'
    },
    // Wii Remote Plus (RVL-CNT-01-TR) - built-in Motion Plus
    PLUS: {
        vendorId: 0x057E,
        productId: 0x0330,
        name: 'RVL-CNT-01-TR'
    }
};

// Bluetooth service UUIDs for Wii Remote
const WIIMOTE_BLUETOOTH = {
    SERVICE_UUID: '00001124-0000-1000-8000-00805f9b34fb', // HID Service
    CONTROL_UUID: '00001124-0000-1000-8000-00805f9b34fb',
    INTERRUPT_UUID: '00001124-0000-1000-8000-00805f9b34fb',
    // Alternative: try standard HID service
    HID_SERVICE: '00001812-0000-1000-8000-00805f9b34fb'
};

/**
 * WiimoteHID - Handles WebHID communication with Wii Remote
 */
export class WiimoteHID {
    constructor() {
        this.device = null;
        this.isConnected = false;
        this._pendingReads = new Map();
        this._readBuffer = new Uint8Array(0);
        this.connectionType = null; // 'hid' or 'bluetooth'
        this.bluetoothDevice = null;
        this.bluetoothCharacteristic = null;
    }

    /**
     * Request and connect to a Wii Remote via WebHID with all variants
     * @returns {Promise<boolean>} True if connected successfully
     */
    async connect() {
        // Try WebHID first
        try {
            return await this.connectWebHID();
        } catch (error) {
            console.warn('WebHID connection failed, trying Bluetooth:', error);
            // If WebHID fails, try Bluetooth
            try {
                return await this.connectBluetooth();
            } catch (btError) {
                console.error('Both WebHID and Bluetooth failed');
                throw new Error('Failed to connect via WebHID or Bluetooth. Make sure the Wii Remote is paired and try again.');
            }
        }
    }

    /**
     * Connect via WebHID with support for all Wii Remote variants
     */
    async connectWebHID() {
        if (!navigator.hid) {
            throw new Error('WebHID API not supported in this browser. Try Chrome or Edge.');
        }

        // Build filters for all known Wii Remote variants
        const filters = Object.values(WIIMOTE_VARIANTS).map(variant => ({
            vendorId: variant.vendorId,
            productId: variant.productId
        }));

        // Also add a generic Nintendo filter to catch any new variants
        filters.push({
            vendorId: 0x057E // Nintendo vendor ID
        });

        const devices = await navigator.hid.requestDevice({ filters });

        if (devices.length === 0) {
            throw new Error('No Wii Remote selected');
        }

        this.device = devices[0];
        
        // Log what we connected to
        const variant = Object.values(WIIMOTE_VARIANTS).find(v => 
            v.vendorId === this.device.vendorId && v.productId === this.device.productId
        );
        console.log('Connected to:', variant ? variant.name : `Unknown Wii Remote (PID: ${this.device.productId?.toString(16)})`);
        
        if (!this.device.opened) {
            await this.device.open();
        }

        // Set up input report handler
        this.device.addEventListener('inputreport', (event) => {
            this._handleInputReport(event);
        });

        this.isConnected = true;
        this.connectionType = 'hid';
        return true;
    }

    /**
     * Connect via Web Bluetooth as fallback
     */
    async connectBluetooth() {
        if (!navigator.bluetooth) {
            throw new Error('Web Bluetooth API not supported');
        }

        // Request Bluetooth device with optional services
        this.bluetoothDevice = await navigator.bluetooth.requestDevice({
            filters: [
                { namePrefix: 'Nintendo RVL' },
                { services: [WIIMOTE_BLUETOOTH.HID_SERVICE] }
            ],
            optionalServices: [
                WIIMOTE_BLUETOOTH.SERVICE_UUID,
                WIIMOTE_BLUETOOTH.HID_SERVICE
            ]
        });

        console.log('Connecting to Bluetooth device:', this.bluetoothDevice.name);

        const server = await this.bluetoothDevice.gatt.connect();
        
        // Try to get HID service
        let service;
        try {
            service = await server.getPrimaryService(WIIMOTE_BLUETOOTH.HID_SERVICE);
        } catch (e) {
            console.warn('Standard HID service not found, trying alternative');
            service = await server.getPrimaryService(WIIMOTE_BLUETOOTH.SERVICE_UUID);
        }

        // Get characteristics - this part may need adjustment based on actual Wii Remote BT profile
        const characteristics = await service.getCharacteristics();
        console.log('Found characteristics:', characteristics.length);

        // Find the right characteristic for communication
        this.bluetoothCharacteristic = characteristics.find(c => c.properties.write && c.properties.notify);
        
        if (!this.bluetoothCharacteristic) {
            throw new Error('Could not find suitable Bluetooth characteristic');
        }

        // Set up notification handler
        await this.bluetoothCharacteristic.startNotifications();
        this.bluetoothCharacteristic.addEventListener('characteristicvaluechanged', (event) => {
            const value = new Uint8Array(event.target.value.buffer);
            this._handleBluetoothData(value);
        });

        this.isConnected = true;
        this.connectionType = 'bluetooth';
        return true;
    }

    /**
     * Handle Bluetooth data
     * @private
     */
    _handleBluetoothData(data) {
        // Parse based on report type
        if (data.length > 0) {
            const reportId = data[0];
            this._handleInputReport({ reportId, data: { buffer: data.slice(1).buffer } });
        }
    }

    /**
     * Connect to a previously paired device
     * @returns {Promise<boolean>}
     */
    async connectPaired() {
        // Try WebHID first
        if (navigator.hid) {
            try {
                const devices = await navigator.hid.getDevices();
                
                // Look for any Nintendo device (covers all Wii Remote variants)
                const wiimote = devices.find(d => d.vendorId === 0x057E);

                if (wiimote) {
                    this.device = wiimote;
                    
                    if (!this.device.opened) {
                        await this.device.open();
                    }

                    this.device.addEventListener('inputreport', (event) => {
                        this._handleInputReport(event);
                    });

                    this.isConnected = true;
                    this.connectionType = 'hid';
                    
                    const variant = Object.values(WIIMOTE_VARIANTS).find(v => 
                        v.vendorId === this.device.vendorId && v.productId === this.device.productId
                    );
                    console.log('Connected to paired device:', variant ? variant.name : 'Unknown variant');
                    
                    return true;
                }
            } catch (error) {
                console.warn('WebHID paired connection failed:', error);
            }
        }

        // Try Bluetooth
        if (navigator.bluetooth) {
            try {
                const devices = await navigator.bluetooth.getDevices();
                const wiimote = devices.find(d => d.name && d.name.includes('Nintendo RVL'));
                
                if (wiimote) {
                    this.bluetoothDevice = wiimote;
                    // Continue with Bluetooth connection...
                    return await this.connectBluetooth();
                }
            } catch (error) {
                console.warn('Bluetooth paired connection failed:', error);
            }
        }

        throw new Error('No paired Wii Remote found. Please pair first using the connect() method.');
    }

    /**
     * Disconnect from the Wii Remote
     */
    async disconnect() {
        if (this.connectionType === 'hid' && this.device && this.device.opened) {
            await this.device.close();
        } else if (this.connectionType === 'bluetooth' && this.bluetoothDevice && this.bluetoothDevice.gatt.connected) {
            await this.bluetoothDevice.gatt.disconnect();
        }
        
        this.device = null;
        this.bluetoothDevice = null;
        this.bluetoothCharacteristic = null;
        this.isConnected = false;
        this.connectionType = null;
    }

    /**
     * Handle incoming HID input reports
     * @private
     */
    _handleInputReport(event) {
        const { reportId, data } = event;
        const dataArray = new Uint8Array(data.buffer);

        // Check for pending read requests
        if (reportId === constants.WIIMOTE_HID_RID_INPUT_READ) {
            this._handleReadResponse(dataArray);
        } else if (reportId === constants.WIIMOTE_HID_RID_INPUT_WRITE_ACK) {
            this._handleWriteAck(dataArray);
        }
    }

    /**
     * Handle read response from Wiimote
     * @private
     */
    _handleReadResponse(data) {
        // Data format: [buttons(2)] [error&size(1)] [offset(2)] [data(16)]
        const errorAndSize = data[2];
        const error = (errorAndSize & 0x0F);
        const size = ((errorAndSize >> 4) & 0x0F) + 1;
        const offset = (data[3] << 8) | data[4];
        const readData = data.slice(5, 5 + Math.min(size, Math.max(0, data.length - 5)));

        // Find matching pending read
        for (const [key, pending] of this._pendingReads) {
            if (pending.isWrite || typeof pending.offset !== 'number' || typeof pending.size !== 'number') {
                continue;
            }

            if (offset >= pending.offset && offset < pending.offset + pending.size) {
                if (error !== 0) {
                    pending.reject(new Error(`Read error 0x${error.toString(16)} at offset 0x${offset.toString(16)}`));
                    this._pendingReads.delete(key);
                    break;
                }

                const localOffset = offset - pending.offset;
                if (localOffset < 0 || localOffset >= pending.size) {
                    break;
                }

                for (let i = 0; i < readData.length; i++) {
                    const destIndex = localOffset + i;
                    if (destIndex >= pending.size) {
                        break;
                    }

                    pending.buffer[destIndex] = readData[i];
                    if (pending.receivedMap[destIndex] === 0) {
                        pending.receivedMap[destIndex] = 1;
                        pending.receivedCount++;
                    }
                }

                if (pending.receivedCount >= pending.size) {
                    pending.resolve(pending.buffer);
                    this._pendingReads.delete(key);
                }
                break;
            }
        }
    }

    /**
     * Handle write acknowledgment
     * @private
     */
    _handleWriteAck(data) {
        // Notify any pending write operations
        const reportId = data[1];
        for (const [key, pending] of this._pendingReads) {
            if (pending.isWrite) {
                pending.resolve(true);
                this._pendingReads.delete(key);
                break;
            }
        }
    }

    /**
     * Send a read request to the Wiimote
     * @param {number} offset - Memory offset to read from
     * @param {number} size - Number of bytes to read
     * @returns {Promise<Uint8Array>} The read data
     */
    async readFromWiimote(offset, size) {
        if (!this.isConnected) {
            throw new Error('Not connected to Wii Remote');
        }

        return new Promise((resolve, reject) => {
            const requestId = `${offset}-${size}-${Date.now()}`;
            const timeout = setTimeout(() => {
                this._pendingReads.delete(requestId);
                reject(new Error('Read timeout'));
            }, constants.HID_READ_TIMEOUT);

            this._pendingReads.set(requestId, {
                offset,
                size,
                buffer: new Uint8Array(size),
                receivedCount: 0,
                receivedMap: new Uint8Array(size),
                resolve: (data) => {
                    clearTimeout(timeout);
                    resolve(data);
                },
                reject: (error) => {
                    clearTimeout(timeout);
                    reject(error);
                }
            });

            (async () => {
                try {
                    // Send read requests in chunks (max 16 bytes per request)
                    const chunkSize = 16;
                    for (let i = 0; i < size; i += chunkSize) {
                        const chunkOffset = offset + i;
                        const bytesToRead = Math.min(chunkSize, size - i);
                        await this._sendReadRequest(chunkOffset, bytesToRead);
                        await this._delay(50);
                    }
                } catch (sendError) {
                    clearTimeout(timeout);
                    this._pendingReads.delete(requestId);
                    reject(sendError);
                }
            })();
        });
    }

    /**
     * Send a single read request
     * @private
     */
    async _sendReadRequest(offset, bytes) {
        const reportData = new Uint8Array(constants.WIIMOTE_HID_REPORT_PAYLOAD_LENGTH);
        
        reportData[0] = 0x00; // Address space (EEPROM)
        reportData[1] = 0x00;
        reportData[2] = (offset >> 8) & 0xFF;
        reportData[3] = offset & 0xFF;
        reportData[4] = (bytes >> 8) & 0xFF;
        reportData[5] = bytes & 0xFF;

        if (this.connectionType === 'hid') {
            await this.device.sendReport(constants.WIIMOTE_HID_CONTROL_READ, reportData);
        } else if (this.connectionType === 'bluetooth' && this.bluetoothCharacteristic) {
            const btData = new Uint8Array(reportData.length + 1);
            btData[0] = constants.WIIMOTE_HID_CONTROL_READ;
            btData.set(reportData, 1);
            await this.bluetoothCharacteristic.writeValue(btData);
        } else {
            throw new Error('No active connection available for read request');
        }
    }

    /**
     * Write data to the Wiimote
     * @param {number} offset - Memory offset to write to
     * @param {Uint8Array} data - Data to write
     * @returns {Promise<boolean>} True if write successful
     */
    async writeToWiimote(offset, data) {
        if (!this.isConnected) {
            throw new Error('Not connected to Wii Remote');
        }

        // Write in chunks of 16 bytes
        const chunkSize = constants.WIIMOTE_HID_WRITE_DATA_SIZE;
        
        for (let i = 0; i < data.length; i += chunkSize) {
            const chunkOffset = offset + i;
            const chunk = data.slice(i, Math.min(i + chunkSize, data.length));
            
            await this._sendWriteData(chunkOffset, chunk);
            
            // Wait for ACK
            await this._waitForWriteAck();
            
            // Small delay between writes
            await this._delay(50);
        }

        return true;
    }

    /**
     * Send a single write command
     * @private
     */
    async _sendWriteData(offset, data) {
        const reportData = new Uint8Array(constants.WIIMOTE_HID_REPORT_PAYLOAD_LENGTH);
        
        reportData[0] = 0x00; // Address space (EEPROM)
        reportData[1] = 0x00;
        reportData[2] = (offset >> 8) & 0xFF;
        reportData[3] = offset & 0xFF;
        reportData[4] = data.length;
        reportData.set(data, 5);

        if (this.connectionType === 'hid') {
            await this.device.sendReport(constants.WIIMOTE_HID_CONTROL_WRITE, reportData);
        } else if (this.connectionType === 'bluetooth' && this.bluetoothCharacteristic) {
            const btData = new Uint8Array(reportData.length + 1);
            btData[0] = constants.WIIMOTE_HID_CONTROL_WRITE;
            btData.set(reportData, 1);
            await this.bluetoothCharacteristic.writeValue(btData);
        }
    }

    /**
     * Wait for write acknowledgment
     * @private
     */
    async _waitForWriteAck() {
        return new Promise((resolve, reject) => {
            const requestId = `write-${Date.now()}`;
            const timeout = setTimeout(() => {
                this._pendingReads.delete(requestId);
                reject(new Error('Write acknowledgment timeout'));
            }, constants.HID_READ_TIMEOUT);

            this._pendingReads.set(requestId, {
                isWrite: true,
                resolve: () => {
                    clearTimeout(timeout);
                    resolve(true);
                },
                reject
            });
        });
    }

    /**
     * Set LED state
     * @param {number} ledMask - LED bitmask (0x01 = LED1, 0x02 = LED2, etc.)
     */
    async setLEDs(ledMask) {
        const reportData = new Uint8Array(constants.WIIMOTE_HID_REPORT_PAYLOAD_LENGTH);
        reportData[0] = ledMask << 4;

        await this.device.sendReport(constants.WIIMOTE_HID_CONTROL_LED, reportData);
    }

    /**
     * Helper delay function
     * @private
     */
    _delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Get connection info
     */
    getConnectionInfo() {
        if (!this.isConnected) {
            return { connected: false };
        }

        if (this.connectionType === 'hid' && this.device) {
            const variant = Object.values(WIIMOTE_VARIANTS).find(v => 
                v.vendorId === this.device.vendorId && v.productId === this.device.productId
            );
            return {
                connected: true,
                type: 'WebHID',
                variant: variant ? variant.name : 'Unknown',
                vendorId: `0x${this.device.vendorId?.toString(16).padStart(4, '0')}`,
                productId: `0x${this.device.productId?.toString(16).padStart(4, '0')}`,
                productName: this.device.productName
            };
        } else if (this.connectionType === 'bluetooth' && this.bluetoothDevice) {
            return {
                connected: true,
                type: 'Web Bluetooth',
                name: this.bluetoothDevice.name,
                id: this.bluetoothDevice.id
            };
        }

        return { connected: false };
    }
}

/**
 * MiiSlot - Represents a single Mii slot
 */
export class MiiSlot {
    constructor(slotNumber, data) {
        this.slotNumber = slotNumber;
        this.data = data;
    }

    /**
     * Check if slot is empty
     */
    get isEmpty() {
        return this.data.every(byte => byte === 0);
    }

    get miiId(){
        return Array.from(this.data.slice(0x18, 0x1C))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Get Mii name (UTF-16BE encoded)
     */
    get name() {
        if (this.isEmpty) return '';
        
        // Name starts at byte 2, max 10 characters (20 bytes)
        const nameBytes = this.data.slice(2, 22);
        let name = '';
        
        for (let i = 0; i < nameBytes.length; i += 2) {
            const charCode = (nameBytes[i] << 8) | nameBytes[i + 1];
            if (charCode === 0) break;
            name += String.fromCharCode(charCode);
        }
        
        return name;
    }

    /**
     * Check if Mii is female
     */
    get isFemale() {
        return (this.data[0] & 0x01) === 1;
    }

    /**
     * Export Mii data as Uint8Array
     */
    toBytes() {
        return new Uint8Array(this.data);
    }

    /**
     * Export Mii data as base64
     */
    toBase64() {
        let binary = '';
        for (let i = 0; i < this.data.length; i++) {
            binary += String.fromCharCode(this.data[i]);
        }
        return btoa(binary);
    }

    /**
     * Import Mii data from base64
     * @param {string} base64 - Base64 encoded Mii data
     */
    static fromBase64(slotNumber, base64) {
        const binary = atob(base64);
        const data = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            data[i] = binary.charCodeAt(i);
        }
        return new MiiSlot(slotNumber, data);
    }
}

/**
 * WiimoteMiiManager - Main class for managing Miis on a Wii Remote
 */
export class WiimoteMiiManager {
    constructor() {
        this.hid = new WiimoteHID();
        this.slots = [];
        this._sectionData = null;
    }

    /**
     * Connect to a Wii Remote
     * @param {boolean} usePaired - If true, try to connect to already paired device
     */
    async connect(usePaired = false) {
        if (usePaired) {
            await this.hid.connectPaired();
        } else {
            await this.hid.connect();
        }
        
        // Flash LEDs to confirm connection
        await this.hid.setLEDs(0x0F);
        await this.hid._delay(200);
        await this.hid.setLEDs(0x01);
        
        // Log connection info
        console.log('Connection established:', this.hid.getConnectionInfo());
    }

    /**
     * Disconnect from the Wii Remote
     */
    async disconnect() {
        await this.hid.disconnect();
    }

    /**
     * Check if connected
     */
    get isConnected() {
        return this.hid.isConnected;
    }

    /**
     * Get connection info
     */
    getConnectionInfo() {
        return this.hid.getConnectionInfo();
    }

    /**
     * Read all Mii slots from the Wii Remote
     * @returns {Promise<MiiSlot[]>} Array of MiiSlot objects
     */
    async readAllSlots() {
        this.slots = [];
        const failures = [];

        for (let i = 0; i < constants.WIIMOTE_MII_SLOT_NUM; i++) {
            let slot;
            try {
                slot = await this.readSlot(i);
            } catch (error) {
                slot = new MiiSlot(i, new Uint8Array(constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT));
                slot.readError = error.message;
                failures.push({ slot: i + 1, error: error.message });
            }
            this.slots.push(slot);
        }

        if (failures.length > 0) {
            console.warn('Wiimote slot read failures:', failures);
        }

        return this.slots;
    }

    /**
     * Read a single Mii slot
     * @param {number} slotNumber - Slot number (0-9)
     * @returns {Promise<MiiSlot>} MiiSlot object
     */
    async readSlot(slotNumber) {
        if (slotNumber < 0 || slotNumber >= constants.WIIMOTE_MII_SLOT_NUM) {
            throw new Error(`Invalid slot number: ${slotNumber}`);
        }

        const offset = constants.WIIMOTE_MII_DATA_BEGIN_1 + 
                       (slotNumber * constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT);

        let lastError = null;
        for (let attempt = 1; attempt <= constants.HID_MAX_RETRIES; attempt++) {
            try {
                const data = await this.hid.readFromWiimote(offset, constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT);
                return new MiiSlot(slotNumber, data);
            } catch (error) {
                lastError = error;
                if (attempt < constants.HID_MAX_RETRIES) {
                    await this.hid._delay(constants.HID_RETRY_DELAY * attempt);
                }
            }
        }

        throw new Error(`Failed to read slot ${slotNumber + 1}: ${lastError?.message || 'Unknown read error'}`);
    }

    /**
     * Write a Mii to a slot
     * @param {number} slotNumber - Slot number (0-9)
     * @param {MiiSlot|Uint8Array} miiData - Mii data to write
     * @returns {Promise<boolean>} True if successful
     */
    async writeSlot(slotNumber, miiData) {
        if (slotNumber < 0 || slotNumber >= constants.WIIMOTE_MII_SLOT_NUM) {
            throw new Error(`Invalid slot number: ${slotNumber}`);
        }

        const data = miiData instanceof MiiSlot ? miiData.toBytes() : miiData;
        
        if (data.length !== constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT) {
            throw new Error(`Invalid Mii data size: ${data.length} (expected ${constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT})`);
        }

        const offset = constants.WIIMOTE_MII_DATA_BEGIN_1 + 
                       (slotNumber * constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT);
        
        await this.hid.writeToWiimote(offset, data);

        // Update checksum after write
        await this._updateChecksum();

        return true;
    }

    /**
     * Clear a Mii slot
     * @param {number} slotNumber - Slot number (0-9)
     */
    async clearSlot(slotNumber) {
        const emptyData = new Uint8Array(constants.WIIMOTE_MII_DATA_BYTES_PER_SLOT);
        emptyData.fill(0);
        await this.writeSlot(slotNumber, emptyData);
    }

    /**
     * Read the Mii section data for checksum calculation
     * @private
     */
    async _readMiiSection() {
        const data = await this.hid.readFromWiimote(
            constants.WIIMOTE_MII_SECTION1_BEGIN_ADDR,
            constants.WIIMOTE_MII_SECTION_SIZE
        );
        this._sectionData = data;
        return data;
    }

    /**
     * Update the checksum after modifying Mii data
     * @private
     */
    async _updateChecksum() {
        // Read the current section data
        const sectionData = await this._readMiiSection();
        
        // Calculate new CRC
        const crc = calculateCRC16(sectionData);
        
        // Write CRC to both checksum locations
        const crcBytes = new Uint8Array(2);
        crcBytes[0] = (crc >> 8) & 0xFF;
        crcBytes[1] = crc & 0xFF;

        await this.hid.writeToWiimote(constants.WIIMOTE_MII_CHECKSUM1_ADDR, crcBytes);
        await this.hid.writeToWiimote(constants.WIIMOTE_MII_CHECKSUM2_ADDR, crcBytes);
    }

    /**
     * Verify the checksum of stored Mii data
     * @returns {Promise<boolean>} True if checksum is valid
     */
    async verifyChecksum() {
        const sectionData = await this._readMiiSection();
        const storedCRC = await this.hid.readFromWiimote(
            constants.WIIMOTE_MII_CHECKSUM1_ADDR, 
            constants.WIIMOTE_MII_CHECKSUM_SIZE
        );
        
        const storedValue = (storedCRC[0] << 8) | storedCRC[1];
        return verifyCRC16(sectionData, storedValue);
    }

    /**
     * Get parade slots (visibility flags)
     * @returns {Promise<number>} Parade slot bitmask
     */
    async getParadeSlots() {
        const data = await this.hid.readFromWiimote(
            constants.WIIMOTE_MII_PARADESLOTS_ADDR,
            constants.WIIMOTE_MII_PARADESLOTS_SIZE
        );
        return (data[0] << 8) | data[1];
    }

    /**
     * Set parade slots (visibility flags)
     * @param {number} mask - Bitmask for slot visibility
     */
    async setParadeSlots(mask) {
        const data = new Uint8Array(2);
        data[0] = (mask >> 8) & 0xFF;
        data[1] = mask & 0xFF;
        await this.hid.writeToWiimote(constants.WIIMOTE_MII_PARADESLOTS_ADDR, data);
    }

    /**
     * Export all Miis as JSON
     * @returns {Object} JSON representation of all Miis
     */
    exportAllAsJSON() {
        return {
            version: '1.0',
            connection: this.getConnectionInfo(),
            slots: this.slots.map((slot, index) => ({
                slot: index,
                isEmpty: slot.isEmpty,
                name: slot.name,
                data: slot.toBase64()
            }))
        };
    }

    /**
     * Import Miis from JSON
     * @param {Object} json - JSON data
     */
    async importFromJSON(json) {
        if (!json.slots || !Array.isArray(json.slots)) {
            throw new Error('Invalid JSON format');
        }

        for (const slotData of json.slots) {
            if (!slotData.isEmpty && slotData.data) {
                const slot = MiiSlot.fromBase64(slotData.slot, slotData.data);
                await this.writeSlot(slotData.slot, slot);
            }
        }
    }
}

// Export everything
export { constants, calculateCRC16, verifyCRC16, WIIMOTE_VARIANTS };

// Default export
export default WiimoteMiiManager;
