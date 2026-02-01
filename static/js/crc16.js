/**
 * CRC16 Calculation for Mii Data
 * Implements CCITT CRC16 with specific Wiimote polynomial and parameters
 */

import * as constants from './constants.js';

/**
 * Calculate CRC16 checksum for Mii data (CCITT variant)
 * Used to verify integrity of Mii data in Wiimote memory
 * 
 * @param {Uint8Array} data - The data to calculate CRC for
 * @returns {number} 16-bit CRC value
 */
export function calculateCRC16(data) {
    let crc = constants.WIIMOTE_MII_CRC16_INITIAL;
    
    for (let i = 0; i < data.length; i++) {
        crc ^= (data[i] << 8);
        
        for (let j = 0; j < 8; j++) {
            crc <<= 1;
            
            if (crc & 0x10000) {
                crc ^= constants.WIIMOTE_MII_CRC16_POLY;
            }
        }
        
        crc &= 0xFFFF;
    }
    
    // Post-XOR with specific value
    return crc ^ constants.WIIMOTE_MII_CRC16_POSTXOR;
}

/**
 * Verify CRC16 checksum
 * 
 * @param {Uint8Array} data - The data to verify
 * @param {number} expectedCRC - The expected CRC value
 * @returns {boolean} True if CRC matches
 */
export function verifyCRC16(data, expectedCRC) {
    const calculated = calculateCRC16(data);
    return calculated === expectedCRC;
}
