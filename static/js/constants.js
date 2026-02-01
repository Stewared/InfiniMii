/**
 * Wii Remote Mii Extraction Library - Protocol Constants
 * Based on WiimoteDataManagementLibrary v0.9.2
 * 
 * These constants define the HID protocol and memory layout for reading/writing
 * Mii data from a paired Wii Remote.
 */

// HID Device IDs
export const WIIMOTE_HID_VENDOR_ID = 0x057E;
export const WIIMOTE_HID_PRODUCT_ID = 0x0306;

// HID Report Constants
export const WIIMOTE_HID_REPORT_LENGTH = 22;
export const WIIMOTE_HID_REPORT_PAYLOAD_LENGTH = WIIMOTE_HID_REPORT_LENGTH - 1;
export const WIIMOTE_HID_WRITE_DATA_SIZE = 16;

// HID Control Report IDs
export const WIIMOTE_HID_CONTROL_LED_FF = 0x11;
export const WIIMOTE_HID_CONTROL_CONTROLLER_STATUS = 0x15;
export const WIIMOTE_HID_CONTROL_WRITE = 0x16;
export const WIIMOTE_HID_CONTROL_READ = 0x17;

// HID Input Report IDs
export const WIIMOTE_HID_RID_INPUT_READ = 0x21;
export const WIIMOTE_HID_RID_INPUT_WRITE_ACK = 0x22;

// Save Data Memory Layout
export const WIIMOTE_SAVEDATA_BEGIN = 0x0000;
export const WIIMOTE_SAVEDATA_SIZE = 0x1700;

// Mii Data Memory Addresses
export const WIIMOTE_MII_DATA_BEGIN_ADDR = 0x0FCA;
export const WIIMOTE_MII_DATA_BEGIN_1 = 0x0FD2;
export const WIIMOTE_MII_DATA_BYTES_PER_SLOT = 74;
export const WIIMOTE_MII_SLOT_NUM = 10;

// Mii Sections (for checksum calculation)
export const WIIMOTE_MII_SECTION1_BEGIN_ADDR = 0x0FCA;
export const WIIMOTE_MII_SECTION2_BEGIN_ADDR = 0x12BA;
export const WIIMOTE_MII_SECTION_SIZE = 750;

// Checksum Addresses
export const WIIMOTE_MII_CHECKSUM1_ADDR = 0x12B8;
export const WIIMOTE_MII_CHECKSUM2_ADDR = 0x15A8;
export const WIIMOTE_MII_CHECKSUM_SIZE = 2;

// Parade Slots (Mii visibility)
export const WIIMOTE_MII_PARADESLOTS_ADDR = 0x0FCE;
export const WIIMOTE_MII_PARADESLOTS_SIZE = 2;

// CRC16 Constants (CCITT variant)
export const WIIMOTE_MII_CRC16_POLY = 0x1021;
export const WIIMOTE_MII_CRC16_INITIAL = 0xFFFF;
export const WIIMOTE_MII_CRC16_POSTXOR = 0xEF4C;

// Mii Data Structure Constants
export const MII_NAME_LENGTH = 10;
export const MII_CREATOR_NAME_LENGTH = 10;

export const MII_HEIGHT_MIN = 0x00;
export const MII_HEIGHT_MAX = 0x7F;

export const MII_WEIGHT_MIN = 0x00;
export const MII_WEIGHT_MAX = 0x7F;

// Timeouts and Retry Constants
export const HID_READ_TIMEOUT = 3000; // milliseconds
export const HID_MAX_RETRIES = 5;
export const HID_RETRY_DELAY = 100; // milliseconds
