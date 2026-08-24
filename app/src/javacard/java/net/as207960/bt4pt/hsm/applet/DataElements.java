package net.as207960.bt4pt.hsm.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

final class DataElements {
    static final byte KEY_NONE      = 0;
    static final byte KEY_NIST_P256 = 1;
    static final byte KEY_SECP256K1 = 2;
    static final byte KEY_NIST_P384 = 3;
    static final byte KEY_NIST_P521 = 4;
    static final byte KEY_ED25519   = 5;
    static final byte KEY_ED448     = 6;

    static final byte MAX_ELEMENTS = 15;
    static final short BUFFER_SIZE = 600;

    // Data contains [format][value][format][value]...
    private final byte[] data;

    private final short[] formatOffsets;
    private final short[] valueOffsets;
    private final short[] valueLengths;

    private final short[] formatLengths;
    private final byte[] flags;

    private final byte[] expiry;
    private boolean hasExpiry;

    private final byte[] bindingKey;
    private byte bindingType;
    private byte bindingKeyLength;
    private short validityDuration;

    private byte count;
    private short used;

    DataElements() {
        data = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        formatOffsets = JCSystem.makeTransientShortArray(MAX_ELEMENTS, JCSystem.CLEAR_ON_DESELECT);
        valueOffsets = JCSystem.makeTransientShortArray(MAX_ELEMENTS, JCSystem.CLEAR_ON_DESELECT);
        valueLengths = JCSystem.makeTransientShortArray(MAX_ELEMENTS, JCSystem.CLEAR_ON_DESELECT);
        formatLengths = JCSystem.makeTransientShortArray(MAX_ELEMENTS, JCSystem.CLEAR_ON_DESELECT);
        flags = JCSystem.makeTransientByteArray(MAX_ELEMENTS, JCSystem.CLEAR_ON_DESELECT);
        expiry = JCSystem.makeTransientByteArray((short)6, JCSystem.CLEAR_ON_DESELECT);
        bindingKey = JCSystem.makeTransientByteArray((short)67, JCSystem.CLEAR_ON_DESELECT);
        clear();
    }

    void clear() {
        count = 0;
        used = 0;
        hasExpiry = false;
        bindingType = KEY_NONE;
        bindingKeyLength = 0;
        validityDuration = 0;
        Util.arrayFillNonAtomic(data, (short)0, BUFFER_SIZE, (byte)0);
    }

    void add(
            boolean critical,
            byte[] format,
            short formatOffset,
            short formatLength,
            byte[] value,
            short valueOffset,
            short valueLength
    ) {
        if (count >= MAX_ELEMENTS) {
            ISOException.throwIt(MainApplet.SW_TOO_MANY_ELEMENTS);
        }

        if (formatLength < 1 || formatLength > 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        for (byte i = 0; i < formatLength; i++) {
            short c = (short)(format[(short)(formatOffset + i)] & 0xff);
            if (c < 0x20 || c > 0x7e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }

        if (valueLength < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short required = (short)(formatLength + valueLength);

        if ((short)(used + required) > BUFFER_SIZE) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        byte index = count;

        flags[index] = (byte)(critical ? 1 : 0);
        formatOffsets[index] = used;
        formatLengths[index] = formatLength;

        Util.arrayCopyNonAtomic(format, formatOffset, data, used, formatLength);

        used += formatLength;

        valueOffsets[index] = used;
        valueLengths[index] = valueLength;

        if (valueLength != 0) {
            Util.arrayCopyNonAtomic(value, valueOffset, data, used, valueLength);
            used += valueLength;
        }

        count++;
    }

    byte count() {
        return count;
    }

    boolean critical(byte index) {
        return flags[index] != 0;
    }

    byte[] buffer() {
        return data;
    }

    short formatOffset(byte index) {
        return formatOffsets[index];
    }

    short formatLength(byte index) {
        return formatLengths[index];
    }

    short valueOffset(byte index) {
        return valueOffsets[index];
    }

    short valueLength(byte index) {
        return valueLengths[index];
    }

    boolean hasExpiry() {
        return hasExpiry;
    }

    short expiryYear() {
        return (short)(((expiry[0] & 0xFF) << 8) | (expiry[1] & 0xFF));
    }

    short expiryDay() {
        return (short)(((expiry[2] & 0xFF) << 8) | (expiry[3] & 0xFF));
    }

    short expiryTime() {
        return (short)(((expiry[4] & 0xFF) << 8) | (expiry[5] & 0xFF));
    }

    void setExpiry(byte[] data) {
        Util.arrayCopyNonAtomic(data, (short)0, expiry, (short)0, (short)6);
        hasExpiry = true;
    }

    void setBinding(byte type, short duration, byte[] src, short off, byte len) {
        if (duration < 1 || duration > 3600)
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        byte expected;
        switch (type) {
            case KEY_NIST_P256:
            case KEY_SECP256K1:
                expected = 33;
                break;

            case KEY_NIST_P384:
                expected = 49;
                break;

            case KEY_NIST_P521:
                expected = 67;
                break;

            case KEY_ED25519:
                expected = 32;
                break;

            case KEY_ED448:
                expected = 57;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return;
        }

        if (len != expected)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        Util.arrayCopyNonAtomic(src, off, bindingKey, (short)0, len);

        bindingType = type;
        bindingKeyLength = len;
        validityDuration = duration;
    }

    boolean hasBinding() {
        return bindingType != KEY_NONE;
    }

    byte bindingType() {
        return bindingType;
    }

    byte[] bindingKey() {
        return bindingKey;
    }

    byte bindingKeyLength() {
        return bindingKeyLength;
    }

    short validityDuration() {
        return validityDuration;
    }
}