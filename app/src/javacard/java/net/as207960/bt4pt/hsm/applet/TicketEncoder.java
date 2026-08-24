package net.as207960.bt4pt.hsm.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

final class TicketEncoder {
    private static final byte[] TRACE_RECORD_ID = {'H', 'S', 'M', '1'};

    private final ECKNREngine ecknr;

    TicketEncoder(ECKNREngine ecknr) {
        this.ecknr = ecknr;
    }

    short create(byte slot, DataElements elements, byte[] output, byte[] hsmId, byte[] signatureCounter) {
        if (elements.count() == 0) {
            ISOException.throwIt(MainApplet.SW_NO_DATA);
        }

        short elementCount = elements.count();
        output[ECKNREngine.SCALAR_SIZE] = 0b0000_0000;
        short offset = ECKNREngine.SCALAR_SIZE;

        if (elements.hasExpiry()) {
            short expiryYear = (short) (elements.expiryYear() - 2026);
            short expiryDay = (short) (elements.expiryDay() - 1);
            short expiryTime = elements.expiryTime();
            if (expiryYear < 0 || expiryYear > 255) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if (expiryDay < 0 || expiryDay > 365) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if (expiryTime < 0 || expiryTime > 1439) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            output[ECKNREngine.SCALAR_SIZE] |= (byte) 0b1000_0000;
            output[(short) (ECKNREngine.SCALAR_SIZE + 1)] = (byte) (expiryYear & 0xff);
            output[(short) (ECKNREngine.SCALAR_SIZE + 2)] = (byte) (expiryDay >> 8);
            output[(short) (ECKNREngine.SCALAR_SIZE + 3)] = (byte) (expiryDay & 0xff);
            output[(short) (ECKNREngine.SCALAR_SIZE + 4)] = (byte) (expiryTime >> 8);
            output[(short) (ECKNREngine.SCALAR_SIZE + 5)] = (byte) (expiryTime & 0xff);
            offset += 6;
        }

        if (elements.hasBinding()) {
            output[ECKNREngine.SCALAR_SIZE] |= (byte)0b0100_0000;
            if (elements.hasExpiry()) {
                output[offset] = 0;
                switch (elements.bindingType()) {
                    case DataElements.KEY_NIST_P256:
                        break;
                    case DataElements.KEY_SECP256K1:
                        output[offset] |= (byte)0b0010_0000;
                        break;
                    case DataElements.KEY_NIST_P384:
                        output[offset] |= (byte)0b0100_0000;
                        break;
                    case DataElements.KEY_NIST_P521:
                        output[offset] |= (byte)0b0110_0000;
                        break;
                    case DataElements.KEY_ED25519:
                        output[offset] |= (byte)0b1000_0000;
                        break;
                    case DataElements.KEY_ED448:
                        output[offset] |= (byte)0b1010_0000;
                        break;
                }
                if (elements.bindingKey()[0] != 0) {
                    output[offset] |= (byte)0b0001_0000;
                }
            } else {
                switch (elements.bindingType()) {
                    case DataElements.KEY_NIST_P256:
                        break;
                    case DataElements.KEY_SECP256K1:
                        output[offset] |= (byte)0b0000_1000;
                        break;
                    case DataElements.KEY_NIST_P384:
                        output[offset] |= (byte)0b0001_0000;
                        break;
                    case DataElements.KEY_NIST_P521:
                        output[offset] |= (byte)0b0001_1000;
                        break;
                    case DataElements.KEY_ED25519:
                        output[offset] |= (byte)0b0010_0000;
                        break;
                    case DataElements.KEY_ED448:
                        output[offset] |= (byte)0b0010_1000;
                        break;
                }
                if (elements.bindingKey()[0] != 0) {
                    output[offset] |= (byte)0b0000_0100;
                }
            }
            Util.arrayCopyNonAtomic(elements.bindingKey(), (short)1, output, (short)(offset + 1), (short)(elements.bindingKeyLength() - 1));
            offset += elements.bindingKeyLength();

            short validityDuration = (short) (elements.validityDuration() - 1);
            if (validityDuration < 0 || validityDuration >= 3600) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            output[offset] = (byte)(validityDuration >> 8);
            output[(short)(offset + 1)] = (byte)(validityDuration & 0xff);
            offset += 2;
        }

        if (elements.hasExpiry() || elements.hasBinding()) {
            output[offset] |= (byte) ((elementCount << 4) & 0b1111_0000);
        } else {
            output[offset] |= (byte) ((elementCount << 2) & 0b0011_1100);
        }

        for (byte i = 0; i < elementCount; i++) {
            short formatLength = elements.formatLength(i);
            short valueLength = elements.valueLength(i);
            if (i == 0) {
                if (elements.hasExpiry() || elements.hasBinding()) {
                    if (elements.critical(i)) {
                        output[offset] |= 0b0000_1000;
                        output[offset] |= (byte) ((formatLength - 1));
                    }
                } else {
                    if (elements.critical(i)) {
                        output[offset] |= 0b0000_0010;
                    }
                    output[offset] |= (byte) ((formatLength - 1) >> 2);
                    output[(short) (offset + 1)] = 0b0000_0000;
                    output[(short) (offset + 1)] |= (byte) ((formatLength - 1) << 6);
                    offset += 1;
                }
                Util.arrayCopyNonAtomic(elements.buffer(), elements.formatOffset(i), output, (short)(offset + 1), formatLength);
                offset += (short)(1 + formatLength);
                output[offset] = (byte) valueLength;
                Util.arrayCopyNonAtomic(elements.buffer(), elements.valueOffset(i), output, (short)(offset + 1), valueLength);
                offset += (short)(1 + valueLength);
            } else {
                output[offset] = 0b0000_0000;
                if (elements.critical(i)) {
                    output[offset] |= (byte)0b1000_0000;
                }
                output[offset] |= (byte)((formatLength - 1) << 4);
                Util.arrayCopyNonAtomic(elements.buffer(), elements.formatOffset(i), output, (short)(offset + 1), formatLength);
                offset += (short)(1 + formatLength);
                output[offset] = (byte) valueLength;
                Util.arrayCopyNonAtomic(elements.buffer(), elements.valueOffset(i), output, (short)(offset + 1), valueLength);
                offset += (short)(1 + valueLength);
            }
        }

        output[offset] = 0b0000_0000;
        output[offset] |= (byte)((TRACE_RECORD_ID.length - 1) << 4);
        Util.arrayCopyNonAtomic(TRACE_RECORD_ID, (short)0, output, (short)(offset + 1), (short)(TRACE_RECORD_ID.length));
        offset += (short)(1 + TRACE_RECORD_ID.length);
        output[offset] = (byte)(hsmId.length + signatureCounter.length + 1);
        Util.arrayCopyNonAtomic(hsmId, (short)0, output, (short)(offset + 1), (short)(hsmId.length));
        offset += (short)(1 + hsmId.length);
        output[offset] = slot;
        Util.arrayCopyNonAtomic(signatureCounter, (short)0, output, (short)(offset + 1), (short)(signatureCounter.length));
        offset += (short)(1 + signatureCounter.length);

        return ecknr.sign(slot, output, (short)(offset - ECKNREngine.SCALAR_SIZE));
    }
}