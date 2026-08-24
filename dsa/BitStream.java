package net.as207960.bt4pt.hsm.applet;

import javacard.framework.Util;

public final class BitStream {
    private final byte[] buffer;

    private short start;
    private short curByte;
    private byte curBit;

    BitStream(byte[] buffer, short offset) {
        this.buffer = buffer;
        reset(offset);
    }

    void reset(short offset) {
        start = offset;
        curByte = offset;
        curBit = 0;
    }

    void clear(short length) {
        Util.arrayFillNonAtomic(buffer, start, length, (byte)0);
    }

    void writeBit(byte value) {
        if (value != 0) {
            buffer[curByte] |= (byte)(0x80 >>> curBit);
        }

        curBit++;

        if (curBit == 8) {
            curBit = 0;
            curByte++;
        }
    }

    void writeBoolean(boolean value) {
        writeBit((byte)(value ? 1 : 0));
    }

    void writeBits(short value, byte count) {
        for (byte i = (byte)(count - 1); i >= 0; i--) {
            writeBit(
                    (byte)((value >>> i) & 1)
            );
        }
    }

    void writeUnsignedByte(byte value) {
        writeBits((short)(value & 0xff), (byte)8);
    }

    void align() {
        if (curBit != 0) {
            curBit = 0;
            curByte++;
        }
    }

    boolean isAligned() {
        return curBit == 0;
    }

    void writeAlignedByte(byte value) {
        align();
        buffer[curByte++] = value;
    }

    void writeAlignedBytes(byte[] source, short offset, short length) {
        align();
        Util.arrayCopyNonAtomic(source, offset, buffer, curByte, length);
        curByte += length;
    }

    short byteLength() {
        return (short)(curByte - start + (curBit == 0 ? 0 : 1));
    }

    short position() {
        return curByte;
    }

    byte bitPosition() {
        return curBit;
    }
}