package net.as207960.bt4pt.hsm.applet;

public class BitStream {
    byte[] buffer;
    short cur_byte;
    byte cur_bit;

    BitStream(byte[] buffer, short offset) {
        this.buffer = buffer;
        this.cur_byte = offset;
        this.cur_bit = 0;
    }

    public void reset(short offset) {
        this.cur_byte = offset;
        this.cur_bit = 0;
    }

    private static byte reverse(byte b) {
        b = (byte) ((b & 0xF0) >> 4 | (b & 0x0F) << 4);
        b = (byte) ((b & 0xCC) >> 2 | (b & 0x33) << 2);
        b = (byte) ((b & 0xAA) >> 1 | (b & 0x55) << 1);
        return b;
    }

    public byte readBit() {
        byte b = (byte) ((reverse(buffer[cur_byte]) >> (7 - cur_bit)) & 1);
        cur_bit += 1;
        if (cur_bit >= 8) {
            cur_bit = 0;
            cur_byte += 1;
        }
        return b;
    }

    public short readBits(short count) {
        short val = 0;
        while (count > 0) {
            short next_byte_bits = min((short) (8 - cur_bit), count);
            byte b = (byte) ((reverse(buffer[cur_byte]) >> (8 - cur_bit - next_byte_bits)) & ((1 << next_byte_bits) - 1));
            cur_bit += (byte)next_byte_bits;
            if (cur_bit >= 8) {
                cur_bit = 0;
                cur_byte += 1;
            }
            val <<= next_byte_bits;
            val |= b;
            count -= next_byte_bits;
        }
        return val;
    }

    public void clearBitAtByte(short offset, byte bit) {
        buffer[offset] &= (byte)(~(1 << bit));
    }

    public void addBit(byte val) {
        if (val != 0) {
            buffer[cur_byte] |= (byte) (1 << cur_bit);
        }
        cur_bit += 1;
        if (cur_bit >= 8) {
            cur_bit = 0;
            cur_byte += 1;
        }
    }

    private short min(short a, short b) {
        if (a < b) {
            return a;
        } else {
            return b;
        }
    }
}
