package net.as207960.bt4pt.hsm.applet;

import javacard.framework.*;
import javacard.security.MessageDigest;

final class TLBSigner {
    private static final byte[] UIC_V2_MAGIC = {'#', 'U', 'T', '0', '2'};

    private static final byte[] SECURITY_PROVIDER_ORG_ID = {'5', '1', '0', '1'};
    private static final byte[] SECURITY_PROVIDER_KEY_ID = {'T', 'T', '9', '9', '9'};

    private static final byte[] EXTRA_DATA_RECORD = {'5', '1', '0', '1', 'H', 'S', '0', '1', '0', '0', '1', '6', 'T', 'E', 'S', 'T'};

    private static final short[] DEFLATE_LENGTH_EXTRA_BITS = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    private static final short[] DEFLATE_LENGTH_BASE = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    private static final short[] DEFLATE_DISTANCE_EXTRA_BITS = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    private static final short[] DEFLATE_DISTANCE_BASE = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16583, 24577};

    private static final short ADLER32_BASE = (short)65521;

    private final MainApplet main;
    private final BitStream ticketOutputBitStream;

    TLBSigner(MainApplet main) {
        this.main = main;
        ticketOutputBitStream = new BitStream(main.outputBuffer, (short)0);
    }

//    private void signTicketTLB(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        short received = apdu.setIncomingAndReceive();
//
//        if (received <= 6) {
//            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//        }
//        if (received == 9999) {
//            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//        }
//        short off = apdu.getOffsetCdata();
//        if ((buffer[off] & 0b000_1111) != 8) {
//            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//        }
//        if (((((buffer[off] & 0xff) * 256) + (buffer[(short)(off+1)] & 0xff)) % 31) != 0) {
//            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//        }
//        boolean dictionary_present = (buffer[(short)(off+1)] & 0b0010_0000) != 0;
//        if (dictionary_present) {
//            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
//        }
//
//        int adler = ((buffer[(short)(off + (received - 4))] & 0xff) << 24) |
//                ((buffer[(short)(off + (received - 3))] & 0xff) << 16) |
//                ((buffer[(short)(off + (received - 2))] & 0xff) << 8) |
//                (buffer[(short)(off + (received - 1))] & 0xff);
//
//        Util.arrayCopyNonAtomic(buffer, off, main.outputBuffer, (short)82, (short)(received - 4));
//
//        Util.arrayCopyNonAtomic(UIC_V2_MAGIC, (short)0, main.outputBuffer, (short)0, (short)5);
//        Util.arrayCopyNonAtomic(SECURITY_PROVIDER_ORG_ID, (short)0, main.outputBuffer, (short)5, (short)4);
//        Util.arrayCopyNonAtomic(SECURITY_PROVIDER_KEY_ID, (short)0, main.outputBuffer, (short)9, (short)5);
//
//        ticketOutputBitStream.reset((short)84);
//
//        boolean blockFinal = false;
//        short lastBlockByteOffset = 0;
//        byte lastBlockBitOffset = 0;
//        while (!blockFinal) {
//            lastBlockByteOffset = ticketOutputBitStream.position();
//            lastBlockBitOffset = ticketOutputBitStream.bitPosition();
//
//            blockFinal = ticketOutputBitStream.readBit() != 0;
//            short blockType = ticketOutputBitStream.readBits((short)2);
//
//            switch (blockType) {
//                case 0:
//                case 1:
//                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
//                    break;
//                case 2:
//                    for (;;) {
//                        short codeValue = ticketOutputBitStream.readBits((short)7);
//                        short literalValue;
//                        if (codeValue <= 0b0010111) {
//                            literalValue = (short) (codeValue + 256);
//                        } else if (codeValue <= 0b1011111) {
//                            codeValue <<= 1;
//                            codeValue |= ticketOutputBitStream.readBit();
//                            literalValue = (short) (codeValue - 0b00110000);
//                        } else if (codeValue <= 0b1100011) {
//                            codeValue <<= 1;
//                            codeValue |= ticketOutputBitStream.readBit();
//                            literalValue = (short) (codeValue + 88);
//                        } else {
//                            codeValue <<= 2;
//                            codeValue |= ticketOutputBitStream.readBits((short)2);
//                            literalValue = (short) (codeValue - 256);
//                        }
//
//                        if (literalValue <= 255) {
//
//                        } else if (literalValue == 256) {
//                            break;
//                        } else {
//                            short lengthCode = (short)(literalValue - 257);
//                            short extraBits = DEFLATE_LENGTH_EXTRA_BITS[lengthCode];
//                            short length = DEFLATE_LENGTH_BASE[lengthCode];
//                            if (extraBits != 0) {
//                                length += ticketOutputBitStream.readBits(extraBits);
//                            }
//
//                            short distanceCode = ticketOutputBitStream.readBits((short)5);
//                            extraBits = DEFLATE_DISTANCE_EXTRA_BITS[distanceCode];
//                            short distance = DEFLATE_DISTANCE_BASE[distanceCode];
//                            if (extraBits != 0) {
//                                distance += ticketOutputBitStream.readBits(extraBits);
//                            }
//                        }
//                    }
//                    break;
//                case 3:
//                default:
//                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//            }
//        }
//
//        ticketOutputBitStream.clearBitAtByte(lastBlockByteOffset, lastBlockBitOffset);
//        ticketOutputBitStream.addBit((byte)1);
//        ticketOutputBitStream.addBit((byte)0);
//        ticketOutputBitStream.addBit((byte)0);
//
//        short newEnd = ticketOutputBitStream.cur_byte;
//        main.outputBuffer[(short)(newEnd + 1)] = (byte)(EXTRA_DATA_RECORD.length & 0xFF);
//        main.outputBuffer[(short)(newEnd + 2)] = (byte)((EXTRA_DATA_RECORD.length >> 8) & 0xFF);
//        main.outputBuffer[(short)(newEnd + 3)] = (byte)((~(EXTRA_DATA_RECORD.length & 0xFF)) & 0xFF);
//        main.outputBuffer[(short)(newEnd + 4)] = (byte)(~((EXTRA_DATA_RECORD.length >> 8) & 0xFF) & 0xFF);
//        Util.arrayCopyNonAtomic(EXTRA_DATA_RECORD, (short)0, main.outputBuffer, (short)(newEnd + 5), (short)EXTRA_DATA_RECORD.length);
//        newEnd += 5;
//        newEnd += (short)EXTRA_DATA_RECORD.length;
//
//        adler = updateAdler32(adler, EXTRA_DATA_RECORD, (short)EXTRA_DATA_RECORD.length);
//
//        main.outputBuffer[newEnd] = (byte)((adler >> 24) & 0xff);
//        main.outputBuffer[(short)(newEnd + 1)] = (byte)((adler >> 16) & 0xff);
//        main.outputBuffer[(short)(newEnd + 2)] = (byte)((adler >> 8) & 0xff);
//        main.outputBuffer[(short)(newEnd + 3)] = (byte)(adler & 0xff);
//
//        MessageDigest.OneShot dig = null;
//        try {
//            dig = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
//            dig.doFinal(main.outputBuffer, (short)84, (short)(newEnd - 78), main.outputBuffer, (short)14);
//        } finally {
//            if (dig != null) {
//                dig.close();
//            }
//        }
////        main.dsa.signDigest(main.outputBuffer, (short)14, (short)14);
//
//        encodeASCIInteger(main.outputBuffer, (short)78, (short)4, (short) (newEnd - 78));
//
//        short finalLength = (short)(newEnd + 4);
//        main.responseOffset = 0;
//        main.responseRemaining = finalLength;
//        main.sendNextChunk(apdu);
//    }

    private static void encodeASCIInteger(byte[] output, short offset, short len, short value) {
        short pos = (short)(offset + len);
        while (value != 0) {
            pos--;
            output[pos] = (byte)(0x30 + (value % 10));
            value /= 10;
        }
        while (pos > offset) {
            pos--;
            output[pos] = 0x30;
        }
    }

    private static int updateAdler32(int adler, byte[] data, short len) {
        int s2 = (adler >> 16) & 0xffff;
        adler &= 0xffff;

        for (short i = 0; i < len; i++) {
            adler += data[i];
            if (adler >= (ADLER32_BASE & 0xffff)) {
                adler -= (ADLER32_BASE & 0xffff);
            }
            s2 = s2 + adler;
            if (s2 >= (ADLER32_BASE & 0xffff)) {
                s2 -= (ADLER32_BASE & 0xffff);
            }
        }

        return adler | (s2 << 16);
    }
}
