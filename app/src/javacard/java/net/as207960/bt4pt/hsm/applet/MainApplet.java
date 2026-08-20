package net.as207960.bt4pt.hsm.applet;

import javacard.framework.*;
import javacard.security.MessageDigest;

/** APDU front-end for the software DSA implementation. */
public final class MainApplet extends Applet {
    public static final byte CLA_II = (byte) 0x00;
    public static final byte CLA_HSM = (byte) 0x80;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_GENERATE_DSA = (byte) 0x10;
    public static final byte INS_GET_PUBLIC = (byte) 0x11;
    public static final byte INS_SIGN_DIGEST = (byte) 0x20;
    public static final byte INS_SIGN_TICKET = (byte) 0x30;

    public static final byte COMPONENT_P = (byte) 0x01;
    public static final byte COMPONENT_Q = (byte) 0x02;
    public static final byte COMPONENT_G = (byte) 0x03;
    public static final byte COMPONENT_Y = (byte) 0x04;

    private final DsaEngine dsa;

    private final byte[] ticketOutput;
    private short responseOffset;
    private short responseRemaining;
    private final BitStream ticketOutputBitStream;

    private static final byte[] UIC_V2_MAGIC = {'#', 'U', 'T', '0', '2'};

    private static final byte[] SECURITY_PROVIDER_ORG_ID = {'5', '1', '0', '1'};
    private static final byte[] SECURITY_PROVIDER_KEY_ID = {'T', 'T', '9', '9', '9'};

    private static final byte[] EXTRA_DATA_RECORD = {'5', '1', '0', '1', 'H', 'S', '0', '1', '0', '0', '1', '6', 'T', 'E', 'S', 'T'};

    private static final short[] DEFLATE_LENGTH_EXTRA_BITS = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    private static final short[] DEFLATE_LENGTH_BASE = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    private static final short[] DEFLATE_DISTANCE_EXTRA_BITS = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    private static final short[] DEFLATE_DISTANCE_BASE = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16583, 24577};

    private static final short ADLER32_BASE = (short)65521;

    public static void install(byte[] buffer, short offset, byte length) {
        new MainApplet();
    }

    public MainApplet() {
        dsa = new DsaEngine();
        ticketOutput = JCSystem.makeTransientByteArray((short)1000, JCSystem.CLEAR_ON_DESELECT);
        ticketOutputBitStream = new BitStream(ticketOutput, (short)0);
        register();
    }

    public boolean select() {
        return true;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();

        switch (buffer[ISO7816.OFFSET_CLA]) {
            case CLA_II:
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INS_GET_RESPONSE:
                        processGetResponse(apdu);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            case CLA_HSM:
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INS_GENERATE_DSA:
                        requireP2Zero(buffer);
                        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00) {
                            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                        }
                        requireNoIncomingData(apdu);
                        dsa.generateKeyPair();
                        return;
                    case INS_GET_PUBLIC:
                        requireP2Zero(buffer);
                        requireNoIncomingData(apdu);
                        dsa.sendPublicComponent(apdu, buffer[ISO7816.OFFSET_P1]);
                        return;
                    case INS_SIGN_DIGEST:
                        requireP2Zero(buffer);
                        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00) {
                            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                        }
                        dsa.signDigestAPDU(apdu);
                        return;
                    case INS_SIGN_TICKET:
                        requireP2Zero(buffer);
                        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00) {
                            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                        }
                        signTicket(apdu);
                        return;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            default:
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    private static void requireP2Zero(byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private static void requireNoIncomingData(APDU apdu) {
        if (apdu.setIncomingAndReceive() != (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    private void sendNextChunk(APDU apdu) {
        short le = apdu.setOutgoing();
        short count = responseRemaining;

        if (count > le) {
            count = le;
        }
        if (count > 256) {
            count = 256;
        }

        apdu.setOutgoingLength(count);
        apdu.sendBytesLong(ticketOutput, responseOffset, count);

        responseOffset += count;
        responseRemaining -= count;

        if (responseRemaining > 0) {
            short sw2;
            if (responseRemaining >= 256) {
                sw2 = 0;
            } else {
                sw2 = responseRemaining;
            }
            ISOException.throwIt((short) (0x6100 | (sw2 & 0x00FF)));
        }
    }

    private void processGetResponse(APDU apdu) {
        if (responseRemaining == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        sendNextChunk(apdu);
    }

    private void signTicket(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short received = apdu.setIncomingAndReceive();

        if (received <= 6) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (received == 9999) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short off = apdu.getOffsetCdata();
        if ((buffer[off] & 0b000_1111) != 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (((((buffer[off] & 0xff) * 256) + (buffer[(short)(off+1)] & 0xff)) % 31) != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        boolean dictionary_present = (buffer[(short)(off+1)] & 0b0010_0000) != 0;
        if (dictionary_present) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        int adler = ((buffer[(short)(off + (received - 4))] & 0xff) << 24) |
                ((buffer[(short)(off + (received - 3))] & 0xff) << 16) |
                ((buffer[(short)(off + (received - 2))] & 0xff) << 8) |
                (buffer[(short)(off + (received - 1))] & 0xff);

        Util.arrayCopyNonAtomic(buffer, off, ticketOutput, (short)82, (short)(received - 4));

        Util.arrayCopyNonAtomic(UIC_V2_MAGIC, (short)0, ticketOutput, (short)0, (short)5);
        Util.arrayCopyNonAtomic(SECURITY_PROVIDER_ORG_ID, (short)0, ticketOutput, (short)5, (short)4);
        Util.arrayCopyNonAtomic(SECURITY_PROVIDER_KEY_ID, (short)0, ticketOutput, (short)9, (short)5);

        ticketOutputBitStream.reset((short)84);

        boolean blockFinal = false;
        short lastBlockByteOffset = 0;
        byte lastBlockBitOffset = 0;
        while (!blockFinal) {
            lastBlockByteOffset = ticketOutputBitStream.cur_byte;
            lastBlockBitOffset = ticketOutputBitStream.cur_bit;

            blockFinal = ticketOutputBitStream.readBit() != 0;
            short blockType = ticketOutputBitStream.readBits((short)2);

            switch (blockType) {
                case 0:
                case 1:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                    break;
                case 2:
                    for (;;) {
                        short codeValue = ticketOutputBitStream.readBits((short)7);
                        short literalValue;
                        if (codeValue <= 0b0010111) {
                            literalValue = (short) (codeValue + 256);
                        } else if (codeValue <= 0b1011111) {
                            codeValue <<= 1;
                            codeValue |= ticketOutputBitStream.readBit();
                            literalValue = (short) (codeValue - 0b00110000);
                        } else if (codeValue <= 0b1100011) {
                            codeValue <<= 1;
                            codeValue |= ticketOutputBitStream.readBit();
                            literalValue = (short) (codeValue + 88);
                        } else {
                            codeValue <<= 2;
                            codeValue |= ticketOutputBitStream.readBits((short)2);
                            literalValue = (short) (codeValue - 256);
                        }

                        if (literalValue <= 255) {

                        } else if (literalValue == 256) {
                            break;
                        } else {
                            short lengthCode = (short)(literalValue - 257);
                            short extraBits = DEFLATE_LENGTH_EXTRA_BITS[lengthCode];
                            short length = DEFLATE_LENGTH_BASE[lengthCode];
                            if (extraBits != 0) {
                                length += ticketOutputBitStream.readBits(extraBits);
                            }

                            short distanceCode = ticketOutputBitStream.readBits((short)5);
                            extraBits = DEFLATE_DISTANCE_EXTRA_BITS[distanceCode];
                            short distance = DEFLATE_DISTANCE_BASE[distanceCode];
                            if (extraBits != 0) {
                                distance += ticketOutputBitStream.readBits(extraBits);
                            }
                        }
                    }
                    break;
                case 3:
                default:
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }

        ticketOutputBitStream.clearBitAtByte(lastBlockByteOffset, lastBlockBitOffset);
        ticketOutputBitStream.addBit((byte)1);
        ticketOutputBitStream.addBit((byte)0);
        ticketOutputBitStream.addBit((byte)0);

        short newEnd = ticketOutputBitStream.cur_byte;
        ticketOutput[(short)(newEnd + 1)] = (byte)(EXTRA_DATA_RECORD.length & 0xFF);
        ticketOutput[(short)(newEnd + 2)] = (byte)((EXTRA_DATA_RECORD.length >> 8) & 0xFF);
        ticketOutput[(short)(newEnd + 3)] = (byte)((~(EXTRA_DATA_RECORD.length & 0xFF)) & 0xFF);
        ticketOutput[(short)(newEnd + 4)] = (byte)(~((EXTRA_DATA_RECORD.length >> 8) & 0xFF) & 0xFF);
        Util.arrayCopyNonAtomic(EXTRA_DATA_RECORD, (short)0, ticketOutput, (short)(newEnd + 5), (short)EXTRA_DATA_RECORD.length);
        newEnd += 5;
        newEnd += (short)EXTRA_DATA_RECORD.length;

        adler = updateAdler32(adler, EXTRA_DATA_RECORD, (short)EXTRA_DATA_RECORD.length);

        ticketOutput[newEnd] = (byte)((adler >> 24) & 0xff);
        ticketOutput[(short)(newEnd + 1)] = (byte)((adler >> 16) & 0xff);
        ticketOutput[(short)(newEnd + 2)] = (byte)((adler >> 8) & 0xff);
        ticketOutput[(short)(newEnd + 3)] = (byte)(adler & 0xff);

        MessageDigest.OneShot dig = null;
        try {
            dig = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
            dig.doFinal(ticketOutput, (short)84, (short)(newEnd - 78), ticketOutput, (short)14);
        } finally {
            if (dig != null) {
                dig.close();
            }
        }
        dsa.signDigest(ticketOutput, (short)14, (short)14);

        encodeASCIInteger(ticketOutput, (short)78, (short)4, (short) (newEnd - 78));

        short finalLength = (short)(newEnd + 4);
        responseOffset = 0;
        responseRemaining = finalLength;

        sendNextChunk(apdu);
    }

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
