package net.as207960.bt4pt.hsm.applet;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import net.as207960.bt4pt.hsm.applet.jcmathlib.OperationSupport;
import net.as207960.bt4pt.hsm.applet.jcmathlib.ResourceManager;

public final class MainApplet extends Applet {
    public static final byte CLA_II  = (byte)0x00;
    public static final byte CLA_HSM = (byte)0x80;
    public static final byte INS_GET_RESPONSE = (byte)0xC0;
    public static final byte INS_GENERATE_KEY = (byte)0x10;
    public static final byte INS_GET_PUBLIC = (byte)0x11;
    public static final byte INS_CLEAR_KEY = (byte)0x12;
    public static final byte INS_CLEAR_TICKET = (byte)0x20;
    public static final byte INS_ADD_DATA = (byte)0x21;
    public static final byte INS_SET_EXPIRY = (byte)0x22;
    public static final byte INS_SET_DEVICE_BINDING = (byte)0x23;
    public static final byte INS_CREATE_TICKET = (byte)0x24;
    public static final byte INS_GET_HSM_INFO = (byte)0x30;

    public static final short SW_INVALID_SLOT = (short)0x6A88;
    public static final short SW_SLOT_EMPTY = (short)0x6984;
    public static final short SW_SLOT_OCCUPIED = (short)0x6985;
    public static final short SW_TOO_MANY_ELEMENTS = (short)0x6A84;
    public static final short SW_NO_DATA = (short)0x6987;

    private final byte[] hsmId;
    private final byte[] signatureCounter;

    private boolean initialised = false;

    private final ECKNREngine ecknr;

    private ResourceManager math;

    private final DataElements dataElements;
    private final TicketEncoder ticketEncoder;

    public final byte[] outputBuffer;
    public short responseOffset;
    public short responseRemaining;

    public static void install(byte[] buffer, short offset, byte length) {
        new MainApplet();
    }

    public MainApplet() {
        OperationSupport.getInstance().setCard(OperationSupport.JCOP4_P71);
//        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR);
        RandomData selectedRandom;
        try {
            selectedRandom = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        } catch (CryptoException unsupported) {
            selectedRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }

        ecknr = new ECKNREngine(selectedRandom);
        dataElements = new DataElements();
        ticketEncoder = new TicketEncoder(ecknr);
        outputBuffer = JCSystem.makeTransientByteArray((short)1000, JCSystem.CLEAR_ON_DESELECT);

        hsmId = new byte[8];
        signatureCounter = new byte[4];
        selectedRandom.nextBytes(hsmId, (short)0, (short)hsmId.length);

        register();
    }

    public boolean select() {
        return true;
    }

    public void initialise() {
        if (initialised) {
            return;
        }

        math = new ResourceManager((short) 256);
        ecknr.initialise(math);
        initialised = true;
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;


        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (cla == CLA_II) {
            if (ins == INS_GET_RESPONSE) {
                processGetResponse(apdu);
                return;
            }
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        if (cla != CLA_HSM) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        initialise();

        switch (ins) {
            case INS_GENERATE_KEY:
                generateKey(apdu);
                return;

            case INS_GET_PUBLIC:
                getPublic(apdu);
                return;

            case INS_CLEAR_KEY:
                clearKey(apdu);
                return;

            case INS_CLEAR_TICKET:
                clearTicket(apdu);
                return;

            case INS_ADD_DATA:
                addData(apdu);
                return;

            case INS_SET_EXPIRY:
                setExpiry(apdu);
                return;

            case INS_SET_DEVICE_BINDING:
                setDeviceBinding(apdu);
                return;

            case INS_CREATE_TICKET:
                createTicket(apdu);
                return;

            case INS_GET_HSM_INFO:
                getHSMInfo(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        requireP2Zero(buffer);
        requireNoIncomingData(apdu);
        byte slot = buffer[ISO7816.OFFSET_P1];
        ecknr.generateKeyPair(slot);
    }

    private void getPublic(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        requireP2Zero(buffer);
        requireNoIncomingData(apdu);
        byte slot = buffer[ISO7816.OFFSET_P1];
        short length = ecknr.getPublicKey(slot, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, length);
    }

    private void clearKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        requireP2Zero(buffer);
        requireNoIncomingData(apdu);
        byte slot = buffer[ISO7816.OFFSET_P1];
        ecknr.clearSlot(slot);
    }

    private void clearTicket(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        requireP1P2Zero(buffer);
        requireNoIncomingData(apdu);
        dataElements.clear();
    }

    private void addData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        byte criticalByte = buffer[ISO7816.OFFSET_P1];
        short formatLength = (short)(buffer[ISO7816.OFFSET_P2] & 0xff);

        if (criticalByte != 0 && criticalByte != 1) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (formatLength < 1 || formatLength > 8) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short length = receiveAll(apdu, outputBuffer, (short)0);
        if (length < formatLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short valueLength = (short) (length - formatLength);
        dataElements.add(
                criticalByte != 0,
                outputBuffer, (short) 0, formatLength,
                outputBuffer, formatLength, valueLength
        );
    }

    private void setExpiry(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        requireP1P2Zero(buffer);

        short length = receiveAll(apdu, outputBuffer, (short)0);
        if (length != 6) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        dataElements.setExpiry(outputBuffer);
    }

    private void setDeviceBinding(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_P2] != 0)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        byte type = buffer[ISO7816.OFFSET_P1];
        short len = receiveAll(apdu, outputBuffer, (short)0);

        if (len < 2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short duration = (short)(((outputBuffer[0] & 0xff) << 8) | (outputBuffer[1] & 0xff));

        dataElements.setBinding(type, duration, outputBuffer, (short)2, (byte)(len - 2));
    }

    private void createTicket(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        requireP2Zero(buffer);
        requireNoIncomingData(apdu);

        byte slot = buffer[ISO7816.OFFSET_P1];
        if (!ecknr.isOccupied(slot)) {
            ISOException.throwIt(SW_SLOT_EMPTY);
        }

        incrementSignatureCounter();

        short length = ticketEncoder.create(slot, dataElements, outputBuffer, hsmId, signatureCounter);
        dataElements.clear();
        beginResponse(apdu, length);
    }

    private void getHSMInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        requireP1P2Zero(buffer);
        requireNoIncomingData(apdu);
        Util.arrayCopyNonAtomic(hsmId, (short)0, buffer, (short)0, (short)hsmId.length);
        Util.arrayCopyNonAtomic(signatureCounter, (short)0, buffer, (short)hsmId.length, (short)(signatureCounter.length));
        apdu.setOutgoingAndSend((short)0, (short)(hsmId.length + signatureCounter.length));
    }

    private void incrementSignatureCounter() {
        JCSystem.beginTransaction();
        for (short i = (short)(signatureCounter.length - 1); i >= 0; i--) {
            signatureCounter[i]++;
            if (signatureCounter[i] != 0) {
                JCSystem.commitTransaction();
                return;
            }
        }
        JCSystem.abortTransaction();
        ISOException.throwIt(SW_SLOT_OCCUPIED);
    }

    private static short receiveAll(APDU apdu, byte[] destination, short destinationOffset) {
        byte[] apduBuffer = apdu.getBuffer();
        short received = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        short sourceOffset = apdu.getOffsetCdata();
        short copied = 0;

        while (received > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, sourceOffset, destination, (short)(destinationOffset + copied), received);
            copied += received;
            if (copied >= total) {
                break;
            }
            received = apdu.receiveBytes(sourceOffset);
        }

        if (copied != total) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return copied;
    }

    private void beginResponse(APDU apdu, short length) {
        responseOffset = 0;
        responseRemaining = length;
        sendNextChunk(apdu);
    }

    private static void requireP2Zero(byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private static void requireP1P2Zero(byte[] buffer) {
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private static void requireNoIncomingData(APDU apdu) {
        if (apdu.setIncomingAndReceive() != 0) {
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
        apdu.sendBytesLong(outputBuffer, responseOffset, count);

        responseOffset += count;
        responseRemaining -= count;

        if (responseRemaining > 0) {
            short sw2;
            if (responseRemaining >= 256) {
                sw2 = 0;
            } else {
                sw2 = responseRemaining;
            }
            ISOException.throwIt((short)(0x6100 | (sw2 & 0xff)));
        }
    }

    private void processGetResponse(APDU apdu) {
        if (responseRemaining == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        sendNextChunk(apdu);
    }
}
