package net.as207960.bt4pt.hsm.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import net.as207960.bt4pt.hsm.applet.jcmathlib.BigNat;
import net.as207960.bt4pt.hsm.applet.jcmathlib.ResourceManager;

final class DsaEngine {
    private static final short P_LENGTH = (short) 256;
    private static final short Q_LENGTH = (short) 32;
    private static final short SIGNATURE_LENGTH = (short) 64;
    private static final byte NO_ACTIVE_KEY = (byte) 0x7f;
    private static final byte MAX_SIGN_ATTEMPTS = (byte) 8;

    private static final byte COMPONENT_P = (byte) 0x01;
    private static final byte COMPONENT_Q = (byte) 0x02;
    private static final byte COMPONENT_G = (byte) 0x03;
    private static final byte COMPONENT_Y = (byte) 0x04;

    private static final byte[] P = {
        (byte)0x95,(byte)0x47,(byte)0x5c,(byte)0xf5,(byte)0xd9,(byte)0x3e,(byte)0x59,(byte)0x6c,(byte)0x3f,(byte)0xcd,(byte)0x1d,(byte)0x90,(byte)0x2a,(byte)0xdd,(byte)0x02,(byte)0xf4,
        (byte)0x27,(byte)0xf5,(byte)0xf3,(byte)0xc7,(byte)0x21,(byte)0x03,(byte)0x13,(byte)0xbb,(byte)0x45,(byte)0xfb,(byte)0x4d,(byte)0x5b,(byte)0xb2,(byte)0xe5,(byte)0xfe,(byte)0x1c,
        (byte)0xbd,(byte)0x67,(byte)0x8c,(byte)0xd4,(byte)0xbb,(byte)0xdd,(byte)0x84,(byte)0xc9,(byte)0x83,(byte)0x6b,(byte)0xe1,(byte)0xf3,(byte)0x1c,(byte)0x07,(byte)0x77,(byte)0x72,
        (byte)0x5a,(byte)0xeb,(byte)0x6c,(byte)0x2f,(byte)0xc3,(byte)0x8b,(byte)0x85,(byte)0xf4,(byte)0x80,(byte)0x76,(byte)0xfa,(byte)0x76,(byte)0xbc,(byte)0xd8,(byte)0x14,(byte)0x6c,
        (byte)0xc8,(byte)0x9a,(byte)0x6f,(byte)0xb2,(byte)0xf7,(byte)0x06,(byte)0xdd,(byte)0x71,(byte)0x98,(byte)0x98,(byte)0xc2,(byte)0x08,(byte)0x3d,(byte)0xc8,(byte)0xd8,(byte)0x96,
        (byte)0xf8,(byte)0x40,(byte)0x62,(byte)0xe2,(byte)0xc9,(byte)0xc9,(byte)0x4d,(byte)0x13,(byte)0x7b,(byte)0x05,(byte)0x4a,(byte)0x8d,(byte)0x80,(byte)0x96,(byte)0xad,(byte)0xb8,
        (byte)0xd5,(byte)0x19,(byte)0x52,(byte)0x39,(byte)0x8e,(byte)0xec,(byte)0xa8,(byte)0x52,(byte)0xa0,(byte)0xaf,(byte)0x12,(byte)0xdf,(byte)0x83,(byte)0xe4,(byte)0x75,(byte)0xaa,
        (byte)0x65,(byte)0xd4,(byte)0xec,(byte)0x0c,(byte)0x38,(byte)0xa9,(byte)0x56,(byte)0x0d,(byte)0x56,(byte)0x61,(byte)0x18,(byte)0x6f,(byte)0xf9,(byte)0x8b,(byte)0x9f,(byte)0xc9,
        (byte)0xeb,(byte)0x60,(byte)0xee,(byte)0xe8,(byte)0xb0,(byte)0x30,(byte)0x37,(byte)0x6b,(byte)0x23,(byte)0x6b,(byte)0xc7,(byte)0x3b,(byte)0xe3,(byte)0xac,(byte)0xdb,(byte)0xd7,
        (byte)0x4f,(byte)0xd6,(byte)0x1c,(byte)0x1d,(byte)0x24,(byte)0x75,(byte)0xfa,(byte)0x30,(byte)0x77,(byte)0xb8,(byte)0xf0,(byte)0x80,(byte)0x46,(byte)0x78,(byte)0x81,(byte)0xff,
        (byte)0x7e,(byte)0x1c,(byte)0xa5,(byte)0x6f,(byte)0xee,(byte)0x06,(byte)0x6d,(byte)0x79,(byte)0x50,(byte)0x6a,(byte)0xde,(byte)0x51,(byte)0xed,(byte)0xbb,(byte)0x54,(byte)0x43,
        (byte)0xa5,(byte)0x63,(byte)0x92,(byte)0x7d,(byte)0xbc,(byte)0x4b,(byte)0xa5,(byte)0x20,(byte)0x08,(byte)0x67,(byte)0x46,(byte)0x17,(byte)0x5c,(byte)0x88,(byte)0x85,(byte)0x92,
        (byte)0x5e,(byte)0xbc,(byte)0x64,(byte)0xc6,(byte)0x14,(byte)0x79,(byte)0x06,(byte)0x77,(byte)0x34,(byte)0x96,(byte)0x99,(byte)0x0c,(byte)0xb7,(byte)0x14,(byte)0xec,(byte)0x66,
        (byte)0x73,(byte)0x04,(byte)0xe2,(byte)0x61,(byte)0xfa,(byte)0xee,(byte)0x33,(byte)0xb3,(byte)0xcb,(byte)0xdf,(byte)0x00,(byte)0x8e,(byte)0x0c,(byte)0x3f,(byte)0xa9,(byte)0x06,
        (byte)0x50,(byte)0xd9,(byte)0x7d,(byte)0x39,(byte)0x09,(byte)0xc9,(byte)0x27,(byte)0x5b,(byte)0xf4,(byte)0xac,(byte)0x86,(byte)0xff,(byte)0xcb,(byte)0x3d,(byte)0x03,(byte)0xe6,
        (byte)0xdf,(byte)0xc8,(byte)0xad,(byte)0xa5,(byte)0x93,(byte)0x42,(byte)0x42,(byte)0xdd,(byte)0x6d,(byte)0x3b,(byte)0xcc,(byte)0xa2,(byte)0xa4,(byte)0x06,(byte)0xcb,(byte)0x0b
    };

    private static final byte[] Q = {
        (byte)0xf8,(byte)0x18,(byte)0x36,(byte)0x68,(byte)0xba,(byte)0x5f,(byte)0xc5,(byte)0xbb,
        (byte)0x06,(byte)0xb5,(byte)0x98,(byte)0x1e,(byte)0x6d,(byte)0x8b,(byte)0x79,(byte)0x5d,
        (byte)0x30,(byte)0xb8,(byte)0x97,(byte)0x8d,(byte)0x43,(byte)0xca,(byte)0x0e,(byte)0xc5,
        (byte)0x72,(byte)0xe3,(byte)0x7e,(byte)0x09,(byte)0x93,(byte)0x9a,(byte)0x97,(byte)0x73
    };

    private static final byte[] G = {
        (byte)0x42,(byte)0xde,(byte)0xbb,(byte)0x9d,(byte)0xa5,(byte)0xb3,(byte)0xd8,(byte)0x8c,(byte)0xc9,(byte)0x56,(byte)0xe0,(byte)0x87,(byte)0x87,(byte)0xec,(byte)0x3f,(byte)0x3a,
        (byte)0x09,(byte)0xbb,(byte)0xa5,(byte)0xf4,(byte)0x8b,(byte)0x88,(byte)0x9a,(byte)0x74,(byte)0xaa,(byte)0xf5,(byte)0x31,(byte)0x74,(byte)0xaa,(byte)0x0f,(byte)0xbe,(byte)0x7e,
        (byte)0x3c,(byte)0x5b,(byte)0x8f,(byte)0xcd,(byte)0x7a,(byte)0x53,(byte)0xbe,(byte)0xf5,(byte)0x63,(byte)0xb0,(byte)0xe9,(byte)0x85,(byte)0x60,(byte)0x32,(byte)0x89,(byte)0x60,
        (byte)0xa9,(byte)0x51,(byte)0x7f,(byte)0x40,(byte)0x14,(byte)0xd3,(byte)0x32,(byte)0x5f,(byte)0xc7,(byte)0x96,(byte)0x2b,(byte)0xf1,(byte)0xe0,(byte)0x49,(byte)0x37,(byte)0x0d,
        (byte)0x76,(byte)0xd1,(byte)0x31,(byte)0x4a,(byte)0x76,(byte)0x13,(byte)0x7e,(byte)0x79,(byte)0x2f,(byte)0x3f,(byte)0x0d,(byte)0xb8,(byte)0x59,(byte)0xd0,(byte)0x95,(byte)0xe4,
        (byte)0xa5,(byte)0xb9,(byte)0x32,(byte)0x02,(byte)0x4f,(byte)0x07,(byte)0x9e,(byte)0xcf,(byte)0x2e,(byte)0xf0,(byte)0x9c,(byte)0x79,(byte)0x74,(byte)0x52,(byte)0xb0,(byte)0x77,
        (byte)0x0e,(byte)0x13,(byte)0x50,(byte)0x78,(byte)0x2e,(byte)0xd5,(byte)0x7d,(byte)0xdf,(byte)0x79,(byte)0x49,(byte)0x79,(byte)0xdc,(byte)0xef,(byte)0x23,(byte)0xcb,(byte)0x96,
        (byte)0xf1,(byte)0x83,(byte)0x06,(byte)0x19,(byte)0x65,(byte)0xc4,(byte)0xeb,(byte)0xc9,(byte)0x3c,(byte)0x9c,(byte)0x71,(byte)0xc5,(byte)0x6b,(byte)0x92,(byte)0x59,(byte)0x55,
        (byte)0xa7,(byte)0x5f,(byte)0x94,(byte)0xcc,(byte)0xcf,(byte)0x14,(byte)0x49,(byte)0xac,(byte)0x43,(byte)0xd5,(byte)0x86,(byte)0xd0,(byte)0xbe,(byte)0xee,(byte)0x43,(byte)0x25,
        (byte)0x1b,(byte)0x0b,(byte)0x22,(byte)0x87,(byte)0x34,(byte)0x9d,(byte)0x68,(byte)0xde,(byte)0x0d,(byte)0x14,(byte)0x44,(byte)0x03,(byte)0xf1,(byte)0x3e,(byte)0x80,(byte)0x2f,
        (byte)0x41,(byte)0x46,(byte)0xd8,(byte)0x82,(byte)0xe0,(byte)0x57,(byte)0xaf,(byte)0x19,(byte)0xb6,(byte)0xf6,(byte)0x27,(byte)0x5c,(byte)0x66,(byte)0x76,(byte)0xc8,(byte)0xfa,
        (byte)0x0e,(byte)0x3c,(byte)0xa2,(byte)0x71,(byte)0x3a,(byte)0x32,(byte)0x57,(byte)0xfd,(byte)0x1b,(byte)0x27,(byte)0xd0,(byte)0x63,(byte)0x9f,(byte)0x69,(byte)0x5e,(byte)0x34,
        (byte)0x7d,(byte)0x8d,(byte)0x1c,(byte)0xf9,(byte)0xac,(byte)0x81,(byte)0x9a,(byte)0x26,(byte)0xca,(byte)0x9b,(byte)0x04,(byte)0xcb,(byte)0x0e,(byte)0xb9,(byte)0xb7,(byte)0xb0,
        (byte)0x35,(byte)0x98,(byte)0x8d,(byte)0x15,(byte)0xbb,(byte)0xac,(byte)0x65,(byte)0x21,(byte)0x2a,(byte)0x55,(byte)0x23,(byte)0x9c,(byte)0xfc,(byte)0x7e,(byte)0x58,(byte)0xfa,
        (byte)0xe3,(byte)0x8d,(byte)0x72,(byte)0x50,(byte)0xab,(byte)0x99,(byte)0x91,(byte)0xff,(byte)0xbc,(byte)0x97,(byte)0x13,(byte)0x40,(byte)0x25,(byte)0xfe,(byte)0x8c,(byte)0xe0,
        (byte)0x4c,(byte)0x43,(byte)0x99,(byte)0xad,(byte)0x96,(byte)0x56,(byte)0x9b,(byte)0xe9,(byte)0x1a,(byte)0x54,(byte)0x6f,(byte)0x49,(byte)0x78,(byte)0x69,(byte)0x3c,(byte)0x7a
    };

    private final byte[] privateX0 = new byte[Q_LENGTH];
    private final byte[] privateX1 = new byte[Q_LENGTH];
    private final byte[] publicY0 = new byte[P_LENGTH];
    private final byte[] publicY1 = new byte[P_LENGTH];
    private byte activeSlot = NO_ACTIVE_KEY;

    private final RandomData random;
    private final RSAPrivateKey modExpKey;
    private final Cipher modExpCipher;
    private final byte[] rsaOutput;
    private final byte[] a;
    private BigNat qNat, natA, natB, natC, natD;

    boolean initialised = false;

    DsaEngine(RandomData random) {
        this.random = random;
        modExpKey = (RSAPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
        modExpCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        rsaOutput = transientBytes(P_LENGTH);
        a = transientBytes(Q_LENGTH);
    }

    public void initialise(ResourceManager math) {
        if (initialised) {
            return;
        }

        qNat = new BigNat(Q_LENGTH, JCSystem.MEMORY_TYPE_PERSISTENT, math);
        qNat.fromByteArray(Q, (short)0, Q_LENGTH);

        natA = new BigNat(P_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, math);
        natB = new BigNat(Q_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, math);
        natC = new BigNat(Q_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, math);
        natD = new BigNat(Q_LENGTH, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, math);

        initialised = true;
    }

    void generateKeyPair() {
        try {
            sampleScalar(a);
            modExp(a, rsaOutput);
        } catch (CryptoException failure) {
            wipeWorkspaces();
            throw failure;
        }
        byte newSlot = activeSlot == (byte)0 ? (byte)1 : (byte)0;
        byte[] newX = newSlot == (byte)0 ? privateX0 : privateX1;
        byte[] newY = newSlot == (byte)0 ? publicY0 : publicY1;
        Util.arrayCopyNonAtomic(a, (short)0, newX, (short)0, Q_LENGTH);
        Util.arrayCopyNonAtomic(rsaOutput, (short)0, newY, (short)0, P_LENGTH);
        JCSystem.beginTransaction();
        activeSlot = newSlot;
        JCSystem.commitTransaction();
        wipeWorkspaces();
    }

    void sendPublicComponent(APDU apdu, byte component) {
        byte[] value;
        short length;
        switch (component) {
            case COMPONENT_P: value = P; length = P_LENGTH; break;
            case COMPONENT_Q: value = Q; length = Q_LENGTH; break;
            case COMPONENT_G: value = G; length = P_LENGTH; break;
            case COMPONENT_Y:
                requireKey(); value = activePublicY(); length = P_LENGTH; break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); return;
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(value, (short)0, length);
    }

    void signDigestAPDU(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short received = apdu.setIncomingAndReceive();
        if (received != Q_LENGTH || apdu.getIncomingLength() != Q_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        signDigest(buffer, apdu.getOffsetCdata(), (short)0);
        apdu.setOutgoingAndSend((short)0, SIGNATURE_LENGTH);
    }

    void signDigest(byte[]buffer, short offset, short outputOffset) {
        requireKey();
        try {
            natC.fromByteArray(buffer, offset, Q_LENGTH);
            natC.mod(qNat);
            byte attempt = (byte)0;
            do {
                if (attempt++ == MAX_SIGN_ATTEMPTS) {
                    wipeWorkspaces();
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                sampleScalar(a);
                modExp(a, rsaOutput);
                natA.resize(P_LENGTH);
                natA.fromByteArray(rsaOutput, (short)0, P_LENGTH);
                natA.mod(qNat);
                natA.resize(Q_LENGTH);
            } while (natA.isZero());

            natB.fromByteArray(activePrivateX(), (short)0, Q_LENGTH);
            natB.modMult(natA, qNat);
            natB.add(natC);

            natD.fromByteArray(a, (short)0, Q_LENGTH);
            natD.modInv(qNat);
            natD.modMult(natB, qNat);
        } catch (CryptoException failure) {
            wipeWorkspaces();
            ISOException.throwIt((short)(0x6f00 | (failure.getReason() & 0xff)));
        }
        if (natD.isZero()) {
            wipeWorkspaces();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        natA.prependZeros(Q_LENGTH, buffer, outputOffset);
        natD.prependZeros(Q_LENGTH, buffer, (short)(outputOffset + Q_LENGTH));
        wipeWorkspaces();
    }

    private void modExp(byte[] exponent, byte[] output) {
        try {
            modExpKey.setModulus(P, (short)0, P_LENGTH);
            modExpKey.setExponent(exponent, (short)0, Q_LENGTH);
            modExpCipher.init(modExpKey, Cipher.MODE_DECRYPT);
            short written = modExpCipher.doFinal(DsaEngine.G, (short)0, P_LENGTH,
                output, (short)0);
            modExpKey.clearKey();
            if (written != P_LENGTH) CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (CryptoException failure) {
            modExpKey.clearKey();
            throw failure;
        }
    }

    private void sampleScalar(byte[] output) {
        do {
            random.nextBytes(output, (short)0, Q_LENGTH);
        } while (isZero(output) || compare(output, Q) >= (short)0);
    }

    private static short compare(byte[] left, byte[] right) {
        short i = (short)0;
        for (; i < Q_LENGTH; i++) {
            short l = (short)(left[i] & 0xff), r = (short)(right[i] & 0xff);
            if (l < r) return (short)-1;
            if (l > r) return (short)1;
        }
        return (short)0;
    }

    private static boolean isZero(byte[] value) {
        byte aggregate = (byte)0;
        short i = (short)0;
        for (; i < Q_LENGTH; i++) aggregate |= value[i];
        return aggregate == (byte)0;
    }

    private void requireKey() {
        if (activeSlot != (byte)0 && activeSlot != (byte)1) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private byte[] activePrivateX() { return activeSlot == (byte)0 ? privateX0 : privateX1; }
    private byte[] activePublicY() { return activeSlot == (byte)0 ? publicY0 : publicY1; }

    private void wipeWorkspaces() {
        clear(rsaOutput);
        clear(a);
        modExpKey.clearKey();
        if (initialised) {
            natA.erase();
            natB.erase();
            natC.erase();
            natD.erase();
        }
    }

    private static byte[] transientBytes(short length) {
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
    }

    private static void clear(byte[] value) {
        Util.arrayFillNonAtomic(value, (short)0, (short)value.length, (byte)0);
    }
}
