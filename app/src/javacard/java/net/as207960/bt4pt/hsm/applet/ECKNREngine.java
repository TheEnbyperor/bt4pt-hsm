package net.as207960.bt4pt.hsm.applet;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import net.as207960.bt4pt.hsm.applet.jcmathlib.BigNat;
import net.as207960.bt4pt.hsm.applet.jcmathlib.ECCurve;
import net.as207960.bt4pt.hsm.applet.jcmathlib.ECPoint;
import net.as207960.bt4pt.hsm.applet.jcmathlib.SecP256k1;
import net.as207960.bt4pt.hsm.applet.jcmathlib.ResourceManager;

final class ECKNREngine {
    public static final byte SLOT_COUNT = 8;

    static final byte SLOT_EMPTY     = 0;
    static final byte SLOT_REQUESTED = 1;
    static final byte SLOT_CERTIFIED = 2;

    private final byte[] slotState;

    public static final short SCALAR_SIZE = 32;

    private static final byte[] MGF_COUNTER_1 = {
            0x00, 0x00, 0x00, 0x01
    };

    private final RandomData random;
    private final MessageDigest sha256;
    private final byte[] work;

    private boolean initialised = false;

    private BigNat order;
    private BigNat[] privateKeys;

    private ECCurve curve;
    private ECPoint publicKey;
    private ECPoint point;

    private BigNat k;
    private BigNat t;
    private BigNat tmp;
    private BigNat s;

    ECKNREngine(RandomData random) {
        this.random = random;
        work = JCSystem.makeTransientByteArray(
                (short) 160,
                JCSystem.CLEAR_ON_RESET
        );
        sha256 = MessageDigest.getInstance(
                MessageDigest.ALG_SHA_256,
                false
        );
        slotState = new byte[SLOT_COUNT];
    }

    public void initialise(ResourceManager math) {
        if (initialised) {
            return;
        }

        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, math);

        publicKey = new ECPoint(curve);
        point = new ECPoint(curve);

        order = new BigNat(SCALAR_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, math);
        order.fromByteArray(SecP256k1.r, (short) 0, SCALAR_SIZE);

        privateKeys = new BigNat[SLOT_COUNT];
        for (byte i = 0; i < SLOT_COUNT; i++) {
            privateKeys[i] = new BigNat(SCALAR_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, math);
            privateKeys[i].zero();
        }

        k = new BigNat(SCALAR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, math);
        t = new BigNat(SCALAR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, math);
        tmp = new BigNat(SCALAR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, math);
        s = new BigNat(SCALAR_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, math);

        initialised = true;
    }

    private void checkSlot(byte slot) {
        if (slot < 0 || slot >= SLOT_COUNT)
            ISOException.throwIt(MainApplet.SW_INVALID_SLOT);
    }

    boolean isOccupied(byte slot) {
        checkSlot(slot);
        return !privateKeys[slot].isZero();
    }

    void generateKeyPair(byte slot) {
        checkSlot(slot);

        if (slotState[slot] != SLOT_EMPTY) {
            ISOException.throwIt(MainApplet.SW_SLOT_OCCUPIED);
        }

        BigNat privateKey = privateKeys[slot];
        if (!privateKey.isZero()) {
            ISOException.throwIt(MainApplet.SW_SLOT_OCCUPIED);
        }
        do {
            random.nextBytes(work, (short)0, SCALAR_SIZE);
            privateKey.setSize(SCALAR_SIZE);
            privateKey.fromByteArray(work, (short)0, SCALAR_SIZE);
            privateKey.mod(order);
        } while (privateKey.isZero());

        slotState[slot] = SLOT_REQUESTED;
    }

    void clearSlot(byte slot) {
        checkSlot(slot);
        privateKeys[slot].erase();
        privateKeys[slot].setSize(SCALAR_SIZE);
        slotState[slot] = SLOT_EMPTY;
    }

    private BigNat selectKey(byte slot) {
        checkSlot(slot);
        BigNat privateKey = privateKeys[slot];
        if (slotState[slot] == SLOT_EMPTY) {
            ISOException.throwIt(MainApplet.SW_SLOT_EMPTY);
        }
        publicKey.setW(SecP256k1.G, (short)0, (short)SecP256k1.G.length);
        publicKey.multiplication(privateKey);
        return privateKey;
    }

    short getPublicKey(
            byte slot,
            byte[] output,
            short outputOffset
    ) {
        selectKey(slot);
        publicKey.getX(output, outputOffset);
        publicKey.getY(output, (short)(outputOffset + SCALAR_SIZE));
        return (short)(SCALAR_SIZE * 2);
    }

    void receiveCertificate(
            byte slot,
            byte[] certificateHash,
            short hashOffset,
            short hashLength,
            byte[] reconstructionValue,
            short reconstructionOffset,
            short reconstructionLength
    ) {
        if (hashLength != SCALAR_SIZE || reconstructionLength != SCALAR_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        checkSlot(slot);
        BigNat privateKey = privateKeys[slot];
        if (slotState[slot] == SLOT_EMPTY) {
            ISOException.throwIt(MainApplet.SW_SLOT_EMPTY);
        }
        if (slotState[slot] != SLOT_REQUESTED) {
            ISOException.throwIt(MainApplet.SW_SLOT_OCCUPIED);
        }

        t.setSize(SCALAR_SIZE);
        t.fromByteArray(certificateHash, hashOffset, SCALAR_SIZE);
        t.mod(order);

        tmp.clone(privateKey);
        tmp.modMult(t, order);

        s.setSize(SCALAR_SIZE);
        s.fromByteArray(reconstructionValue, reconstructionOffset, SCALAR_SIZE);
        if (s.isZero() || !s.isLesser(order)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        s.modAdd(tmp, order);
        if (s.isZero()) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        JCSystem.beginTransaction();
        try {
            privateKey.setSize(SCALAR_SIZE);
            privateKey.copy(s);
            slotState[slot] = SLOT_CERTIFIED;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throw e;
        }
    }

    short sign(
            byte slot,
            byte[] buffer,
            short messageLength
    ) {
        BigNat privateKey = selectKey(slot);
        if (slotState[slot] != SLOT_CERTIFIED) {
            ISOException.throwIt(MainApplet.SW_SLOT_NOT_CERTIFIED);
        }

        short recoverableLen = messageLength < SCALAR_SIZE ? messageLength : SCALAR_SIZE;
        short remainderLen = (short) (messageLength - recoverableLen);

        generateK();

        final short MR   = 0;
        final short KBUF = 32;
        final short BUF  = 64;
        final short HASH = 97;

        Util.arrayFillNonAtomic(work, MR, SCALAR_SIZE, (byte) 0);
        Util.arrayCopyNonAtomic(buffer, SCALAR_SIZE, work, MR, recoverableLen);

        // r = kG
        point.setW(SecP256k1.G, (short)0, (short)SecP256k1.G.length);
        point.multiplication(k);

        // Get r as SEC-1 compressed
        point.getW(work, BUF);
        work[BUF] = (byte) (0x02 | (work[(short) (BUF + SCALAR_SIZE + SCALAR_SIZE)] & 0x01));

        // pi = MGF(r)
        mgf2_32(work, BUF, (short)(SCALAR_SIZE + 1), work, HASH);

        // r_sig = recoverable XOR pi
        for (short i = 0; i < SCALAR_SIZE; ++i) {
            buffer[i] = (byte) (work[(short) (MR + i)] ^ work[(short) (HASH + i)]);
        }

        // r_sig = r_sig XOR MGF(X_Q || Y_Q || remainder)
        sha256.reset();
        publicKey.getW(work, BUF);
        sha256.update(work, (short) (BUF + 1), (short)(SCALAR_SIZE * 2));
        if (remainderLen != 0) {
            sha256.update(buffer, (short)(2 * SCALAR_SIZE), remainderLen);
        }
        sha256.doFinal(MGF_COUNTER_1, (short) 0, (short) 4, work, HASH);
        for (short i = 0; i < SCALAR_SIZE; ++i) {
            buffer[i] ^= work[(short) (HASH + i)];
        }

        // t = OS2IP(r)
        t.setSize(SCALAR_SIZE);
        t.fromByteArray(buffer, (short)0, SCALAR_SIZE);
        if (t.isZero() || !t.isLesser(order)) {
            javacard.framework.ISOException.throwIt((short) 0x6F01);
        }

        // s_sig = priv*t mod n
        tmp.clone(privateKey);
        tmp.modMult(t, order);
        s.clone(k);
        s.modSub(tmp, order);

        Util.arrayFillNonAtomic(buffer, SCALAR_SIZE, SCALAR_SIZE, (byte)0);
        short sLen = s.copyToByteArray(work, KBUF);
        Util.arrayCopyNonAtomic(work, KBUF, buffer, (short)((2 * SCALAR_SIZE) - sLen), sLen);

        return (short)((2 * SCALAR_SIZE) + remainderLen);
    }

    private void generateK() {
        do {
            random.nextBytes(work, (short)0, SCALAR_SIZE);
            k.setSize(SCALAR_SIZE);
            k.fromByteArray(work, (short)0, SCALAR_SIZE);
        } while (k.isZero() || !k.isLesser(order));
    }

    private void mgf2_32(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        sha256.reset();
        sha256.update(in, inOff, inLen);
        sha256.doFinal(MGF_COUNTER_1, (short) 0, (short) 4, out, outOff);
    }
}
