package net.as207960.bt4pt.hsm;

import cz.muni.fi.crocs.rcard.client.CardManager;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class DsaEngineTest extends BaseTest {
    private static final int CLA = 0x80;
    private static final int INS_GENERATE = 0x10;
    private static final int INS_GET_PUBLIC = 0x11;
    private static final int INS_SIGN_DIGEST = 0x20;

    @Test
    void generatedKeyProducesVerifiableSignature() throws Exception {
        CardManager card = connect();

        ResponseAPDU beforeGeneration = getComponent(card, 4, 256);
        assertEquals(0x6985, beforeGeneration.getSW());

        assertSuccess(card.transmit(new CommandAPDU(CLA, INS_GENERATE, 0, 0)));

        byte[] pBytes = successfulData(getComponent(card, 1, 256));
        byte[] qBytes = successfulData(getComponent(card, 2, 32));
        byte[] gBytes = successfulData(getComponent(card, 3, 256));
        byte[] yBytes = successfulData(getComponent(card, 4, 256));

        assertEquals(256, pBytes.length);
        assertEquals(32, qBytes.length);
        assertEquals(256, gBytes.length);
        assertEquals(256, yBytes.length);

        BigInteger p = unsigned(pBytes);
        BigInteger q = unsigned(qBytes);
        BigInteger g = unsigned(gBytes);
        BigInteger y = unsigned(yBytes);

        assertTrue(p.isProbablePrime(100));
        assertTrue(q.isProbablePrime(100));
        assertEquals(BigInteger.ZERO, p.subtract(BigInteger.ONE).mod(q));
        assertEquals(BigInteger.ONE, g.modPow(q, p));
        assertTrue(y.signum() > 0 && y.compareTo(p) < 0);
        assertEquals(BigInteger.ONE, y.modPow(q, p));

        for (int round = 0; round < 16; round++) {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                ("bt4pt software DSA test " + round).getBytes(StandardCharsets.UTF_8));
            ResponseAPDU signed = card.transmit(
                new CommandAPDU(CLA, INS_SIGN_DIGEST, 0, 0, digest));
            byte[] signature = successfulData(signed);
            assertEquals(64, signature.length);

            BigInteger r = unsigned(Arrays.copyOfRange(signature, 0, 32));
            BigInteger s = unsigned(Arrays.copyOfRange(signature, 32, 64));
            assertTrue(r.signum() > 0 && r.compareTo(q) < 0);
            assertTrue(s.signum() > 0 && s.compareTo(q) < 0,
                () -> "s=" + s.toString(16));
            assertTrue(verify(p, q, g, y, unsigned(digest), r, s));
        }
    }

    @Test
    void regenerationReplacesThePublicKey() throws Exception {
        CardManager card = connect();
        assertSuccess(card.transmit(new CommandAPDU(CLA, INS_GENERATE, 0, 0)));
        byte[] first = successfulData(getComponent(card, 4, 256));
        assertSuccess(card.transmit(new CommandAPDU(CLA, INS_GENERATE, 0, 0)));
        byte[] second = successfulData(getComponent(card, 4, 256));
        assertFalse(Arrays.equals(first, second));
    }

    private static boolean verify(BigInteger p, BigInteger q, BigInteger g,
                                  BigInteger y, BigInteger hash,
                                  BigInteger r, BigInteger s) {
        BigInteger w = s.modInverse(q);
        BigInteger u1 = hash.mod(q).multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);
        BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
        return v.equals(r);
    }

    private static ResponseAPDU getComponent(CardManager card, int component, int length)
        throws Exception {
        return card.transmit(new CommandAPDU(CLA, INS_GET_PUBLIC, component, 0, length));
    }

    private static void assertSuccess(ResponseAPDU response) {
        assertEquals(0x9000, response.getSW(),
            () -> String.format("Unexpected status %04X", response.getSW()));
    }

    private static byte[] successfulData(ResponseAPDU response) {
        assertSuccess(response);
        return response.getData();
    }

    private static BigInteger unsigned(byte[] value) {
        return new BigInteger(1, value);
    }
}
