package net.as207960.bt4pt.hsm.main;

import net.as207960.bt4pt.hsm.applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Run {
    public static void main(String[] args){
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, MainApplet.class);

        byte[] ticketData = fromHex("789c0b8d77f3718d3030363032314d5ac2dce3dccd6a10a41024bc3a3b5b3b5998dbb990a3dda937ed9c449483a8f0019eae5b976e5c3a24d273e8c6b553778e9c7a724ef49c28234bf6fa6d821360ea6492d485d818cd0eb0c9a5ac489c69b42be1e9e434bf195b7364276b2fe38bdc96f2b25b8c2f8255c360e7ce0dbb26a8181ab36b1a6ddeb4dd72a3d54e631097d57c8bb9d104ad6dbb376d6e1460683ad2757272138340c4c448e394b8b30a1c720c1df28c0aa62c0b0d56ae3299a069b089a18141cc4138ef1083dc16af33b78d33109633b970f047a9a6ad9130606464d64f9bc0c2cfe0f8da65cdd566360600ceb458dc");

        simulator.selectApplet(appletAID);

        ResponseAPDU signedTicketData = simulator.transmitCommand(new CommandAPDU(0x80, 0x30, 0x00, 0x00, ticketData, 256));
        requireSuccess(signedTicketData);
        System.out.println("Ticket data: " + toHex(signedTicketData.getData()));

//        requireSuccess(simulator.transmitCommand(
//            new CommandAPDU(0x80, 0x10, 0x00, 0x00)));
//
//        ResponseAPDU publicKey = simulator.transmitCommand(
//            new CommandAPDU(0x80, 0x11, 0x04, 0x00, 256));
//        requireSuccess(publicKey);
//        System.out.println("DSA public Y: " + toHex(publicKey.getData()));
//
//        try {
//            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
//                "bt4pt".getBytes(StandardCharsets.UTF_8));
//            ResponseAPDU signature = simulator.transmitCommand(
//                new CommandAPDU(0x80, 0x20, 0x00, 0x00, digest));
//            requireSuccess(signature);
//            System.out.println("DSA signature r||s: " + toHex(signature.getData()));
//        } catch (java.security.NoSuchAlgorithmException impossible) {
//            throw new IllegalStateException(impossible);
//        }
    }

    private static void requireSuccess(ResponseAPDU response) {
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException(
                String.format("Card returned %04X", response.getSW()));
        }
    }

    private static String toHex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte b : value) result.append(String.format("%02x", b & 0xff));
        return result.toString();
    }

    private static byte[] fromHex(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
