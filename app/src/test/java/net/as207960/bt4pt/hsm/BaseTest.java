package net.as207960.bt4pt.hsm;

import net.as207960.bt4pt.hsm.applet.MainApplet;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import cz.muni.fi.crocs.rcard.client.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;


public class BaseTest {
    private static final String APPLET_AID = "01ffff0405060708090102";
    private static final byte[] APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);

    protected CardType cardType = CardType.JCARDSIMLOCAL;

    protected boolean simulateStateful = false;
    protected CardManager statefulCard = null;

    public BaseTest() {

    }

    public CardManager connect() throws Exception {
        return connect(null);
    }

    public CardManager connect(byte[] installData) throws Exception {
        if (simulateStateful && statefulCard != null){
            return statefulCard;
        } else if (simulateStateful){
            statefulCard = connectRaw(installData);
            return statefulCard;
        }

        return connectRaw(installData);
    }

    public CardManager connectRaw(byte[] installData) throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
        System.setProperty("com.licel.jcardsim.sign.dsasigner.computedhash", "1");


        runCfg.setTestCardType(cardType);
        if (cardType == CardType.REMOTE){
            runCfg.setRemoteAddress("http://127.0.0.1:9901");

            runCfg.setRemoteCardType(CardType.PHYSICAL);

            runCfg.setAid(APPLET_AID_BYTE);

        } else if (cardType != CardType.PHYSICAL && cardType != CardType.PHYSICAL_JAVAX) {
            runCfg.setAppletToSimulate(MainApplet.class)
                    .setTestCardType(CardType.JCARDSIMLOCAL)
                    .setbReuploadApplet(true)
                    .setInstallData(installData);
        }

        if (!cardMngr.connect(runCfg)) {
            throw new RuntimeException("Connection failed");
        }

        return cardMngr;
    }

    public ResponseAPDU connectAndSend(CommandAPDU cmd) throws Exception {
        return connect().transmit(cmd);
    }

    public static CommandAPDU buildApdu(String data){
        return new CommandAPDU(Util.hexStringToByteArray(data));
    }

    public static CommandAPDU buildApdu(byte[] data){
        return new CommandAPDU(data);
    }

    public static CommandAPDU buildApdu(CommandAPDU data){
        return data;
    }

    public ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<String> initCommands) throws CardException {
        if (initCommands != null) {
            for (String cmd : initCommands) {
                cardMngr.getChannel().transmit(buildApdu(cmd));
            }
        }

        return cardMngr.getChannel().transmit(buildApdu(command));
    }

    public CardType getCardType() {
        return cardType;
    }

    public BaseTest setCardType(CardType cardType) {
        this.cardType = cardType;
        return this;
    }

    public boolean isSimulateStateful() {
        return simulateStateful;
    }

    public BaseTest setSimulateStateful(boolean simulateStateful) {
        this.simulateStateful = simulateStateful;
        return this;
    }

    public boolean isPhysical() {
        return cardType == CardType.PHYSICAL || cardType == CardType.PHYSICAL_JAVAX;
    }

    public boolean isStateful(){
        return isPhysical() || simulateStateful;
    }

    public boolean canReinstall(){
        return !isPhysical() && !simulateStateful;
    }
}