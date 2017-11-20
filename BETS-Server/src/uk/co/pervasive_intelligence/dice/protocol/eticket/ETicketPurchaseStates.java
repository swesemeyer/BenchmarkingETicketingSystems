/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.eticket;

import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * Ticket purchase states of the e-ticket state machine protocol.
 *
 * @author Matthew Casey
 */
public class ETicketPurchaseStates {

  /**
   * State 3.
   */
  public static class PState03 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the service from the user.
        return new Action<>(Status.CONTINUE, 4, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 4.
   */
  public static class PState04 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Get the challenge and send it back.
        final byte[] data = this.getChallenge(message.getData());

        if (data != null) {
          LOG.debug("get challenge complete");
          return new Action<>(Status.CONTINUE, 5, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }

    /**
     * Gets a challenge.
     *
     * @param data The data to build the challenge from.
     * @return The challenge to be sent.
     */
    private byte[] getChallenge(byte[] data) {
      final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      final Crypto crypto = Crypto.getInstance();

      // Extract out the returned data (not specified in protocol). Note, TOR connection assumed.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 6) {
        return null;
      }

      sharedMemory.PseuU = listData.getList().get(0);
      sharedMemory.HU = new BigInteger(listData.getList().get(1));
      sharedMemory.A1 = new BigInteger(listData.getList().get(2));
      sharedMemory.A2 = new BigInteger(listData.getList().get(3));
      sharedMemory.hrUn = listData.getList().get(4);
      sharedMemory.Sv = listData.getList().get(5);

      // Extract yU from PsueU.
      final ListData PseuUData = ListData.fromBytes(sharedMemory.PseuU);

      if (PseuUData.getList().size() != 2) {
        return null;
      }

      sharedMemory.yU = new BigInteger(PseuUData.getList().get(0));

      // 1. Generates and sends challenge c. Note not sent yet.
      sharedMemory.c = crypto.secureRandom(crypto.getDhParameters().getQ());

      // 2. Pre-compute yU^c (mod p).
      sharedMemory.yUc = sharedMemory.yU.modPow(sharedMemory.c, crypto.getDhParameters().getP());

      // 3. Pre-compute HU^c (mod p).
      sharedMemory.HUc = sharedMemory.HU.modPow(sharedMemory.c, crypto.getDhParameters().getP());

      return sharedMemory.c.toByteArray();
    }
  }

  /**
   * State 5.
   */
  public static class PState05 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the challenge response from the user.
        return new Action<>(Status.CONTINUE, 6, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 6.
   */
  public static class PState06 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Get the ticket using the challenge response and send it back.
        final byte[] data = this.getTicket(message.getData());

        if (data != null) {
          // Clear out shared memory as we have finished acting as the ticket issuer.
          final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
          sharedMemory.clear();

          LOG.debug("get ticket complete");
          return new Action<>(Status.CONTINUE, 7, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }

    /**
     * Gets the ticket.
     *
     * @param data The data to build the ticket from.
     * @return The ticket to be sent.
     */
    private byte[] getTicket(byte[] data) {
      final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      final Crypto crypto = Crypto.getInstance();

      // 1. Decrypt challenge response.
      final byte[] userData = Crypto.getInstance().decrypt(data, crypto.getPrivateKey());
      final ListData listData = ListData.fromBytes(userData);

      if (listData.getList().size() != 2) {
        return null;
      }

      sharedMemory.w1 = new BigInteger(listData.getList().get(0));
      sharedMemory.w2 = new BigInteger(listData.getList().get(1));

      // 2. Computes aw1.
      final BigInteger aw1 = crypto.getDhParameters().getG().modPow(sharedMemory.w1, crypto.getDhParameters().getP());

      // 3. Computes aw2.
      final BigInteger aw2 = crypto.getDhParameters().getG().modPow(sharedMemory.w2, crypto.getDhParameters().getP());

      // 4. Verify aw1.
      final BigInteger aw1Check = sharedMemory.A1.multiply(sharedMemory.yUc).mod(crypto.getDhParameters().getP());

      if (!aw1Check.equals(aw1)) {
        return null;
      }

      // 5. Verify aw2.
      final BigInteger aw2Check = sharedMemory.A2.multiply(sharedMemory.HUc).mod(crypto.getDhParameters().getP());

      if (!aw2Check.equals(aw2)) {
        return null;
      }

      // 6. Computes the shared session key.
      sharedMemory.K = crypto.getHash(sharedMemory.w2.toByteArray());

      // 7. Obtains a unique serial number Sn and random value rI.
      sharedMemory.Sn = new byte[] { 1 }; // Arbitrary.
      sharedMemory.rI = crypto.secureRandom(crypto.getDhParameters().getP());

      // 8. Compute hash chain of rI for n.
      sharedMemory.hrIn = crypto.getHash(sharedMemory.rI.toByteArray(), sharedMemory.n);

      // 9. Composes kappa and signs it kappaStar.
      final ListData kappaData = new ListData(Arrays.asList(sharedMemory.K, sharedMemory.rI.toByteArray()));
      final byte[] kappa = kappaData.toBytes();

      final byte[] hashKappa = crypto.getHash(kappa);
      final byte[] sigIKappa = crypto.encrypt(hashKappa, crypto.getPrivateKey());

      final ListData kappaStarData = new ListData(Arrays.asList(kappa, sigIKappa));
      final byte[] kappaStar = kappaStarData.toBytes();

      // 10. Encrypt kappaStar to deltaTP. Here we assume the public key is common to the server elements.
      final byte[] deltaTP = crypto.encrypt(kappaStar, crypto.getPublicKey());

      // 11. Fills out the ticket information.
      final byte[] Tv = new byte[] { 1, 1, 1, 1 }; // Arbitrary ticket validity time.
      final byte[] Ti = new byte[] { 2, 2, 2, 2 }; // Arbitrary date of issue.

      final ListData T = new ListData(Arrays.asList(sharedMemory.Sn, sharedMemory.Sv, sharedMemory.PseuU, Tv, Ti,
          sharedMemory.hrIn, sharedMemory.hrUn, deltaTP));
      final byte[] TData = T.toBytes();

      // 12. Sign the ticket T.
      final byte[] hashT = crypto.getHash(TData);
      final byte[] sigIT = crypto.encrypt(hashT, crypto.getPrivateKey());

      // 13. Send TStar.
      final ListData TStarData = new ListData(Arrays.asList(sharedMemory.Sn, sharedMemory.Sv, sharedMemory.PseuU, Tv, Ti,
          sharedMemory.hrIn, sharedMemory.hrUn, deltaTP, sigIT));
      sharedMemory.TStar = TStarData.toBytes();

      // Make sure j is 0 as we are not using a database.
      sharedMemory.j = 0;

      return sharedMemory.TStar;
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ETicketPurchaseStates.class);
}
