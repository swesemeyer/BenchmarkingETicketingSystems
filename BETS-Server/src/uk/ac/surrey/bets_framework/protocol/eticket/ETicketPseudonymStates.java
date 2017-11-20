/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.eticket;

import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

/**
 * Pseudonym renewal states of the e-ticket state machine protocol.
 *
 * @author Matthew Casey
 */
public class ETicketPseudonymStates {

  /**
   * State 0.
   */
  public static class NState00 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      // Clear out shared memory as we are acting as the pseudonym authority.
      final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      sharedMemory.clear();

      if (message.getType() == Type.START) {
        // Open the connection.
        return new Action<>(1, NFCReaderCommand.OPEN);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 1.
   */
  public static class NState01 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the pseudonym data from the user.
        return new Action<>(Status.CONTINUE, 2, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 2.
   */
  public static class NState02 extends State<NFCReaderCommand> {

    /**
     * Generates a pseudonym for the user.
     *
     * @param data The data received from the user.
     * @return The pseudonym response data.
     */
    private byte[] generatePseudonym(byte[] data) {
      final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      final Crypto crypto = Crypto.getInstance();

      // 1. Decrypt the data.
      final byte[] userData = Crypto.getInstance().decrypt(data, crypto.getPrivateKey());
      final ListData listData = ListData.fromBytes(userData);

      // 2. Verify yU by verifying the signature sigU and the contained hash.
      if (listData.getList().size() != 2) {
        return null;
      }

      sharedMemory.yU = new BigInteger(listData.getList().get(0));
      sharedMemory.hyU = crypto.getHash(sharedMemory.yU.toByteArray());
      final byte[] sigU = listData.getList().get(1);
      final byte[] hyUCheck = crypto.decrypt(sigU, crypto.getRemotePublicKey());

      if ((sharedMemory.yU == null) || (sharedMemory.hyU == null) || (sigU == null) || (hyUCheck == null)
          || !Arrays.equals(hyUCheck, sharedMemory.hyU)) {
        return null;
      }

      // 3. Compute signature sigT of yU.
      final byte[] sigT = crypto.encrypt(sharedMemory.hyU, crypto.getPrivateKey());

      // 4. Encrypt and send sigT.
      return Crypto.getInstance().encrypt(sigT, crypto.getRemotePublicKey());
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Generate the pseudonym from the user's data and send it back.
        final byte[] data = this.generatePseudonym(message.getData());

        if (data != null) {
          // Clear out shared memory as we have finished acting as the pseudonym generator.
          final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
          sharedMemory.clear();

          LOG.debug("generate pseudonym complete");
          return new Action<>(Status.CONTINUE, 3, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ETicketPseudonymStates.class);
}
