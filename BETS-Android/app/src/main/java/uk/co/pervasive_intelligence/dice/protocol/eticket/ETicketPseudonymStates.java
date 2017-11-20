/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.eticket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidState;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;

/**
 * Pseudonym renewal states of the e-ticket state machine protocol.
 *
 * @author Matthew Casey
 */
public class ETicketPseudonymStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ETicketPseudonymStates.class);

  /**
   * State 0.
   */
  public static class NState00 extends NFCAndroidState {

    /**
     * Generates the user authentication data for the user.
     *
     * @return The user authentication response data.
     */
    private byte[] authenticateUser() {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // 1. Generate a random number xU and corresponding yU.
      sharedMemory.xU = crypto.secureRandom(crypto.getDhParameters().getQ());
      sharedMemory.yU = crypto.getDhParameters().getG().modPow(sharedMemory.xU, crypto.getDhParameters().getP());

      // 2. Compute hash hyU and signature sigU of yU.
      sharedMemory.hyU = crypto.getHash(sharedMemory.yU.toByteArray());
      byte[] sigU = crypto.encrypt(sharedMemory.hyU, crypto.getPrivateKey());

      // 3. Put together the information to be sent. Note that CertU is not included as the server already has the client's
      // public key.
      ListData authUData = new ListData(Arrays.asList(sharedMemory.yU.toByteArray(), sigU));
      byte[] authU = authUData.toBytes();

      // 4. Encrypt and send.
      return Crypto.getInstance().encrypt(authU, crypto.getRemotePublicKey());
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Send back the user authentication data.
        if (message.getData() == null) {
          byte[] data = this.authenticateUser();

          if (data != null) {
            LOG.debug("authenticate user complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 1, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 1.
   */
  public static class NState01 extends NFCAndroidState {

    /**
     * Verifies the returned pseudonym data.
     *
     * @return True if the verification is successful.
     */
    private boolean verifyPseudonym(byte[] data) {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // 1. Decrypt sigT.
      byte[] sigT = crypto.decrypt(data, crypto.getPrivateKey());

      // Form PseuU is the composition of yU and sigT.
      ListData PseuUData = new ListData(Arrays.asList(sharedMemory.yU.toByteArray(), sigT));
      sharedMemory.PseuU = PseuUData.toBytes();

      // 2. Verify sigT.
      byte[] hyUCheck = crypto.decrypt(sigT, crypto.getRemotePublicKey());

      return (sigT != null) && (hyUCheck != null) && (Arrays.equals(hyUCheck, sharedMemory.hyU));
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Verify the generated pseudonym.
        if (message.getData() != null) {
          if (this.verifyPseudonym(message.getData())) {
            LOG.debug("verify pseudonym complete");
            return new Action<>(Action.Status.END_SUCCESS, 2, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
