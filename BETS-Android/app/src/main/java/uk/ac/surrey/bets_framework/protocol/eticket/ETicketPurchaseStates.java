/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.eticket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;

import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * Ticket purchase states of the e-ticket state machine protocol.
 *
 * @author Matthew Casey
 */
public class ETicketPurchaseStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ETicketPurchaseStates.class);

  /**
   * State 2.
   */
  public static class PState02 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Send back the service data.
        if (message.getData() == null) {
          byte[] data = this.getService();

          if (data != null) {
            LOG.debug("get service complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 3, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }

    /**
     * Gets the service information.
     *
     * @return The service information.
     */
    private byte[] getService() {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // 1. Selects and pays for the service Sv.
      sharedMemory.Sv = new byte[]{1}; // Arbitrary.

      // 2. Generates a random value rU and computes hash hrUn where n is ticket use maximum.
      sharedMemory.rU = crypto.secureRandom(crypto.getDhParameters().getQ());
      sharedMemory.hrUn = crypto.getHash(sharedMemory.rU.toByteArray(), sharedMemory.n);

      // 3. Compute HU.
      sharedMemory.HU = crypto.getDhParameters().getG().modPow(sharedMemory.rU, crypto.getDhParameters().getP());

      // 4. Generates two more random values for Schnorr proof.
      sharedMemory.a1 = crypto.secureRandom(crypto.getDhParameters().getQ());
      sharedMemory.a2 = crypto.secureRandom(crypto.getDhParameters().getQ());

      // 5. Computes A1.
      sharedMemory.A1 = crypto.getDhParameters().getG().modPow(sharedMemory.a1, crypto.getDhParameters().getP());

      // 6. Computes A2.
      sharedMemory.A2 = crypto.getDhParameters().getG().modPow(sharedMemory.a2, crypto.getDhParameters().getP());

      // 7. Sends data to ticket issuer.  Note no encryption.
      ListData serviceRequest = new ListData(Arrays.asList(sharedMemory.PseuU, sharedMemory.HU.toByteArray(), sharedMemory
          .A1.toByteArray(), sharedMemory.A2.toByteArray(), sharedMemory.hrUn, sharedMemory.Sv));

      return serviceRequest.toBytes();
    }
  }

  /**
   * State 3.
   */
  public static class PState03 extends NFCAndroidState {

    /**
     * Solves the challenge.
     *
     * @param data The challenge data.
     * @return The data to be sent back.
     */
    private byte[] solveChallenge(byte[] data) {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // Extract the value of the challenge c.
      sharedMemory.c = new BigInteger(data);

      // 1. Compute w1.
      sharedMemory.w1 = sharedMemory.a1.add(sharedMemory.c.multiply(sharedMemory.xU)).mod(crypto.getDhParameters().getQ());

      // 2. Compute w2.
      sharedMemory.w2 = sharedMemory.a2.add(sharedMemory.c.multiply(sharedMemory.rU)).mod(crypto.getDhParameters().getQ());

      // 3. Encrypts. Note not sent yet.
      ListData solvedChallenge = new ListData(Arrays.asList(sharedMemory.w1.toByteArray(), sharedMemory.w2.toByteArray()));
      byte[] result = solvedChallenge.toBytes();

      // 4. Pre-computes shared session key K.
      sharedMemory.K = crypto.getHash(sharedMemory.w2.toByteArray());

      // And sent.
      return Crypto.getInstance().encrypt(result, crypto.getRemotePublicKey());
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
        // Solve the generated challenge.
        if (message.getData() != null) {
          byte[] data = this.solveChallenge(message.getData());

          if (data != null) {
            LOG.debug("solve challenge complete");

            // Save the data for the corresponding GET.
            ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = data;
            return new Action<>(Action.Status.END_SUCCESS, 4, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 4.
   */
  public static class PState04 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Send back the delayed response if we have a GET.
        if (message.getData() == null) {
          byte[] data = ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse;
          ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = null;

          if (data != null) {
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 5, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 5.
   */
  public static class PState05 extends NFCAndroidState {

    /**
     * Verifies the received ticket.
     *
     * @param data The ticket data.
     * @return True if the received ticket was verified.
     */
    private boolean receiveTicket(byte[] data) {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // Save off the signed ticket.
      sharedMemory.TStar = data;

      // Extract out the fields of the ticket for verification.
      final ListData TStarData = ListData.fromBytes(data);

      if (TStarData.getList().size() != 9) {
        return false;
      }

      sharedMemory.Sn = TStarData.getList().get(0);
      byte[] SvCheck = TStarData.getList().get(1);
      byte[] PseuUCheck = TStarData.getList().get(2);
      byte[] Tv = TStarData.getList().get(3);
      byte[] Ti = TStarData.getList().get(4);
      sharedMemory.hrIn = TStarData.getList().get(5);
      byte[] hrUnCheck = TStarData.getList().get(6);
      byte[] deltaTP = TStarData.getList().get(7);
      byte[] sigIT = TStarData.getList().get(8);

      // 1. Verifies signature.
      final ListData T = new ListData(Arrays.asList(sharedMemory.Sn, sharedMemory.Sv, sharedMemory.PseuU, Tv, Ti, sharedMemory
          .hrIn, sharedMemory.hrUn, deltaTP));
      byte[] TData = T.toBytes();

      final byte[] hashT = crypto.getHash(TData);
      byte[] hashTCheck = crypto.decrypt(sigIT, crypto.getRemotePublicKey());

      boolean result = (sigIT != null) && (hashT != null) && (hashTCheck != null) && (Arrays.equals(hashTCheck, hashT));

      // 2. Verifies that the ticket data and request match.
      result &= Arrays.equals(SvCheck, sharedMemory.Sv);
      result &= Arrays.equals(hrUnCheck, sharedMemory.hrUn);

      // 3. Verifies the ticket validity.
      // Do nothing - assume valid since they are arbitrary.

      // 4. Verifies PseuUCheck.
      result &= Arrays.equals(PseuUCheck, sharedMemory.PseuU);

      // 5. Stores TStar (done), rU (done) and j = 0 for journey.
      sharedMemory.j = 0;

      return result;
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
        // Verify the received ticket.
        if (message.getData() != null) {
          if (this.receiveTicket(message.getData())) {
            LOG.debug("receive ticket complete");
            return new Action<>(Action.Status.END_SUCCESS, 6, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
