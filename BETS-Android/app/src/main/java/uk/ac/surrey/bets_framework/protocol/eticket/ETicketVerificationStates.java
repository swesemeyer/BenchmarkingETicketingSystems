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
 * Ticket verification states of the e-ticket state machine protocol.
 *
 * @author Matthew Casey
 */
public class ETicketVerificationStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ETicketVerificationStates.class);

  /**
   * State 6.
   */
  public static class VState06 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Send back the ticket data.
        if (message.getData() == null) {
          byte[] data = this.showTicket();

          if (data != null) {
            LOG.debug("show ticket complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 7, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }

    /**
     * Shows the ticket.
     *
     * @return The ticket.
     */
    private byte[] showTicket() {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();

      // 1. Sends ticket m1 which is TStar and accumulated total of requested service cost i = j + s.
      sharedMemory.i = sharedMemory.j + sharedMemory.s;

      ListData m1Data = new ListData(Arrays.asList(sharedMemory.TStar, BigInteger.valueOf(sharedMemory.i).toByteArray()));
      return m1Data.toBytes();
    }
  }

  /**
   * State 7.
   */
  public static class VState07 extends NFCAndroidState {

    /**
     * Shows proof.
     *
     * @param data The verify ticket response.
     * @return The data to be sent back.
     */
    private byte[] showProof(byte[] data) {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // Extract out the fields of the verify ticket data.
      final ListData VStarData = ListData.fromBytes(data);

      if (VStarData.getList().size() != 2) {
        return null;
      }

      byte[] VData = VStarData.getList().get(0);
      byte[] sigPV = VStarData.getList().get(1);

      // Note that the fields in the data have been re-ordered in the server to make them consistent and to allow us to
      // understand whether the message is a Vsucc or Vfail.

      // 1. Verifies P's signature.
      final byte[] hashVDataCheck = crypto.getHash(VData);
      final byte[] hashVData = crypto.decrypt(sigPV, crypto.getRemotePublicKey());

      boolean result = (VData != null) && (sigPV != null) && (hashVDataCheck != null) && (hashVData != null) && (Arrays.equals
          (hashVDataCheck, hashVData));

      if (!result) {
        return null;
      }

      // 2. If VsuccStar or VfailStar are not received.  We have received them because, although this could happen independently
      // of the receipt (or not) of Vsucc or Vfail, we are running it sequentially.
      // 2a. Ignored - not doing claims.
      // 2b. Ignored - not doing claims.

      // 3. Calculate AUi.
      byte[] hrUni = crypto.getHash(sharedMemory.rU.toByteArray(), sharedMemory.n - sharedMemory.i);
      byte[] AUi = Crypto.xor(crypto.getPRNGRandom(sharedMemory.K, hrUni.length), hrUni);

      // 4. Sends m3.
      ListData m3Data = new ListData(Arrays.asList(sharedMemory.Sn, AUi));
      return m3Data.toBytes();
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
        // Show proof.
        if (message.getData() != null) {
          byte[] data = this.showProof(message.getData());

          if (data != null) {
            LOG.debug("show proof complete");

            // Save the data for the corresponding GET.
            ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = data;
            return new Action<>(Action.Status.END_SUCCESS, 8, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 8.
   */
  public static class VState08 extends NFCAndroidState {

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
            return new Action<>(Action.Status.END_SUCCESS, 9, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 9.
   */
  public static class VState09 extends NFCAndroidState {

    /**
     * Validates the confirmation.
     *
     * @param data The validation data.
     * @return True if validation data was confirmed.
     */
    private boolean getValidationConfirmation(byte[] data) {
      ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      Crypto crypto = Crypto.getInstance();

      // Extract out the fields of the signed verification response data.
      final ListData RStarData = ListData.fromBytes(data);

      if (RStarData.getList().size() != 2) {
        return false;
      }

      byte[] RData = RStarData.getList().get(0);
      byte[] sigPR = RStarData.getList().get(1);

      // And the fields of the verification response data.
      final ListData R = ListData.fromBytes(RData);

      if (R.getList().size() != 3) {
        return false;
      }

      sharedMemory.APi = R.getList().get(0);
      // Sn not used.
      // tau2 not used.

      // 1. Check's the signature of RStar.
      final byte[] hashRDataCheck = crypto.getHash(RData);
      final byte[] hashRData = crypto.decrypt(sigPR, crypto.getRemotePublicKey());

      boolean result = (RData != null) && (sigPR != null) && (hashRDataCheck != null) && (hashRData != null) && (Arrays.equals
          (hashRDataCheck, hashRData));

      if (!result) {
        return false;
      }

      // 2. Computes hrIni.
      byte[] hK = crypto.getHash(sharedMemory.K);
      final byte[] hrIni = Crypto.xor(sharedMemory.APi, crypto.getPRNGRandom(hK, sharedMemory.APi.length));

      // Make sure we have a hrInCurrent the first time round a ticket is used.
      if (sharedMemory.hrInCurrent == null) {
        sharedMemory.hrInCurrent = sharedMemory.hrIn;
      }

      // 3. Verifies hrIni.
      if (!Arrays.equals(sharedMemory.hrInCurrent, crypto.getHash(hrIni, sharedMemory.i - sharedMemory.j))) {
        return false;
      }

      // 4. Stores and updates.
      sharedMemory.RStar = data;
      sharedMemory.hrInCurrent = hrIni;
      sharedMemory.j = sharedMemory.i;

      return true;
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
        // Get the validation confirmation.
        if (message.getData() != null) {
          if (this.getValidationConfirmation(message.getData())) {
            LOG.debug("get validation confirmation complete");

            // Continue but allowing another ticket to be requested via state 6.
            return new Action<>(Action.Status.END_SUCCESS, 6, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
