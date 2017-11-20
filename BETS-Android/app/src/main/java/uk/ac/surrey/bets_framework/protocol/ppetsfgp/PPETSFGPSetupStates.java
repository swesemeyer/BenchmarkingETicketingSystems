/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.Data;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.SellerData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * Setup states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPSetupStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPSetupStates.class);

  /**
   * State 0.
   */
  public static class SState00 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Process the setup data.
        if (message.getData() != null) {
          if (processSetup(message.getData())) {
            return new Action<>(Action.Status.END_SUCCESS, 1, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }

    /**
     * Processes the setup data bytes.
     *
     * @param data The received setup data.
     * @return True if processing was successful.
     */
    private boolean processSetup(byte[] data) {
      // Use the data to re-create the shared memory so that we have all of the public parameters.
      try {
        // Decode the shared memory.
        PPETSFGPSharedMemory sharedMemory = PPETSFGPSharedMemory.fromJson(new String(data, Data.UTF8));

        // Initialise the shared memory which has not been copied in.
        sharedMemory.clearAndroid();

        this.setSharedMemory(sharedMemory);
        LOG.debug("deserialised the shared memory");

      }
      catch (UnsupportedEncodingException e) {
        LOG.error("could not setup", e);
      }

      return true;
    }
  }

  /**
   * State 1.
   */
  public static class SState01 extends NFCAndroidState {

    /**
     * Generates the setup data.
     *
     * @return The setup data to return
     */
    private byte[] generateSetup() {
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(PPETSFGPSharedMemory.Actor.SELLER);

      // Generate the seller's random number.
      final Crypto crypto = Crypto.getInstance();
      ((SellerData) sharedMemory.getData(PPETSFGPSharedMemory.Actor.SELLER)).x_s = crypto.secureRandom(sharedMemory.p);

      // Send back x_s.
      return ((SellerData) sharedMemory.getData(PPETSFGPSharedMemory.Actor.SELLER)).x_s.toByteArray();
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
        // Send back the setup data.
        if (message.getData() == null) {
          byte[] data = this.generateSetup();

          if (data != null) {
            LOG.debug("generate setup complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 2, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
