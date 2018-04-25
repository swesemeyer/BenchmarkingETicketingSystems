package uk.ac.surrey.bets_framework.protocol.anonsso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.Data;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * The set-up states for the AnonSSO protocol.
 * <p>
 * (c) Steve Wesemeyer 2017
 */

public class AnonSSOSetupStates {


  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AnonSSOSetupStates.class);

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
      // Decode the shared memory.
      LOG.debug("deserialising the shared memory");
      AnonSSOSharedMemory sharedMemory = AnonSSOSharedMemory.fromJson(new String(data, Data.UTF8));

      LOG.debug("initialising the Android client");
      // Initialise the shared memory which has not been copied in.
      sharedMemory.clearAndroid();

      LOG.debug("storing the shared memory");
      this.setSharedMemory(sharedMemory);

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
          LOG.debug("generate setup complete");
          return new Action<>(Action.Status.END_SUCCESS, 2, NFCAndroidCommand.RESPONSE,
                  NFCAndroidSharedMemory.RESPONSE_OK, 0);
        }
      }
      return super.getAction(message);
    }
  }


}
