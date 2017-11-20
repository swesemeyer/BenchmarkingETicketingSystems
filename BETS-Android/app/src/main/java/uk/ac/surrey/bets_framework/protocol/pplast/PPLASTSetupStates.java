package uk.ac.surrey.bets_framework.protocol.pplast;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.Data;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * The set-up states for the PPLAST protocol.
 *
 * (c) Steve Wesemeyer 2017
 */

public class PPLASTSetupStates {


  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PPLASTSetupStates.class);

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
        PPLASTSharedMemory sharedMemory = PPLASTSharedMemory.fromJson(new String(data, Data.UTF8));

        // Initialise the shared memory which has not been copied in.
        sharedMemory.clearAndroid();

        this.setSharedMemory(sharedMemory);
        LOG.debug("deserialised the shared memory");

      } catch (UnsupportedEncodingException e) {
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
