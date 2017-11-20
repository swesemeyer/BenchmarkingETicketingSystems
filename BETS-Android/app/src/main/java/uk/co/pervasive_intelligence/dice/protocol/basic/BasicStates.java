/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.basic;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidState;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;

/**
 * States of the basic state machine protocol.
 *
 * @author Matthew Casey
 */
public class BasicStates {

  /**
   * State 0.
   */
  public static class BasicState0 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // If there is any data, this is a PUT command - just store the data.  Otherwise it is a GET command, in which case we just
        // send the stored data back.
        if (message.getData() != null) {

          // Store the data.
          ((BasicSharedMemory) this.getSharedMemory()).data = message.getData();
          return new Action<>(Action.Status.END_SUCCESS, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE,
              NFCAndroidSharedMemory.RESPONSE_OK, 0);
        }
        else {

          // Send back the data.
          byte[] response = this.addResponseCode(((BasicSharedMemory) this.getSharedMemory()).data, NFCAndroidSharedMemory
              .RESPONSE_OK);
          return new Action<>(Action.Status.END_SUCCESS, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE, response, 0);
        }
      }

      return super.getAction(message);
    }
  }
}
