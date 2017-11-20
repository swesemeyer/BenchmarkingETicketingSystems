/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol;

import java.util.Arrays;

import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * Abstract NFC Android state.
 *
 * @author Matthew Casey
 */
public class NFCAndroidState extends State<NFCAndroidCommand> {

  /**
   * Adds the response code to the end of the data buffer.
   *
   * @param data         The data buffer.
   * @param responseCode The response code to add.
   * @return The new response buffer.
   */
  protected byte[] addResponseCode(byte[] data, byte[] responseCode) {
    byte[] response = Arrays.copyOf(data, data.length + responseCode.length);
    System.arraycopy(responseCode, 0, response, data.length, responseCode.length);

    return response;
  }

  /**
   * Gets the required action given a message. Override this method to prevent failure being returned.
   *
   * @param message The received message to process.
   * @return The required action.
   */
  @Override
  public Action<NFCAndroidCommand> getAction(Message message) {
    return new Action<>(Action.Status.END_FAILURE, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory
        .RESPONSE_FAIL, 0);
  }
}
