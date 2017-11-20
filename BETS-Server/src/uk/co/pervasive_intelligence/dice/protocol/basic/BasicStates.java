/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.basic;

import java.util.Arrays;

import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * States of the basic state machine protocol.
 *
 * @author Matthew Casey
 */
public class BasicStates {

  /**
   * State 0.
   */
  public static class BasicState0 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.START) {
        
       // Open the connection.
        return new Action<>(1, NFCReaderCommand.OPEN);
      }
      else if (message.getType() == Type.SUCCESS) {

        // Successful completion.
        return new Action<>(Status.END_SUCCESS);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 1.
   */
  public static class BasicState1 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {

        // Put the basic data payload.
        return new Action<>(Status.CONTINUE, 2, NFCReaderCommand.PUT, ((BasicSharedMemory) this.getSharedMemory()).data, 0);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 2.
   */
  public static class BasicState2 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the data payload.
        return new Action<>(Status.CONTINUE, 3, NFCReaderCommand.GET, null,
            ((BasicSharedMemory) this.getSharedMemory()).data.length);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 3.
   */
  public static class BasicState3 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Check that the data payload is correct.
        if (Arrays.equals(((BasicSharedMemory) this.getSharedMemory()).data, message.getData())) {
          return new Action<>(0, NFCReaderCommand.CLOSE);
        }
      }

      return super.getAction(message);
    }
  }
}
