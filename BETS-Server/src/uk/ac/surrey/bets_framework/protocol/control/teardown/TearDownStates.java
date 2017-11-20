/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.control.teardown;

import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.control.teardown.TearDown.TearDownSharedMemory;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

/**
 * States of the tear down state machine protocol.
 *
 * @author Matthew Casey
 */
public class TearDownStates {

  /**
   * State 2.
   */
  public static class TearDownState2 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the timings.
        return new Action<>(Status.CONTINUE, 3, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 3.
   */
  public static class TearDownState3 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Extract the client timings.
        final TimingsData timingsData = TimingsData.fromBytes(message.getData());

        if (timingsData != null) {
          ((TearDownSharedMemory) this.getSharedMemory()).timingsData = timingsData;
          return new Action<>(0, NFCReaderCommand.CLOSE);
        }
      }

      return super.getAction(message);
    }
  }
}
