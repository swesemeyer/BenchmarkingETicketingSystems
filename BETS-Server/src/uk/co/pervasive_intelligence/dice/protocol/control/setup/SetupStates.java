/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.control.setup;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.control.setup.Setup.SetupSharedMemory;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * States of the setup state machine protocol.
 *
 * @author Matthew Casey
 */
public class SetupStates {

  /**
   * State 2.
   */
  public static class SetupState2 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Put the setup information.
        return new Action<>(Status.CONTINUE, 3, NFCReaderCommand.PUT,
            ((SetupSharedMemory) this.getSharedMemory()).serverData.toBytes(), 0);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 3.
   */
  public static class SetupState3 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the client data.
        return new Action<>(Status.CONTINUE, 4, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 4.
   */
  public static class SetupState4 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Extract the client's data.
        final ClientData clientData = ClientData.fromBytes(message.getData());

        if (clientData != null) {
          Crypto.getInstance().setRemotePublicKey(clientData.getEncodedPublicKey());
          return new Action<>(0, NFCReaderCommand.CLOSE);
        }
      }

      return super.getAction(message);
    }
  }
}
