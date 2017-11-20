/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol;

import java.util.List;

import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.StateMachine;

/**
 * Abstract state machine for the NFC reader.
 *
 * @author Matthew Casey
 */
public abstract class NFCReaderStateMachine extends StateMachine<NFCReaderCommand> {

  /**
   * Constructor for the state machine which takes an array of the states. The first state is assumed to be the initial state.
   *
   * @param states The array of states in the state machine.
   */
  protected NFCReaderStateMachine(List<State<NFCReaderCommand>> states) {
    super(states);
  }

  /**
   * Performs the required action. Use this to execute the action's command with its associated data.
   *
   * @param action The action to perform.
   * @return The resulting message to be fed into the next stage of the state machine.
   */
  @Override
  protected Message performAction(Action<NFCReaderCommand> action) {
    Message message = null;
    boolean result = false;

    switch (action.getCommand()) {
      case CLOSE:
        result = NFC.getInstance().close();
        message = result ? new Message() : new Message(NFC.getInstance().getResponseCode());
        break;

      case GET:
        result = NFC.getInstance().get(action.getCommandResponseLength());
        message = result ? new Message(NFC.getInstance().getData()) : new Message(NFC.getInstance().getResponseCode());
        break;
        
      case GET_INTERNAL:
        result = NFC.getInstance().get_internal(action.getCommandResponseLength());
        message = result ? new Message(NFC.getInstance().getData()) : new Message(NFC.getInstance().getResponseCode());
        break;        

      case OPEN:
        result = NFC.getInstance().open();
        message = result ? new Message() : new Message(NFC.getInstance().getResponseCode());
        break;

      case PUT:
        result = NFC.getInstance().put(action.getCommandData());
        message = result ? new Message() : new Message(NFC.getInstance().getResponseCode());
        break;
        
      case PUT_INTERNAL:
        result = NFC.getInstance().put_internal(action.getCommandData());
        message = result ? new Message() : new Message(NFC.getInstance().getResponseCode());
        break;        

      case SELECT:
        result = NFC.getInstance().select(action.getCommandData());
        message = result ? new Message() : new Message(NFC.getInstance().getResponseCode());
        break;

      default:
        // Do nothing.
        break;
    }

    return message;
  }
}
