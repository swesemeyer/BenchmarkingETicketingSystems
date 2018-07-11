/**
 * DICE Protocol evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol;

import java.util.List;

import uk.ac.surrey.bets_framework.icc.ICC;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.StateMachine;

/**
 * Abstract state machine for the Internal Comms Channel
 *
 * @author Steve Wesemeyer
 */
public abstract class ICCStateMachine extends StateMachine<ICCCommand> {

  /**
   * Constructor for the state machine which takes an array of the states. The first state is assumed to be the initial state.
   *
   * @param states The array of states in the state machine.
   */
  protected ICCStateMachine(List<State<ICCCommand>> states) {
    super(states);
  }

  /**
   * Performs the required action. Use this to execute the action's command with its associated data.
   *
   * @param action The action to perform.
   * @return The resulting message to be fed into the next stage of the state machine.
   */
  @Override
  protected Message performAction(Action<ICCCommand> action) {
    Message message = null;
    boolean result = false;

    switch (action.getCommand()) {
      case CLOSE:
        result = ICC.getInstance().close();
        message = result ? new Message() : new Message(ICC.getInstance().getResponseCode());
        break;

      case GET:
        result = ICC.getInstance().get(action.getCommandResponseLength());
        message = result ? new Message(ICC.getInstance().getData()) : new Message(ICC.getInstance().getResponseCode());
        break;
      

      case OPEN:
        result = ICC.getInstance().open();
        message = result ? new Message() : new Message(ICC.getInstance().getResponseCode());
        break;

      case PUT:
        result = ICC.getInstance().put(action.getCommandData());
        message = result ? new Message() : new Message(ICC.getInstance().getResponseCode());
        break;
              
      default:
        // Do nothing.
        break;
    }

    return message;
  }
}
