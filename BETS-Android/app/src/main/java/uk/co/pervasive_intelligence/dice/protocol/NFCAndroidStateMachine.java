/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol;

import java.util.List;

import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.State;
import uk.co.pervasive_intelligence.dice.state.StateMachine;

/**
 * Abstract state machine for the NFC Android.
 *
 * @author Matthew Casey
 */
public abstract class NFCAndroidStateMachine extends StateMachine<NFCAndroidCommand> {

  /**
   * Constructor for the state machine which takes an array of the states. The first state is assumed to be the initial state.
   *
   * @param states The array of states in the state machine.
   */
  protected NFCAndroidStateMachine(List<State<NFCAndroidCommand>> states) {
    super(states);
  }

  /**
   * Performs the required action.
   *
   * @param action The action to perform.
   * @return The resulting message to be fed into the next stage of the state machine.
   */
  @Override
  protected Message performAction(Action<NFCAndroidCommand> action) {
    if (action.getCommand() == NFCAndroidCommand.RESPONSE) {
      // Store the response data for return to the server.
      ((NFCAndroidSharedMemory) this.getSharedMemory()).response = action.getCommandData();
    }

    return null; // No resulting message.
  }

  /**
   * Runs the state machine.
   *
   * @param message The message to be processed.
   * @return True if everything went successfully.
   */
  @Override
  public boolean run(Message message) {
    // Reset the response which will be built during the run.
    ((NFCAndroidSharedMemory) this.getSharedMemory()).response = null;

    return super.run(message);
  }
}
