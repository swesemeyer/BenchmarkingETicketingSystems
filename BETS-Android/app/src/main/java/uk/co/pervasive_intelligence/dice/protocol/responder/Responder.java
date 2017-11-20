/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.responder;

import java.util.Arrays;
import java.util.List;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidStateMachine;
import uk.co.pervasive_intelligence.dice.state.SharedMemory;
import uk.co.pervasive_intelligence.dice.state.State;
import uk.co.pervasive_intelligence.dice.state.StateMachine;

/**
 * Responder state machine which responds to all server messages.
 *
 * @author Matthew Casey
 */
public class Responder extends NFCAndroidStateMachine {

  /** The shared memory. */
  private ResponderSharedMemory sharedMemory = new ResponderSharedMemory();

  /**
   * Constructor requiring the list of available classes.
   *
   * @param classes The list of available classes.
   */
  public Responder(List<String> classes) {
    super(Arrays.<State<NFCAndroidCommand>>asList(new ResponderStates.ResponderState0(), new ResponderStates.ResponderState1(),
            new ResponderStates.ResponderState2()));

    this.sharedMemory.classes = classes;
  }

  /**
   * @return The shared memory for the state machine.
   */
  @Override
  public SharedMemory getSharedMemory() {
    return this.sharedMemory;
  }

  /**
   * Sets the shared memory for the state machine.
   *
   * @param sharedMemory The shared memory to set.
   */
  @Override
  public void setSharedMemory(SharedMemory sharedMemory) {
    this.sharedMemory = (ResponderSharedMemory) sharedMemory;
  }


}
