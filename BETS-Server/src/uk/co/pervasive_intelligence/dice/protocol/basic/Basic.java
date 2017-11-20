/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.basic;

import java.util.Arrays;

import uk.co.pervasive_intelligence.dice.protocol.NFCReaderStateMachine;
import uk.co.pervasive_intelligence.dice.state.SharedMemory;

/**
 * Implements a basic NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class Basic extends NFCReaderStateMachine {

  /** The shared memory. */
  private BasicSharedMemory sharedMemory = new BasicSharedMemory();

  /**
   * Default constructor.
   */
  public Basic() {
    super(Arrays.asList(new BasicStates.BasicState0(), new BasicStates.BasicState1(), new BasicStates.BasicState2(),
        new BasicStates.BasicState3()));
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
    this.sharedMemory = (BasicSharedMemory) sharedMemory;
  }
}
