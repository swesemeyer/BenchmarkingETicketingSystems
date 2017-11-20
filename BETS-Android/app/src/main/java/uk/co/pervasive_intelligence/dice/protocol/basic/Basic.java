/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.basic;

import java.util.Arrays;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidStateMachine;
import uk.co.pervasive_intelligence.dice.state.SharedMemory;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * Implements a basic NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class Basic extends NFCAndroidStateMachine {

  /**
   * The shared memory.
   */
  private BasicSharedMemory sharedMemory = new BasicSharedMemory();

  /**
   * Default constructor.
   */
  public Basic() {
    super(Arrays.<State<NFCAndroidCommand>>asList(new BasicStates.BasicState0()));
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
