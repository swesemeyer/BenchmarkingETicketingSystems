/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.basic;

import java.util.Arrays;

import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidStateMachine;
import uk.ac.surrey.bets_framework.state.SharedMemory;
import uk.ac.surrey.bets_framework.state.State;

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
