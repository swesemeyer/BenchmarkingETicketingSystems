/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.control.teardown;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import uk.ac.surrey.bets_framework.protocol.NFCReaderStateMachine;
import uk.ac.surrey.bets_framework.protocol.NFCSharedMemory;
import uk.ac.surrey.bets_framework.protocol.control.ControlStates;
import uk.ac.surrey.bets_framework.state.SharedMemory;
import uk.ac.surrey.bets_framework.state.Timing;

/**
 * Control protocol state machine used to tear down the client.
 *
 * @author Matthew Casey
 */
public class TearDown extends NFCReaderStateMachine {

  /**
   * The implementation of the state machine's shared memory.
   */
  public class TearDownSharedMemory extends NFCSharedMemory {

    /** The timings data retrieved from the client. */
    public TimingsData timingsData = null;

  }

  /** The shared memory. */
  private TearDownSharedMemory sharedMemory = new TearDownSharedMemory();

  /**
   * Default constructor.
   */
  public TearDown() {
    super(Arrays.asList(new ControlStates.ControlState0(), new ControlStates.ControlState1(), new TearDownStates.TearDownState2(),
        new TearDownStates.TearDownState3()));
  }

  /**
   * @return The timings data retrieved from the client on successful completion of tear down.
   */
  public List<Map<String, Timing>> getClientTimings() {
    return this.sharedMemory.timingsData.getTimings();
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
    this.sharedMemory = (TearDownSharedMemory) sharedMemory;
  }
}
