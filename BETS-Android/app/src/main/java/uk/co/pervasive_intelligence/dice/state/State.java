/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.state;

import java.lang.ref.WeakReference;

import uk.co.pervasive_intelligence.dice.state.Action.Status;

/**
 * Abstract state class which determines what happens when a message is received, where the action command to be executed is
 * abstracted as a generic type.
 *
 * @author Matthew Casey
 */
public abstract class State<T> {

  /** The parent state machine so that access to shared memory can be obtained. Weak to prevent retain loops. */
  private WeakReference<StateMachine<T>> stateMachine = null;

  /**
   * Gets the required action given a message. Override this method to execute the required actions, but call back to it at the end
   * of processing to cause a failure if no action has been set.
   *
   * @param message The received message to process.
   * @return The required action.
   */
  public Action<T> getAction(Message message) {
    return new Action<>(Status.END_FAILURE);
  }

  /**
   * @return The shared memory for the state machine.
   */
  protected SharedMemory getSharedMemory() {
    return this.getStateMachine().getSharedMemory();
  }

  /**
   * Sets the shared memory for the state machine.
   *
   * @param sharedMemory The shared memory to set.
   */
  protected void setSharedMemory(SharedMemory sharedMemory) {
    this.getStateMachine().setSharedMemory(sharedMemory);
  }

  /**
   * @return The parent state machine so that access to shared memory can be obtained.
   */
  final StateMachine<T> getStateMachine() {
    return this.stateMachine.get();
  }

  /**
   * Sets the parent state machine.
   *
   * @param stateMachine The parent state machine so that access to shared memory can be obtained.
   */
  final void setStateMachine(StateMachine<T> stateMachine) {
    this.stateMachine = new WeakReference<StateMachine<T>>(stateMachine);
  }

  /**
   * Starts timing against the specified name. Convenience method to call back to the parent state machine to start timing.
   *
   * @param name The name of the timing block.
   */
  protected void startTiming(String name) {
    this.getStateMachine().startTiming(name);
  }

  /**
   * Starts timing against the specified name and accumulates the number of bytes processed.
   * Convenience method to call back to the parent state machine to start timing.
   *
   * @param name The name of the timing block.
   * @param data The data to be processed
   */
  protected void startTiming(String name, byte[] data) {
    this.getStateMachine().startTiming(name, data);
  }

  /**
   * Stops timing against the specified name. Convenience method to call back to the parent state machine to stop timing.
   *
   * @param name The name of the timing block.
   */
  protected void stopTiming(String name) {
    this.getStateMachine().stopTiming(name);
  }

  /**
   * @return Returns a string representation of the object.
   */
  @Override
  public String toString() {
    return this.getClass().getSimpleName();
  }
}
