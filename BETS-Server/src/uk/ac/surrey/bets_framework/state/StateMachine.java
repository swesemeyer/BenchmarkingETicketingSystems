/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.state;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

/**
 * Abstract state machine, where the action command to be executed is abstracted as a generic type. Extend this class to create a
 * working state machine.
 *
 * @author Matthew Casey
 */
public abstract class StateMachine<T> {

  /** Logback logger. */
  private static final Logger       LOG            = LoggerFactory.getLogger(StateMachine.class);

  /** Suffix to timing block name used for timing actions. */
  private static final String       TIMING_ACTION  = "-Action";

  /** Suffix to timing block name used for timing commands. */
  private static final String       TIMING_COMMAND = "-Command";

  /** The current state. */
  private int                       currentState   = 0;

  /** The state machine parameters. */
  private final List<String>        parameters     = new ArrayList<>();

  /** The list of states in the state machine. */
  private final List<State<T>>      states         = new ArrayList<>();

  /** The recorded timings for this state machine. */
  private final Map<String, Timing> timings        = new HashMap<>();

  /**
   * Constructor for the state machine which takes an array of the states. The first state is assumed to be the initial state.
   *
   * @param states The array of states in the state machine.
   */
  protected StateMachine(List<State<T>> states) {
    super();

    this.states.addAll(states);

    // Set the state machine for each of the states.
    for (final State<T> state : this.states) {
      state.setStateMachine(this);
    }
  }

  /**
   * @return The (unmodifiable) list of parameters.
   */
  public List<String> getParameters() {
    return Collections.unmodifiableList(this.parameters);
  }

  /**
   * @return The shared memory for the state machine.
   */
  public abstract SharedMemory getSharedMemory();

  /**
   * @return The recorded timings for this state machine (immutable).
   */
  public Map<String, Timing> getTimings() {
    return Collections.unmodifiableMap(this.timings);
  }

  /**
   * Performs the required action. Use this to execute the action's command with its associated data.
   *
   * @param action The action to perform.
   * @return The resulting message to be fed into the next stage of the state machine.
   */
  protected abstract Message performAction(Action<T> action);

  /**
   * Runs the state machine from the start.
   *
   * @return True if everything went successfully.
   */
  public boolean run() {
    return this.run(new Message(Type.START));
  }

  /**
   * Runs the state machine.
   *
   * @return True if everything went successfully.
   */
  public boolean run(Message message) {
    boolean result = false;

    // Run the state machine until we get an end message.
    this.startTiming(this.getClass().getSimpleName());
    LOG.debug("started timing of "+this.getClass().getSimpleName());
    
    boolean finished = false;

    while (!finished) {
      if ((this.currentState >= 0) && (this.currentState < this.states.size())) {
        final State<T> state = this.states.get(this.currentState);
        LOG.debug("processing {} in state {}", message, state);

        this.startTiming(state.getClass().getSimpleName() + TIMING_ACTION,message.getData());
        final Action<T> action = state.getAction(message);
        this.stopTiming(state.getClass().getSimpleName() + TIMING_ACTION);

        // Move to the next state, if required.
        if (action.getNextState() != Action.NO_STATE_CHANGE) {
          this.currentState = action.getNextState();
          LOG.debug("moving to state {}", this.states.get(this.currentState));
        }

        // Perform the required action and construct the next message.
        if (action.getCommand() != null) {
          LOG.debug("executing action {}", action);

          this.startTiming(state.getClass().getSimpleName() + TIMING_COMMAND,action.getCommandData());
          message = this.performAction(action);
          this.stopTiming(state.getClass().getSimpleName() + TIMING_COMMAND);
        }
        else {
          // No action, so construct a dummy success message.
          message = new Message();
        }

        // Add in any end message.
        if (action.getStatus().equals(Status.END_SUCCESS)) {
          finished = true;
          result = true;
          LOG.debug("ending successfully");
        }
        else if (action.getStatus().equals(Status.END_FAILURE)) {
          finished = true;
          LOG.debug("ending on error");
        }
      }
      else {
        LOG.error("invalid current state {}", this.currentState);
      }
    }

    this.stopTiming(this.getClass().getSimpleName());
    LOG.debug("stopped timing of "+this.getClass().getSimpleName());
    return result;
  }

  /**
   * Sets the state machine parameters, clearing out any existing parameters.
   *
   * @param parameters The list of parameters.
   */
  public void setParameters(List<String> parameters) {
    this.parameters.clear();
    this.parameters.addAll(parameters);
  }

  /**
   * Sets the shared memory for the state machine.
   *
   * @param sharedMemory The shared memory to set.
   */
  public abstract void setSharedMemory(SharedMemory sharedMemory);

  /**
   * Starts timing against the specified name. Call this with a relevant name to time any block of execution.
   *
   * @param name The name of the timing block.
   */
  protected void startTiming(String name) {
    // Find any existing timing for the name, creating one if needed.
    Timing timing = this.timings.get(name);

    if (timing == null) {
      timing = new Timing(name);
      this.timings.put(name, timing);
    }

    // Start timing.
    timing.start();
  }

  /**
   * Starts timing against the specified name and accumulates the number of bytes processed
   *
   * @param name The name of the timing block.
   * @param data The data to be processed
   */
  protected void startTiming(String name, byte[] data) {
    // Find any existing timing for the name, creating one if needed.
    Timing timing = this.timings.get(name);

    if (timing == null) {
      timing = new Timing(name);
      this.timings.put(name, timing);
    }

    // Start timing.
    timing.start();
    timing.addData(data);
  }
  
  
  /**
   * Stops timing against the specified name. Call this with a relevant name to time any block of execution. If
   * {@link #startTiming(String)} has not been called previously for the same name, this method does nothing.
   *
   * @param name The name of the timing block.
   */
  protected void stopTiming(String name) {
    // Find any existing timing for the name. We do nothing if the timing block does not exist.
    final Timing timing = this.timings.get(name);

    // Stop timing.
    if (timing != null) {
      timing.stop();
    }
  }

  /**
   * @return Returns a string representation of the object.
   */
  @Override
  public String toString() {
    return this.getClass().getSimpleName();
  }
}
