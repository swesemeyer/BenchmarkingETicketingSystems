/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.state;

import uk.co.pervasive_intelligence.dice.Utils;

/**
 * State machine action which determines what happens next, where the action command to be executed is abstracted as a generic type.
 *
 * @author Matthew Casey
 */
public class Action<T> {

  /**
   * Enumeration of possible state machine action status.
   */
  public enum Status {
    CONTINUE, END_FAILURE, END_SUCCESS
  }

  /** Indicates that the action does not cause any state change. */
  public static final int NO_STATE_CHANGE       = -1;

  /** Which command should be run? May be null to indicate no command. */
  private T               command               = null;

  /** command data. May be null to indicate no command data. */
  private byte[]          commandData           = null;

  /** The required command response data length, if any. */
  private int             commandResponseLength = 0;

  /** What should the next state be? Use {@link #NO_STATE_CHANGE} to stay in the same state. */
  private int             nextState             = NO_STATE_CHANGE;

  /** The status of the state machine. */
  private Status          status                = null;

  /**
   * Default constructor which assumes that the state machine can continue and there is no state change or command.
   */
  public Action() {
    this(Status.CONTINUE, NO_STATE_CHANGE, null, null, 0);
  }

  /**
   * Constructor which assumes that the state machine can continue and omits the optional command, command data and response length.
   *
   * @param nextState What should the next state be? Use {@link #NO_STATE_CHANGE} to stay in the same state.
   */
  public Action(int nextState) {
    this(Status.CONTINUE, nextState, null, null, 0);
  }

  /**
   * Constructor which assumes that the state machine can continue and omits the optional command data and response length.
   *
   * @param nextState What should the next state be? Use {@link #NO_STATE_CHANGE} to stay in the same state.
   * @param command Which NFC command should be run? May be null to indicate no command.
   */
  public Action(int nextState, T command) {
    this(Status.CONTINUE, nextState, command, null, 0);
  }

  /**
   * Constructor which allows the status to be set, but otherwise assumes that there is no state change or command.
   *
   * @param status The status of the state machine.
   */
  public Action(Status status) {
    this(status, NO_STATE_CHANGE, null, null, 0);
  }

  /**
   * Constructor requiring all fields.
   *
   * @param status The status of the state machine.
   * @param nextState What should the next state be? Use {@link #NO_STATE_CHANGE} to stay in the same state.
   * @param command Which command should be run? May be null to indicate no command.
   * @param commandData command data. May be null to indicate no command data.
   * @param commandResponseLength The required command response data length, if any.
   */
  public Action(Status status, int nextState, T command, byte[] commandData, int commandResponseLength) {
    super();

    this.status = status;
    this.nextState = nextState;
    this.command = command;
    this.commandData = commandData;
    this.commandResponseLength = commandResponseLength;
  }

  public static int getNoStateChange() {
    return NO_STATE_CHANGE;
  }

  /**
   * @return Which command should be run? May be null to indicate no command.
   */
  public T getCommand() {
    return this.command;
  }

  /**
   * @return command data. May be null to indicate no command data.
   */
  public byte[] getCommandData() {
    return this.commandData;
  }

  /**
   * @return The required command response data length, if any.
   */
  public int getCommandResponseLength() {
    return this.commandResponseLength;
  }

  /**
   * @return What should the next state be? Use {@link #NO_STATE_CHANGE} to stay in the same state.
   */
  public int getNextState() {
    return this.nextState;
  }

  /**
   * @return The status of the state machine.
   */
  public Status getStatus() {
    return this.status;
  }

  /**
   * @return Returns a string representation of the object.
   */
  @Override
  public String toString() {
    return this.command + " (" + Utils.toHex(this.commandData) + ", " + this.commandResponseLength + ") -> " + this.nextState;
  }
}
