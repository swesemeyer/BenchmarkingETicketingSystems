/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.state;

import uk.ac.surrey.bets_framework.Utils;

/**
 * State machine message.
 *
 * @author Matthew Casey
 */
public class Message {

  /** Any associated data for {@link Type#DATA} messages. */
  private byte[] data = null;

  /** Any associated failure code for {@link Type#FAILURE} messages. */
  private int failureCode = 0;

  /** The message type. */
  private Type type = null;

  /**
   * Default constructor for a {@link Type#SUCCESS} message.
   */
  public Message() {
    this(Type.SUCCESS, 0, null);
  }

  /**
   * Constructor for a {@link Type#DATA} message with data.
   *
   * @param data The data.
   */
  public Message(byte[] data) {
    this(Type.DATA, 0, data);
  }

  /**
   * Constructor for a {@link Type#FAILURE} message with failure code.
   *
   * @param failureCode The failure code.
   */
  public Message(int failureCode) {
    this(Type.FAILURE, failureCode, null);
  }

  /**
   * Constructor for an arbitrary message which does not have a failure code or data.
   *
   * @param type The message type.
   */
  public Message(Type type) {
    this(type, 0, null);
  }

  /**
   * Constructor requiring all fields.
   *
   * @param type        The message type.
   * @param failureCode Any associated failure code for {@link Type#FAILURE} messages.
   * @param data        Any associated data for {@link Type#DATA} messages.
   */
  public Message(Type type, int failureCode, byte[] data) {
    super();

    this.type = type;
    this.failureCode = failureCode;
    this.data = data;
  }

  /**
   * @return Any associated data for {@link Type#DATA} messages.
   */
  public byte[] getData() {
    return this.data;
  }

  /**
   * @return Any associated failure code for {@link Type#FAILURE} messages.
   */
  public int getFailureCode() {
    return this.failureCode;
  }

  /**
   * @return The message type.
   */
  public Type getType() {
    return this.type;
  }

  /**
   * @return Returns a string representation of the object.
   */
  @Override
  public String toString() {
    return this.type + " (" + Utils.toHex(this.data) + ", " + this.failureCode + ")";
  }

  /**
   * Defines all possible message types.
   */
  public enum Type {
    DATA, FAILURE, START, SUCCESS
  }
}
