/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.data;

/**
 * Exception for data exchange.
 *
 * @author Matthew Casey
 */
public class DataException extends Exception {

  /** Serialisation. */
  private static final long serialVersionUID = 8212781622699713842L;

  /**
   * Default constructor.
   */
  public DataException() {
    super();
  }

  /**
   * Constructs a new exception with the specified detail message. The cause is not initialized, and may subsequently be initialized
   * by a call to {@link #initCause}.
   *
   * @param message the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
   */
  public DataException(String message) {
    super(message);
  }

  /**
   * Constructs a new exception with the specified detail message and cause.
   * <p>
   * Note that the detail message associated with {@code cause} is <i>not</i> automatically incorporated in this exception's detail
   * message.
   *
   * @param message the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
   * @param cause   the cause (which is saved for later retrieval by the {@link #getCause()} method). (A <tt>null</tt> value is
   *                permitted, and indicates that the cause is nonexistent or unknown.)
   * @since 1.4
   */
  public DataException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new exception with the specified cause and a detail message of <tt>(cause==null ? null : cause.toString())</tt>
   * (which typically contains the class and detail message of <tt>cause</tt>). This constructor is useful for exceptions that are
   * little more than wrappers for other throwables (for example, {@link java.security.PrivilegedActionException}).
   *
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method). (A <tt>null</tt> value is
   *              permitted, and indicates that the cause is nonexistent or unknown.)
   * @since 1.4
   */
  public DataException(Throwable cause) {
    super(cause);
  }
}
