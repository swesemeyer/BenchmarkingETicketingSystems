/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol;

/**
 * Shared memory for the NFC Android state machine.
 *
 * @author Matthew Casey
 */
public class NFCAndroidSharedMemory extends NFCSharedMemory {

  /** Response continue code. */
  public static final byte[] RESPONSE_CONTINUE = new byte[]{(byte) 0x90, 0x01};

  /** Response failure code. */
  public static final byte[] RESPONSE_FAIL = new byte[]{(byte) 0x63, 0x00};

  /** Function not support response code. */
  public static final byte[] RESPONSE_FUNCTION_NOT_SUPPORTED = new byte[]{0x6A, (byte) 0x81};

  /** Response OK code. */
  public static final byte[] RESPONSE_OK = new byte[]{(byte) 0x90, 0x00};
  /** The response to a PUT which must wait for a GET. */
  public byte[] delayedResponse = null;
  /** The response to be sent to the server. */
  public byte[] response = null;


}
