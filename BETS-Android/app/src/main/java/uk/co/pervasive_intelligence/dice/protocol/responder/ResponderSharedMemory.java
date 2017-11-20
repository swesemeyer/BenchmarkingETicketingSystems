package uk.co.pervasive_intelligence.dice.protocol.responder;

import java.util.List;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.state.StateMachine;

/**
 * The implementation of the state machine's shared memory.
 */
public class ResponderSharedMemory extends NFCAndroidSharedMemory {

  /**
   * The length of a command.
   */
  public static final int COMMAND_CLA_INS_P1_P2_LENGTH = 4;

  /**
   * The location of the data length in the APDU.
   */
  public static final int COMMAND_CLA_INS_P1_P2_DATA = COMMAND_CLA_INS_P1_P2_LENGTH;

  /**
   * Get data command APDU.
   */
  public static final byte[] COMMAND_GET_CLA_INS_P1_P2 = new byte[]{0x00, (byte) 0xCA, 0x00, 0x00};

  /**
   * Put data command APDU.
   */
  public static final byte[] COMMAND_PUT_CLA_INS_P1_P2 = new byte[]{0x00, (byte) 0xDA, 0x00, 0x00};

  /**
   * Select command APDU.
   */
  public static final byte[] COMMAND_SELECT_CLA_INS_P1_P2 = new byte[]{0x00, (byte) 0xA4, 0x04, 0x00};

  /**
   * The list of all classes within the parent package.
   */
  public List<String> classes = null;

  /**
   * The data which is currently being chunked up as a series of requests.
   */
  public byte[] requestChunked = null;

  /**
   * The current index into the response chunked data.
   */
  public int responseChunkIndex = 0;

  /**
   * The data which is currently being chunked up as a series of responses.
   */
  public byte[] responseChunked = null;

  /**
   * The protocol state machine.
   */
  public StateMachine<?> stateMachine = null;

  /**
   * Default constructor
   */
  public ResponderSharedMemory(){
    super();
  }
}