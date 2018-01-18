/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol;

import java.nio.charset.StandardCharsets;

import uk.ac.surrey.bets_framework.state.SharedMemory;

/**
 * Shared memory for the NFC state machine.
 *
 * @author Matthew Casey
 */
public class NFCSharedMemory implements SharedMemory {

  /** Arbitrary proprietary AID (starts with "F") for Android app. Hopefully doesn't clash with anything else. */
  public static final byte[] AID = new byte[]{(byte) 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

  /** The maximum size of a response before it needs to be chunked. */
  public static final int APDU_CHUNK_SIZE = 32;

  /**
   * Convenience method to create a String from a byte array.
   *
   * @param bytes The bytes containing the string data.
   * @return The new String.
   */
  public String stringFromBytes(byte[] bytes) {
    final String string = new String(bytes, StandardCharsets.UTF_8);
    return string;
  }

  /**
   * Convenience method to create a byte array from a string
   *
   * @param msg The string to be converted.
   * @return The byte array.
   */
  public byte[] stringToBytes(String msg) {
    return msg.getBytes(StandardCharsets.UTF_8);
  }

}
