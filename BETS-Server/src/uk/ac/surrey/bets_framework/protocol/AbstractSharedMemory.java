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
 * @author Steve Wesemeyer
 */
public abstract class AbstractSharedMemory implements SharedMemory {
  
  
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
