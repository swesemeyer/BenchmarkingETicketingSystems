package uk.co.pervasive_intelligence.dice.protocol.basic;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;


/**
 * The implementation of the state machine's shared memory.
 */
public class BasicSharedMemory extends NFCAndroidSharedMemory {

  /** The received data. */
  public byte[] data = null;


  /**
   * default constructor
   */
  public BasicSharedMemory() {
    super();
  }
}