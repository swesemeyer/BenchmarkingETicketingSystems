package uk.co.pervasive_intelligence.dice.protocol.basic;

import uk.co.pervasive_intelligence.dice.protocol.NFCSharedMemory;

/**
 * The implementation of the state machine's shared memory.
 */
public class BasicSharedMemory extends NFCSharedMemory {

  /** The basic data payload exchanged with the phone app. */
  public byte[] data       = new String("Hello World").getBytes();

  
  /**
   * default constructor
   */
  public BasicSharedMemory() {
    super();
  }
}

