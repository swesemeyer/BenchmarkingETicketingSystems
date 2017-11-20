package uk.ac.surrey.bets_framework.protocol.basic;

import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;


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