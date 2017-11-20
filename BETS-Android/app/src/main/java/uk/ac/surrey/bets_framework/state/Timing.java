/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.state;

/**
 * Encapsulates a named timing block and the number of times it has been recorded.
 *
 * @author Matthew Casey
 */
public class Timing {

  /** The total number of times that a block of time has been recorded. */
  private long   count        = 0L;

  /** The creation time of the timer. This will help with ordering them in the CSV file */
  private long   creationTime = 0L;

  /** The number of bytes processed */
  private long   dataSize     = 0L;

  /** The name of the block. */
  private String name         = null;

  /** The last start time of a block. */
  private long   start        = 0L;

  /** The total time that this block has recorded. */
  private long   time         = 0L;

  /**
   * Constructs a timing block with the associated name.
   *
   * @param name The name of the timing block.
   */
  public Timing(String name) {
    super();

    this.name = name;
    this.creationTime = System.currentTimeMillis();

    // Just in case, make sure we have a valid start point.
    this.start();
  }

  public void addData(byte[] data) {
    if ((data != null) && (data.length > 0)) {
      this.dataSize = this.dataSize + data.length;
    }

  }

  /**
   * @return The total number of times that a block of time has been recorded.
   */
  public long getCount() {
    return this.count;
  }

  /**
   * returns the time the timer was created
   *
   * @return The time the timer was created in millisecs
   */
  public long getCreationTime() {
    return this.creationTime;
  }

  /**
   * @return Returns the size of data processed
   */
  public long getDataSize() {
    return this.dataSize;
  }

  /**
   * @return The name of the block.
   */
  public String getName() {
    return this.name;
  }

  /**
   * @return The total time that this block has recorded.
   */
  public long getTime() {
    return this.time;
  }

  /**
   * Starts timing.
   */
  public void start() {
    this.start = System.currentTimeMillis();
  }

  /**
   * Stops timing and accumulates the total time and count.
   */
  public void stop() {
    final long stop = System.currentTimeMillis();

    this.time += stop - this.start;
    this.count++;
  }

  /**
   * @return Returns a string representation of the object.
   */
  @Override
  public String toString() {
    String toString = this.name + ": " + this.time + "ms x " + this.count;
    if (this.dataSize > 0) {
      toString = toString + " data bytes processed: " + this.dataSize;
    }
    return toString;
  }
}
