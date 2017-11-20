/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.command;

import java.util.ArrayList;
import java.util.List;

/**
 * Class to link together protocol names and their number of iterations.
 *
 * @author Matthew Casey
 */
public class ProtocolRun {

  /** The number of times the protocol should be run. */
  private int                iteration  = 1;

  /** The class name for the protocol. */
  private String             name       = null;

  /** Any protocol parameters. */
  private final List<String> parameters = new ArrayList<>();

  /**
   * Constructor requiring fields.
   *
   * @param name The class name for the protocol.
   * @param iteration The number of times the protocol should be run.
   * @param parameters Any protocol parameters.
   */
  public ProtocolRun(String name, int iteration, List<String> parameters) {
    super();

    this.name = name;
    this.iteration = iteration;

    if (parameters != null) {
      this.parameters.addAll(parameters);
    }
  }

  /**
   * @return The number of times the protocol should be run.
   */
  public int getIteration() {
    return this.iteration;
  }

  /**
   * @return The class name for the protocol.
   */
  public String getName() {
    return this.name;
  }

  /**
   * @return Any protocol parameters.
   */
  public List<String> getParameters() {
    return this.parameters;
  }

  /**
   * @return Returns a string representation of the object.
   */
  @Override
  public String toString() {
    final StringBuilder buffer = new StringBuilder();

    buffer.append(this.name);
    buffer.append(":");
    buffer.append(this.iteration);

    if (this.parameters.size() > 0) {
      buffer.append(":");
      final int i = 0;

      for (final String parameter : this.parameters) {
        buffer.append(parameter);

        if (i < (this.parameters.size() - 1)) {
          buffer.append(":");
        }
      }
    }

    return buffer.toString();
  }
}
