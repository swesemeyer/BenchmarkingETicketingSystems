/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.command;

import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.IStringConverter;

/**
 * JCommander converter used to convert {@link ProtocolRun} arguments to objects.
 *
 * @author Matthew Casey
 */
public class ProtocolRunConverter implements IStringConverter<ProtocolRun> {

  /**
   * @return An object of type {@link ProtocolRun} created from the parameter value.
   */
  @Override
  public ProtocolRun convert(String value) {
    final String[] arguments = value.split(":");

    int iterations = 1;
    final List<String> parameters = new ArrayList<>();

    for (int i = 1; i < arguments.length; i++) {
      try {
        if (i == 1) {
          iterations = Integer.parseInt(arguments[i]);
        }
        else {
          parameters.add(arguments[i]);
        }
      }
      catch (final NumberFormatException e) {
        // Ignore and use default.
      }
    }

    return new ProtocolRun(arguments[0], iterations, parameters);
  }
}
