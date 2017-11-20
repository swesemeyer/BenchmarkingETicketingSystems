/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.command;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.IStringConverterFactory;

/**
 * JCommander factory used to convert custom arguments.
 *
 * @author Matthew Casey
 */
public class JCommanderFactory implements IStringConverterFactory {

  /**
   * Works out which converter should be used.
   *
   * @param forType The type to convert.
   * @return The corresponding converter, or null if unknown.
   */
  @Override
  @SuppressWarnings("unchecked")
  public Class<? extends IStringConverter<?>> getConverter(@SuppressWarnings("rawtypes") Class forType) {
    if (forType.getName().equals(ProtocolRun.class.getName())) {
      return ProtocolRunConverter.class;
    }
    else {
      return null;
    }
  }
}
