/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol;

/**
 * Defines all possible NFC commands that can be run against the NFC reader.
 *
 * @author Matthew Casey
 */
public enum NFCReaderCommand {
  CLOSE, GET, GET_INTERNAL, OPEN, PUT, PUT_INTERNAL, SELECT, 
}
