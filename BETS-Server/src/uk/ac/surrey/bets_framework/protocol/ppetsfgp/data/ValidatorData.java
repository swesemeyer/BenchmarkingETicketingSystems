/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp.data;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory;

import java.math.BigInteger;

/**
 * Implements validator data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class ValidatorData implements PPETSFGPSharedMemory.ActorData {

  /** Ticket transcript D. */
  public Element    D      = null;

  /** Previous ticket transcript D. */
  public Element    D_last = null;

  /** Ticket transcript E. */
  public Element    E      = null;

  /** Previous ticket transcript E. */
  public Element    E_last = null;

  /** Ticket transcript F. */
  public Element    F      = null;

  /** Previous ticket transcript F. */
  public Element    F_last = null;

  /** Ticket transcript J. */
  public Element    J      = null;

  /** Previous ticket transcript J. */
  public Element    J_last = null;

  /** Ticket transcript r. */
  public BigInteger r      = null;

  /** Previous ticket transcript r. */
  public BigInteger r_last = null;

  /** Ticket transcript Y. */
  public Element    Y      = null;

  /** Previous ticket transcript Y. */
  public Element    Y_last = null;

}
