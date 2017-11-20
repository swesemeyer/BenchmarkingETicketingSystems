/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;

import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory;

/**
 * Implements user data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class UserData implements PPETSFGPSharedMemory.ActorData {

  /** The range policy attributes of U. */
  public static final BigInteger[] A_U_range   = { BigInteger.valueOf(3), BigInteger.valueOf(2) };

  /** The set policy attributes of U. */
  public static final String[]     A_U_set     = { "South", "Commuter", "No disability" };

  /** The identity of U as an arbitrary array of bytes. */
  public static final byte[]       ID_U        = new byte[] { 0x01, 0x01, 0x02, 0x03 };

  /** User credentials: c_u. */
  public BigInteger                c_u         = null;

  /** Random d for ticket. */
  public BigInteger                d           = null;

  /** Ticket_U (d_dash). */
  public BigInteger                d_dash      = null;

  /** Ticket_U (d_u). */
  public BigInteger                d_u         = null;

  /** User credentials: delta_U. */
  public Element                   delta_U     = null;

  /** Ticket_U (omega_u). */
  public BigInteger                omega_u     = null;

  /** Ticket price. */
  public byte[]                    price       = null;

  /** Random r. */
  public BigInteger                r           = null;

  /** User credentials: r_u. */
  public BigInteger                r_u         = null;

  /** Ticket_U (s_u). */
  public byte[]                    s_u         = null;

  /** Ticket service. */
  public byte[]                    service     = null;

  /** Ticket_U (T_U). */
  public Element                   T_U         = null;

  /** Ticket time. */
  public byte[]                    time        = null;

  /** Ticket valid period. */
  public byte[]                    validPeriod = null;

  /** Random x_u. */
  public BigInteger                x_u         = null;

  /** User ticket identifier. */
  public Element                   Y           = null;

  /** Seller pseudonym */
  public Element                   Y_S         = null;

  /** User pseudonym. */
  public Element                   Y_U         = null;
}
