/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory;

/**
 * Implements seller data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class SellerData implements PPETSFGPSharedMemory.ActorData {

  /** The identity of S as an arbitrary array of bytes. */
  public static final byte[] ID_S = new byte[]{0x00, 0x01, 0x02, 0x03};

  /** The fixed ticket price as an arbitrary array of bytes. */
  public static final byte[] TICKET_PRICE = new byte[]{0x12};

  /** The fixed ticket service as an arbitrary array of bytes. */
  public static final byte[] TICKET_SERVICE = new byte[]{0x11};

  /** The fixed ticket time as an arbitrary array of bytes. */
  public static final byte[] TICKET_TIME = new byte[]{0x10};

  /** The fixed ticket validity period as an arbitrary array of bytes. */
  public static final byte[] TICKET_VALID_PERIOD = new byte[]{0x13};

  /** User ticket identifier. */
  public Element Y = null;

  /** Seller pseudonym. */
  public Element Y_S = null;

  /** Seller credentials: c_s. */
  public BigInteger c_s = null;

  /** Seller credentials: delta_s. */
  public Element delta_S = null;

  /** Seller credentials: r_s. */
  public BigInteger r_s = null;

  /** Random x_s. */
  public BigInteger x_s = null;
}
