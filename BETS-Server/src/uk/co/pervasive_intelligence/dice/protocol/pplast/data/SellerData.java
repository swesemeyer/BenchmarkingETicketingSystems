/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.pplast.data;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import it.unisa.dia.gas.jpbc.Element;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.protocol.pplast.PPLASTSharedMemory;

/**
 * Implements seller data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class SellerData implements PPLASTSharedMemory.ActorData {

  /** The identity of S. */
  public String              ID_S                = null;
  
  /** The text included with a ticket */
  public static final String TICKET_TEXT="Some Text";

  /** The fixed ticket price as an arbitrary array of bytes. */
  public static final byte[] TICKET_PRICE        = new byte[] { 0x12 };

  /** The fixed ticket service as an arbitrary array of bytes. */
  public static final byte[] TICKET_SERVICE      = new byte[] { 0x11 };

  /** The fixed ticket time as an arbitrary array of bytes. */
  public static final byte[] TICKET_TIME         = new byte[] { 0x10 };

  /** The fixed ticket validity period as an arbitrary array of bytes. */
  public static final byte[] TICKET_VALID_PERIOD = new byte[] { 0x13 };

  /** Seller credentials: e_S */
  public BigInteger          e_S                 = null;

  /** Seller credentials: r_S */
  public BigInteger          r_S                 = null;

  /** Seller credentials: sigma_S. */
  public Element             sigma_S             = null;

  /** Random x_s. */
  public BigInteger          x_S                 = null;

  /** Seller secret key. */
  public Element             Y_S                 = null;

  /** Seller public key. */
  public Element             Y_bar_S            = null;

  public SellerData() {
    super();
  }

  /**
   * constructor of SellerData
   * 
   * @param p a prime number representing the size of the G1
   * @param xi a generator of G1
   * @param g_frak a generator of G2
   */
  public SellerData(String name, BigInteger p, Element xi, Element g_frak) {
    super();

    this.ID_S = name;
    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    // create the CA's master key
    this.x_S = crypto.secureRandom(p);

    // compute the secret key
    this.Y_S = xi.mul(this.x_S).getImmutable();

    // compute the public key
    this.Y_bar_S = g_frak.mul(this.x_S).getImmutable();

  }

  @Override
  public Element getPublicKey() {
    return this.Y_bar_S;
  }
  
  public Element getTraceKey() {
    return this.Y_S;
  }
}
