/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.anonsso.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory;

/**
 * Implements seller data for the AnonProxy NFC protocol as a state machine.
 *
 * @author Steve Wesemeyer
 */
public class IssuerData implements AnonSSOSharedMemory.ActorData {

  /** The identity of ISSUER */
  public String              ID_I                = null;
  
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

  /** Issuer credentials: e_I */
  public BigInteger          e_I                 = null;

  /** Issuer credentials: r_I */
  public BigInteger          r_I                 = null;

  /** Issuer credentials: sigma_I. */
  public Element             sigma_I             = null;

  /** Random x_s. */
  public BigInteger          x_I                 = null;

  /** Issuer public key1. */
  public Element             Y_I                 = null;

  /** Issuer public key2. */
  public Element             Y_bar_I            = null;

  public IssuerData() {
    super();
  }

  /**
   * constructor of IssuerData
   * 
   * @param p a prime number representing the size of the G1
   * @param xi a generator of G1
   * @param g_frak a generator of G2
   */
  public IssuerData(String name, BigInteger p, Element xi, Element g_frak) {
    super();

    this.ID_I = name;
    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    // create the seller's master key
    this.x_I = crypto.secureRandom(p);

    // compute the secret key
    this.Y_I = xi.mul(this.x_I).getImmutable();

    // compute the public key
    this.Y_bar_I = g_frak.mul(this.x_I).getImmutable();

  }

  @Override
  public Element getPublicKey() {
    return this.Y_bar_I;
  }
  
  public Element getTraceKey() {
    return this.Y_I;
  }
}
