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
 * Implements seller data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class SellerData implements PPETSFGPSharedMemory.ActorData {

  /** The identity of S as an arbitrary array of bytes. */
  public static final byte[] ID_S                = new byte[] { 0x00, 0x01, 0x02, 0x03 };

  /** The fixed ticket price as an arbitrary array of bytes. */
  public static final byte[] TICKET_PRICE        = new byte[] { 0x12 };

  /** The fixed ticket service as an arbitrary array of bytes. */
  public static final byte[] TICKET_SERVICE      = new byte[] { 0x11 };

  /** The fixed ticket time as an arbitrary array of bytes. */
  public static final byte[] TICKET_TIME         = new byte[] { 0x10 };

  /** Seller credentials: c_s. */
  public BigInteger          c_s                 = null;

  /** Seller credentials: delta_s. */
  public Element             delta_S             = null;

  /** Seller credentials: r_s. */
  public BigInteger          r_s                 = null;

  /** Random x_s. */
  public BigInteger          x_s                 = null;

  /** User ticket identifier. */
  public Element             Y                   = null;

  /** Seller pseudonym. */
  public Element             Y_S                 = null;
  
  /** some generic valid period for the seller credentials */
  public String VP_S        = "one-year";

  /** some generic valid period for a ticket */
  public String VP_T       = "one week";
  
  /** store the user's policy membership details during issuing  */
  public String U_membershipDetails = null;

}



