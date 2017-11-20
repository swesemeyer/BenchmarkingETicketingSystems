/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.pplast.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory;

/**
 * Implements central authority data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class CentralAuthorityData implements PPLASTSharedMemory.ActorData {

  public String     ID_CA   = null;

  /** Random number x_a. The private key of the CA */
  public BigInteger x_a     = null;

  /** the public key of the CA */
  public Element    Y_A     = null;

  /** the seller's credentials */
  public Element    ID_S    = null;
  public Element    Y_S     = null;
  public Element    Y_bar_S = null;
  public BigInteger r_S     = null;
  public BigInteger e_S     = null;
  public Element    sigma_S = null;

  /** the verifier's credentials */
  public Element    ID_V    = null;
  public Element    Y_V     = null;
  public BigInteger r_V     = null;
  public BigInteger e_V     = null;
  public Element    sigma_V = null;

  /** the user's credentials */
  public Element    ID_U    = null;
  public Element    Y_U     = null;
  public BigInteger r_U     = null;
  public BigInteger e_U     = null;
  public Element    sigma_U = null;

  /** the Police's credentials */
  public Element    ID_P    = null;
  public Element    Y_P     = null;
  public BigInteger r_P     = null;
  public BigInteger e_P     = null;
  public Element    sigma_P = null;

  /**
   * Constructor.
   *
   * @param p The order of the bilinear group.
   */
  public CentralAuthorityData(String ID_CA, BigInteger p, CurveElement<?, ?> g_frak) {
    super();
   
    this.ID_CA = ID_CA;

    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    // create the CA's master key
    this.x_a = crypto.secureRandom(p);

    // compute the public key
    this.Y_A = g_frak.mul(this.x_a).getImmutable();
  }

  @Override
  public Element getPublicKey() {
    return this.Y_A;
  }

}
