/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018
 */
package uk.ac.surrey.bets_framework.protocol.pplast.data;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory;

/**
 * Implements central authority data for the PPLAST NFC protocol as a state
 * machine.
 *
 * @author Steve Wesemeyer
 */
public class CentralAuthorityData implements PPLASTSharedMemory.ActorData {

  public class VerifierCredentials {
    public String ID_V = null;
    public Element Y_V = null;
    public BigInteger r_V = null;
    public BigInteger e_V = null;
    public Element sigma_V = null;

    public VerifierCredentials() {
			/* default constructor */
    }

  }

  public String ID_CA = null;

  /** Random number x_a. The private key of the CA */
  public BigInteger x_a = null;

  /** the public key of the CA */
  public Element Y_A = null;

  /** the issuer's credentials */
  public String ID_I = null;
  public Element Y_I = null;
  public Element Y_bar_I = null;
  public BigInteger r_I = null;
  public BigInteger e_I = null;
  public Element sigma_I = null;

  /** the verifier's credentials */
  public Map<String, VerifierCredentials> verifiers = new HashMap<String, VerifierCredentials>();

  /** the user's credentials */
  public String ID_U = null;
  public Element Y_U = null;
  public BigInteger r_u = null;
  public BigInteger e_u = null;
  public Element sigma_U = null;

  /** the central verifier's credentials */
  public String ID_CV = null;
  public Element Y_CV = null;
  public BigInteger r_CV = null;
  public BigInteger e_CV = null;
  public Element sigma_CV = null;

  /**
   * Constructor.
   *
   * @param p
   *            The order of the bilinear group.
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

  /**
   *  helper method to create a instance of the VerifierCredentials class
   * @return vc
   * 				A new instance of the VerifierCredential class
   */
  public VerifierCredentials getVerifierCredentialsInstance() {
    return new VerifierCredentials();
  }
}
