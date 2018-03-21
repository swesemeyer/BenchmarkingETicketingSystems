/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.pplast.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory;

/**
 * Implements verifier data for the PPLAST NFC protocol as a state machine.
 *
 * @author Steve Wesemeyer
 */
public class VerifierData implements PPLASTSharedMemory.ActorData {

  /** The identity of S as an arbitrary array of bytes. */
  public String     ID_V    = null;
  /** Verifier credentials: e_V */
  public BigInteger e_V     = null;

  /** Verifier credentials: r_V */
  public BigInteger r_V     = null;

  /** Verifier credentials: Z_V. */
  public Element    sigma_V = null;

  /** the private key of the verifier */
  public BigInteger x_V     = null;

  /** the public key of the verifier */
  public Element    Y_V     = null;

  public VerifierData() {
    super();
  }

  public VerifierData(String ID_V, BigInteger p, Element xi) {
    super();

    this.ID_V = ID_V;

    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    // generate the private key
    this.x_V = crypto.secureRandom(p);

    // compute the public key
    this.Y_V = xi.mul(this.x_V).getImmutable();

  }

  @Override
  public Element getPublicKey() {
    return this.Y_V;
  }

}
