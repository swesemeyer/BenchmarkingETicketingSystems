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
 * Implements the police data for the PPLAST NFC protocol as a state machine.
 *
 * @author Steve Wesemeyer
 */
public class PoliceData implements PPLASTSharedMemory.ActorData {

  /** The identity of P as an arbitrary array of bytes. */
  public String     ID_P    = null;

  /** Police credentials: e_P */
  public BigInteger e_P     = null;

  /** Police credentials: r_P */
  public BigInteger r_P     = null;

  /** Police credentials: sigma_P */
  public Element    sigma_P = null;

  /** the private key of the police */
  public BigInteger x_P     = null;

  /** Police public key. */
  public Element    Y_P     = null;

  public PoliceData() {
    super();
  }

  public PoliceData(String ID_P, BigInteger p, Element xi) {
    super();
    this.ID_P = ID_P;

    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    // generate the private key
    this.x_P = crypto.secureRandom(p);

    // compute the public key
    this.Y_P = xi.mul(this.x_P).getImmutable();

  }

  @Override
  public Element getPublicKey() {
    return Y_P;
  }

}
