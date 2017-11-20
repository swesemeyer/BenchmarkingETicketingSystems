/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp.data;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory;

import java.math.BigInteger;

/**
 * Implements central authority data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class CentralAuthorityData implements PPETSFGPSharedMemory.ActorData {

  /** The range policy attributes of U. */
  public BigInteger[] A_U_range = null;

  /** The set policy attributes of U. */
  public String[]     A_U_set   = null;

  /** The user credentials. */
  public Element      delta_U   = null;

  /** The identity of U. */
  public byte[]       ID_U      = null;

  /** Random numbers mu_1 to mu_N2. */
  public BigInteger[] mu_n      = null;

  /** Random number x. */
  public BigInteger   x         = null;

  /** Random number y. */
  public BigInteger   y         = null;

  /** The user pseudonym. */
  public Element      Y_U       = null;

  /**
   * Constructor.
   *
   * @param p The order of the bilinear group.
   * @param N2 The number of set policies.
   */
  public CentralAuthorityData(BigInteger p, int N2) {
    super();

    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    this.x = crypto.secureRandom(p);
    this.y = crypto.secureRandom(p);
    this.mu_n = new BigInteger[N2];
    for (int i = 0; i < this.mu_n.length; i++) {
      this.mu_n[i] = crypto.secureRandom(p);
    }
  }
}
