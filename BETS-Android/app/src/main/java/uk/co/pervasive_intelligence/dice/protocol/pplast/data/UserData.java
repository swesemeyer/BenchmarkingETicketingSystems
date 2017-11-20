/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.pplast.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.protocol.pplast.PPLASTSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.pplast.PPLASTSharedMemory.Actor;

/**
 * Implements user data for the PPETS-FGP NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class UserData implements PPLASTSharedMemory.ActorData {

  /** The identity of U */
  public String ID_U = null;

  // TODO make this a longer list...Note that the names need to match the IDs of the verifiers
  public final String[] VerifierList =  { Actor.VERIFIER[1],Actor.VERIFIER[2],Actor.VERIFIER[5] };

  /** User credentials: e_U */
  public BigInteger e_U = null;

  /** User credentials: r_U */
  public BigInteger r_U = null;

  /** User credentials: sigma_U */
  public Element sigma_U = null;

  /** the private key of the user */
  public BigInteger x_U = null;

  /** User pseudonym. */
  public Element Y_U = null;

  /** secret ticket number */
  public BigInteger z_U = null;

  /** secret ticket element */
  public Element C_U = null;
  /** ticket details */
  public TicketDetails ticketDetails = null;

  /** current Time in MilliSecs */
  public BigInteger currentTimeInMilliSec = null;

  public UserData() {
    super();
  }

  public UserData(String ID_U, BigInteger p, Element xi) {
    super();
    this.ID_U = ID_U;
    // Generate the required random numbers.
    final Crypto crypto = Crypto.getInstance();

    // generate the private key
    this.x_U = crypto.secureRandom(p);

    // compute the public key
    this.Y_U = xi.mul(this.x_U).getImmutable();

    this.currentTimeInMilliSec = BigInteger.valueOf(System.currentTimeMillis());

  }

  @Override
  public Element getPublicKey() {
    return Y_U;
  }
}
