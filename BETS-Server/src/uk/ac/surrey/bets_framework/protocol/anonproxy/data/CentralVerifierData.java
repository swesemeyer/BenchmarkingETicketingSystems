/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;

/**
 * Implements the central verifier data for the AnonProxy protocol as a state
 * machine.
 *
 * @author Steve Wesemeyer
 */
public class CentralVerifierData extends VerifierData {

	// The secret key of the Central Verifier
	public BigInteger x_cv;
	
	//The public key of the Central Verifier
	public Element Y_CV=null;
	
	//note that the normal verifier elements are
	//available through the parent class
	
	// The credentials  of the Central Verifier
	public BigInteger d_cv;
	public BigInteger e_cv;
	public Element sigma_CV=null;

	// default constructor
	public CentralVerifierData(String ID_CV, BigInteger p, Element g_tilde) {
		super(ID_CV);	

		// Generate the required random numbers.
		final Crypto crypto = Crypto.getInstance();

		// create the CV's secret key
		this.x_cv = crypto.secureRandom(p);

		// compute the public key
		this.Y_CV = g_tilde.mul(this.x_cv).getImmutable();

	}

	@Override
	public Element[] getPublicKey() {
		// return both public keys - 
		// the first one is the one of the CV acting as a verifier, 
		// the second one is that of the CV acting as the Central Verifier
		Element [] pks= {this.Y_V, this.Y_CV};
		return pks;
	}
}
