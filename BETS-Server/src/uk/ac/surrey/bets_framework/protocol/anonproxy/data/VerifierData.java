/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory;

/**
 * Implements verifier data for the AnonProxy protocol as a state machine.
 *
 * @author Steve Wesemeyer
 */
public class VerifierData implements AnonProxySharedMemory.ActorData {

	/** The identity of S as an arbitrary array of bytes. */
	public String ID_V = null;
	
	/** Verifier credentials: e_V */
	public BigInteger e_v = null;

	/** Verifier credentials: r_V */
	public BigInteger d_v = null;

	/** Verifier credentials: Z_V. */
	public Element sigma_V = null;

	/** the secret key of the verifier */
	public Element SK_V = null;

	/** the public key of the verifier */
	public Element Y_V = null;

	public VerifierData() {
		super();
	}

	public VerifierData(String ID_V) {
		super();

		this.ID_V = ID_V;

	}

	@Override
	public Element[] getPublicKey() {
		Element[] pks= {this.Y_V};
		return pks;
	}

}
