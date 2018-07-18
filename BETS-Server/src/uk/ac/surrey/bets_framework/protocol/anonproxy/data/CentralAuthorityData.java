/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy.data;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.CentralAuthorityData.VerifierCredentials;


/**
 * Implements central authority data for the AnonProxy NFC protocol as a state
 * machine.
 *
 * @author Steve Wesemeyer
 */
public class CentralAuthorityData implements AnonProxySharedMemory.ActorData {

	public class VerifierCredentials {
		public String ID_V = null;
		public BigInteger d_v = null;
		public BigInteger e_v = null;
		public Element sigma_V = null;
		public Element SK_V = null;

		public VerifierCredentials() {
			/* default constructor */
		}

	}

	public String ID_CA = null;

	/** Random number alpha. The first private key of the CA */
	public BigInteger alpha = null;

	/** Random number beta. The second private key of the CA */
	public BigInteger beta = null;
	
	/** the first public key of the CA */
	public Element Y_A = null;
	
	/** the second public key of the CA */
	public Element Y_tilde_A = null;
	
	
	/** the issuer's credentials */
	public String ID_I = null;
	public Element Y_I = null;
	public Element Y_tilde_I = null;
	public BigInteger e_i = null;
	public BigInteger d_i = null;
	public Element sigma_I = null;


	/** the user's credentials */
	public String ID_U = null;
	public Element Y_U = null;
	public BigInteger d_u = null;
	public BigInteger e_u = null;
	public Element sigma_U = null;

	/** the central verifier's credentials */
	public String ID_CV = null;
	public Element Y_CV = null;
	public BigInteger d_cv = null;
	public BigInteger e_cv = null;
	public Element sigma_CV = null;
	
	/** the verifier's credentials */
	public Map<String, VerifierCredentials> verifiers = new HashMap<String, VerifierCredentials>();

	/**
	 * Constructor.
	 *
	 * @param p
	 *            The order of the bilinear group.
	 */
	public CentralAuthorityData(String ID_CA, BigInteger p, Element g_frak, Element g_tilde) {
		super();

		this.ID_CA = ID_CA;

		// Generate the required random numbers.
		final Crypto crypto = Crypto.getInstance();

		// create the CA's master key
		this.alpha = crypto.secureRandom(p);
		this.beta = crypto.secureRandom(p);
				
		
		// compute the first public key
		this.Y_A = g_frak.mul(this.alpha).getImmutable();
		// compute the second public key
		this.Y_tilde_A = g_tilde.mul(this.beta).getImmutable();
	}

	@Override
	public Element[] getPublicKey() {
		Element[] result={this.Y_A, this.Y_tilde_A};
		return result;
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
