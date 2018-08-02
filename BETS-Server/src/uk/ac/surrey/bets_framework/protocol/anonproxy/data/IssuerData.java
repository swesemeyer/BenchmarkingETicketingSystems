/**
 * DICE Protocol evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory;

/**
 * Implements issuer data for the AnonProxy protocol as a state machine.
 *
 * @author Steve Wesemeyer
 */
public class IssuerData implements AnonProxySharedMemory.ActorData {

	/** The identity of ISSUER */
	public String ID_I = null;

	/** The text included with a ticket */
	public static final String TICKET_TEXT = "Some Text";

	/** The fixed ticket price as an arbitrary array of bytes. */
	public static final byte[] TICKET_PRICE = new byte[] { 0x12 };

	/** The fixed ticket service as an arbitrary array of bytes. */
	public static final byte[] TICKET_SERVICE = new byte[] { 0x11 };

	/** The fixed ticket time as an arbitrary array of bytes. */
	public static final byte[] TICKET_TIME = new byte[] { 0x10 };

	/** The fixed ticket validity period as an arbitrary array of bytes. */
	public static final byte[] TICKET_VALID_PERIOD = new byte[] { 0x13 };

	/** Issuer credentials: d_i */
	public BigInteger d_i = null;

	/** Issuer credentials: e_i */
	public BigInteger e_i = null;

	/** Issuer credentials: sigma_I. */
	public Element sigma_I = null;

	/** Random x_i secret key of Issuer*/
	public BigInteger x_i = null;

	/** Issuer public key1. */
	public Element Y_I = null;

	/** Issuer public key2. */
	public Element Y_tilde_I = null;

	public IssuerData() {
		super();
	}

	/**
	 * constructor of IssuerData
	 * 
	 * @param p
	 *            a prime number representing the size of the G1
	 * @param xi
	 *            a generator of G1
	 * @param g_frak
	 *            a generator of G2
	 */
	public IssuerData(String name, BigInteger p, Element g_tilde, Element g_frak) {
		super();

		this.ID_I = name;
		// Generate the required random numbers.
		final Crypto crypto = Crypto.getInstance();

		// create the seller's master key
		this.x_i = crypto.secureRandom(p);

		// compute the secret key
		this.Y_I = g_tilde.mul(this.x_i).getImmutable();

		// compute the public key
		this.Y_tilde_I = g_frak.mul(this.x_i).getImmutable();

	}

	@Override
	public Element[] getPublicKey() {
		Element[] pks = { this.Y_I, this.Y_tilde_I };
		return pks;
	}

}
