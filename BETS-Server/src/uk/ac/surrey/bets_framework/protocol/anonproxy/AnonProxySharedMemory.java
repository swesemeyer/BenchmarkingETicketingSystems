package uk.ac.surrey.bets_framework.protocol.anonproxy;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeFCurveGenerator;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.ICCSharedMemory;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.CentralVerifierData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.UserData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.VerifierData;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory.Actor;

public class AnonProxySharedMemory extends ICCSharedMemory {
	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonProxySharedMemory.class);

	/**
	 * static class enumerating the names of the different types of actor in the
	 * protocol.
	 */
	public static class Actor {
		public static final String CENTRAL_AUTHORITY = "CA";
		public static final String ISSUER = "Issuer1";
		public static final String USER = "User1";
		public static final String CENTRAL_VERIFIER = "CentralVerifier1";
		public static final String[] VERIFIERS = { "Verifier0", "Verifier1", "Verifier2", "Verifier3", "Verifier4",
				"Verifier5" };
	}

	/**
	 * The list of services the user wants to access
	 */
	public static final String[] J_U = 
		{ Actor.VERIFIERS[0], Actor.VERIFIERS[1], Actor.VERIFIERS[2], Actor.VERIFIERS[3] };
	
	/**
	 * the list of verifiers - needs to be the same length as J_U and if the entries differ the verifier can act as  proxy for the
	 * service the user originally needed. We don't test the case where a user does not have a valid token.
	 */
	public static final String[] Verifiers_for_J_U = 
		//{ Actor.VERIFIERS[0], Actor.VERIFIERS[1], Actor.VERIFIERS[2], Actor.VERIFIERS[3] };
		{ Actor.VERIFIERS[0], Actor.VERIFIERS[1], Actor.VERIFIERS[4], Actor.VERIFIERS[5] };
	
	/**
	 * Interface defining actor data.
	 */
	public interface ActorData {
		Element[] getPublicKey();
	}

	/**
	 * Arbitrary bytes to act as random seed for pairing secure random so that we
	 * can re-create the pairing.
	 */
	public static final byte[] PAIRING_RANDOM_SEED = AnonProxySharedMemory.class.getSimpleName().getBytes();

	/** Mapping of actor ID to their data. */
	private transient final Map<String, ActorData> actorData = new HashMap<>();

	/** The current actor so that access to shared memory can be checked. */
	private transient String actor = Actor.CENTRAL_AUTHORITY;

	/**
	 * Number of r bits in type a elliptic curve - optionally set as a parameter.
	 */
	public int rBits = 256;

	/** flag to indicate whether to validate verifiers */

	boolean validateVerifiers = true; // this can be quite time consuming, esp if done on Android!

	/** Random generator of the group G1. */
	public Element g = null;

	/** Random generator of the group G1. */
	public Element g_tilde = null;

	/** Random generator of the group G1. */
	public Element g_bar = null;

	/** Random generator of the group G1. */
	public Element g_1 = null;

	/** Random generator of the group G1. */
	public Element g_2 = null;

	/** Random generator of the group G1. */
	public Element g_3 = null;

	// /** Random generator of the group G1. */
	// public Element g_5 = null;
	//
	// /** Random generator of the group G1. */
	// public Element g_6 = null;
	//
	/** Random generator of the group G2. */
	public Element g_frak = null;

	/** some random generator for G2 chosen by the CA */
	public Element theta1 = null;

	/** some random generator for G2 chosen by the CA */
	public Element theta2 = null;

	/** Value of p */
	public BigInteger p = null;

	/**
	 * The bilinear group pairing: transient because we cannot serialise it and
	 * instead use the parameters and random seed.
	 */
	public transient Pairing pairing = null;

	/** The bilinear group pairing parameters. */
	public PropertiesParameters pairingParameters = null;

	/** The name of the first hash algorithm */
	public static final String Hash1 = "RIPEMD256";

	/** The name of the second hash algorithm */
	public static final String[] Hash2 = { "randomOracle", "H2" };

	/** The name of the second hash algorithm */
	public static final String Hash3 = "SHA-256";


	/** the text parts of the tickets */

	public static final String TT = "Token to limit proxying";
	public static final String ticket_Text_1 = "Travel time information";
	public static final String ticket_Text_2 = "Service information,eg valid period, ticket type";


	/** The first public key of the CA */

	public Element Y_A = null;

	/** The second public key of the CA */

	public Element Y_tilde_A = null;

	/** The first public key of the Issuer */

	public Element Y_I = null;

	/** The second public key of the Issuer */

	public Element Y_tilde_I = null;

	/** The public key of the User */

	public Element Y_U = null;

	/** The public key of the CV acting as CV */

	public Element Y_CV = null;

	/** The public key of the CV acting just as a verifier */

	public Element Y_V_cv = null;

	/** The public keys of the Verifiers */
	public Map<String, Element> Y_Vs = new HashMap<>();
	
	//

	/**
	 * Change the current actor.
	 *
	 * @param String
	 *            The new actor.
	 */
	public void actAs(String actorName) {
		this.actor = actorName;
	}

	/**
	 * Clears out the shared memory except for those parameters set for the state
	 * machine.
	 */
	public void clear() {
		// Reset the shared parameters. Other parameters are kept as they are required
		// across protocol runs.
		Crypto.getInstance().clearRandomOracleHashes();
		this.actor = Actor.CENTRAL_AUTHORITY;
		this.setBilinearGroup();

		// Set up the public parameters, which need the bilinear group
		this.setPublicParameters();

		// Create all the entities needed for a protocol run

		// The Central Authority
		CentralAuthorityData caData = new CentralAuthorityData(Actor.CENTRAL_AUTHORITY, this.p, this.g_frak,
				this.g_tilde);
		this.actorData.put(Actor.CENTRAL_AUTHORITY, caData);

		// The CA's public keys
		this.Y_A = caData.Y_A;
		this.Y_tilde_A = caData.Y_tilde_A;

		// The Issuer
		IssuerData issuerData = new IssuerData(Actor.ISSUER, this.p, this.g, this.g_frak);
		this.actorData.put(Actor.ISSUER, issuerData);

		// The issuer's public keys
		this.Y_I = issuerData.Y_I;
		this.Y_tilde_I = issuerData.Y_tilde_I;

		// The User
		UserData userData = new UserData(Actor.USER, this.p, this.g_tilde);
		this.actorData.put(Actor.USER, userData);

		// The user's public key
		this.Y_U = userData.Y_U;

		for (int i = 0; i < Actor.VERIFIERS.length; i++) {
			this.actorData.put(Actor.VERIFIERS[i], new VerifierData(Actor.VERIFIERS[i]));
			// we need to register these verifiers first before we can store their
			// public keys
		}

		// The Central Verifier
		CentralVerifierData cvData = new CentralVerifierData(Actor.CENTRAL_VERIFIER, this.p, this.g_tilde);
		this.actorData.put(Actor.CENTRAL_VERIFIER, cvData);

		// we can only store the public key of the CV when it acts as the CV
		this.Y_CV = cvData.Y_CV;

	}

	private void setPublicParameters() {
		// Generate the required elements from the pairing.

		// create some random generators for G1
		this.g = this.pairing.getG1().newRandomElement().getImmutable();
		this.g_tilde = this.pairing.getG1().newRandomElement().getImmutable();
		this.g_bar = this.pairing.getG1().newRandomElement().getImmutable();
		this.g_1 = this.pairing.getG1().newRandomElement().getImmutable();
		this.g_2 = this.pairing.getG1().newRandomElement().getImmutable();
		this.g_3 = this.pairing.getG1().newRandomElement().getImmutable();

		// create some random generator for G2
		this.g_frak = this.pairing.getG2().newRandomElement().getImmutable();
		this.theta1 = this.pairing.getG2().newRandomElement().getImmutable();
		this.theta2 = this.pairing.getG2().newRandomElement().getImmutable();
	}

	private void setBilinearGroup() {
		// Build an elliptic curve generator that will give us our p (the order r of the
		// generator), and subsequently our bilinear group
		// pairing.
		final SecureRandom prng = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);
		final PairingParametersGenerator<?> generator = new PBCTypeFCurveGenerator(this.rBits);
		PairingFactory.getInstance().setUsePBCWhenPossible(true);
		this.pairingParameters = (PropertiesParameters) generator.generate();
		this.pairing = PairingFactory.getPairing(this.pairingParameters, prng);
		this.p = this.pairingParameters.getBigInteger("r");
		if (!Crypto.getInstance().isPrime(p)) {
			throw new IllegalStateException("p is not prime: " + this.p);
		}
		LOG.debug("size of G1: " + this.pairing.getG1().getOrder());
		LOG.debug("size of G2: " + this.pairing.getG2().getOrder());
		LOG.debug("size of GT: " + this.pairing.getGT().getOrder());
		LOG.debug("G1==G2 is " + (this.pairing.getG1() == this.pairing.getG2()));

	}

	public Element[] getPublicKey(String actorName) {
		final ActorData aData = this.actorData.get(actorName);
		if (aData != null) {
			return aData.getPublicKey();
		}
		return null;
	}

	/**
	 * Gets the data associated with the specified actor.
	 *
	 * @param actor
	 *            The actor to obtain data for.
	 * @return The data or null if the current actor does not match the required
	 *         data.
	 */
	public ActorData getData(String actorName) {
		ActorData data = null;

		if (actorName == this.actor) {
			data = this.actorData.get(actorName);
		}

		return data;
	}

	/**
	 * Convenience method to create a G1 finite element from a byte array.
	 *
	 * @param bytes
	 *            The bytes containing the G1 finite element data.
	 * @return The restored G1 finite element.
	 */
	public Element G1ElementFromBytes(byte[] bytes) {
		final Element element = this.pairing.getG1().newElementFromBytes(bytes);
		return element.getImmutable();
	}

	/**
	 * Convenience method to create a G2 finite element from a byte array.
	 *
	 * @param bytes
	 *            The bytes containing the G2 finite element data.
	 * @return The restored G2 finite element.
	 */
	public Element G2ElementFromBytes(byte[] bytes) {
		final Element element = this.pairing.getG2().newElementFromBytes(bytes);
		return element.getImmutable();
	}

	/**
	 * Convenience method to create a GT finite element from a byte array.
	 *
	 * @param bytes
	 *            The bytes containing the GT finite element data.
	 * @return The restored GT finite element.
	 */
	public Element GTElementFromBytes(byte[] bytes) {
		final Element element = this.pairing.getGT().newElementFromBytes(bytes);
		return element.getImmutable();
	}

}
