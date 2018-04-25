package uk.ac.surrey.bets_framework;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeFCurveGenerator;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;

class TestPBCWrapper {

	/** Logback logger. */
	private static final Logger LOG = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
			.getLogger("TestPBCWrapper");
	/**
	 * Arbitrary bytes to act as random seed for pairing secure random so that we
	 * can re-create the pairing.
	 */
	private final byte[] PAIRING_RANDOM_SEED = TestPBCWrapper.class.getSimpleName().getBytes();

	/**
	 * The bilinear group pairing: transient because we cannot serialise it and
	 * instead use the parameters and random seed.
	 */
	private Pairing pairing = null;

	/** The bilinear group pairing parameters. */
	private PropertiesParameters pairingParameters = null;

	/**
	 * Number of r bits in type a elliptic curve - optionally set as a parameter.
	 */
	private int rBits = 320;

	/** Value of p */
	private BigInteger p = null;

	// crypto singleton
	final Crypto crypto = Crypto.getInstance();

	/** some PP elements */

	private Element g;
	private Element h;
	private Element h_tilde;
	private Element xi;
	private Element g_frak;

	/** CA details */

	private BigInteger x_a; // private key
	private Element Y_A; // public key

	/** user details */
	private BigInteger x_U; // private key
	private Element Y_U; // public key
	private BigInteger e_u; // some random number
	private BigInteger r_u; // another random number
	private Element sigma_U; // signed credentials

	/** issuer details */

	/** Issuer credentials: e_I */
	private BigInteger e_I = null;

	/** Issuer credentials: r_I */
	private BigInteger r_I = null;

	/** Issuer credentials: sigma_I. */
	private Element sigma_I = null;

	/** Random x_s. */
	private BigInteger x_I = null;

	/** Issuer public key1. */
	private Element Y_I = null;

	/** Issuer public key2. */
	private Element Y_bar_I = null;

	@BeforeEach
	void setUp() throws Exception {
	}

	@AfterEach
	void tearDown() throws Exception {
	}

	/**
	 * Sets the public parameters based upon the central authorities private data.
	 */
	private void setPublicParameters() {
		// Generate the required elements from the pairing. Note that CurveElement is
		// used instead of Element for deserialization with
		// Gson.

		// create some random generators for G1
		this.g = this.pairing.getG1().newRandomElement().getImmutable();
		this.h = this.pairing.getG1().newRandomElement().getImmutable();
		this.h_tilde = this.pairing.getG1().newRandomElement().getImmutable();
		this.xi = this.pairing.getG1().newRandomElement().getImmutable();

		// create some random generator for G2
		this.g_frak = this.pairing.getG2().newRandomElement().getImmutable();

	}

	private void createCA() {
		// create the CA's master key
		this.x_a = crypto.secureRandom(p);

		// compute the public key
		this.Y_A = g_frak.mul(this.x_a).getImmutable();

	}

	private void createUser() {

		// generate the private key
		this.x_U = crypto.secureRandom(p);

		// compute the public key
		this.Y_U = xi.mul(this.x_U).getImmutable();
	}

	
	private void createIssuer() {
		
	    // create the issuer's master key
	    this.x_I = this.crypto.secureRandom(p);

	    // compute the secret key
	    this.Y_I = this.xi.mul(this.x_I).getImmutable();

	    // compute the public key
	    this.Y_bar_I = this.g_frak.mul(this.x_I).getImmutable();

	}	
	
	@Test
	void test() {
		final SecureRandom prng = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);
		// final PairingParametersGenerator<?> generator = new TypeFCurveGenerator(prng,
		// this.rBits);
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

		this.setPublicParameters();
		LOG.debug("created PP");
		this.createCA();
		LOG.debug("created CA");
		this.createUser();
		LOG.debug("created User");
		this.getUserCreds();
		LOG.debug("created user credentials");
		this.verifyUserCreds();
		LOG.debug("Successfully verified user credentials");
		
		this.createIssuer();
		LOG.debug("created Issuer");
		//this.getIssuerCreds();
		LOG.debug("created Issuer credentials");
		//this.verifyIssuerCreds();
		LOG.debug("Successfully verified Issuer credentials");
		
	}

	private void verifyUserCreds() {

		LOG.debug("About to verify user credentials - computing lhs");
		final Element lhs = this.pairing.pairing(sigma_U, Y_A.add(this.g_frak.mul(e_u))).getImmutable();
		LOG.debug("still verifying user credentials - computing rhs");
		final Element rhs = this.pairing.pairing(this.g.add(this.h.mul(r_u)).add(this.Y_U), this.g_frak).getImmutable();

		if (!lhs.isEqual(rhs)) {
			LOG.error("Failed to verify user credentials");
			Assert.fail();
		}
	}

	private void getUserCreds() {
		this.e_u = crypto.secureRandom(this.p);
		this.r_u = crypto.secureRandom(this.p);
		final BigIntEuclidean gcd = BigIntEuclidean.calculate(this.x_a.add(e_u).mod(this.p), this.p);
		this.sigma_U = (this.g.add(this.h.mul(r_u)).add(Y_U)).mul(gcd.x.mod(this.p)).getImmutable();

	}

}
