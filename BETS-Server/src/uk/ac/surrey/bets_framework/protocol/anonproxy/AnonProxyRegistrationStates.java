/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.icc.ICC;
import uk.ac.surrey.bets_framework.protocol.ICCCommand;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.CentralVerifierData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.UserData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.VerifierData;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

/**
 * Registration states of the AnonProxy state machine protocol.
 *
 * @author Steve Wesemeyer
 */
public class AnonProxyRegistrationStates {

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonProxyRegistrationStates.class);

	/**
	 * State 02: As Issuer: generate the issuer identity
	 */
	public static class RState02 extends State<ICCCommand> {

		private byte[] generateIssuerIdentity() {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final IssuerData issuerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);

			// Send ID_I, Y_I, Y_tilde_I
			final ListData sendData = new ListData(
					Arrays.asList(issuerData.ID_I.getBytes(), issuerData.Y_I.toBytes(), issuerData.Y_tilde_I.toBytes()));
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.ISSUER);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generateIssuerIdentity();

				if (data != null) {
					return new Action<>(Status.CONTINUE, 3, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}

	}

	/**
	 * State 04: As Central Authority: generate the issuer credentials and send them
	 * to the issuer
	 */
	public static class RState04 extends State<ICCCommand> {

		private byte[] generateIssuerCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}
			final String ID_I = sharedMemory.stringFromBytes(listData.getList().get(0));
			final Element Y_I = sharedMemory.G1ElementFromBytes(listData.getList().get(1));
			final Element Y_tilde_I = sharedMemory.G2ElementFromBytes(listData.getList().get(2));

			// compute sigma_I
			final BigInteger d_i = crypto.secureRandom(sharedMemory.p);
			final BigInteger e_i = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.alpha.add(d_i).mod(sharedMemory.p),
					sharedMemory.p);
			final Element sigma_I = (sharedMemory.g_1.add(sharedMemory.g_2.mul(e_i)).add(Y_I))
					.mul(gcd.x.mod(sharedMemory.p)).getImmutable();

			centralAuthorityData.ID_I = ID_I;
			centralAuthorityData.Y_I = Y_I;
			centralAuthorityData.Y_tilde_I = Y_tilde_I;
			centralAuthorityData.e_i = e_i;
			centralAuthorityData.d_i = d_i;
			centralAuthorityData.sigma_I = sigma_I;

			// Send sigma_I, d_i, e_i
			final ListData sendData = new ListData(
					Arrays.asList(sigma_I.toBytes(), d_i.toByteArray(), e_i.toByteArray()));
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generateIssuerCredentials(message.getData());
				if (data != null) {
					return new Action<>(Status.CONTINUE, 5, ICCCommand.PUT, data, 0);
				}
			}
			return super.getAction(message);
		}
	}

	/**
	 * State 06 As issuer: verify the Central Authority's data and store the
	 * issuer credentials
	 */
	public static class RState06 extends State<ICCCommand> {

		private boolean verifyIssuerCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final IssuerData issuerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}
			final Element sigma_I = sharedMemory.G1ElementFromBytes(listData.getList().get(0));
			final BigInteger d_i = new BigInteger(listData.getList().get(1));
			final BigInteger e_i = new BigInteger(listData.getList().get(2));

			// verify the credentials
			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[0];
			final Element lhs = sharedMemory.pairing.pairing(sigma_I, Y_A.add(sharedMemory.g_frak.mul(d_i)))
					.getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(sharedMemory.g_1.add(sharedMemory.g_2.mul(e_i)).add(issuerData.Y_I), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				return false;
			}

			issuerData.e_i = e_i;
			issuerData.d_i = d_i;
			issuerData.sigma_I = sigma_I;
			return true;
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.ISSUER);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifyIssuerCredentials(message.getData());
				if (success) {
					LOG.debug("Successfully registered issuer!");
					return new Action<>(7);
				}
			}
			return super.getAction(message);
		}
	}

	
	/**
	 * State 07: As User: generate the user identity
	 */
	public static class RState07 extends State<ICCCommand> {

		private byte[] generateUserIdentity() {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final UserData userData = (UserData) sharedMemory.getData(Actor.USER);

			// Send ID_U, Y_U
			final ListData sendData = new ListData(
					Arrays.asList(userData.ID_U.getBytes(), userData.Y_U.toBytes()));
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.USER);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generateUserIdentity();

				if (data != null) {
					return new Action<>(Status.CONTINUE, 8, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}

	}	
	
	

	/**
	 * State 09: As Central Authority: generate the user's credentials and send them
	 * to the user
	 */
	
	public static class RState09 extends State<ICCCommand> {

		private byte[] generateUserCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();
			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 2) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}
			final String ID_U = sharedMemory.stringFromBytes(listData.getList().get(0));
			final Element Y_U = sharedMemory.G1ElementFromBytes(listData.getList().get(1));
			// compute sigma_v
			final BigInteger e_u = crypto.secureRandom(sharedMemory.p);
			final BigInteger d_u = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(
					centralAuthorityData.alpha.add(e_u).mod(sharedMemory.p),sharedMemory.p);
			final Element sigma_U = (sharedMemory.g_1.add(sharedMemory.g_2.mul(d_u)).add(Y_U))
					.mul(gcd.x.mod(sharedMemory.p)).getImmutable();
			centralAuthorityData.ID_U = ID_U;
			centralAuthorityData.Y_U = Y_U;
			centralAuthorityData.d_u = d_u;
			centralAuthorityData.e_u = e_u;
			centralAuthorityData.sigma_U = sigma_U;
			// Send sigma_U, e_u, d_u
			final ListData sendData = new ListData(
					Arrays.asList(sigma_U.toBytes(), d_u.toByteArray(), e_u.toByteArray()));
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				if (message.getData() != null) {
					final byte[] data = this.generateUserCredentials(message.getData());
					LOG.debug("Generated the user's credentials");
					// Send the setup data.
					if (data != null) {
						return new Action<>(Status.CONTINUE, 10, ICCCommand.PUT, data, 0);
					}
				}
			}
			return super.getAction(message);
		}
	}
	
	/**
	 * State 11 As user: verify the Central Authority's data and store the
	 * issuer credentials
	 */
	public static class RState11 extends State<ICCCommand> {

		private boolean verifyUserCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final UserData userData = (UserData) sharedMemory.getData(Actor.USER);

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}
			final Element sigma_U = sharedMemory.G1ElementFromBytes(listData.getList().get(0));
			final BigInteger d_u = new BigInteger(listData.getList().get(1));
			final BigInteger e_u = new BigInteger(listData.getList().get(2));

			// verify the credentials
			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[0];
			final Element lhs = sharedMemory.pairing.pairing(sigma_U, Y_A.add(sharedMemory.g_frak.mul(e_u)))
					.getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(sharedMemory.g_1.add(sharedMemory.g_2.mul(d_u)).add(userData.Y_U), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				return false;
			}

			userData.e_u = e_u;
			userData.d_u = d_u;
			userData.sigma_U = sigma_U;
			return true;
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.USER);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifyUserCredentials(message.getData());
				if (success) {
					LOG.debug("Successfully registered user!");
					return new Action<>(12);
				}
			}
			return super.getAction(message);
		}
	}


	/**
	 * State 12: As Verifier: generate the verifier's identity
	 */
	public static class RState12 extends State<ICCCommand> {

		private String[] verifiers;
		private int index;

		public RState12(String[] verifiers) {
			this.verifiers = verifiers;
			this.index = 0;
		}

		private byte[] generateVerifierIdentity() {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final VerifierData verifierData = (VerifierData) sharedMemory.getData(this.verifiers[this.index]);
			// Send ID_V
			final ListData sendData = new ListData(
					Arrays.asList(sharedMemory.stringToBytes(verifierData.ID_V)));
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.VERIFIERS[this.index]);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generateVerifierIdentity();

				if (data != null) {
					LOG.debug("sending verifier identity data for " + Actor.VERIFIERS[this.index]);
					this.index++;
					return new Action<>(Status.CONTINUE, 13, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}

	}

	/**
	 * State 14: As Central Authority: generate the verifier credentials and send
	 * them to the verifier
	 */
	public static class RState14 extends State<ICCCommand> {

		private byte[] generateVerifierCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();

			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();
			
		
			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 1) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			final String ID_V = sharedMemory.stringFromBytes(listData.getList().get(0));
			BigInteger e_v; 
			BigInteger d_v;
			Element sigma_V;
			Element SK_V;
			
			//check if we already computed the details for this verifier
			if (centralAuthorityData.verifiers.containsKey(ID_V)) {
				// we can simply retrieve its details
				CentralAuthorityData.VerifierCredentials verifierDetails=centralAuthorityData.verifiers.get(ID_V);
				d_v=verifierDetails.d_v;
				e_v=verifierDetails.e_v;
				sigma_V=verifierDetails.sigma_V;
				SK_V=verifierDetails.SK_V;
			}else {
				// we need to do some computation
				final List<byte[]> hash_IDvData = new ArrayList<>();
				final byte[] ID_V_bytes=sharedMemory.stringToBytes(ID_V);
				hash_IDvData.add(ID_V_bytes);
				
				final BigInteger hash_IDvNum = (new BigInteger(1, crypto.getHash((new ListData(hash_IDvData)).toBytes(), sharedMemory.Hash1))).mod(sharedMemory.p);

				// compute sigma_v
				e_v = crypto.secureRandom(sharedMemory.p);
				d_v = crypto.secureRandom(sharedMemory.p);
				final BigIntEuclidean gcd = BigIntEuclidean
						.calculate(centralAuthorityData.alpha.add(e_v).mod(sharedMemory.p), sharedMemory.p);

				sigma_V = (sharedMemory.g_1.add(sharedMemory.g_2.mul(d_v)).add(sharedMemory.g_tilde.mul(hash_IDvNum)))
						.mul(gcd.x.mod(sharedMemory.p)).getImmutable();
				
				SK_V=crypto.getHash(ID_V_bytes, sharedMemory.Hash2,sharedMemory.pairing.getG2()).mul(centralAuthorityData.beta).getImmutable();

				
				CentralAuthorityData.VerifierCredentials verifierDetails = centralAuthorityData
						.getVerifierCredentialsInstance();
				verifierDetails.ID_V = ID_V;
				verifierDetails.d_v = d_v;
				verifierDetails.e_v = e_v;
				verifierDetails.sigma_V = sigma_V;
				verifierDetails.SK_V=SK_V;

				centralAuthorityData.verifiers.put(ID_V, verifierDetails);
			}
			// Send sigma_V, d_V, e_V, SK_V back
			final ListData sendData = new ListData(
					Arrays.asList(sigma_V.toBytes(), d_v.toByteArray(), e_v.toByteArray(), SK_V.toBytes()));
			return sendData.toBytes();

		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generateVerifierCredentials(message.getData());

				if (data != null) {
					LOG.debug("sending verifier credentials data");
					return new Action<>(Status.CONTINUE, 15, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}
	}


	/**
	 * State 16 As verifier: verify the Central Authority's data and store the
	 * verifier's credentials
	 */
	public static class RState16 extends State<ICCCommand> {

		private String[] verifiers;
		private int index;

		public RState16(String[] verifiers) {
			this.verifiers = verifiers;
			this.index = 0;
		}

		private boolean verifyVerifierCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final VerifierData verifierData = (VerifierData) sharedMemory.getData(this.verifiers[index]);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 4) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			final Element sigma_V = sharedMemory.G1ElementFromBytes(listData.getList().get(0));
			final BigInteger d_v = new BigInteger(listData.getList().get(1));
			final BigInteger e_v = new BigInteger(listData.getList().get(2));
			LOG.debug("Byte data for SK_V:"+crypto.base64Encode(listData.getList().get(3)));
			final Element SK_V= sharedMemory.G2ElementFromBytes(listData.getList().get(3));
			
			final List<byte[]> hash_IDvData = new ArrayList<>();
			final byte[] ID_V_bytes=sharedMemory.stringToBytes(verifierData.ID_V);
			hash_IDvData.add(ID_V_bytes);
			final BigInteger hash_IDvNum = (new BigInteger(1, crypto.getHash((new ListData(hash_IDvData)).toBytes(), sharedMemory.Hash1))).mod(sharedMemory.p);


			// verify the credentials

			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[0];
			final Element Y_tilde_A=sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[1];

			final Element lhs1 = sharedMemory.pairing.pairing(sigma_V, Y_A.add(sharedMemory.g_frak.mul(e_v)))
					.getImmutable();
			final Element rhs1 = sharedMemory.pairing
					.pairing(sharedMemory.g_1.add(sharedMemory.g_2.mul(d_v)).add(sharedMemory.g_tilde.mul(hash_IDvNum)), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs1.isEqual(rhs1)) {
				LOG.debug("failed the first verification check");
				return false;
			}
			LOG.debug("passed the first verification check");
			//check SK_V
			final Element lhs2=sharedMemory.pairing.pairing(sharedMemory.g_tilde,SK_V);
			final Element rhs2=sharedMemory.pairing.pairing(Y_tilde_A,crypto.getHash(ID_V_bytes, sharedMemory.Hash2,sharedMemory.pairing.getG2()));
			
			if (!lhs2.isEqual(rhs2)) {
				LOG.debug("failed the second verification check");
				return false;
			}
			LOG.debug("passed the second verification check");
			verifierData.d_v = d_v;
			verifierData.e_v = e_v;
			verifierData.sigma_V = sigma_V;
			verifierData.SK_V=SK_V;
			return true;
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(this.verifiers[index]);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifyVerifierCredentials(message.getData());

				if (success) {
					LOG.debug("Successfully registered verifier details for " + this.verifiers[index]);
					this.index++;
					if (this.index == this.verifiers.length) {
						LOG.debug("all verifier details registered now!");
						return new Action<>(17);
					} else {
						LOG.debug("more verifier details to be registered...");
						return new Action<>(12);
					}
				}
			}
			return super.getAction(message);
		}
	}

	
	
	
	
	
	
	/**
	 * State 17: As Central Verifier: generate the CV identity
	 */
	public static class RState17 extends State<ICCCommand> {

		private byte[] generateCVIdentity() {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);

			// Send ID_CV, Y_CV
			final ListData sendData = new ListData(Arrays.asList(cenVerData.ID_V.getBytes(), cenVerData.Y_CV.toBytes()));
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generateCVIdentity();

				if (data != null) {
					LOG.debug("sending central verifier identity data");
					return new Action<>(Status.CONTINUE, 18, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}

	}


	/**
	 * State 19: As Central Authority: generate the central verifier credentials and send them
	 * to the central verifier
	 */
	public static class RState19 extends State<ICCCommand> {

		private byte[] generateCVCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();

			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 2) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			final String ID_CV = sharedMemory.stringFromBytes(listData.getList().get(0));
			final Element Y_CV = sharedMemory.G1ElementFromBytes(listData.getList().get(1));

			//compute the "normal" verifier stuff first
			BigInteger e_v; 
			BigInteger d_v;
			Element sigma_V;
			Element SK_V;
			
			//check if we already computed the details for this verifier
			if (centralAuthorityData.verifiers.containsKey(ID_CV)) {
				// we can simply retrieve its details
				CentralAuthorityData.VerifierCredentials verifierDetails=centralAuthorityData.verifiers.get(ID_CV);
				d_v=verifierDetails.d_v;
				e_v=verifierDetails.e_v;
				sigma_V=verifierDetails.sigma_V;
				SK_V=verifierDetails.SK_V;
			}else {
				// we need to do some computation
				final List<byte[]> hash_IDvData = new ArrayList<>();
				final byte[] ID_V_bytes=sharedMemory.stringToBytes(ID_CV);
				hash_IDvData.add(ID_V_bytes);
				
				final BigInteger hash_IDvNum = (new BigInteger(1, crypto.getHash((new ListData(hash_IDvData)).toBytes(), sharedMemory.Hash1))).mod(sharedMemory.p);

				// compute sigma_CV
				e_v = crypto.secureRandom(sharedMemory.p);
				d_v = crypto.secureRandom(sharedMemory.p);
				final BigIntEuclidean gcd = BigIntEuclidean
						.calculate(centralAuthorityData.alpha.add(e_v).mod(sharedMemory.p), sharedMemory.p);

				sigma_V = (sharedMemory.g_1.add(sharedMemory.g_2.mul(d_v)).add(sharedMemory.g_tilde.mul(hash_IDvNum)))
						.mul(gcd.x.mod(sharedMemory.p)).getImmutable();
				
				SK_V=crypto.getHash(ID_V_bytes, sharedMemory.Hash2,sharedMemory.pairing.getG2()).mul(centralAuthorityData.beta).getImmutable();

				CentralAuthorityData.VerifierCredentials verifierDetails = centralAuthorityData
						.getVerifierCredentialsInstance();
				verifierDetails.ID_V = ID_CV;
				verifierDetails.d_v = d_v;
				verifierDetails.e_v = e_v;
				verifierDetails.sigma_V = sigma_V;
				verifierDetails.SK_V=SK_V;

				centralAuthorityData.verifiers.put(ID_CV, verifierDetails);
			}
			
			//now compute the specific CV keys
			
			// compute sigma_CV
			final BigInteger d_cv = crypto.secureRandom(sharedMemory.p);
			final BigInteger e_cv = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.alpha.add(e_cv).mod(sharedMemory.p),
					sharedMemory.p);

			final Element sigma_CV = (sharedMemory.g_1.add(sharedMemory.g_2.mul(d_cv)).add(Y_CV))
					.mul(gcd.x.mod(sharedMemory.p)).getImmutable();

			centralAuthorityData.ID_CV = ID_CV;
			centralAuthorityData.Y_CV = Y_CV;
			centralAuthorityData.d_cv = d_cv;
			centralAuthorityData.e_cv = e_cv;
			centralAuthorityData.sigma_CV = sigma_CV;

			
			
			// Send sigma_V, d_v, e_v, SK_V, sigma_CV, d_cv, e_cv back
			final ListData sendData = new ListData(
					Arrays.asList(sigma_V.toBytes(), d_v.toByteArray(), e_v.toByteArray(), SK_V.toBytes(),
							sigma_CV.toBytes(), d_cv.toByteArray(), e_cv.toByteArray()));
		
			return sendData.toBytes();
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generateCVCredentials(message.getData());

				if (data != null) {
					LOG.debug("sending central verifier credentials data");
					return new Action<>(Status.CONTINUE, 20, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}
	}



	/**
	 * State 21 As Central Verifier: verify the Central Authority's data and store the
	 * CV's credentials
	 */
	public static class RState21 extends State<ICCCommand> {

		private boolean verifyCVCredentials(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);
			final Crypto crypto = Crypto.getInstance();
			
			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 7) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			final Element sigma_V = sharedMemory.G1ElementFromBytes(listData.getList().get(0));
			final BigInteger d_v = new BigInteger(listData.getList().get(1));
			final BigInteger e_v = new BigInteger(listData.getList().get(2));
			final Element SK_V= sharedMemory.G2ElementFromBytes(listData.getList().get(3));
			final Element sigma_CV = sharedMemory.G1ElementFromBytes(listData.getList().get(4));
			final BigInteger d_cv = new BigInteger(listData.getList().get(5));
			final BigInteger e_cv = new BigInteger(listData.getList().get(6));
			
			final List<byte[]> hash_IDvData = new ArrayList<>();
			final byte[] ID_V_bytes=sharedMemory.stringToBytes(cenVerData.ID_V);
			hash_IDvData.add(ID_V_bytes);
			final BigInteger hash_IDvNum = (new BigInteger(1, crypto.getHash((new ListData(hash_IDvData)).toBytes(), sharedMemory.Hash1))).mod(sharedMemory.p);


			// verify the credentials

			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[0];
			final Element Y_tilde_A=sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[1];

			final Element lhs1 = sharedMemory.pairing.pairing(sigma_V, Y_A.add(sharedMemory.g_frak.mul(e_v)))
					.getImmutable();
			final Element rhs1 = sharedMemory.pairing
					.pairing(sharedMemory.g_1.add(sharedMemory.g_2.mul(d_v)).add(sharedMemory.g_tilde.mul(hash_IDvNum)), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs1.isEqual(rhs1)) {
				LOG.debug("failed the first CV as V verification check");
				return false;
			}
			LOG.debug("passed the first CV as V verification check");
			//check SK_V
			final Element lhs2=sharedMemory.pairing.pairing(sharedMemory.g_tilde,SK_V);
			final Element rhs2=sharedMemory.pairing.pairing(Y_tilde_A,crypto.getHash(ID_V_bytes, sharedMemory.Hash2,sharedMemory.pairing.getG2()));
			
			if (!lhs2.isEqual(rhs2)) {
				LOG.debug("failed the second CV as V verification check");
				return false;
			}
			LOG.debug("passed the second verification check");
			cenVerData.d_v = d_v;
			cenVerData.e_v = e_v;
			cenVerData.sigma_V = sigma_V;
			cenVerData.SK_V=SK_V;

			// verify the credentials


			final Element lhs = sharedMemory.pairing.pairing(sigma_CV, Y_A.add(sharedMemory.g_frak.mul(e_cv)))
					.getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(sharedMemory.g_1.add(sharedMemory.g_2.mul(d_cv)).add(cenVerData.Y_CV), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				LOG.debug("failed the CV as CV verification check");
				return false;
			}
			LOG.debug("passed the CV as CV verification check");
			cenVerData.e_cv = e_cv;
			cenVerData.d_cv = d_cv;
			cenVerData.sigma_CV = sigma_CV;
			return true;
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifyCVCredentials(message.getData());

				if (success) {
					LOG.debug("Successfully registered central verifier details!");
					//return new Action<>(Status.END_SUCCESS, 0, null, null, 0);
					return new Action<>(22);
				}
			}

			return super.getAction(message);
		}
	}

	

	
	
}
