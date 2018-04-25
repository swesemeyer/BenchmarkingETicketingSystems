/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.pplast;

import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.pplast.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.CentralVerifierData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.VerifierData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

/**
 * Registration states of the PPLAST state machine protocol.
 *
 * @author Steve Wesemeyer
 */
public class PPLASTRegistrationStates {

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(PPLASTRegistrationStates.class);

	/**
	 * State 04: As Seller: generate the seller identity
	 */
	public static class RState04 extends State<NFCReaderCommand> {

		private byte[] generateSellerIdentity() {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final IssuerData sellerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);

			// Send ID_I, Y_bar_I, Y_S_bar
			final ListData sendData = new ListData(
					Arrays.asList(sellerData.ID_I.getBytes(), sellerData.Y_I.toBytes(), sellerData.Y_bar_I.toBytes()));
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.ISSUER);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generateSellerIdentity();

				if (data != null) {
					return new Action<>(Status.CONTINUE, 5, NFCReaderCommand.PUT_INTERNAL, data, 0);
				}
			}

			return super.getAction(message);
		}

	}

	/**
	 * State 05: As Central Authority: get the data from the seller
	 */
	public static class RState05 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);

			// Get the seller identity data.
			return new Action<>(Status.CONTINUE, 6, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 06: As Central Authority: generate the seller credentials and send them
	 * to the seller
	 */
	public static class RState06 extends State<NFCReaderCommand> {

		private byte[] generateSellerCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}
			final String ID_S = sharedMemory.stringFromBytes(listData.getList().get(0));
			final Element Y_S = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));
			final Element Y_bar_S = sharedMemory.curveG2ElementFromBytes(listData.getList().get(2));

			// compute sigma_s
			final BigInteger e_S = crypto.secureRandom(sharedMemory.p);
			final BigInteger r_S = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_S).mod(sharedMemory.p),
					sharedMemory.p);
			final Element sigma_S = (sharedMemory.g.add(sharedMemory.h.mul(r_S)).add(Y_S))
					.mul(gcd.x.mod(sharedMemory.p)).getImmutable();

			centralAuthorityData.ID_I = ID_S;
			centralAuthorityData.Y_I = Y_S;
			centralAuthorityData.Y_bar_I = Y_bar_S;
			centralAuthorityData.r_I = r_S;
			centralAuthorityData.e_I = e_S;
			centralAuthorityData.sigma_I = sigma_S;

			// Send sigma_s, e_s, r_s
			final ListData sendData = new ListData(
					Arrays.asList(sigma_S.toBytes(), r_S.toByteArray(), e_S.toByteArray()));
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generateSellerCredentials(message.getData());
				if (data != null) {
					return new Action<>(Status.CONTINUE, 7, NFCReaderCommand.PUT_INTERNAL, data, 0);
				}
			}
			return super.getAction(message);
		}
	}

	/**
	 * State 07 As seller: Get the data from the Central Authority
	 */
	public static class RState07 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {

			// Get the seller credentials data.
			return new Action<>(Status.CONTINUE, 8, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 08 As seller: verify the Central Authority's data and store the
	 * seller's credentials
	 */
	public static class RState08 extends State<NFCReaderCommand> {

		private boolean verifySellerCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final IssuerData sellerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}
			final Element sigma_S = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
			final BigInteger r_S = new BigInteger(listData.getList().get(1));
			final BigInteger e_S = new BigInteger(listData.getList().get(2));

			// verify the credentials
			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);
			final Element lhs = sharedMemory.pairing.pairing(sigma_S, Y_A.add(sharedMemory.g_frak.mul(e_S)))
					.getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_S)).add(sellerData.Y_I), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				return false;
			}

			sellerData.e_I = e_S;
			sellerData.r_I = r_S;
			sellerData.sigma_I = sigma_S;
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.ISSUER);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifySellerCredentials(message.getData());
				if (success) {
					LOG.debug("Successfully registered seller!");
					return new Action<>(9);
				}
			}
			return super.getAction(message);
		}
	}

	/**
	 * State 09 As Central Authority: get the user's identity
	 */

	public static class RState09 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {

			// Get the user's identity data.
			LOG.debug("Getting the user's identity details");
			return new Action<>(Status.CONTINUE, 10, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 10: As Central Authority: generate the user's credentials and send them
	 * to the user
	 */
	public static class RState10 extends State<NFCReaderCommand> {

		private byte[] generateUserCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
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
			final Element Y_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));
			// store the user's public key in the sharedMemory
			sharedMemory.Y_U = (CurveElement<?, ?>) Y_U.getImmutable();

			// compute sigma_v
			final BigInteger e_u = crypto.secureRandom(sharedMemory.p);
			final BigInteger r_u = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_u).mod(sharedMemory.p),
					sharedMemory.p);

			final Element sigma_U = (sharedMemory.g.add(sharedMemory.h.mul(r_u)).add(Y_U))
					.mul(gcd.x.mod(sharedMemory.p)).getImmutable();

			centralAuthorityData.ID_U = ID_U;
			centralAuthorityData.Y_U = Y_U;
			centralAuthorityData.r_u = r_u;
			centralAuthorityData.e_u = e_u;
			centralAuthorityData.sigma_U = sigma_U;

			// Send sigma_s, e_s, r_s
			final ListData sendData = new ListData(
					Arrays.asList(sigma_U.toBytes(), r_u.toByteArray(), e_u.toByteArray()));

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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				if (message.getData() != null) {
					final byte[] data = this.generateUserCredentials(message.getData());
					LOG.debug("Generated the user's credentials");
					// Send the setup data.
					if (data != null) {
						return new Action<>(Status.CONTINUE, 11, NFCReaderCommand.PUT, data, 0);
					}
				}
			}
			return super.getAction(message);
		}
	}

	/**
	 * State 11
	 */
	public static class RState11 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {
			if (message.getType() == Type.SUCCESS) {
				LOG.debug("successfully registered user via NFC");
				return new Action<>(12);
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 12: As Police: generate the police identity
	 */
	public static class RState12 extends State<NFCReaderCommand> {

		private byte[] generatePoliceIdentity() {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);

			// Send ID_U, Y_U
			final ListData sendData = new ListData(Arrays.asList(cenVerData.ID_V.getBytes(), cenVerData.Y_V.toBytes()));
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generatePoliceIdentity();

				if (data != null) {
					LOG.debug("sending police identity data");
					return new Action<>(Status.CONTINUE, 13, NFCReaderCommand.PUT_INTERNAL, data, 0);
				}
			}

			return super.getAction(message);
		}

	}

	/**
	 * State 13: As Central Authority: get the data from the police
	 */
	public static class RState13 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {
			LOG.debug("getting police identity data");
			return new Action<>(Status.CONTINUE, 14, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 14: As Central Authority: generate the police credentials and send them
	 * to the police
	 */
	public static class RState14 extends State<NFCReaderCommand> {

		private byte[] generatePoliceCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();

			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 2) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			final String ID_P = sharedMemory.stringFromBytes(listData.getList().get(0));
			final Element Y_P = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));

			// compute Z_CV
			final BigInteger e_P = crypto.secureRandom(sharedMemory.p);
			final BigInteger r_P = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_P).mod(sharedMemory.p),
					sharedMemory.p);

			final Element sigma_P = (sharedMemory.g.add(sharedMemory.h.mul(r_P)).add(Y_P))
					.mul(gcd.x.mod(sharedMemory.p)).getImmutable();

			centralAuthorityData.ID_CV = ID_P;
			centralAuthorityData.Y_CV = Y_P;
			centralAuthorityData.r_CV = r_P;
			centralAuthorityData.e_CV = e_P;
			centralAuthorityData.sigma_CV = sigma_P;

			// Send sigma_s, e_s, r_s
			final ListData sendData = new ListData(
					Arrays.asList(sigma_P.toBytes(), r_P.toByteArray(), e_P.toByteArray()));

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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generatePoliceCredentials(message.getData());

				if (data != null) {
					LOG.debug("sending police credentials data");
					return new Action<>(Status.CONTINUE, 15, NFCReaderCommand.PUT_INTERNAL, data, 0);
				}
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 15 As police: Get the data from the Central Authority
	 */
	public static class RState15 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {

			LOG.debug("getting police credential data");
			return new Action<>(Status.CONTINUE, 16, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 16 As police: verify the Central Authority's data and store the
	 * police's credentials
	 */
	public static class RState16 extends State<NFCReaderCommand> {

		private boolean verifyPoliceCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			final Element sigma_CV = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
			final BigInteger r_CV = new BigInteger(listData.getList().get(1));
			final BigInteger e_CV = new BigInteger(listData.getList().get(2));

			// verify the credentials

			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

			final Element lhs = sharedMemory.pairing.pairing(sigma_CV, Y_A.add(sharedMemory.g_frak.mul(e_CV)))
					.getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_CV)).add(cenVerData.Y_V), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				return false;
			}

			cenVerData.e_V = e_CV;
			cenVerData.r_V = r_CV;
			cenVerData.sigma_V = sigma_CV;
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifyPoliceCredentials(message.getData());

				if (success) {
					LOG.debug("Successfully registered police details!");
					return new Action<>(17);
				}
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 17: As Verifier: generate the verifier's identity
	 */
	public static class RState17 extends State<NFCReaderCommand> {

		private String[] verifiers;
		private int index;

		public RState17(String[] verifiers) {
			this.verifiers = verifiers;
			this.index = 0;
		}

		private byte[] generateVerifierIdentity() {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final VerifierData verifierData = (VerifierData) sharedMemory.getData(this.verifiers[this.index]);
			// Send ID_V, Y_V
			final ListData sendData = new ListData(
					Arrays.asList(verifierData.ID_V.getBytes(), verifierData.Y_V.toBytes()));
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.VERIFIERS[this.index]);
			if (message.getType() == Type.SUCCESS) {
				// Send the setup data.
				final byte[] data = this.generateVerifierIdentity();

				if (data != null) {
					LOG.debug("sending verifier identity data for " + Actor.VERIFIERS[this.index]);
					this.index++;
					return new Action<>(Status.CONTINUE, 18, NFCReaderCommand.PUT_INTERNAL, data, 0);
				}
			}

			return super.getAction(message);
		}

	}

	/**
	 * State 18: As Central Authority: get the data from the verifier
	 */
	public static class RState18 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {
			LOG.debug("getting verifier identity data");
			return new Action<>(Status.CONTINUE, 19, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 19: As Central Authority: generate the verifier credentials and send
	 * them to the verifier
	 */
	public static class RState19 extends State<NFCReaderCommand> {

		private byte[] generateVerifierCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();

			final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 2) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			final String ID_V = sharedMemory.stringFromBytes(listData.getList().get(0));
			BigInteger e_V; 
			BigInteger r_V; 
			Element sigma_V;
			//check if we already computed the details for this verifier
			if (centralAuthorityData.verifiers.containsKey(ID_V)) {
				// we can simply retrieve its details
				CentralAuthorityData.VerifierCredentials verifierDetails=centralAuthorityData.verifiers.get(ID_V);
				r_V=verifierDetails.r_V;
				e_V=verifierDetails.e_V;
				sigma_V=verifierDetails.sigma_V;
			}else {
				// we need to do some computation
				final Element Y_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));

				// compute sigma_v
				 e_V = crypto.secureRandom(sharedMemory.p);
				r_V = crypto.secureRandom(sharedMemory.p);
				final BigIntEuclidean gcd = BigIntEuclidean
						.calculate(centralAuthorityData.x_a.add(e_V).mod(sharedMemory.p), sharedMemory.p);

				sigma_V = (sharedMemory.g.add(sharedMemory.h.mul(r_V)).add(Y_V))
						.mul(gcd.x.mod(sharedMemory.p)).getImmutable();

				CentralAuthorityData.VerifierCredentials veriferDetails = centralAuthorityData
						.getVerifierCredentialsInstance();
				veriferDetails.ID_V = ID_V;
				veriferDetails.Y_V = Y_V;
				veriferDetails.r_V = r_V;
				veriferDetails.e_V = e_V;
				veriferDetails.sigma_V = sigma_V;

				centralAuthorityData.verifiers.put(ID_V, veriferDetails);
			}
			// Send Z_V, e_V, r_V back
			final ListData sendData = new ListData(
					Arrays.asList(sigma_V.toBytes(), r_V.toByteArray(), e_V.toByteArray()));

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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generateVerifierCredentials(message.getData());

				if (data != null) {
					LOG.debug("sending verifier credentials data");
					return new Action<>(Status.CONTINUE, 20, NFCReaderCommand.PUT_INTERNAL, data, 0);
				}
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 20 As verifier: Get the data from the Central Authority
	 */
	public static class RState20 extends State<NFCReaderCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<NFCReaderCommand> getAction(Message message) {

			LOG.debug("getting verifier credential data");
			return new Action<>(Status.CONTINUE, 21, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * State 21 As verifier: verify the Central Authority's data and store the
	 * verifier's credentials
	 */
	public static class RState21 extends State<NFCReaderCommand> {

		private String[] verifiers;
		private int index;

		public RState21(String[] verifiers) {
			this.verifiers = verifiers;
			this.index = 0;
		}

		private boolean verifyVerifierCredentials(byte[] data) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			final VerifierData verifierData = (VerifierData) sharedMemory.getData(this.verifiers[index]);

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			final Element sigma_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
			final BigInteger r_V = new BigInteger(listData.getList().get(1));
			final BigInteger e_V = new BigInteger(listData.getList().get(2));

			// verify the credentials

			// get the public key of the CA
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

			final Element lhs = sharedMemory.pairing.pairing(sigma_V, Y_A.add(sharedMemory.g_frak.mul(e_V)))
					.getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_V)).add(verifierData.Y_V), sharedMemory.g_frak)
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				return false;
			}

			verifierData.e_V = e_V;
			verifierData.r_V = r_V;
			verifierData.sigma_V = sigma_V;
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
		public Action<NFCReaderCommand> getAction(Message message) {
			final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(this.verifiers[index]);
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final boolean success = this.verifyVerifierCredentials(message.getData());

				if (success) {
					LOG.debug("Successfully registered verifier details for " + this.verifiers[index]);
					this.index++;
					if (this.index == this.verifiers.length) {
						return new Action<>(22);
					} else {
						return new Action<>(17);
					}
				}
			}
			return super.getAction(message);
		}
	}

}
