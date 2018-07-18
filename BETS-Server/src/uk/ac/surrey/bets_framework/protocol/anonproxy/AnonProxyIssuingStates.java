package uk.ac.surrey.bets_framework.protocol.anonproxy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.icc.ICC;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.ICCCommand;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.TicketDetails;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.UserData;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.Message.Type;
import uk.ac.surrey.bets_framework.state.State;

/**
 * Ticket issuing states of the AnonProxy state machine protocol.
 *
 * @author Steve Wesemeyer
 */

public class AnonProxyIssuingStates {

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonProxyIssuingStates.class);

	/**
	 * State 22. As User: generate the ticket request
	 */
	public static class IState22 extends State<ICCCommand> {

		/**
		 * this method computes the necessary details for a ticket request
		 * 
		 * @return the ticket request details
		 */
		private byte[] generateTicketRequest() {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
			final Crypto crypto = Crypto.getInstance();

			// get some elements from sharedMemory
			LOG.debug("computing ZK_PI_1_U");
			final BigInteger p = sharedMemory.p;
			final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER)[1].getImmutable();
			final Element g_1 = sharedMemory.g_1.getImmutable();
			final Element g_2 = sharedMemory.g_2.getImmutable();
			final Element g_tilde = sharedMemory.g_tilde.getImmutable();

			// need to include Central Verifier in the list of verifiers
			final int numberOfVerifiers = userData.VerifierList.length + 1;

			// compute some stuff for the ZKP PI_1_U
			final Element A_U = g_1.add(g_2.mul(userData.d_u)).add(userData.Y_U);
			final BigInteger y_1 = crypto.secureRandom(p);
			final BigInteger y_2 = crypto.secureRandom(p);
			final BigInteger y_3 = crypto.secureRandom(p);
			// store y_3 for later use...
			 userData.y_3 = y_3;

			final BigInteger x_dash_u = crypto.secureRandom(p);
			final BigInteger e_dash_u = crypto.secureRandom(p);
			final BigInteger y_dash = crypto.secureRandom(p);
			final BigInteger y_dash_1 = crypto.secureRandom(p);
			final BigInteger y_dash_2 = crypto.secureRandom(p);
			final BigInteger[] k_dash_v = new BigInteger[numberOfVerifiers];
			for (int i = 0; i < numberOfVerifiers; i++) {
				k_dash_v[i] = crypto.secureRandom(p);
			}

			BigIntEuclidean gcd = BigIntEuclidean.calculate(y_1, p);
			final BigInteger y_4 = gcd.x.mod(p);

			final Element sigma_bar_U = userData.sigma_U.mul(y_1).getImmutable();
			final BigInteger y = (userData.d_u.subtract(y_2.multiply(y_4))).mod(p);

			final Element A_bar_U = A_U.mul(y_1).add(g_2.mul(y_2.negate().mod(p))).getImmutable();
			final Element sigma_tilde_U = (sigma_bar_U.mul(userData.e_u.negate().mod(p))).add(A_U.mul(y_1))
					.getImmutable();

			final Element W_bar_1 = ((sigma_bar_U.mul(e_dash_u.negate().mod(p))).add(g_2.mul(y_dash_1))).getImmutable();
			LOG.debug("W_bar_1=" + W_bar_1);
			final Element W_bar_2 = (((A_bar_U.mul(y_dash_2.negate().mod(p))).add(g_tilde.mul(x_dash_u)))
					.add(g_2.mul(y_dash))).getImmutable();

			final byte[][] k_v = new byte[numberOfVerifiers][];
			final Element[] P_V = new Element[numberOfVerifiers];
			final Element[] P_dash_V = new Element[numberOfVerifiers];
			final Element[] Q_V = new Element[numberOfVerifiers];
			final Element[] Q_dash_V = new Element[numberOfVerifiers];

			for (int i = 0; i < numberOfVerifiers; i++) {
				if (i < numberOfVerifiers - 1) {
					LOG.debug("adding verifier: " + i);
					final ListData kvData = new ListData(
							Arrays.asList(y_3.toByteArray(), userData.VerifierList[i].getBytes()));
					k_v[i] = crypto.getHash(kvData.toBytes(), sharedMemory.Hash1);
					final BigInteger k_vNum = (new BigInteger(1, k_v[i])).mod(sharedMemory.p);
					P_V[i] = userData.Y_U.add(Y_CV.mul(k_vNum)).getImmutable();
					P_dash_V[i] = ((g_tilde.mul(x_dash_u)).add(Y_CV.mul(k_dash_v[i]))).getImmutable();
					Q_V[i] = g_tilde.mul(k_vNum).getImmutable();
					Q_dash_V[i] = g_tilde.mul(k_dash_v[i]).getImmutable();
				} else {
					LOG.debug("adding central verifier!");
					final ListData kvData = new ListData(
							Arrays.asList(y_3.toByteArray(), Actor.CENTRAL_VERIFIER.getBytes()));
					k_v[i] = crypto.getHash(kvData.toBytes(), sharedMemory.Hash1);
					final BigInteger k_vnum = (new BigInteger(1, k_v[i])).mod(sharedMemory.p);
					P_V[i] = userData.Y_U.add(Y_CV.mul(k_vnum)).getImmutable();
					P_dash_V[i] = ((g_tilde.mul(x_dash_u)).add(Y_CV.mul(k_dash_v[i]))).getImmutable();
					Q_V[i] = g_tilde.mul(k_vnum).getImmutable();
					Q_dash_V[i] = g_tilde.mul(k_dash_v[i]).getImmutable();
				}
			}
			LOG.debug("finished computing ZK_PI_1_U");
			final List<byte[]> c_DataList = new ArrayList<>();

			c_DataList.addAll(Arrays.asList(sigma_bar_U.toBytes(), sigma_tilde_U.toBytes(), A_bar_U.toBytes(),
					W_bar_1.toBytes(), W_bar_2.toBytes()));
			for (int i = 0; i < numberOfVerifiers; i++) {
				c_DataList.add(P_V[i].toBytes());
				c_DataList.add(P_dash_V[i].toBytes());
				c_DataList.add(Q_V[i].toBytes());
				c_DataList.add(Q_dash_V[i].toBytes());
			}
			final byte[] c_hash = crypto.getHash((new ListData(c_DataList)).toBytes(), sharedMemory.Hash1);
			final BigInteger c_hashNum = (new BigInteger(1, c_hash)).mod(p);

			final BigInteger e_hat_U = (e_dash_u.subtract(c_hashNum.multiply(userData.e_u))).mod(p);
			final BigInteger y_hat_1 = (y_dash.subtract(c_hashNum.multiply(y))).mod(p);
			final BigInteger y_hat_2 = (y_dash_1.subtract(c_hashNum.multiply(y_2))).mod(p);
			final BigInteger y_hat_3 = (y_dash_2.subtract(c_hashNum.multiply(y_4))).mod(p);
			final BigInteger x_hat_u = (x_dash_u.subtract(c_hashNum.multiply(userData.x_u))).mod(p);

			final BigInteger[] k_hat_v = new BigInteger[numberOfVerifiers];
			for (int i = 0; i < numberOfVerifiers; i++) {
				final BigInteger k_vNum = (new BigInteger(1, k_v[i])).mod(p);
				k_hat_v[i] = (k_dash_v[i].subtract(c_hashNum.multiply(k_vNum))).mod(p);
			}

			final List<byte[]> sendDataList = new ArrayList<>();
			sendDataList.addAll(Arrays.asList(sigma_bar_U.toBytes(), sigma_tilde_U.toBytes(), A_bar_U.toBytes(),
					W_bar_1.toBytes(), W_bar_2.toBytes()));

			// need to send all the verifier IDs
			sendDataList.add(BigInteger.valueOf(numberOfVerifiers).toByteArray());
			for (int i = 0; i < numberOfVerifiers; i++) {
				if (i < numberOfVerifiers - 1) {
					sendDataList.add(userData.VerifierList[i].getBytes(StandardCharsets.UTF_8));
				} else {
					sendDataList.add(Actor.CENTRAL_VERIFIER.getBytes(StandardCharsets.UTF_8));
				}
			}

			// send the Ps and Qs
			for (int i = 0; i < numberOfVerifiers; i++) {
				sendDataList.add(P_V[i].toBytes());
				sendDataList.add(P_dash_V[i].toBytes());
				sendDataList.add(Q_V[i].toBytes());
				sendDataList.add(Q_dash_V[i].toBytes());
			}

			// add the last few items...
			sendDataList.addAll(Arrays.asList(c_hash, e_hat_U.toByteArray(), y_hat_1.toByteArray(),
					y_hat_2.toByteArray(), y_hat_3.toByteArray(), x_hat_u.toByteArray()));

			for (int i = 0; i < numberOfVerifiers; i++) {
				sendDataList.add(k_hat_v[i].toByteArray());
			}

			final ListData sendData = new ListData(sendDataList);
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
			// We are now the user.
			((AnonProxySharedMemory) this.getSharedMemory()).actAs(AnonProxySharedMemory.Actor.USER);

			if (message.getType() == Message.Type.SUCCESS) {
				LOG.debug("about to generate a ticket request");
				byte[] data = this.generateTicketRequest();

				if (data != null) {
					LOG.debug("generate user ticket request complete");
					return new Action<>(Status.CONTINUE, 23, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}

	}


	/**
	 * State 24 As issuer: verify user proof and issue ticket
	 */
	public static class IState24 extends State<ICCCommand> {

		private byte[] generateTicketDetails(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final IssuerData issuerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() <= 0) { // dependent on the number of verifiers...
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			// some constants from sharedMemory
			final BigInteger p = sharedMemory.p;

			// G1 generators
			final Element g_tilde = sharedMemory.g_tilde.getImmutable();
			final Element g_bar = sharedMemory.g_bar.getImmutable();
			final Element g_1 = sharedMemory.g_1.getImmutable();
			final Element g_2 = sharedMemory.g_2.getImmutable();
			final Element g_3 = sharedMemory.g_3.getImmutable();

			// G2 generators
			final Element g_frak = sharedMemory.g_frak.getImmutable();
			final Element theta_1 = sharedMemory.theta1.getImmutable();
			final Element theta_2 = sharedMemory.theta2.getImmutable();

			// check the ZKP here:

			int index = 0;
			final List<byte[]> verifyc_hashData = new ArrayList<>();

			final Element sigma_bar_U = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element sigma_tilde_U = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[0];
			final Element Y_tilde_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY)[1];

			final Element lhs = sharedMemory.pairing.pairing(sigma_bar_U, Y_A).getImmutable();
			final Element rhs = sharedMemory.pairing.pairing(sigma_tilde_U, g_frak).getImmutable();

			if (!lhs.isEqual(rhs)) {
				LOG.debug("verify user proof: simple pairing check failed");
				return null;
			}

			LOG.debug("passed simple pairing check");

			// compute the hash
			verifyc_hashData.add(sigma_bar_U.toBytes());
			verifyc_hashData.add(sigma_tilde_U.toBytes());
			final Element A_bar_U = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			verifyc_hashData.add(A_bar_U.toBytes());
			final Element W_bar_1 = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			verifyc_hashData.add(W_bar_1.toBytes());
			final Element W_bar_2 = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			verifyc_hashData.add(W_bar_2.toBytes());

			final int numberOfVerifiers = new BigInteger(1, listData.getList().get(index++)).intValue();

			final TicketDetails ticketDetails = new TicketDetails(numberOfVerifiers);

			for (int i = 0; i < numberOfVerifiers; i++) {
				ticketDetails.VerifierList[i] = new String(listData.getList().get(index++), StandardCharsets.UTF_8);
			}

			final Element[] P_dash_V = new Element[numberOfVerifiers];
			final Element[] Q_dash_V = new Element[numberOfVerifiers];
			for (int i = 0; i < numberOfVerifiers; i++) {
				ticketDetails.P_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
				P_dash_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
				ticketDetails.Q_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
				Q_dash_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
				verifyc_hashData.add(ticketDetails.P_V[i].toBytes());
				verifyc_hashData.add(P_dash_V[i].toBytes());
				verifyc_hashData.add(ticketDetails.Q_V[i].toBytes());
				verifyc_hashData.add(Q_dash_V[i].toBytes());
			}

			final byte[] c_hash = listData.getList().get(index++);

			// check the hash value is correct
			final byte[] verifyc_hash = crypto.getHash((new ListData(verifyc_hashData)).toBytes(), sharedMemory.Hash1);
			if (!Arrays.equals(c_hash, verifyc_hash)) {
				LOG.debug("c_hash verification failed!");
				return null;
			}
			LOG.debug("Passed c_hash verification!");
			// need the BigInteger value of c_hash now
			final BigInteger c_hashNum = (new BigInteger(1, c_hash)).mod(p);

			// add the last few items...

			final BigInteger e_hat_u = new BigInteger(1, listData.getList().get(index++));
			final BigInteger y_hat_1 = new BigInteger(1, listData.getList().get(index++));
			final BigInteger y_hat_2 = new BigInteger(1, listData.getList().get(index++));
			final BigInteger y_hat_3 = new BigInteger(1, listData.getList().get(index++));
			final BigInteger x_hat_u = new BigInteger(1, listData.getList().get(index++));

			final BigInteger[] k_hat_v = new BigInteger[numberOfVerifiers];
			for (int i = 0; i < numberOfVerifiers; i++) {
				k_hat_v[i] = new BigInteger(1, listData.getList().get(index++));
			}
			LOG.debug("W_bar_1=" + W_bar_1);
			// check W_bar_1
			final Element W_1lhs = ((sigma_bar_U.mul(e_hat_u.negate().mod(p))).add(g_2.mul(y_hat_2)))
					.add((sigma_tilde_U.sub(A_bar_U)).mul(c_hashNum)).getImmutable();

			if (!W_bar_1.isEqual(W_1lhs)) {
				LOG.debug("W_bar_1 verification failed!");
				return null;
			}

			LOG.debug("passed W_bar_1 verification!");

			// check W_2
			Element W_2lhs = (A_bar_U.mul(y_hat_3.negate().mod(p))).getImmutable();
			W_2lhs = W_2lhs.add(g_tilde.mul(x_hat_u)).getImmutable();
			W_2lhs = W_2lhs.add(g_2.mul(y_hat_1)).getImmutable();
			W_2lhs = W_2lhs.add(g_1.mul(c_hashNum.negate().mod(p))).getImmutable();

			if (!W_bar_2.isEqual(W_2lhs)) {
				LOG.debug("W_bar_2 verification failed!");
				return null;
			}

			LOG.debug("passed W_bar_2 verification!");

			final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER)[1];

			for (int i = 0; i < numberOfVerifiers; i++) {
				final Element P_dash_Vlhs = (g_tilde.mul(x_hat_u)).add(Y_CV.mul(k_hat_v[i]))
						.add(ticketDetails.P_V[i].mul(c_hashNum)).getImmutable();
				if (!P_dash_V[i].isEqual(P_dash_Vlhs)) {
					LOG.debug("P_dash_V[" + i + "] verification failed!");
					return null;
				}
			}

			LOG.debug("passed P_dash_V verification!");

			for (int i = 0; i < numberOfVerifiers; i++) {
				final Element Q_dash_Vlhs = ((g_tilde.mul(k_hat_v[i])).add(ticketDetails.Q_V[i].mul(c_hashNum)))
						.getImmutable();
				if (!Q_dash_V[i].isEqual(Q_dash_Vlhs)) {
					LOG.debug("Q_dash_V[" + i + "] verification failed!");
					return null;
				}
			}
			LOG.debug("passed Q_dash_V verification!");
			LOG.debug("PI_U_1 proof passed");

			// Creating the ticket now

			final BigInteger r_u = crypto.secureRandom(p);
			final Element R_U = g_bar.mul(r_u);
			LOG.debug("R_U = " + R_U);

			BigIntEuclidean gcd = null;
			boolean hasCV = false;

			for (int i = 0; i < numberOfVerifiers; i++) {
				if (ticketDetails.VerifierList[i].equalsIgnoreCase(Actor.CENTRAL_VERIFIER)) {
					hasCV = true;
				}
				ticketDetails.t_v[i] = crypto.secureRandom(p);
				ticketDetails.w_v[i] = crypto.secureRandom(p);
				ticketDetails.z_v[i] = crypto.secureRandom(p);
				final ListData D_Vdata = new ListData(
						Arrays.asList(R_U.toBytes(), ticketDetails.VerifierList[i].getBytes()));
				final byte[] D_VdataHash = crypto.getHash(D_Vdata.toBytes(), sharedMemory.Hash3);
				ticketDetails.D_V[i] = sharedMemory.pairing.getG2().newElementFromHash(D_VdataHash, 0,
						D_VdataHash.length);
				LOG.debug("Verifier:" + ticketDetails.VerifierList[i]);
				Element ID_Vhash = crypto.getHash(ticketDetails.VerifierList[i].getBytes(), sharedMemory.Hash2,
						sharedMemory.pairing.getG2());

				ticketDetails.E_V_1[i] = sharedMemory.pairing.pairing(Y_tilde_A, ID_Vhash).mul(ticketDetails.t_v[i])
						.getImmutable();
				ticketDetails.E_V_2[i] = g_tilde.mul(ticketDetails.t_v[i]);

				final BigInteger text1_hashNum = (new BigInteger(1,
						crypto.getHash(ticketDetails.ticket_Text_1.getBytes(), sharedMemory.Hash1))).mod(p);
				ticketDetails.E_V_3[i] = (theta_1.add(theta_2.mul(text1_hashNum))).mul(ticketDetails.t_v[i]);

				final BigInteger ID_VhashNum = (new BigInteger(1,
						crypto.getHash(ticketDetails.VerifierList[i].getBytes(), sharedMemory.Hash1))).mod(p);
				ticketDetails.T_V[i] = (g_tilde.mul(ID_VhashNum)).add(Y_CV.mul(ticketDetails.t_v[i]));

				final ListData s_Vdata = new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(),
						ticketDetails.Q_V[i].toBytes(), ticketDetails.E_V_1[i].toBytes(),
						ticketDetails.E_V_2[i].toBytes(), ticketDetails.E_V_3[i].toBytes(),
						ticketDetails.T_V[i].toBytes(), ticketDetails.ticket_Text_2.getBytes()));
				
				ticketDetails.s_V[i] = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
				
				
				LOG.debug("Issuing s_v[i]"+crypto.base64Encode(ticketDetails.s_V[i]));
				final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);
				gcd = BigIntEuclidean.calculate(issuerData.x_i.add(ticketDetails.z_v[i]).mod(p), p);
				ticketDetails.Z_V[i] = (g_1.add(g_2.mul(ticketDetails.w_v[i])).add(g_3.mul(s_Vnum))).mul(gcd.x.mod(p))
						.getImmutable();

			}

			if (!hasCV) {
				LOG.debug("Central Verifier was not included: verification failed!");
				return null;
			}

			ticketDetails.w_cv = crypto.secureRandom(p);
			ticketDetails.z_cv = crypto.secureRandom(p);
			final List<byte[]> s_cvDataList = new ArrayList<>();
			for (int i = 0; i < numberOfVerifiers; i++) {
				s_cvDataList.add(ticketDetails.s_V[i]);
			}
			ticketDetails.s_CV = crypto.getHash((new ListData(s_cvDataList)).toBytes(), sharedMemory.Hash1);
			final BigInteger s_cvDataNum = new BigInteger(1, ticketDetails.s_CV).mod(p);
			gcd = BigIntEuclidean.calculate(issuerData.x_i.add(ticketDetails.z_cv).mod(p), p);
			ticketDetails.Z_CV = ((g_1.add(g_2.mul(ticketDetails.w_cv))).add(g_3.mul(s_cvDataNum))).mul(gcd.x.mod(p));

			final List<byte[]> sendDataList = new ArrayList<>();
			sendDataList.add(R_U.toBytes());
			sendDataList.add(BigInteger.valueOf(numberOfVerifiers).toByteArray()); // need to keep track of the array
																					// size
			ticketDetails.getTicketDetails(sendDataList);
			final ListData sendData = new ListData(sendDataList);

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
			if (message.getType() == Type.DATA) {
				// Send the setup data.
				final byte[] data = this.generateTicketDetails(message.getData());

				if (data != null) {
					LOG.debug("sending ticket details to the client");
					return new Action<>(Status.CONTINUE, 25, ICCCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}

	}


	/**
	 * State 26
	 * 
	 */
	public static class IState26 extends State<ICCCommand> {

		private boolean verifyTicketDetails(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() <= 0) { // dependent on the number of verifiers...
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}
			int indx = 0;
			final Element R_U = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
			LOG.debug("R_U: " + R_U);
			final int numOfVerifiers = new BigInteger(1, listData.getList().get(indx++)).intValue();
			LOG.debug("numOfVerifiers: " + numOfVerifiers);

			final TicketDetails ticketDetails = new TicketDetails(numOfVerifiers);
			indx = ticketDetails.populateTicketDetails(sharedMemory, listData, indx);

			// only check the verifiers if we really want to...
			if (sharedMemory.validateVerifiers) {
				for (int i = 0; i < numOfVerifiers; i++) {

					final ListData D_Vdata = new ListData(
							Arrays.asList(R_U.toBytes(), ticketDetails.VerifierList[i].getBytes()));
					final byte[] D_VdataHash = crypto.getHash(D_Vdata.toBytes(), sharedMemory.Hash3);
					final Element verifyD_V = sharedMemory.pairing.getG2().newElementFromHash(D_VdataHash, 0,
							D_VdataHash.length);
					if (!ticketDetails.D_V[i].isEqual(verifyD_V)) {
						LOG.error("failed to verify D_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
						return false;
					}
				}
				LOG.debug("Passed D_V verification!");

				for (int i = 0; i < numOfVerifiers; i++) {
					LOG.debug("Verifier to be processed: " + ticketDetails.VerifierList[i]);
					final ListData s_VdataVerify = new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(),
							ticketDetails.Q_V[i].toBytes(), ticketDetails.E_V_1[i].toBytes(),
							ticketDetails.E_V_2[i].toBytes(), ticketDetails.E_V_3[i].toBytes(),
							ticketDetails.T_V[i].toBytes(), ticketDetails.ticket_Text_2.getBytes()));
					final byte[] verifys_V = crypto.getHash(s_VdataVerify.toBytes(), sharedMemory.Hash1);
					LOG.debug("verifys_V: "+crypto.base64Encode(verifys_V));
					LOG.debug("ticket s_v[i]: "+crypto.base64Encode(ticketDetails.s_V[i]));
					if (!Arrays.equals(ticketDetails.s_V[i], verifys_V)) {
						LOG.error("failed to verify s_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
						return false;
					}

				}
				LOG.debug("Passed s_V verification!");

				// some elements from sharedMemory
				final Element Y_tilde_I = sharedMemory.getPublicKey(Actor.ISSUER)[1];
				final Element g_1 = sharedMemory.g_1.getImmutable();
				final Element g_2 = sharedMemory.g_2.getImmutable();
				final Element g_3 = sharedMemory.g_3.getImmutable();
				final Element g_frak = sharedMemory.g_frak.getImmutable();
				final BigInteger p = sharedMemory.p;

				for (int i = 0; i < numOfVerifiers; i++) {
					LOG.debug("Verifier: " + i + " is being checked.");

					final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.Z_V[i],
							Y_tilde_I.add(g_frak.mul(ticketDetails.z_v[i])))).getImmutable();
					final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);

					final Element rhs = (sharedMemory.pairing
							.pairing((g_1.add(g_2.mul(ticketDetails.w_v[i]))).add(g_3.mul(s_Vnum)), g_frak))
									.getImmutable();

					if (!lhs.isEqual(rhs)) {
						LOG.error("failed to verify pairing check [" + i + "] for verifier: "
								+ ticketDetails.VerifierList[i]);
						return false;
					}
				}
				LOG.debug("Passed Z_V pairing verification!");

				final List<byte[]> verifys_PData = new ArrayList<>();
				for (int i = 0; i < numOfVerifiers; i++) {
					verifys_PData.add(ticketDetails.s_V[i]);
				}

				if (!Arrays.equals(ticketDetails.s_CV,
						crypto.getHash((new ListData(verifys_PData)).toBytes(), sharedMemory.Hash1))) {
					LOG.error("failed to verify s_CV hash");
					return false;
				}

				LOG.debug("Passed s_CV verification!");

				final BigInteger s_cvNum = (new BigInteger(1, ticketDetails.s_CV)).mod(p);
				LOG.debug("Central Verifier is being checked.");
				final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.Z_CV,
						Y_tilde_I.add(g_frak.mul(ticketDetails.z_cv)))).getImmutable();
				LOG.debug("Central Verifier is still being checked. Computed lhs" + lhs);
				final Element rhs = (sharedMemory.pairing
						.pairing(g_1.add(g_2.mul(ticketDetails.w_cv)).add(g_3.mul(s_cvNum)), g_frak)).getImmutable();
				LOG.debug("Central Verifier is still being checked. Computed rhs" + rhs);

				if (!lhs.isEqual(rhs)) {
					LOG.error("failed to verify Z_CV pairing check");
					return false;
				}

				LOG.debug("Passed Z_CV pairing verification!");
			}
			// store the ticket details
			// note that z_U was stored during the ticket request generation
			userData.R_U = R_U;
			userData.ticketDetails = ticketDetails;

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
			// We are now the user.
			((AnonProxySharedMemory) this.getSharedMemory()).actAs(AnonProxySharedMemory.Actor.USER);

			if (message.getType() == Message.Type.DATA) {
				if (message.getData() != null) {
					if (this.verifyTicketDetails(message.getData())) {
						LOG.debug("successfully obtained a ticket !");
						//return new Action<>(Status.END_SUCCESS, 0, null, null, 0);
						 return new Action<>(27);
					}
				}
			}

			return super.getAction(message);
		}

	}

}
