package uk.ac.surrey.bets_framework.protocol.anonproxy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.ICCCommand;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.CentralVerifierData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.TicketDetails;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.UserData;
import uk.ac.surrey.bets_framework.protocol.anonproxy.data.VerifierData;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.Message.Type;
import uk.ac.surrey.bets_framework.state.SharedMemory;
import uk.ac.surrey.bets_framework.state.State;

public class AnonProxyVerifyingStates {

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonProxyVerifyingStates.class);

	/**
	 * State 27: As Verifier: send the ID
	 */
	public static class VState27 extends State<ICCCommand> {

		private String[] user_services;
		private String[] verifiers;
		private int index;

		public VState27(String[] user_services, String[] verifiers) {
			if (verifiers == null || user_services == null) {
				throw new RuntimeException("null value passed into constructor");
			}
			LOG.debug("Verifiers: " + verifiers.length);
			LOG.debug("user_services: " + user_services.length);
			if (verifiers.length != user_services.length) {
				throw new RuntimeException("lengths are not the same");
			}
			this.verifiers = verifiers;
			this.user_services = user_services;
			this.index = 0;
		}

		private byte[] generateVerifierID(String verifierName, String serviceName) {
			LOG.debug("Acting as verifier: " + verifierName);
			LOG.debug("Acting as proxy for: " + serviceName);
			boolean actAsProxy = false;
			if (serviceName.compareTo(verifierName) != 0) {
				actAsProxy = true;
			}
			LOG.debug("We are acting as a proxy is :" + actAsProxy);
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(verifierName);
			final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierName);
			LOG.debug("Verifier Name, ID = " + verifierName + ", " + verifierData.ID_V);
			final List<byte[]> sendDataList = new ArrayList<>();
			sendDataList.add(sharedMemory.stringToBytes(verifierData.ID_V));

			if (actAsProxy) {
				sendDataList.add(sharedMemory.stringToBytes(serviceName));
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
			LOG.debug("reached the verifying state - meesage type is " + message.getType());
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(this.verifiers[this.index]);
			VerifierData verData = (VerifierData) sharedMemory.getData(this.verifiers[this.index]);
			boolean obtainRekeys = false;

			if (message.getType() == Type.SUCCESS) {
				final byte[] data = this.generateVerifierID(this.verifiers[this.index], this.user_services[this.index]);
				if (this.verifiers[this.index].compareTo(this.user_services[this.index]) != 0) {
					// proxying needed
					LOG.debug("We are proxying - do we need the keys?");
					if (verData.RK_1 == null || verData.RK_1 == null) {
						// we need to obtained the re-keys.
						LOG.debug("Yes we do...");
						obtainRekeys = true;
					} else {
						LOG.debug("No we have obtained them already...");
					}
				}
				if (data != null) {
					if (obtainRekeys) {
						LOG.debug("sending verifier/proxy details to CA to obtain rekeys");
						return new Action<>(Status.CONTINUE, 35, ICCCommand.PUT, data, 0);
					} else {
						this.index++;
						LOG.debug("sending verifier/proxy details to user to get tag/ticket");
						return new Action<>(Status.CONTINUE, 28, ICCCommand.PUT, data, 0);
					}
				}

			}
			return super.getAction(message);
		}
	}

	/**
	 * State 29 As User: generate the ticket proof for ID_V
	 */
	public static class VState29 extends State<ICCCommand> {

		private boolean inProxyMode = false;
		private boolean isTicketTrace = false;

		private byte[] generateTagProof(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();

			final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			int numOfIDVs = listData.getList().size();
			if (numOfIDVs < 1) { // depends on whether the verifier acts as a proxy
				LOG.error("wrong number of data elements: " + numOfIDVs);
				return null;
			}

			final String ID_V = sharedMemory.stringFromBytes(listData.getList().get(0));
			String ID_proxy = null;
			if (numOfIDVs == 2) {
				this.inProxyMode = true;
				LOG.debug("We are in proxy mode");
				ID_proxy = sharedMemory.stringFromBytes(listData.getList().get(1));
				LOG.debug(ID_V + " is also a proxy for " + ID_proxy);
			}
			LOG.debug("If we have a tag for ID_V = " + ID_V + " then send that...");

			byte[] D_VdataHash = crypto.getHash(
					(new ListData(Arrays.asList(userData.R_U.toBytes(), ID_V.getBytes()))).toBytes(),
					sharedMemory.Hash1);
			Element D_Vhash = sharedMemory.pairing.getG2().newElementFromHash(D_VdataHash, 0, D_VdataHash.length);

			TicketDetails userTicket = userData.ticketDetails;
			int index = userTicket.getVerifierIndex(D_Vhash);
			if (index == -1) {
				LOG.debug("Did not find a tag for ID_V: " + ID_V);
				LOG.debug("Now looking for ID_proxy: " + ID_proxy);
				D_VdataHash = crypto.getHash(
						(new ListData(Arrays.asList(userData.R_U.toBytes(), ID_proxy.getBytes()))).toBytes(),
						sharedMemory.Hash1);
				D_Vhash = sharedMemory.pairing.getG2().newElementFromHash(D_VdataHash, 0, D_VdataHash.length);
				index = userTicket.getVerifierIndex(D_Vhash);
				if (index == -1) {
					LOG.debug("Did not find a tag for ID_Proxy: " + ID_proxy + ", either. Aborting!");
					return null;
				}

			}
			// found the verifier - now proceed with ZKP PI^2_U.
			// get some constants from shared memory...
			LOG.debug("generating ZK_PI_2_U");
			final BigInteger p = sharedMemory.p;
			final Element g_tilde = sharedMemory.g_tilde;
			final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER)[1];

			String hashIDV = (inProxyMode ? ID_proxy : ID_V);
			LOG.debug("Using hasIDV=" + hashIDV);

			final byte[] k_vHash = crypto.getHash(
					(new ListData(Arrays.asList(userData.y_3.toByteArray(), hashIDV.getBytes()))).toBytes(),
					sharedMemory.Hash1);
			final BigInteger k_vNum = (new BigInteger(1, k_vHash)).mod(p);

			final BigInteger x_dash_u = crypto.secureRandom(p);
			final BigInteger k_dash_v = crypto.secureRandom(p);

			final Element P_dash_V = ((g_tilde.mul(x_dash_u)).add(Y_CV.mul(k_dash_v))).getImmutable();
			final Element Q_dash_V = (g_tilde.mul(k_dash_v)).getImmutable();

			final byte[] c_vHash = crypto
					.getHash(
							(new ListData(Arrays.asList(userTicket.P_V[index].toBytes(), P_dash_V.toBytes(),
									userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes()))).toBytes(),
							sharedMemory.Hash1);

			final BigInteger c_vNum = (new BigInteger(1, c_vHash)).mod(p);

			final BigInteger x_hat_u = (x_dash_u.subtract(c_vNum.multiply(userData.x_u))).mod(p);
			final BigInteger k_hat_v = (k_dash_v.subtract(c_vNum.multiply(k_vNum))).mod(p);
			LOG.debug("finished generating ZK_PI_2_U");

			// collect everything that needs to be sent
			final List<byte[]> sendDataList = new ArrayList<>();
			sendDataList.add(sharedMemory.stringToBytes(hashIDV));

			sendDataList.addAll(Arrays.asList(userTicket.P_V[index].toBytes(), P_dash_V.toBytes(),
					userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes(), c_vHash, x_hat_u.toByteArray(),
					k_hat_v.toByteArray(), userTicket.E_V_1[index].toBytes(), userTicket.E_V_2[index].toBytes(),
					userTicket.E_V_3[index].toBytes(), userTicket.K_V[index].toBytes(),
					sharedMemory.stringToBytes(userTicket.ticket_Text_2), userTicket.s_V[index],
					userTicket.w_v[index].toByteArray(), userTicket.z_v[index].toByteArray(),
					userTicket.Z_V[index].toBytes()));

			// if it was the central verifier who asked then we need to add the whole
			// ticket, too
			if (ID_V.equalsIgnoreCase(Actor.CENTRAL_VERIFIER)) {
				this.isTicketTrace = true;
				LOG.debug("it's a trace so add the whole ticket, too!");
				userData.ticketDetails.getTicketDetails(sendDataList);
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
			this.inProxyMode = false;
			this.isTicketTrace = false;
			LOG.debug("Ticket Proof or Ticket Details");
			if (message.getType() == Message.Type.DATA) {
				if (message.getData() != null) {
					LOG.debug("There was some data so we are expecting a verifier ID.");
					// generate the user ticket proof
					byte[] data = this.generateTagProof(message.getData());

					if (data != null) {
						LOG.debug("generate user tag proof complete");
						if (!isTicketTrace) {
							return new Action<>(Status.CONTINUE, 30, ICCCommand.PUT, data, 0);
						} else {
							return new Action<>(Status.CONTINUE, 33, ICCCommand.PUT, data, 0);
						}
					}
				}
			}
			return super.getAction(message);

		}
	}

	/**
	 * State 31 As verifier: verify the tag
	 */
	public static class VState31 extends State<ICCCommand> {

		private String[] user_services;
		private String[] verifiers;
		private int index;

		public VState31(String[] user_services, String[] verifiers) {
			if (verifiers == null || user_services == null) {
				throw new RuntimeException("null value passed into constructor");
			}
			LOG.debug("Verifiers: " + verifiers.length);
			LOG.debug("user_services: " + user_services.length);
			if (verifiers.length != user_services.length) {
				throw new RuntimeException("lengths are not the same");
			}
			this.verifiers = verifiers;
			this.user_services = user_services;
			this.index = 0;
		}

		private boolean verifyTagProof(byte[] data, String verifierID) {
			this.startTiming("Common Tag verification");
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierID);
			final Crypto crypto = Crypto.getInstance();
			boolean isProxy = false;
			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);
			if (listData.getList().size() != 17) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}
			// some constants from shared Memory
			final BigInteger p = sharedMemory.p;
			final Element g_1 = sharedMemory.g_1;
			final Element g_2 = sharedMemory.g_2;
			final Element g_3 = sharedMemory.g_3;
			final Element g_tilde = sharedMemory.g_tilde.getImmutable();
			final Element g_frak = sharedMemory.g_frak.getImmutable();
			final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER)[1].getImmutable();
			final Element Y_tilde_I = sharedMemory.getPublicKey(Actor.ISSUER)[1].getImmutable();

			// get the elements needed for the ZKP
			int index = 0;
			String ID_V = sharedMemory.stringFromBytes(listData.getList().get(index++));
			if (ID_V.compareTo(verifierID) != 0) {
				LOG.debug("This is proxy mode ! We received the tag of " + ID_V);

				isProxy = true;
			}
			final Element P_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element P_dash_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element Q_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element Q_dash_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final byte[] c_vHash = listData.getList().get(index++);
			final BigInteger c_vNum = (new BigInteger(1, c_vHash)).mod(p);
			final BigInteger x_hat_u = (new BigInteger(1, listData.getList().get(index++))).mod(p);
			final BigInteger k_hat_v = (new BigInteger(1, listData.getList().get(index++))).mod(p);

			final byte[] verifyc_Vhash = crypto.getHash(
					(new ListData(Arrays.asList(P_V.toBytes(), P_dash_V.toBytes(), Q_V.toBytes(), Q_dash_V.toBytes())))
							.toBytes(),
					sharedMemory.Hash1);
			if (!Arrays.equals(c_vHash, verifyc_Vhash)) {
				LOG.debug("c_vHash verification failed");
				return false;
			}

			LOG.debug("passed c_vHash verification");

			final Element P_dash_Vlhs = (((g_tilde.mul(x_hat_u)).add(Y_CV.mul(k_hat_v))).add(P_V.mul(c_vNum)))
					.getImmutable();
			LOG.debug("P_dash_Vlhs = " + P_dash_Vlhs);
			if (!P_dash_V.isEqual(P_dash_Vlhs)) {
				LOG.debug("P_dash_V verification failed");
				return false;
			}
			LOG.debug("passed P_dash_V verification");

			final Element Q_dash_Vlhs = ((g_tilde.mul(k_hat_v)).add(Q_V.mul(c_vNum))).getImmutable();
			if (!Q_dash_V.isEqual(Q_dash_Vlhs)) {
				LOG.debug("Q_dash_V verification failed");
				return false;
			}

			LOG.debug("passed Q_dash_V verification. This completes the ZKP.");

			// get the elements for the remaining checks

			final Element E_V_1 = sharedMemory.GTElementFromBytes(listData.getList().get(index++));
			final Element E_V_2 = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element E_V_3 = sharedMemory.G2ElementFromBytes(listData.getList().get(index++));
			final Element T_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			String ticket_Text_2 = sharedMemory.stringFromBytes(listData.getList().get(index++));
			final byte[] s_Vhash = listData.getList().get(index++);
			final BigInteger s_Vnum = (new BigInteger(1, s_Vhash)).mod(p);
			final BigInteger w_v = (new BigInteger(1, listData.getList().get(index++))).mod(p);
			final BigInteger z_v = (new BigInteger(1, listData.getList().get(index++))).mod(p);
			final Element Z_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));

			final ListData s_Vdata = new ListData(Arrays.asList(P_V.toBytes(), Q_V.toBytes(), E_V_1.toBytes(),
					E_V_2.toBytes(), E_V_3.toBytes(), T_V.toBytes(), ticket_Text_2.getBytes()));
			final byte[] s_Vrhs = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
			if (!Arrays.equals(s_Vhash, s_Vrhs)) {
				LOG.debug("s_V hash verification failed!");
				return false;
			}
			LOG.debug("passed s_V hash verification!");

			final Element lhs = sharedMemory.pairing.pairing(Z_V, Y_tilde_I.add(g_frak.mul(z_v))).getImmutable();
			final Element rhs = sharedMemory.pairing.pairing(g_1.add(g_2.mul(w_v)).add(g_3.mul(s_Vnum)), g_frak)
					.getImmutable();
			if (!lhs.isEqual(rhs)) {
				LOG.debug("pairing verification failed!");
				return false;
			}
			this.stopTiming("Common Tag verification");
			if (!isProxy) {
				this.startTiming("NoProxy EV1 check");
				final Element E_V_1rhs = sharedMemory.pairing.pairing(E_V_2, verifierData.SK_V).getImmutable();
				if (!E_V_1.isEqual(E_V_1rhs)) {
					LOG.debug("E_V_1 verification failed!");
					return false;
				}
				LOG.debug("passed E_V_1 verification!");
				this.stopTiming("NoProxy EV1 check");
			} else {
				this.startTiming("Proxy EV1 check");
				LOG.debug("Proxy check for E_V_1 happening");
				final Element Theta_1 = verifierData.RK_2.add(verifierData.SK_V).getImmutable();
				final Element Theta_2 = sharedMemory.pairing.pairing(E_V_2, Theta_1)
						.sub(sharedMemory.pairing.pairing(verifierData.RK_1, E_V_3)).getImmutable();
				if (!E_V_1.isEqual(Theta_2)) {
					LOG.debug("E_V_1 verification failed!");
					return false;
				}
				this.stopTiming("Proxy EV1 check");
			}

			LOG.debug("passed pairing verification! Tag is valid");
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
			String currentVerifier = this.verifiers[this.index];
			sharedMemory.actAs(currentVerifier);
			LOG.debug("Acting as verifier: " + currentVerifier);
			sharedMemory.actAs(currentVerifier);
			if (message.getType() == Type.DATA) {
				// check the tag & proof
				if (this.verifyTagProof(message.getData(), currentVerifier)) {
					this.index++;
					if (this.index < this.verifiers.length) {
						// keep checking with a different identifier
						LOG.debug("there are more ticket verifiers!");
						return new Action<>(27);
					} else {
						LOG.debug("finished the ticket proof verification");
						// return new Action<>(Status.END_SUCCESS, 0, null, null, 0);
						return new Action<>(32);
					}
				}
			}
			return super.getAction(message);
		}
	}

	public static class VState32 extends State<ICCCommand> {

		private byte[] generateCVID() {
			LOG.debug("Acting as central verifier");
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
			final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);
			final ListData sendData = new ListData(Arrays.asList(cenVerData.ID_V.getBytes(StandardCharsets.UTF_8)));
			LOG.debug("Central Verifier ID = " + cenVerData.ID_V);
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
			LOG.debug("reached the tracing state - meesage type is " + message.getType());
			if (message.getType() == Type.SUCCESS) {

				// Obtain the verifier ID_V and send it to the client.
				final byte[] data = this.generateCVID();

				if (data != null) {
					LOG.debug("sending central verifier details");
					return new Action<>(Status.CONTINUE, 28, ICCCommand.PUT, data, 0);
				}
			}
			return super.getAction(message);
		}
	}

	/**
	 * State 34 trace the user's ticket details
	 */
	public static class VState34 extends State<ICCCommand> {

		private byte[] traceTicket(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);
			final Crypto crypto = Crypto.getInstance();
			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			String verifierID = cenVerData.ID_V;

			if ((listData.getList().size() - 23) % 12 != 0) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			// some constants from shared Memory
			final BigInteger p = sharedMemory.p;
			final Element g_1 = sharedMemory.g_1;
			final Element g_2 = sharedMemory.g_2;
			final Element g_3 = sharedMemory.g_3;
			final Element g_tilde = sharedMemory.g_tilde.getImmutable();
			final Element g_frak = sharedMemory.g_frak.getImmutable();
			final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER)[1].getImmutable();
			final Element Y_tilde_I = sharedMemory.getPublicKey(Actor.ISSUER)[1].getImmutable();

			// get the elements needed for the ZKP
			int index = 0;
			String ID_V = sharedMemory.stringFromBytes(listData.getList().get(index++));
			LOG.debug("The tag proof is for: " + ID_V);
			if (ID_V.compareTo(verifierID) != 0) {
				LOG.debug("This is proxy mode - not yet implemented...");
				return null;
			}
			final Element P_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element P_dash_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element Q_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element Q_dash_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final byte[] c_vHash = listData.getList().get(index++);
			final BigInteger c_vNum = (new BigInteger(1, c_vHash)).mod(p);
			final BigInteger x_hat_u = (new BigInteger(1, listData.getList().get(index++))).mod(p);
			final BigInteger k_hat_v = (new BigInteger(1, listData.getList().get(index++))).mod(p);

			final byte[] verifyc_Vhash = crypto.getHash(
					(new ListData(Arrays.asList(P_V.toBytes(), P_dash_V.toBytes(), Q_V.toBytes(), Q_dash_V.toBytes())))
							.toBytes(),
					sharedMemory.Hash1);
			if (!Arrays.equals(c_vHash, verifyc_Vhash)) {
				LOG.debug("c_vHash verification failed");
				return null;
			}

			LOG.debug("passed c_vHash verification");

			final Element P_dash_Vlhs = (((g_tilde.mul(x_hat_u)).add(Y_CV.mul(k_hat_v))).add(P_V.mul(c_vNum)))
					.getImmutable();
			LOG.debug("P_dash_Vlhs = " + P_dash_Vlhs);
			if (!P_dash_V.isEqual(P_dash_Vlhs)) {
				LOG.debug("P_dash_V verification failed");
				return null;
			}
			LOG.debug("passed P_dash_V verification");

			final Element Q_dash_Vlhs = ((g_tilde.mul(k_hat_v)).add(Q_V.mul(c_vNum))).getImmutable();
			if (!Q_dash_V.isEqual(Q_dash_Vlhs)) {
				LOG.debug("Q_dash_V verification failed");
				return null;
			}

			LOG.debug("passed Q_dash_V verification. This completes the ZKP.");

			// get the elements for the remaining checks

			final Element E_V_1 = sharedMemory.GTElementFromBytes(listData.getList().get(index++));
			final Element E_V_2 = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			final Element E_V_3 = sharedMemory.G2ElementFromBytes(listData.getList().get(index++));
			final Element T_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));
			String ticket_Text_2 = sharedMemory.stringFromBytes(listData.getList().get(index++));
			byte[] s_Vhash = listData.getList().get(index++);
			BigInteger s_Vnum = (new BigInteger(1, s_Vhash)).mod(p);
			final BigInteger w_v = (new BigInteger(1, listData.getList().get(index++))).mod(p);
			final BigInteger z_v = (new BigInteger(1, listData.getList().get(index++))).mod(p);
			final Element Z_V = sharedMemory.G1ElementFromBytes(listData.getList().get(index++));

			final ListData s_Vdata = new ListData(Arrays.asList(P_V.toBytes(), Q_V.toBytes(), E_V_1.toBytes(),
					E_V_2.toBytes(), E_V_3.toBytes(), T_V.toBytes(), ticket_Text_2.getBytes()));
			final byte[] s_Vrhs = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
			if (!Arrays.equals(s_Vhash, s_Vrhs)) {
				LOG.debug("s_V hash verification failed!");
				return null;
			}
			LOG.debug("passed s_V hash verification!");

			final Element E_V_1rhs = sharedMemory.pairing.pairing(E_V_2, cenVerData.SK_V).getImmutable();
			if (!E_V_1.isEqual(E_V_1rhs)) {
				LOG.debug("E_V_1 verification failed!");
				return null;
			}
			LOG.debug("passed E_V_1 verification!");

			Element lhs = sharedMemory.pairing.pairing(Z_V, Y_tilde_I.add(g_frak.mul(z_v))).getImmutable();
			Element rhs = sharedMemory.pairing.pairing(g_1.add(g_2.mul(w_v)).add(g_3.mul(s_Vnum)), g_frak)
					.getImmutable();
			if (!lhs.isEqual(rhs)) {
				LOG.debug("pairing verification failed!");
				return null;
			}
			LOG.debug("passed pairing verification! Central Verification Tag is valid");

			int numOfVerifiers = (listData.getList().size() - 23) / 12;
			LOG.debug("We should have " + numOfVerifiers + " verifiers");
			TicketDetails ticketDetails = new TicketDetails(numOfVerifiers);
			ticketDetails.populateTicketDetails(sharedMemory, listData, index);

			Element Y_U_1 = null;
			Element Y_U_2 = null;
			Element verifierPK = null;

			boolean ZKPTagPresent = false;

			Y_U_1 = ticketDetails.P_V[0].div(ticketDetails.Q_V[0].mul(cenVerData.x_cv)).getImmutable();
			LOG.debug("Ticket details for: " + ticketDetails.VerifierList[0]);
			LOG.debug("Public key of user from tag[0]: " + Y_U_1);
			LOG.debug("Public key of user from sharedMemory: " + sharedMemory.Y_U);

			verifierPK = ticketDetails.K_V[0].div(ticketDetails.E_V_2[0].mul(cenVerData.x_cv));
			if ((P_V.equals(ticketDetails.P_V[0]) && (Q_V.equals(ticketDetails.Q_V[0])))) {
				ZKPTagPresent = true;
			}
			LOG.debug("Verifier[0] has public key: " + verifierPK);
			for (int i = 1; i < numOfVerifiers; i++) {
				Y_U_2 = ticketDetails.P_V[i].div(ticketDetails.Q_V[i].mul(cenVerData.x_cv)).getImmutable();
				LOG.debug("Ticket details for: " + ticketDetails.VerifierList[i]);
				LOG.debug("Public key of user from tag[" + i + "]: " + Y_U_2);
				verifierPK = ticketDetails.K_V[i].div(ticketDetails.E_V_2[i].mul(cenVerData.x_cv));
				if ((P_V.equals(ticketDetails.P_V[i]) && (Q_V.equals(ticketDetails.Q_V[i])))) {
					ZKPTagPresent = true;
				}
				LOG.debug("Verifier[" + i + "] has public key: " + verifierPK);
				if (!Y_U_1.equals(Y_U_2)) {
					LOG.debug("ticket verification of Y_U failed");
					return null;
				} else {
					Y_U_1 = Y_U_2;
				}
			}

			LOG.debug("The user has public key: " + Y_U_1);

			if (!ZKPTagPresent) {
				LOG.debug("the tag used for the ZKP was not present - ticket is wrong!");
				return null;
			}
			LOG.debug("the tag used for the ZKP was present - ticket is linked to user");

			for (int i = 0; i < numOfVerifiers; i++) {
				final byte[] verifys_V = crypto.getHash((new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(),
						ticketDetails.Q_V[i].toBytes(), ticketDetails.E_V_1[i].toBytes(),
						ticketDetails.E_V_2[i].toBytes(), ticketDetails.E_V_3[i].toBytes(),
						ticketDetails.K_V[i].toBytes(), ticketDetails.ticket_Text_2.getBytes()))).toBytes(),
						sharedMemory.Hash1);
				if (!Arrays.equals(ticketDetails.s_V[i], verifys_V)) {
					LOG.error("failed to verify s_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
					return null;
				}
				s_Vnum = (new BigInteger(1, verifys_V)).mod(p);
				lhs = sharedMemory.pairing
						.pairing(ticketDetails.Z_V[i], Y_tilde_I.add(g_frak.mul(ticketDetails.z_v[i]))).getImmutable();
				rhs = sharedMemory.pairing.pairing(g_1.add(g_2.mul(ticketDetails.w_v[i])).add(g_3.mul(s_Vnum)), g_frak);
				if (!lhs.isEqual(rhs)) {
					LOG.debug("first pairing check failed for ID_V[" + i + "]: " + ticketDetails.VerifierList[i]);
				}
				LOG.debug("passed tag verification for verifier: " + ticketDetails.VerifierList[i]);
				LOG.debug("PK of the verifier is: " + sharedMemory.getPublicKey(ticketDetails.VerifierList[i]));
			}
			LOG.debug("passed s_V hash and corresponding pairing checks!");

			final List<byte[]> verifys_PData = new ArrayList<>();
			for (int i = 0; i < numOfVerifiers; i++) {
				verifys_PData.add(ticketDetails.s_V[i]);
			}

			if (!Arrays.equals(ticketDetails.s_CV,
					crypto.getHash((new ListData(verifys_PData)).toBytes(), sharedMemory.Hash1))) {
				LOG.error("failed to verify s_CV hash");
				return null;
			}
			LOG.debug("passed s_CV hash checks!");

			final BigInteger s_cvNum = (new BigInteger(1, ticketDetails.s_CV)).mod(p);

			lhs = (sharedMemory.pairing.pairing(ticketDetails.Z_CV, Y_tilde_I.add(g_frak.mul(ticketDetails.z_cv))))
					.getImmutable();
			rhs = (sharedMemory.pairing.pairing(g_1.add(g_2.mul(ticketDetails.w_cv)).add(g_3.mul(s_cvNum)), g_frak))
					.getImmutable();

			if (!lhs.isEqual(rhs)) {
				LOG.error("failed to verify Z_CV pairing check");
				return null;
			}

			LOG.debug("Passed Z_CV pairing verification!");

			return "Success".getBytes();
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
			LOG.debug("Acting as the central verifier!");

			if (message.getType() == Type.DATA) {
				LOG.debug("We should have the tag, its proof and the ticket details now");
				if (message.getData() != null) {

					if (this.traceTicket(message.getData()) != null) {
						LOG.debug("Successfully extracted all the  verifier details from the ticket");
						return new Action<>(Status.END_SUCCESS, 0, null, null, 0);

					}
				}
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 36 generate the proxy rekeys for ID_V
	 */
	public static class VState36 extends State<ICCCommand> {

		private byte[] generateReKeys(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			final CentralAuthorityData cenAuthData = (CentralAuthorityData) sharedMemory
					.getData(Actor.CENTRAL_AUTHORITY);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			// currently limited to one proxy but could be more...

			if (listData.getList().size() != 2) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return null;
			}

			final String ID_V = sharedMemory.stringFromBytes(listData.getList().get(0));
			final String ID_Proxy = sharedMemory.stringFromBytes(listData.getList().get(1));
			LOG.debug(ID_V + " wants to be a proxy for " + ID_Proxy);

			if (ID_V.compareTo(ID_Proxy) == 0) {
				LOG.error("ID_V is the same as ID_Proxy. This should not happen!");
				return null;
			}

			// find ID_V details
			CentralAuthorityData.VerifierCredentials verCred_IDV = cenAuthData.verifiers.get(ID_V);
			// find the ID_Proxy details
			CentralAuthorityData.VerifierCredentials verCred_IDProxy = cenAuthData.verifiers.get(ID_Proxy);
			if (verCred_IDProxy == null || verCred_IDV == null) {
				LOG.error("ID_V or ID_Proxy does not exist. This should not happen!");
				return null;
			}

			// get some constants from sharedMemory
			final BigInteger p = sharedMemory.p;
			final Element g_tilde = sharedMemory.g_tilde;
			final Element theta_1 = sharedMemory.theta1;
			final Element theta_2 = sharedMemory.theta2;

			final BigInteger beta_v = crypto.secureRandom(p);

			// compute the rekeys
			final Element RK_1 = g_tilde.mul(beta_v);

			byte[] hashText = crypto.getHash((new ListData(
					Arrays.asList(AnonProxySharedMemory.TT.getBytes(), AnonProxySharedMemory.ticket_Text_1.getBytes())))
							.toBytes(),
					AnonProxySharedMemory.Hash1);

			final BigInteger hashTextNum = new BigInteger(1, hashText).mod(p);
			final Element tmp =verCred_IDProxy.SK_V.sub(verCred_IDV.SK_V);
			final Element RK_2 = (theta_1.add(theta_2.mul(hashTextNum))).mul(beta_v).add(tmp);

			// send the rekey back.
			final ListData sendData = new ListData(
					Arrays.asList(sharedMemory.stringToBytes(ID_V), RK_1.toBytes(), RK_2.toBytes()));
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
			LOG.debug("reached the proxy rekeying state - meesage type is " + message.getType());
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			// we are the CA
			if (message.getType() == Type.DATA) {

				// Obtain rekeying info for the verifier ID_V
				final byte[] data = this.generateReKeys(message.getData());

				if (data != null) {
					LOG.debug("sending rekey details");
					return new Action<>(Status.CONTINUE, 37, ICCCommand.PUT, data, 0);
				}
			}
			return super.getAction(message);
		}
	}

	/**
	 * State 38 store the rekey details for the verifier
	 */
	public static class VState38 extends State<ICCCommand> {

		private boolean storeReKeys(byte[] data) {
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 3) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			// extract the ID_V for which we are receiving the keys
			final String ID_V = sharedMemory.stringFromBytes(listData.getList().get(0));
			sharedMemory.actAs(ID_V);
			LOG.debug("acting as: " + ID_V);
			VerifierData verifierData = (VerifierData) sharedMemory.getData(ID_V);
			verifierData.RK_1 = sharedMemory.G1ElementFromBytes(listData.getList().get(1));
			verifierData.RK_2 = sharedMemory.G2ElementFromBytes(listData.getList().get(2));
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
			LOG.debug("store the proxy keys state- meesage type is " + message.getType());
			if (message.getType() == Type.DATA) {
				// store the keys and progress to the standard tag validation
				if (this.storeReKeys(message.getData())) {
					LOG.debug("successfully stored proxy keys");
					return new Action<>(27);
				}
			}
			return super.getAction(message);
		}
	}

}