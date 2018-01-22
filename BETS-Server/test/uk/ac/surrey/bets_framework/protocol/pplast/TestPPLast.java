/**
 *
 */
package uk.ac.surrey.bets_framework.protocol.pplast;

import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.GsonUtils;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.pplast.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.PoliceData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.SellerData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.TicketDetails;
import uk.ac.surrey.bets_framework.protocol.pplast.data.UserData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.VerifierData;

/**
 * @author swesemeyer
 *
 */
public class TestPPLast {

	/** Logback logger. */
	private static final Logger LOG = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("TestPPLast");
	Encoder base64 = Base64.getEncoder();
	Crypto crypto;
	PPLASTSharedMemory sharedMemory = null;

	@Before
	public void setUp() throws Exception {
		// set the desired log level
		LOG.setLevel(Level.DEBUG);

		LOG.info("Starting Setup");

		crypto = Crypto.getInstance();
		sharedMemory = new PPLASTSharedMemory();
		sharedMemory.rBits = 160;
		sharedMemory.clearTest();
		LOG.debug("Y_A=" + sharedMemory.Y_A);
		LOG.debug("g_frak=" + sharedMemory.g_frak);
		LOG.debug("g=" + sharedMemory.g);
		LOG.debug("h=" + sharedMemory.h);
		String json = sharedMemory.toJson();
		LOG.debug("JSON version of sharedMemory: " + json);
		PPLASTSharedMemory deserialSharedMemory = PPLASTSharedMemory.fromJson(json);
		LOG.debug("Y_A_deserial=" + deserialSharedMemory.Y_A);
		LOG.debug("g_frak_deserial=" + deserialSharedMemory.g_frak);
		LOG.debug("g_deserial=" + deserialSharedMemory.g);
		LOG.debug("h_deserial=" + deserialSharedMemory.h);
		LOG.debug("p: " + sharedMemory.pairingParameters.getBigInteger("r"));
		LOG.debug("q: " + sharedMemory.pairingParameters.getBigInteger("q"));
		LOG.debug("Size of G1=G2=GT:" + sharedMemory.pairing.getG1().getOrder() + "="
				+ sharedMemory.pairing.getG2().getOrder() + "=" + sharedMemory.pairing.getGT().getOrder());
		LOG.debug("G1=?G2:" + sharedMemory.pairing.getG1().equals(sharedMemory.pairing.getG2()));
		LOG.debug("Testing the various hashes: ");
		byte[] testHash = "HelloWorld".getBytes();
		LOG.debug("Hash1: RipeMD256: " + base64.encodeToString(crypto.getHash(testHash, "RipeMD256")));// sharedMemory.Hash1)));
		LOG.debug("Hash1: " + sharedMemory.Hash1 + " :" + base64.encodeToString(crypto.getHash(testHash, "RipeMD256")));// sharedMemory.Hash1)));
		LOG.debug("Hash2: " + sharedMemory.Hash2 + " : "
				+ base64.encodeToString(crypto.getHash(testHash, sharedMemory.Hash2)));

		LOG.debug("Computing an element from Hash");
		Element e1 = sharedMemory.pairing.getG1().newRandomElement();
		LOG.debug("e1=" + e1);
		byte[] myHash = "12345678912345667891233456IDV1ismyhashValue!!!!!".getBytes();
		Element e2 = e1.setFromHash(myHash, 0, 32);
		LOG.debug("e2=" + e2);
		e1 = sharedMemory.pairing.getG1().newRandomElement();
		LOG.debug("new e1=" + e1);
		Element e3 = e1.setFromHash(myHash, 0, 32);
		LOG.debug("e3=" + e3);
		Assert.assertTrue(e2.isEqual(e3));

		LOG.info("Setup complete:");

	}

	@Test

	public void testProtocol() {
		byte[] data;
		boolean success;
		long overall_start;
		long time_start;
		long time_end;
		long durationInMS;

		// Registration States:

		LOG.info("Going through Registration states");

		// Generate Seller Identify: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		overall_start = time_start;
		sharedMemory.actAs(Actor.SELLER);
		data = this.generateSellerIdentity();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate Seller Identify: RState02 (Android) took (ms): " + durationInMS);
		LOG.info("Data sent to server (in bytes): " + data.length);

		// Generates the seller's credentials: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
		data = this.generateSellerCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generates the seller's credentials: RState05 (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("Seller credential creation failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);

		// Verify Seller credentials: RState03 (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.SELLER);
		success = this.verifySellerCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Verify Seller credentials: RState03 (Android) took (ms): " + durationInMS);
		if (!success) {
			fail("Seller credentials did not validate");
		}

		for (int i = 0; i < Actor.VERIFIERS.length; i++) {
			// Generate Verifier Identify: RStateXX (Server)
			time_start = Instant.now().toEpochMilli();
			overall_start = time_start;
			sharedMemory.actAs(Actor.VERIFIERS[i]);
			data = this.generateVerifierIdentity(Actor.VERIFIERS[i]);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("Generate Verifier Identify: RStateXX (Server) took (ms): " + durationInMS);

			// Generates the verifier's credentials: RStateXX (Server)
			time_start = Instant.now().toEpochMilli();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			data = this.generateVerifierCredentials(data);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("Generates the verifier's credentials: RStateXX (Server) took (ms): " + durationInMS);
			if (data == null) {
				fail("Verifier credential creation failed");
			}

			// Verify Verifier's credentials: RStateXX (Server)
			time_start = Instant.now().toEpochMilli();
			sharedMemory.actAs(Actor.VERIFIERS[i]);
			success = this.verifyVerifierCredentials(Actor.VERIFIERS[i], data);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("Verify Verifier's credentials: RState03 (Server) took (ms): " + durationInMS);
			if (!success) {
				fail("Verifier credentials did not validate");
			}

		}
		// Generate User's Identify: RStateXX (Android)
		time_start = Instant.now().toEpochMilli();
		overall_start = time_start;
		sharedMemory.actAs(Actor.USER);
		data = this.generateUserIdentity();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate User Identify: RStateXX (Android) took (ms): " + durationInMS);
		LOG.info("Data sent to server (in bytes): " + data.length);

		// Generates the user's credentials: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
		data = this.generateUserCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generates the user's credentials: RStateXX (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("User credential creation failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);

		// Verify user's credentials: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		success = this.verifyUserCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Verify User credentials: RState03 (Server) took (ms): " + durationInMS);
		if (!success) {
			fail("User credentials did not validate");
		}

		// Generate Police's Identify: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		overall_start = time_start;
		sharedMemory.actAs(Actor.POLICE);
		data = this.generatePoliceIdentity();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate Police Identify: RStateXX (Server) took (ms): " + durationInMS);

		// Generates the user's credentials: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
		data = this.generatePoliceCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generates the police's credentials: RStateXX (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("Police credential creation failed");
		}

		// Verify police's credentials: RStateXX (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.POLICE);
		success = this.verifyPoliceCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Verify Police credentials: RStateXX (Server) took (ms): " + durationInMS);
		if (!success) {
			fail("Police credentials did not validate");
		}

		LOG.info("Finished Registration states");

		LOG.info("Going through Issuing states");

		// Generate the user ticket request: IStateXX (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		data = this.generateTicketRequest();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate the user's ticket request: IStateXX (Android) took (ms): " + durationInMS);
		LOG.info("Data sent to server: " + data.length);

		// Generate ticket serial number: IState10 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.SELLER);
		data = this.generateTicketDetails(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate ticket details: IState10 (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("ticket details verification failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);

		// Verify the returned ticket serial number data: IState08 (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		success = this.verifyTicketDetails(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Verify the returned ticket details: IState08 (Android) took (ms): " + durationInMS);
		if (!success) {
			fail("ticket details verification failed");
		}
		LOG.info("Finished Issuing states");

		LOG.info("Going through Verification states");

		// Generate the verifier ID vStateXX(Server)
		time_start = Instant.now().toEpochMilli();
		String verifierID = Actor.VERIFIERS[1];
		sharedMemory.actAs(verifierID);
		data = this.generateVerifierID(verifierID);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generating the verifier ID finished: " + durationInMS);
		if (data == null) {
			fail("Verifier ID generation failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);

		// Generate ticket proof: VStateXX (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		data = this.generateTicketProof(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate ticket proof: VStateXX (Android) took (ms): " + durationInMS);
		if (data == null) {
			fail("ticket proof generation failed");
		}
		LOG.info("Data sent to server (in bytes): " + data.length);

		// check the user's proof of his ticket vStateXX(Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(verifierID);
		success = this.verifyTicketProof(data, verifierID);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Checking the user's proof took (ms): " + durationInMS);
		if (!success) {
			fail("Checking the user's proof failed");
		}

		LOG.info("Finished Verfication states");

		LOG.info("Going through tracing states states");

		// send the user's ticket: tStateXX(Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		data = this.sendTicketDetails();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("sending the user's ticket details took (ms): " + durationInMS);
		if (data == null) {
			fail("sending the user's ticket failed");
		}

		// retrieve the verifier IDs from the ticket
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.POLICE);
		data = this.extractVerifierIDs(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("extraction of the verifier IDs finished: " + durationInMS);
		if (data == null) {
			fail("Verifier ID extraction failed");
		}

		LOG.info("Total run of the protocol with no comms overhead took (ms):" + (time_end - overall_start));
	}

	private byte[] extractVerifierIDs(byte[] data) {
		final PoliceData policeData = (PoliceData) sharedMemory.getData(Actor.POLICE);
		// final Crypto crypto = Crypto.getInstance();
		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);
		if ((listData.getList().size() - 5) % 11 != 0) {
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return null;
		}
		int numOfVerifiers = (listData.getList().size() - 4) / 11;
		TicketDetails ticketDetails = new TicketDetails(numOfVerifiers);
		ticketDetails.populateTicketDetails(sharedMemory, listData, 0);

		Element Y_U_1 = null;
		Element Y_U_2 = null;

		Y_U_1 = ticketDetails.P_V[0].div(ticketDetails.Q_V[0].mul(policeData.x_P)).getImmutable();
		for (int i = 1; i < numOfVerifiers; i = i + 2) {
			Y_U_2 = ticketDetails.P_V[i].div(ticketDetails.Q_V[i].mul(policeData.x_P)).getImmutable();
			if (!Y_U_1.equals(Y_U_2)) {
				LOG.debug("ticket verification of Y_U failed");
				return null;
			} else {
				Y_U_1 = Y_U_2;
			}
		}

		LOG.debug("The user has public key: " + Y_U_1);

		final Element Y_bar_S = sharedMemory.getPublicKey(Actor.SELLER).getImmutable();
		final Element g_frak = sharedMemory.g_frak.getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element h = sharedMemory.h.getImmutable();
		final Element h_tilde = sharedMemory.h_tilde.getImmutable();
		final BigInteger p = sharedMemory.p;

		for (int i = 0; i < numOfVerifiers; i++) {
			final byte[] verifys_V = crypto.getHash(
					(new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(), ticketDetails.Q_V[i].toBytes(),
							ticketDetails.E_V[i].toBytes(), ticketDetails.F_V[i].toBytes(),
							ticketDetails.K_V[i].toBytes(), ticketDetails.ticketText.getBytes()))).toBytes(),
					sharedMemory.Hash1);
			if (!Arrays.equals(ticketDetails.s_V[i], verifys_V)) {
				LOG.error("failed to verify s_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
				return null;
			}
			final BigInteger s_Vnum = (new BigInteger(1, verifys_V)).mod(p);
			final Element lhs = sharedMemory.pairing
					.pairing(ticketDetails.sigma_V[i], Y_bar_S.add(g_frak.mul(ticketDetails.e_v[i]))).getImmutable();
			final Element rhs = sharedMemory.pairing
					.pairing(g.add(h.mul(ticketDetails.w_v[i])).add(h_tilde.mul(s_Vnum)), g_frak);
			if (!lhs.isEqual(rhs)) {
				LOG.debug("first pairing check failed for ID_V[" + i + "]: " + ticketDetails.VerifierList[i]);
			}

		}
		LOG.debug("passed s_V hash and corresponding pairing checks!");

		final List<byte[]> verifys_PData = new ArrayList<>();
		for (int i = 0; i < numOfVerifiers; i++) {
			verifys_PData.add(ticketDetails.s_V[i]);
		}

		if (!Arrays.equals(ticketDetails.s_P,
				crypto.getHash((new ListData(verifys_PData)).toBytes(), sharedMemory.Hash1))) {
			LOG.error("failed to verify s_P hash");
			return null;
		}
		LOG.debug("passed s_P hash checks!");

		final BigInteger s_PNum = (new BigInteger(1, ticketDetails.s_P)).mod(p);

		final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.sigma_P,
				Y_bar_S.add(g_frak.mul(ticketDetails.e_P)))).getImmutable();
		final Element rhs = (sharedMemory.pairing.pairing(g.add(h.mul(ticketDetails.w_P)).add(h_tilde.mul(s_PNum)),
				g_frak)).getImmutable();

		if (!lhs.isEqual(rhs)) {
			LOG.error("failed to verify sigma_P pairing check");
			return null;
		}

		LOG.debug("Passed sigma_P pairing verification!");

		return "Success".getBytes();
	}

	private byte[] sendTicketDetails() {
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		// final Crypto crypto = Crypto.getInstance();

		final List<byte[]> sendDataList = new ArrayList<>();
		userData.ticketDetails.getTicketDetails(sendDataList);
		return (new ListData(sendDataList)).toBytes();
	}

	private boolean verifyTicketProof(byte[] data, String verifierID) {
		final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierID);
		// final Crypto crypto = Crypto.getInstance();
		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);
		if (listData.getList().size() != 14) {
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return false;
		}
		// some constants from shared Memory
		final BigInteger p = sharedMemory.p;
		final Element xi = sharedMemory.xi.getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element h = sharedMemory.h.getImmutable();
		final Element h_tilde = sharedMemory.h_tilde.getImmutable();
		final Element g_frak = sharedMemory.g_frak.getImmutable();
		final Element Y_P = sharedMemory.getPublicKey(Actor.POLICE).getImmutable();
		final Element Y_S = sharedMemory.getPublicKey(Actor.SELLER).getImmutable();

		// get the elements needed for the ZKP
		int index = 0;
		final Element P_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element P_dash_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element Q_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element Q_dash_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final byte[] c_Vhash = listData.getList().get(index++);
		final BigInteger c_Vnum = (new BigInteger(1, c_Vhash)).mod(p);
		final BigInteger x_hat_U = (new BigInteger(1, listData.getList().get(index++))).mod(p);
		final BigInteger z_hat_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);

		final byte[] verifyc_Vhash = crypto.getHash(
				(new ListData(Arrays.asList(P_V.toBytes(), P_dash_V.toBytes(), Q_V.toBytes(), Q_dash_V.toBytes())))
						.toBytes(),
				sharedMemory.Hash1);
		if (!Arrays.equals(c_Vhash, verifyc_Vhash)) {
			LOG.debug("c_Vhash verification failed");
			return false;
		}

		LOG.debug("passed c_Vhash verification");

		final Element P_dash_Vlhs = (((xi.mul(x_hat_U)).add(Y_P.mul(z_hat_V))).add(P_V.mul(c_Vnum))).getImmutable();
		LOG.debug("P_dash_Vlhs = " + P_dash_Vlhs);
		if (!P_dash_V.isEqual(P_dash_Vlhs)) {
			LOG.debug("P_dash_V verification failed");
			return false;
		}
		LOG.debug("passed P_dash_V verification");

		final Element Q_dash_Vlhs = ((xi.mul(z_hat_V)).add(Q_V.mul(c_Vnum))).getImmutable();
		if (!Q_dash_V.isEqual(Q_dash_Vlhs)) {
			LOG.debug("Q_dash_V verification failed");
			return false;
		}

		LOG.debug("passed Q_dash_V verification. This completes the ZKP.");

		// get the elements for the remaining checks

		final Element E_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element F_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element K_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final byte[] s_Vhash = listData.getList().get(index++);
		final BigInteger s_Vnum = (new BigInteger(1, s_Vhash)).mod(p);
		final BigInteger w_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);
		final BigInteger e_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);
		final Element sigma_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));

		final ListData s_Vdata = new ListData(Arrays.asList(P_V.toBytes(), Q_V.toBytes(), E_V.toBytes(), F_V.toBytes(),
				K_V.toBytes(), SellerData.TICKET_TEXT.getBytes()));
		final byte[] s_Vrhs = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
		if (!Arrays.equals(s_Vhash, s_Vrhs)) {
			LOG.debug("s_V hash verification failed!");
			return false;
		}
		LOG.debug("passed s_V hash verification!");

		final Element F_Vrhs = (E_V.mul(verifierData.x_V)).getImmutable();
		if (!F_V.isEqual(F_Vrhs)) {
			LOG.debug("F_V verification failed!");
			return false;
		}
		LOG.debug("passed F_V verification!");

		final Element lhs = sharedMemory.pairing.pairing(sigma_V, Y_S.add(g_frak.mul(e_V))).getImmutable();
		final Element rhs = sharedMemory.pairing.pairing(g.add(h.mul(w_V)).add(h_tilde.mul(s_Vnum)), g_frak);
		if (!lhs.isEqual(rhs)) {
			LOG.debug("pairing verification failed!");
			return false;
		}
		LOG.debug("passed pairing verification! Ticket is valid");
		return true;
	}

	private byte[] generateTicketProof(byte[] data) {
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		// final Crypto crypto = Crypto.getInstance();

		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);
		if (listData.getList().size() != 1) { // dependent on the number of verifiers...
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return null;
		}
		final String ID_V = new String(listData.getList().get(0), StandardCharsets.UTF_8);
		LOG.debug("Looking for ID_V = " + ID_V);

		final byte[] D_Vhash = crypto.getHash(
				(new ListData(Arrays.asList(userData.C_U.toBytes(), ID_V.getBytes()))).toBytes(), sharedMemory.Hash2);

		LOG.debug("Search for D_Vhash= " + base64.encodeToString(D_Vhash));
		TicketDetails userTicket = userData.ticketDetails;
		int index = userTicket.getVerifierIndex(D_Vhash);
		if (index == -1) {
			LOG.debug("Aborting as verifier not found: " + ID_V);
		}
		// found the verifier - now proceed with ZKP PI^2_U.
		// get some constants from shared memory...

		final BigInteger p = sharedMemory.p;
		final Element xi = sharedMemory.xi.getImmutable();
		final Element Y_P = sharedMemory.getPublicKey(Actor.POLICE);

		final byte[] z_Vhash = crypto.getHash(
				(new ListData(Arrays.asList(userData.z_u.toByteArray(), ID_V.getBytes()))).toBytes(),
				sharedMemory.Hash1);
		final BigInteger z_Vnum = (new BigInteger(1, z_Vhash)).mod(p);

		final BigInteger x_dash_U = crypto.secureRandom(p);
		final BigInteger z_dash_V = crypto.secureRandom(p);

		final Element P_dash_V = ((xi.mul(x_dash_U)).add(Y_P.mul(z_dash_V))).getImmutable();
		final Element Q_dash_V = (xi.mul(z_dash_V)).getImmutable();

		final byte[] c_Vhash = crypto.getHash((new ListData(Arrays.asList(userTicket.P_V[index].toBytes(),
				P_dash_V.toBytes(), userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes()))).toBytes(),
				sharedMemory.Hash1);

		final BigInteger c_Vnum = (new BigInteger(1, c_Vhash)).mod(p);

		final BigInteger x_hat_U = (x_dash_U.subtract(c_Vnum.multiply(userData.x_U))).mod(p);
		final BigInteger z_hat_V = (z_dash_V.subtract(c_Vnum.multiply(z_Vnum))).mod(p);

		final ListData sendData = new ListData(Arrays.asList(userTicket.P_V[index].toBytes(), P_dash_V.toBytes(),
				userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes(), c_Vhash, x_hat_U.toByteArray(),
				z_hat_V.toByteArray(), userTicket.E_V[index].toBytes(), userTicket.F_V[index].toBytes(),
				userTicket.K_V[index].toBytes(), userTicket.s_V[index], userTicket.w_v[index].toByteArray(),
				userTicket.e_v[index].toByteArray(), userTicket.sigma_V[index].toBytes()));
		return sendData.toBytes();
	}

	private byte[] generateVerifierID(String verifierID) {
		final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierID);
		final ListData sendData = new ListData(Arrays.asList(verifierData.ID_V.getBytes(StandardCharsets.UTF_8)));
		LOG.debug("Verifier ID = " + verifierData.ID_V);
		return sendData.toBytes();
	}

	private boolean verifyTicketDetails(byte[] data) {
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		// final Crypto crypto = Crypto.getInstance();

		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);
		if (listData.getList().size() <= 0) { // dependent on the number of verifiers...
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return false;
		}
		int indx = 0;
		final Element C_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
		// final String ticketText = new String(listData.getList().get(indx++),
		// StandardCharsets.UTF_8);
		final int numOfVerifiers = new BigInteger(1, listData.getList().get(indx++)).intValue();

		final TicketDetails ticketDetails = new TicketDetails(numOfVerifiers);
		indx = ticketDetails.populateTicketDetails(sharedMemory, listData, indx);

		// verify ticket details
		for (int i = 0; i < numOfVerifiers; i++) {
			// final Element Y_V = sharedMemory.getPublicKey(ticketDetails.VerifierList[i]);
			final byte[] verifyD_V = crypto.getHash(
					(new ListData(Arrays.asList(C_U.toBytes(), ticketDetails.VerifierList[i].getBytes()))).toBytes(),
					sharedMemory.Hash2);
			if (!Arrays.equals(ticketDetails.D_V[i], verifyD_V)) {
				LOG.error("failed to verify D_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
				return false;
			}
		}
		LOG.debug("Passed D_V verification!");
		for (int i = 0; i < numOfVerifiers; i++) {
			final byte[] verifys_V = crypto.getHash(
					(new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(), ticketDetails.Q_V[i].toBytes(),
							ticketDetails.E_V[i].toBytes(), ticketDetails.F_V[i].toBytes(),
							ticketDetails.K_V[i].toBytes(), ticketDetails.ticketText.getBytes()))).toBytes(),
					sharedMemory.Hash1);
			if (!Arrays.equals(ticketDetails.s_V[i], verifys_V)) {
				LOG.error("failed to verify s_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
				return false;
			}

		}
		LOG.debug("Passed s_V verification!");

		// some elements from sharedMemory
		final Element Y_bar_S = sharedMemory.getPublicKey(Actor.SELLER).getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element g_frak = sharedMemory.g_frak.getImmutable();
		final Element h = sharedMemory.h.getImmutable();
		final Element h_tilde = sharedMemory.h_tilde.getImmutable();
		final BigInteger p = sharedMemory.p;

		for (int i = 0; i < numOfVerifiers; i++) {

			final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.sigma_V[i],
					Y_bar_S.add(g_frak.mul(ticketDetails.e_v[i])))).getImmutable();

			final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);

			final Element rhs = (sharedMemory.pairing
					.pairing((g.add(h.mul(ticketDetails.w_v[i]))).add(h_tilde.mul(s_Vnum)), g_frak)).getImmutable();
			if (!lhs.isEqual(rhs)) {
				LOG.error("failed to verify pairing check [" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
				return false;
			}
		}
		LOG.debug("Passed sigma_V pairing verification!");

		final List<byte[]> verifys_PData = new ArrayList<>();
		for (int i = 0; i < numOfVerifiers; i++) {
			verifys_PData.add(ticketDetails.s_V[i]);
		}

		if (!Arrays.equals(ticketDetails.s_P,
				crypto.getHash((new ListData(verifys_PData)).toBytes(), sharedMemory.Hash1))) {
			LOG.error("failed to verify s_P hash");
			return false;
		}

		LOG.debug("Passed s_P verification!");

		final BigInteger s_PNum = (new BigInteger(1, ticketDetails.s_P)).mod(p);

		final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.sigma_P,
				Y_bar_S.add(g_frak.mul(ticketDetails.e_P)))).getImmutable();
		final Element rhs = (sharedMemory.pairing.pairing(g.add(h.mul(ticketDetails.w_P)).add(h_tilde.mul(s_PNum)),
				g_frak)).getImmutable();

		if (!lhs.isEqual(rhs)) {
			LOG.error("failed to verify sigma_P pairing check");
			return false;
		}

		LOG.debug("Passed sigma_P pairing verification!");

		// store the ticket details
		// note that z_U was stored during the ticket request generation
		userData.C_U = C_U;
		userData.ticketDetails = ticketDetails;

		return true;
	}

	private byte[] generateTicketDetails(byte[] data) {
		final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
		// final Crypto crypto = Crypto.getInstance();

		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);
		if (listData.getList().size() <= 0) { // dependent on the number of verifiers...
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return null;
		}

		// some constants from sharedMemory
		final BigInteger p = sharedMemory.p;
		final Element xi = sharedMemory.xi.getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element g_frak = sharedMemory.g_frak.getImmutable();
		final Element h = sharedMemory.h.getImmutable();
		final Element h_tilde = sharedMemory.h_tilde.getImmutable();

		// check the ZKP here:

		int index = 0;
		final List<byte[]> verifyc_hashData = new ArrayList<>();

		final Element sigma_bar_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element sigma_tilde_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

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
		final Element B_bar_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		verifyc_hashData.add(B_bar_U.toBytes());
		final Element W_1 = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		verifyc_hashData.add(W_1.toBytes());
		final Element W_2 = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		verifyc_hashData.add(W_2.toBytes());

		final int numberOfVerifiers = new BigInteger(1, listData.getList().get(index++)).intValue();
		/**
		 * We don't do the dummy verifiers at them moment
		 * 
		 * // if numberOfVerifiers is odd then add one to make an even number. int
		 * evenNumberOfVerifiers = numberOfVerifiers + (numberOfVerifiers % 2); final
		 * TicketDetails ticketDetails = new TicketDetails(evenNumberOfVerifiers);
		 * 
		 **/
		final TicketDetails ticketDetails = new TicketDetails(numberOfVerifiers);

		for (int i = 0; i < numberOfVerifiers; i++) {
			ticketDetails.VerifierList[i] = new String(listData.getList().get(index++), StandardCharsets.UTF_8);
		}

		final Element[] P_dash_V = new Element[numberOfVerifiers];
		final Element[] Q_dash_V = new Element[numberOfVerifiers];
		for (int i = 0; i < numberOfVerifiers; i++) {
			ticketDetails.P_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
			P_dash_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
			ticketDetails.Q_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
			Q_dash_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
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

		final BigInteger e_hat_u = new BigInteger(1, listData.getList().get(index++));
		final BigInteger v_hat_2 = new BigInteger(1, listData.getList().get(index++));
		final BigInteger v_hat_3 = new BigInteger(1, listData.getList().get(index++));
		final BigInteger v_hat = new BigInteger(1, listData.getList().get(index++));
		final BigInteger x_hat_u = new BigInteger(1, listData.getList().get(index++));

		final BigInteger[] z_hat_v = new BigInteger[numberOfVerifiers];
		for (int i = 0; i < numberOfVerifiers; i++) {
			z_hat_v[i] = new BigInteger(1, listData.getList().get(index++));
		}

		// check W_1
		final Element W_1lhs = ((sigma_bar_U.mul(e_hat_u.negate().mod(p))).add(h.mul(v_hat_2)))
				.add((sigma_tilde_U.sub(B_bar_U)).mul(c_hashNum)).getImmutable();

		if (!W_1.isEqual(W_1lhs)) {
			LOG.debug("W_1 verification failed!");
			return null;
		}

		LOG.debug("passed W_1 verification!");

		// check W_2
		Element W_2lhs = (B_bar_U.mul(v_hat_3.negate().mod(p))).getImmutable();
		W_2lhs = W_2lhs.add(xi.mul(x_hat_u)).getImmutable();
		W_2lhs = W_2lhs.add(h.mul(v_hat)).getImmutable();
		W_2lhs = W_2lhs.add(g.mul(c_hashNum.negate().mod(p))).getImmutable();

		if (!W_2.isEqual(W_2lhs)) {
			LOG.debug("W_2 verification failed!");
			return null;
		}

		LOG.debug("passed W_2 verification!");

		final Element Y_P = sharedMemory.getPublicKey(Actor.POLICE);

		for (int i = 0; i < numberOfVerifiers; i++) {
			final Element P_dash_Vlhs = (xi.mul(x_hat_u)).add(Y_P.mul(z_hat_v[i]))
					.add(ticketDetails.P_V[i].mul(c_hashNum)).getImmutable();
			if (!P_dash_V[i].isEqual(P_dash_Vlhs)) {
				LOG.debug("P_dash_V[" + i + "] verification failed!");
				return null;
			}
		}

		LOG.debug("passed P_dash_V verification!");

		for (int i = 0; i < numberOfVerifiers; i++) {
			final Element Q_dash_Vlhs = ((xi.mul(z_hat_v[i])).add(ticketDetails.Q_V[i].mul(c_hashNum))).getImmutable();
			if (!Q_dash_V[i].isEqual(Q_dash_Vlhs)) {
				LOG.debug("Q_dash_V[" + i + "] verification failed!");
				return null;
			}
		}
		LOG.debug("passed Q_dash_V verification!");

		// Creating the ticket now

		final BigInteger t_u = crypto.secureRandom(p);
		final Element C_U = xi.mul(t_u);
		LOG.debug("C_U = " + C_U);

		BigIntEuclidean gcd = null;

		for (int i = 0; i < numberOfVerifiers; i++) {

			ticketDetails.d_v[i] = crypto.secureRandom(p);
			ticketDetails.E_V[i] = xi.mul(ticketDetails.d_v[i]).getImmutable();

			ticketDetails.w_v[i] = crypto.secureRandom(p);
			ticketDetails.e_v[i] = crypto.secureRandom(p);
			final ListData D_Vdata = new ListData(
					Arrays.asList(C_U.toBytes(), ticketDetails.VerifierList[i].getBytes()));
			ticketDetails.D_V[i] = crypto.getHash(D_Vdata.toBytes(), sharedMemory.Hash2);
			final Element Y_V = sharedMemory.getPublicKey(ticketDetails.VerifierList[i]);
			ticketDetails.F_V[i] = Y_V.mul(ticketDetails.d_v[i]).getImmutable();
			ticketDetails.K_V[i] = Y_V.add(Y_P.mul(ticketDetails.d_v[i])).getImmutable();
			final ListData s_Vdata = new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(),
					ticketDetails.Q_V[i].toBytes(), ticketDetails.E_V[i].toBytes(), ticketDetails.F_V[i].toBytes(),
					ticketDetails.K_V[i].toBytes(), SellerData.TICKET_TEXT.getBytes()));
			ticketDetails.s_V[i] = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
			final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);
			gcd = BigIntEuclidean.calculate(sellerData.x_S.add(ticketDetails.e_v[i]).mod(p), p);
			final BigInteger xs_plus_ev_inverse = gcd.x.mod(p);
			ticketDetails.sigma_V[i] = (g.add(h.mul(ticketDetails.w_v[i])).add(h_tilde.mul(s_Vnum)))
					.mul(xs_plus_ev_inverse).getImmutable();
			ticketDetails.ticketText = SellerData.TICKET_TEXT;

		}
		/**
		 * remove dummy verifier for now
		 * 
		 * // Do we need to create a dummy verifier? if (numberOfVerifiers !=
		 * evenNumberOfVerifiers) { // Yes - so give it a name and make up some stuff...
		 * final String ID_du = Actor.VERIFIERS[Actor.dummyVerifierIndx];
		 * ticketDetails.VerifierList[numberOfVerifiers] = ID_du; final BigInteger
		 * d_dash = crypto.secureRandom(p); final BigInteger w_dash =
		 * crypto.secureRandom(p); final BigInteger e_dash = crypto.secureRandom(p); //
		 * final Element D_du =
		 * sharedMemory.pairing.getG1().newRandomElement().getImmutable(); final
		 * ListData D_duData = new ListData(Arrays.asList(C_U.toBytes(),
		 * ID_du.getBytes())); final byte[] D_du = crypto.getHash(D_duData.toBytes(),
		 * sharedMemory.Hash2); // TODO: Discuss with Jinguang final BigInteger z_Vdu =
		 * crypto.secureRandom(p); // final Element P_du =
		 * sharedMemory.pairing.getG1().newRandomElement().getImmutable(); final Element
		 * P_du = sharedMemory.getPublicKey(Actor.USER).add(Y_P.mul(z_Vdu)); final
		 * Element Q_du = xi.mul(z_Vdu).getImmutable(); final Element F_du =
		 * sharedMemory.pairing.getG1().newRandomElement().getImmutable(); // compute
		 * the equivalent values as above but for this dummy verifier
		 * 
		 * final Element E_du = xi.mul(d_dash).getImmutable(); final ListData
		 * hashDataList = new
		 * ListData(Arrays.asList(ticketDetails.VerifierList[numberOfVerifiers].getBytes()));
		 * final byte[] hashData = crypto.getHash(hashDataList.toBytes(),
		 * sharedMemory.Hash3); final BigInteger hashNum = (new BigInteger(1,
		 * hashData)).mod(p); final Element K_du =
		 * Y_P.mul(d_dash).add(sharedMemory.pairing.getG1().newOneElement().mul(hashNum)).getImmutable();
		 * final ListData s_dashList = new ListData(Arrays.asList(P_du.toBytes(),
		 * Q_du.toBytes(), E_du.toBytes(), F_du.toBytes(), K_du.toBytes(),
		 * SellerData.TICKET_TEXT.getBytes())); final byte[] s_dash =
		 * crypto.getHash(s_dashList.toBytes(), sharedMemory.Hash1); final BigInteger
		 * s_dashNum = new BigInteger(1, s_dash).mod(p); gcd =
		 * BigIntEuclidean.calculate(sellerData.x_S.add(e_dash).mod(p), p);
		 * 
		 * final Element sigma_du =
		 * ((g.add(h.mul(w_dash))).add(h_tilde.mul(s_dashNum))).mul(gcd.x.mod(p));
		 * 
		 * ticketDetails.D_V[numberOfVerifiers] = D_du;
		 * ticketDetails.E_V[numberOfVerifiers] = E_du;
		 * ticketDetails.F_V[numberOfVerifiers] = F_du;
		 * ticketDetails.P_V[numberOfVerifiers] = P_du;
		 * ticketDetails.Q_V[numberOfVerifiers] = Q_du;
		 * ticketDetails.K_V[numberOfVerifiers] = K_du;
		 * ticketDetails.s_V[numberOfVerifiers] = s_dash;
		 * ticketDetails.sigma_V[numberOfVerifiers] = sigma_du;
		 * ticketDetails.w_V[numberOfVerifiers] = w_dash;
		 * ticketDetails.e_V[numberOfVerifiers] = e_dash;
		 * 
		 * }
		 **/

		ticketDetails.w_P = crypto.secureRandom(p);
		ticketDetails.e_P = crypto.secureRandom(p);
		final List<byte[]> s_pDataList = new ArrayList<>();
		for (int i = 0; i < numberOfVerifiers; i++) {
			s_pDataList.add(ticketDetails.s_V[i]);
		}
		ticketDetails.s_P = crypto.getHash((new ListData(s_pDataList)).toBytes(), sharedMemory.Hash1);
		final BigInteger s_pDataNum = new BigInteger(1, ticketDetails.s_P).mod(p);
		gcd = BigIntEuclidean.calculate(sellerData.x_S.add(ticketDetails.e_P).mod(p), p);
		ticketDetails.sigma_P = ((g.add(h.mul(ticketDetails.w_P))).add(h_tilde.mul(s_pDataNum))).mul(gcd.x.mod(p));

		final List<byte[]> sendDataList = new ArrayList<>();
		sendDataList.add(C_U.toBytes());
		sendDataList.add(BigInteger.valueOf(numberOfVerifiers).toByteArray()); // need to keep track of the array size
		ticketDetails.getTicketDetails(sendDataList);
		final ListData sendData = new ListData(sendDataList);

		return sendData.toBytes();

	}

	private byte[] generateTicketRequest() {
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		// final Crypto crypto = Crypto.getInstance();

		// get some element from sharedMemory
		final BigInteger p = sharedMemory.p;
		final Element Y_P = sharedMemory.getPublicKey(Actor.POLICE).getImmutable();
		final Element xi = sharedMemory.xi.getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element h = sharedMemory.h.getImmutable();

		final int numberOfVerifiers = userData.VerifierList.length;

		// compute some stuff for the ZKP PI_1_U
		final Element B_U = g.add(h.mul(userData.r_u)).add(userData.Y_U);
		final BigInteger v_1 = crypto.secureRandom(p);
		final BigInteger v_2 = crypto.secureRandom(p);
		final BigInteger z_U = crypto.secureRandom(p);
		// store z_U for later use...
		userData.z_u = z_U;

		// final BigInteger r_dash_U = crypto.secureRandom(p);
		final BigInteger x_dash_U = crypto.secureRandom(p);
		final BigInteger e_dash_U = crypto.secureRandom(p);
		final BigInteger v_dash_2 = crypto.secureRandom(p);
		final BigInteger v_dash_3 = crypto.secureRandom(p);
		final BigInteger v_dash = crypto.secureRandom(p);
		final BigInteger[] z_dash = new BigInteger[numberOfVerifiers];
		for (int i = 0; i < numberOfVerifiers; i++) {
			z_dash[i] = crypto.secureRandom(p);
		}
		BigIntEuclidean gcd = BigIntEuclidean.calculate(v_1, p);
		final BigInteger v_3 = gcd.x.mod(p);
		final BigInteger v = (userData.r_u.subtract(v_2.multiply(v_3))).mod(p);
		final Element sigma_bar_U = userData.sigma_U.mul(v_1).getImmutable();
		final Element sigma_tilde_U = (sigma_bar_U.mul(userData.e_u.negate().mod(p))).add(B_U.mul(v_1)).getImmutable();
		final Element B_bar_U = B_U.mul(v_1).add(sharedMemory.h.mul(v_2.negate().mod(p))).getImmutable();
		final Element W_1 = ((sigma_bar_U.mul(e_dash_U.negate().mod(p))).add(h.mul(v_dash_2))).getImmutable();
		final Element W_2 = (((B_bar_U.mul(v_dash_3.negate().mod(p))).add(xi.mul(x_dash_U))).add(h.mul(v_dash)))
				.getImmutable();

		final byte[][] z_V = new byte[numberOfVerifiers][];
		final Element[] P_V = new Element[numberOfVerifiers];
		final Element[] P_dash_V = new Element[numberOfVerifiers];
		final Element[] Q_V = new Element[numberOfVerifiers];
		final Element[] Q_dash_V = new Element[numberOfVerifiers];

		for (int i = 0; i < numberOfVerifiers; i++) {
			final ListData zvData = new ListData(Arrays.asList(z_U.toByteArray(), userData.VerifierList[i].getBytes()));
			z_V[i] = crypto.getHash(zvData.toBytes(), sharedMemory.Hash1);
			final BigInteger z_Vnum = (new BigInteger(1, z_V[i])).mod(sharedMemory.p);
			P_V[i] = userData.Y_U.add(Y_P.mul(z_Vnum)).getImmutable();
			P_dash_V[i] = ((xi.mul(x_dash_U)).add(Y_P.mul(z_dash[i]))).getImmutable();
			Q_V[i] = xi.mul(z_Vnum).getImmutable();
			Q_dash_V[i] = xi.mul(z_dash[i]).getImmutable();
		}

		final List<byte[]> c_DataList = new ArrayList<>();
		c_DataList.addAll(Arrays.asList(sigma_bar_U.toBytes(), sigma_tilde_U.toBytes(), B_bar_U.toBytes(),
				W_1.toBytes(), W_2.toBytes()));
		for (int i = 0; i < numberOfVerifiers; i++) {
			c_DataList.add(P_V[i].toBytes());
			c_DataList.add(P_dash_V[i].toBytes());
			c_DataList.add(Q_V[i].toBytes());
			c_DataList.add(Q_dash_V[i].toBytes());
		}
		final byte[] c_hash = crypto.getHash((new ListData(c_DataList)).toBytes(), sharedMemory.Hash1);
		final BigInteger c_hashNum = (new BigInteger(1, c_hash)).mod(p);

		final BigInteger e_hat_U = (e_dash_U.subtract(c_hashNum.multiply(userData.e_u))).mod(p);
		final BigInteger v_hat_2 = (v_dash_2.subtract(c_hashNum.multiply(v_2))).mod(p);
		final BigInteger v_hat_3 = (v_dash_3.subtract(c_hashNum.multiply(v_3))).mod(p);
		final BigInteger v_hat = (v_dash.subtract(c_hashNum.multiply(v))).mod(p);
		final BigInteger x_hat_U = (x_dash_U.subtract(c_hashNum.multiply(userData.x_U))).mod(p);

		final BigInteger[] z_hat_V = new BigInteger[numberOfVerifiers];
		for (int i = 0; i < numberOfVerifiers; i++) {
			final BigInteger z_VNum = (new BigInteger(1, z_V[i])).mod(p);
			z_hat_V[i] = (z_dash[i].subtract(c_hashNum.multiply(z_VNum))).mod(p);
		}

		final List<byte[]> sendDataList = new ArrayList<>();
		sendDataList.addAll(Arrays.asList(sigma_bar_U.toBytes(), sigma_tilde_U.toBytes(), B_bar_U.toBytes(),
				W_1.toBytes(), W_2.toBytes()));

		// need to send all the verifier IDs
		sendDataList.add(BigInteger.valueOf(numberOfVerifiers).toByteArray());
		for (int i = 0; i < numberOfVerifiers; i++) {
			sendDataList.add(userData.VerifierList[i].getBytes(StandardCharsets.UTF_8));
		}

		// send the Ps and Qs
		for (int i = 0; i < numberOfVerifiers; i++) {
			sendDataList.add(P_V[i].toBytes());
			sendDataList.add(P_dash_V[i].toBytes());
			sendDataList.add(Q_V[i].toBytes());
			sendDataList.add(Q_dash_V[i].toBytes());
		}

		// add the last few items...
		sendDataList.addAll(Arrays.asList(c_hash, e_hat_U.toByteArray(), v_hat_2.toByteArray(), v_hat_3.toByteArray(),
				v_hat.toByteArray(), x_hat_U.toByteArray()));

		for (int i = 0; i < numberOfVerifiers; i++) {
			sendDataList.add(z_hat_V[i].toByteArray());
		}

		final ListData sendData = new ListData(sendDataList);
		return sendData.toBytes();
	}

	private byte[] generateSellerIdentity() {
		final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);

		// Send ID_S, Y_S, Y_S_bar
		final ListData sendData = new ListData(
				Arrays.asList(sellerData.ID_S.getBytes(), sellerData.Y_S.toBytes(), sellerData.Y_bar_S.toBytes()));
		return sendData.toBytes();
	}

	private byte[] generateVerifierIdentity(String verifierName) {
		final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierName);

		// Send ID_V, Y_V
		final ListData sendData = new ListData(Arrays.asList(verifierData.ID_V.getBytes(), verifierData.Y_V.toBytes()));
		return sendData.toBytes();
	}

	private byte[] generateUserIdentity() {
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);

		// Send ID_U, Y_U
		final ListData sendData = new ListData(Arrays.asList(userData.ID_U.getBytes(), userData.Y_U.toBytes()));
		LOG.debug("User public key = " + userData.Y_U);
		return sendData.toBytes();
	}

	private byte[] generatePoliceIdentity() {
		final PoliceData policeData = (PoliceData) sharedMemory.getData(Actor.POLICE);

		// Send ID_U, Y_U
		final ListData sendData = new ListData(Arrays.asList(policeData.ID_P.getBytes(), policeData.Y_P.toBytes()));
		return sendData.toBytes();
	}

	private byte[] generateSellerCredentials(byte[] data) {

		final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory
				.getData(Actor.CENTRAL_AUTHORITY);
		// final Crypto crypto = Crypto.getInstance();

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

		final Element sigma_S = (sharedMemory.g.add(sharedMemory.h.mul(r_S)).add(Y_S)).mul(gcd.x.mod(sharedMemory.p))
				.getImmutable();

		centralAuthorityData.ID_S = ID_S;
		centralAuthorityData.Y_S = Y_S;
		centralAuthorityData.Y_bar_S = Y_bar_S;
		centralAuthorityData.r_S = r_S;
		centralAuthorityData.e_S = e_S;
		centralAuthorityData.sigma_S = sigma_S;

		// Send sigma_s, e_s, r_s
		final ListData sendData = new ListData(Arrays.asList(sigma_S.toBytes(), r_S.toByteArray(), e_S.toByteArray()));

		return sendData.toBytes();
	}

	private byte[] generateVerifierCredentials(byte[] data) {

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
		// check if we already computed the details for this verifier
		if (centralAuthorityData.verifiers.containsKey(ID_V)) {
			// we can simply retrieve its details
			CentralAuthorityData.VerifierCredentials verifierDetails = centralAuthorityData.verifiers.get(ID_V);
			r_V = verifierDetails.r_V;
			e_V = verifierDetails.e_V;
			sigma_V = verifierDetails.sigma_V;
		} else {
			// we need to do some computation
			final Element Y_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));

			// compute sigma_v
			e_V = crypto.secureRandom(sharedMemory.p);
			r_V = crypto.secureRandom(sharedMemory.p);
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_V).mod(sharedMemory.p),
					sharedMemory.p);

			sigma_V = (sharedMemory.g.add(sharedMemory.h.mul(r_V)).add(Y_V)).mul(gcd.x.mod(sharedMemory.p))
					.getImmutable();

			CentralAuthorityData.VerifierCredentials veriferDetails = centralAuthorityData
					.getVerifierCredentialsInstance();
			veriferDetails.ID_V = ID_V;
			veriferDetails.Y_V = Y_V;
			veriferDetails.r_V = r_V;
			veriferDetails.e_V = e_V;
			veriferDetails.sigma_V = sigma_V;

			centralAuthorityData.verifiers.put(ID_V, veriferDetails);
		}
		// Send sigma_V, e_V, r_V back
		final ListData sendData = new ListData(Arrays.asList(sigma_V.toBytes(), r_V.toByteArray(), e_V.toByteArray()));

		return sendData.toBytes();
	}

	private byte[] generateUserCredentials(byte[] data) {

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

		final Element sigma_U = (sharedMemory.g.add(sharedMemory.h.mul(r_u)).add(Y_U)).mul(gcd.x.mod(sharedMemory.p))
				.getImmutable();

		centralAuthorityData.ID_U = ID_U;
		centralAuthorityData.Y_U = Y_U;
		centralAuthorityData.r_u = r_u;
		centralAuthorityData.e_u = e_u;
		centralAuthorityData.sigma_U = sigma_U;

		// Send sigma_s, e_s, r_s
		final ListData sendData = new ListData(Arrays.asList(sigma_U.toBytes(), r_u.toByteArray(), e_u.toByteArray()));

		return sendData.toBytes();
	}

	private byte[] generatePoliceCredentials(byte[] data) {

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

		// compute sigma_P
		final BigInteger e_P = crypto.secureRandom(sharedMemory.p);
		final BigInteger r_P = crypto.secureRandom(sharedMemory.p);
		final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_P).mod(sharedMemory.p),
				sharedMemory.p);

		final Element sigma_P = (sharedMemory.g.add(sharedMemory.h.mul(r_P)).add(Y_P)).mul(gcd.x.mod(sharedMemory.p))
				.getImmutable();

		centralAuthorityData.ID_P = ID_P;
		centralAuthorityData.Y_P = Y_P;
		centralAuthorityData.r_P = r_P;
		centralAuthorityData.e_P = e_P;
		centralAuthorityData.sigma_P = sigma_P;

		// Send sigma_s, e_s, r_s
		final ListData sendData = new ListData(Arrays.asList(sigma_P.toBytes(), r_P.toByteArray(), e_P.toByteArray()));

		return sendData.toBytes();
	}

	private boolean verifySellerCredentials(byte[] data) {

		final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
		// final Crypto crypto = Crypto.getInstance();

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

		final Element lhs = sharedMemory.pairing.pairing(sigma_S, Y_A.add(sharedMemory.g_frak.mul(e_S))).getImmutable();
		final Element rhs = sharedMemory.pairing
				.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_S)).add(sellerData.Y_S), sharedMemory.g_frak)
				.getImmutable();

		if (!lhs.isEqual(rhs)) {
			return false;
		}

		sellerData.e_S = e_S;
		sellerData.r_S = r_S;
		sellerData.sigma_S = sigma_S;
		return true;
	}

	private boolean verifyVerifierCredentials(String verifierName, byte[] data) {

		final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierName);
		// final Crypto crypto = Crypto.getInstance();

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

		final Element lhs = sharedMemory.pairing.pairing(sigma_V, Y_A.add(sharedMemory.g_frak.mul(e_V))).getImmutable();
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

	private boolean verifyUserCredentials(byte[] data) {

		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		final Crypto crypto = Crypto.getInstance();

		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);

		if (listData.getList().size() != 3) {
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return false;
		}

		final Element sigma_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
		final BigInteger r_u = new BigInteger(listData.getList().get(1));
		final BigInteger e_u = new BigInteger(listData.getList().get(2));

		// verify the credentials
		// TODO: Need to send the CA public key across during set-up. Ignore check for
		// now.

		// get the public key of the CA
		final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

		final Element lhs = sharedMemory.pairing.pairing(sigma_U, Y_A.add(sharedMemory.g_frak.mul(e_u))).getImmutable();
		final Element rhs = sharedMemory.pairing
				.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_u)).add(userData.Y_U), sharedMemory.g_frak)
				.getImmutable();

		if (!lhs.isEqual(rhs)) {
			return false;
		}
		userData.e_u = e_u;
		userData.r_u = r_u;
		userData.sigma_U = sigma_U;
		return true;
	}

	private boolean verifyPoliceCredentials(byte[] data) {

		final PoliceData policeData = (PoliceData) sharedMemory.getData(Actor.POLICE);
		// final Crypto crypto = Crypto.getInstance();

		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);

		if (listData.getList().size() != 3) {
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return false;
		}

		final Element sigma_P = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
		final BigInteger r_P = new BigInteger(listData.getList().get(1));
		final BigInteger e_P = new BigInteger(listData.getList().get(2));

		// verify the credentials

		// get the public key of the CA
		final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

		final Element lhs = sharedMemory.pairing.pairing(sigma_P, Y_A.add(sharedMemory.g_frak.mul(e_P))).getImmutable();
		final Element rhs = sharedMemory.pairing
				.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_P)).add(policeData.Y_P), sharedMemory.g_frak)
				.getImmutable();

		if (!lhs.isEqual(rhs)) {
			return false;
		}

		policeData.e_P = e_P;
		policeData.r_P = r_P;
		policeData.sigma_P = sigma_P;
		return true;
	}

}