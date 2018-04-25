/**
 *
 */
package uk.ac.surrey.bets_framework.protocol.anonsso;

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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.CentralVerifierData;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.TicketDetails;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.UserData;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.VerifierData;
import uk.ac.surrey.bets_framework.protocol.data.ListData;

/**
 * @author swesemeyer
 *
 */
public class TestAnonSSO {

	/** Logback logger. */
	private static final Logger LOG = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("TestAnonSSO");
	Encoder base64 = Base64.getEncoder();
	Crypto crypto;
	AnonSSOSharedMemory sharedMemory = null;
	long overall_start;
	long time_start;
	long time_end;
	long durationInMS;

	@Before
	public void setUp() throws Exception {
		// set the desired log level
		LOG.setLevel(Level.DEBUG);
		LOG.info("=============================================================");
		LOG.info("                     Starting Setup");
		LOG.info("=============================================================");
		time_start = Instant.now().toEpochMilli();
		overall_start = time_start;
		crypto = Crypto.getInstance();
		sharedMemory = new AnonSSOSharedMemory();
		sharedMemory.rBits = 320;
		sharedMemory.clearTest();
		/*LOG.debug("Y_A=" + sharedMemory.Y_A);
		LOG.debug("g_frak=" + sharedMemory.g_frak);
		LOG.debug("g=" + sharedMemory.g);
		LOG.debug("h=" + sharedMemory.h);
		String json = sharedMemory.toJson();
		LOG.debug("JSON version of sharedMemory: " + json);
		AnonSSOSharedMemory deserialSharedMemory = AnonSSOSharedMemory.fromJson(json);
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
*/
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("System setup took (ms): " + durationInMS);
		LOG.info("*************************************************************");
		LOG.info("Setup complete:");

	}

	@Test

	public void testProtocol() {
		byte[] data;
		boolean success;

		// Registration States:
		LOG.info("=============================================================");
		LOG.info("            Going through Registration states");
		LOG.info("=============================================================");

		// Generate Issuer Identify: RState04 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.ISSUER);
		data = this.generateIssuerIdentity();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("Generate Issuer Identify: RState04 (Server) took (ms): " + durationInMS);
		LOG.info("Data sent to server (in bytes): " + data.length);

		// Generates the issuer's credentials: RState06 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
		data = this.generateIssuerCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generated the issuer's credentials: RState06 (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("Issuer credential creation failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);
		LOG.info("*************************************************************");

		// Verify Issuer credentials: RState08 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.ISSUER);
		success = this.verifyIssuerCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Verify Issuer credentials: RState08 (Server) took (ms): " + durationInMS);
		if (!success) {
			fail("Issuer credentials did not validate");
		}
		LOG.info("*************************************************************");

		for (int i = 0; i < Actor.VERIFIERS.length; i++) {
			// Generate Verifier Identify: RState17 (Server)
			time_start = Instant.now().toEpochMilli();
			overall_start = time_start;
			sharedMemory.actAs(Actor.VERIFIERS[i]);
			data = this.generateVerifierIdentity(Actor.VERIFIERS[i]);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("*************************************************************");
			LOG.info("Generate Verifier Identify: RState17 (Server) took (ms): " + durationInMS);
			LOG.info("*************************************************************");

			// Generates the verifier's credentials: RState19 (Server)
			time_start = Instant.now().toEpochMilli();
			sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
			data = this.generateVerifierCredentials(data);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("*************************************************************");
			LOG.info("Generate the verifier's credentials: RState19 (Server) took (ms): " + durationInMS);
			if (data == null) {
				fail("Verifier credential creation failed");
			}
			LOG.info("*************************************************************");

			// Verify Verifier's credentials: RState21 (Server)
			time_start = Instant.now().toEpochMilli();
			sharedMemory.actAs(Actor.VERIFIERS[i]);
			success = this.verifyVerifierCredentials(Actor.VERIFIERS[i], data);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("*************************************************************");
			LOG.info("Verify Verifier's credentials: RState21 (Server) took (ms): " + durationInMS);
			if (!success) {
				fail("Verifier credentials did not validate");
			}
			LOG.info("*************************************************************");

		}
		// Generate User's Identify: RState02 (Android)
		time_start = Instant.now().toEpochMilli();
		overall_start = time_start;
		sharedMemory.actAs(Actor.USER);
		data = this.generateUserIdentity();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Retrieve User Identify: RState02 (Android) took (ms): " + durationInMS);
		LOG.info("Data sent to server (in bytes): " + data.length);
		LOG.info("*************************************************************");

		// Generate the user's credentials: RState10 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
		data = this.generateUserCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generated the user's credentials: RState10 (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("User credential creation failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);
		LOG.info("*************************************************************");

		// Verify user's credentials: RState03 (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		success = this.verifyUserCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Verify User credentials: RState03 (Android) took (ms): " + durationInMS);
		if (!success) {
			fail("User credentials did not validate");
		}
		LOG.info("*************************************************************");

		// Generate Central Verifier Identify: RState12 (Server)
		time_start = Instant.now().toEpochMilli();
		overall_start = time_start;
		sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
		data = this.generateCenVerIdentity();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generate Central Verifier Identify: RState12 (Server) took (ms): " + durationInMS);
		LOG.info("*************************************************************");

		// Generates the CV's credentials: RState14 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
		data = this.generateCenVerCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generated the CV's credentials: RState14 (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("CV credential creation failed");
		}
		LOG.info("*************************************************************");

		// Verify CV credentials: RState16 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
		success = this.verifyCenVerCredentials(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Verify CV credentials: RState16 (Server) took (ms): " + durationInMS);
		if (!success) {
			fail("CV credentials did not validate");
		}
		LOG.info("*************************************************************");

		LOG.info("=============================================================");
		LOG.info("                Finished Registration states");
		LOG.info("=============================================================");
		LOG.info("                Going through Issuing states");
		LOG.info("=============================================================");

		// Generate the user ticket request: IState04 (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		data = this.generateTicketRequest();
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generate the user's ticket request: IState04 (Android) took (ms): " + durationInMS);
		LOG.info("Data sent to server: " + data.length);
		LOG.info("*************************************************************");

		// Generate ticket serial number: IState23 (Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.ISSUER);
		data = this.generateTicketDetails(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generate ticket details: IState23 (Server) took (ms): " + durationInMS);
		if (data == null) {
			fail("ticket details verification failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);
		LOG.info("*************************************************************");

		// Verify the returned ticket data: IState05 (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		success = this.verifyTicketDetails(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Verify the returned ticket details: IState05 (Android) took (ms): " + durationInMS);
		if (!success) {
			fail("ticket details verification failed");
		}
		LOG.info("*************************************************************");

		LOG.info("=============================================================");
		LOG.info("                 Finished Issuing states");
		LOG.info("=============================================================");
		LOG.info("             Going through Verification states");
		LOG.info("=============================================================");

		String[] VerifierList = ((UserData) sharedMemory.getData(Actor.USER)).VerifierList;

		for (int i = 0; i < VerifierList.length; i++) {

			// Generate the verifier ID vState25(Server)
			time_start = Instant.now().toEpochMilli();
			String verifierID = VerifierList[i];
			sharedMemory.actAs(verifierID);
			data = this.generateVerifierID(verifierID);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("*************************************************************");
			LOG.info("Generating the verifier ID finished: vState25(Server) " + durationInMS);
			if (data == null) {
				fail("Verifier ID generation failed");
			}
			LOG.info("Data sent to client (in bytes): " + data.length);
			LOG.info("*************************************************************");

			// Generate ticket proof: VState06 (Android)
			time_start = Instant.now().toEpochMilli();
			sharedMemory.actAs(Actor.USER);
			data = this.generateTagProof(data);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("*************************************************************");
			LOG.info("Generate tag proof: VState06 (Android) took (ms): " + durationInMS);
			if (data == null) {
				fail("tag proof generation failed");
			}
			LOG.info("Data sent to server (in bytes): " + data.length);
			LOG.info("*************************************************************");

			// check the user's proof of his ticket vState27(Server)
			time_start = Instant.now().toEpochMilli();
			sharedMemory.actAs(verifierID);
			success = this.verifyTagProof(data, verifierID);
			time_end = Instant.now().toEpochMilli();
			durationInMS = time_end - time_start;
			LOG.info("*************************************************************");
			LOG.info("Checking the user's tag & proof: VState27 took (ms): " + durationInMS);
			if (!success) {
				fail("Checking the user's proof failed");
			}
			LOG.info("*************************************************************");
			
		}

		LOG.info("=============================================================");
		LOG.info("              Finished Verfication states");
		LOG.info("=============================================================");
		LOG.info("            Going through tracing states states");
		LOG.info("=============================================================");
		// Generate the verifier ID vState25(Server)
		time_start = Instant.now().toEpochMilli();
		String verifierID = Actor.CENTRAL_VERIFIER;
		sharedMemory.actAs(verifierID);
		data = this.generateVerifierID(verifierID);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generating the central verifier ID finished: vState25(Server) " + durationInMS);
		if (data == null) {
			fail("Verifier ID generation failed");
		}
		LOG.info("Data sent to client (in bytes): " + data.length);
		LOG.info("*************************************************************");

		// Generate tag proof+ticket details: VState06 (Android)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.USER);
		data = this.generateTagProof(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("Generate tag proof + ticket details: VState06 (Android) took (ms): " + durationInMS);
		if (data == null) {
			fail("ticket proof generation failed");
		}
		LOG.info("Data sent to server (in bytes): " + data.length);
		LOG.info("*************************************************************");


		// retrieve the verifier IDs from the ticket: vState29(Server)
		time_start = Instant.now().toEpochMilli();
		sharedMemory.actAs(Actor.CENTRAL_VERIFIER);
		data = this.traceTicket(data);
		time_end = Instant.now().toEpochMilli();
		durationInMS = time_end - time_start;
		LOG.info("*************************************************************");
		LOG.info("ticket trace finished: vState30(Server) took (ms):" + durationInMS);
		if (data == null) {
			fail("Ticket trace failed");
		}
		LOG.info("*************************************************************");

		LOG.info("=============================================================");
		LOG.info("            Finished tracing states states");
		LOG.info("=============================================================");

		LOG.info("*************************************************************");
		LOG.info("Total run of the protocol with no comms overhead took (ms):" + (time_end - overall_start));
		LOG.info("*************************************************************");

	}

	private byte[] traceTicket(byte[] data) {
		final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);
		// final Crypto crypto = Crypto.getInstance();
		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);
		
		//each verifier has 11 entries
		//there are 14 entries for the ZKP and the CV tag
		//there are 5 extra entries for checking the integrity of the overall ticket.
		//so (the number of elements in the list sent through - (14+5)) must be divisible by 11.
		
		if ((listData.getList().size() - 19) % 11 != 0) {
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return null;
		}
		
		// some constants from shared Memory
		final Element Y_bar_I = sharedMemory.getPublicKey(Actor.ISSUER).getImmutable();
		final BigInteger p = sharedMemory.p;
		final Element xi = sharedMemory.xi.getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element h = sharedMemory.h.getImmutable();
		final Element h_tilde = sharedMemory.h_tilde.getImmutable();
		final Element g_frak = sharedMemory.g_frak.getImmutable();
		final Element Y_P = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER).getImmutable();

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
			return null;
		}

		LOG.debug("passed c_Vhash verification");

		final Element P_dash_Vlhs = (((xi.mul(x_hat_U)).add(Y_P.mul(z_hat_V))).add(P_V.mul(c_Vnum))).getImmutable();
		LOG.debug("P_dash_Vlhs = " + P_dash_Vlhs);
		if (!P_dash_V.isEqual(P_dash_Vlhs)) {
			LOG.debug("P_dash_V verification failed");
			return null;
		}
		LOG.debug("passed P_dash_V verification");

		final Element Q_dash_Vlhs = ((xi.mul(z_hat_V)).add(Q_V.mul(c_Vnum))).getImmutable();
		if (!Q_dash_V.isEqual(Q_dash_Vlhs)) {
			LOG.debug("Q_dash_V verification failed");
			return null;
		}

		LOG.debug("passed Q_dash_V verification. This completes the ZKP.");

		// get the elements for the remaining checks

		final Element E_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element F_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final Element K_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
		final byte[] s_Vhash = listData.getList().get(index++);
		BigInteger s_Vnum = (new BigInteger(1, s_Vhash)).mod(p);
		final BigInteger w_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);
		final BigInteger e_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);
		final Element sigma_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));

		final ListData s_Vdata = new ListData(Arrays.asList(P_V.toBytes(), Q_V.toBytes(), E_V.toBytes(), F_V.toBytes(),
				K_V.toBytes(), IssuerData.TICKET_TEXT.getBytes()));
		final byte[] s_Vrhs = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
		if (!Arrays.equals(s_Vhash, s_Vrhs)) {
			LOG.debug("s_V hash verification failed!");
			return null;
		}
		LOG.debug("passed s_V hash verification!");

		final Element F_Vrhs = (E_V.mul(cenVerData.x_V)).getImmutable();
		if (!F_V.isEqual(F_Vrhs)) {
			LOG.debug("F_V verification failed!");
			return null;
		}
		LOG.debug("passed F_V verification!");

		Element lhs = sharedMemory.pairing.pairing(sigma_V, Y_bar_I.add(g_frak.mul(e_V))).getImmutable();
		Element rhs = sharedMemory.pairing.pairing(g.add(h.mul(w_V)).add(h_tilde.mul(s_Vnum)), g_frak);
		if (!lhs.isEqual(rhs)) {
			LOG.debug("pairing verification failed!");
			return null;
		}
		LOG.debug("passed pairing verification! The Central Verifier Tag is valid");
		
		int numOfVerifiers = (listData.getList().size() - 19) / 11;
		LOG.debug("We should have "+numOfVerifiers+" verifiers");
		TicketDetails ticketDetails = new TicketDetails(numOfVerifiers);
		ticketDetails.populateTicketDetails(sharedMemory, listData, 14);

		Element Y_U_1 = null;
		Element Y_U_2 = null;
		Element verifierPK=null;

		boolean ZKPTagPresent=false;
		
		Y_U_1 = ticketDetails.P_V[0].div(ticketDetails.Q_V[0].mul(cenVerData.x_V)).getImmutable();
		verifierPK=ticketDetails.K_V[0].div(ticketDetails.E_V[0].mul(cenVerData.x_V));
		if ((P_V.equals(ticketDetails.P_V[0]) && (Q_V.equals(ticketDetails.Q_V[0])))){
			ZKPTagPresent=true;
		}
		LOG.debug("Verifier[0] has public key: "+verifierPK);
		for (int i = 1; i < numOfVerifiers; i++) {
			Y_U_2 = ticketDetails.P_V[i].div(ticketDetails.Q_V[i].mul(cenVerData.x_V)).getImmutable();
			verifierPK=ticketDetails.K_V[i].div(ticketDetails.E_V[i].mul(cenVerData.x_V));
			if ((P_V.equals(ticketDetails.P_V[i]) && (Q_V.equals(ticketDetails.Q_V[i])))){
				ZKPTagPresent=true;
			}
			LOG.debug("Verifier["+i+"] has public key: "+verifierPK);
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
			final byte[] verifys_V = crypto.getHash(
					(new ListData(Arrays.asList(ticketDetails.P_V[i].toBytes(), ticketDetails.Q_V[i].toBytes(),
							ticketDetails.E_V[i].toBytes(), ticketDetails.F_V[i].toBytes(),
							ticketDetails.K_V[i].toBytes(), ticketDetails.ticketText.getBytes()))).toBytes(),
					sharedMemory.Hash1);
			if (!Arrays.equals(ticketDetails.s_V[i], verifys_V)) {
				LOG.error("failed to verify s_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
				return null;
			}
			s_Vnum = (new BigInteger(1, verifys_V)).mod(p);
			lhs = sharedMemory.pairing
					.pairing(ticketDetails.Z_V[i], Y_bar_I.add(g_frak.mul(ticketDetails.e_v[i]))).getImmutable();
			rhs = sharedMemory.pairing
					.pairing(g.add(h.mul(ticketDetails.w_v[i])).add(h_tilde.mul(s_Vnum)), g_frak);
			if (!lhs.isEqual(rhs)) {
				LOG.debug("first pairing check failed for ID_V[" + i + "]: " + ticketDetails.VerifierList[i]);
			}
			LOG.debug("passed tag verification for verifier: " + ticketDetails.VerifierList[i]);
			LOG.debug("PK of the verifier is: "+sharedMemory.getPublicKey(ticketDetails.VerifierList[i]));
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

		final BigInteger s_PNum = (new BigInteger(1, ticketDetails.s_CV)).mod(p);

		lhs = (sharedMemory.pairing.pairing(ticketDetails.Z_CV,
				Y_bar_I.add(g_frak.mul(ticketDetails.e_CV)))).getImmutable();
		rhs = (sharedMemory.pairing.pairing(g.add(h.mul(ticketDetails.w_CV)).add(h_tilde.mul(s_PNum)),
				g_frak)).getImmutable();

		if (!lhs.isEqual(rhs)) {
			LOG.error("failed to verify Z_CV pairing check");
			return null;
		}

		LOG.debug("Passed Z_CV pairing verification!");

		return "Success".getBytes();
	}

	private boolean verifyTagProof(byte[] data, String verifierID) {
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
		final Element Y_P = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER).getImmutable();
		final Element Y_S = sharedMemory.getPublicKey(Actor.ISSUER).getImmutable();

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
				K_V.toBytes(), IssuerData.TICKET_TEXT.getBytes()));
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

	private byte[] generateTagProof(byte[] data) {
		// final AnonSSOSharedMemory sharedMemory = (AnonSSOSharedMemory)
		// this.getSharedMemory();

		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		final Crypto crypto = Crypto.getInstance();

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

		TicketDetails userTicket = userData.ticketDetails;
		int index = userTicket.getVerifierIndex(D_Vhash);
		if (index == -1) {
			LOG.debug("Aborting as verifier not found: " + ID_V);
			return null;
		}
		// found the verifier - now proceed with ZKP PI^2_U.
		// get some constants from shared memory...
		LOG.debug("generating ZK_PI_2_U");
		final BigInteger p = sharedMemory.p;
		final Element xi = sharedMemory.xi.getImmutable();
		final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER);

		final byte[] z_Vhash = crypto.getHash(
				(new ListData(Arrays.asList(userData.z_u.toByteArray(), ID_V.getBytes()))).toBytes(),
				sharedMemory.Hash1);
		final BigInteger z_Vnum = (new BigInteger(1, z_Vhash)).mod(p);

		final BigInteger x_dash_U = crypto.secureRandom(p);
		final BigInteger z_dash_V = crypto.secureRandom(p);

		final Element P_dash_V = ((xi.mul(x_dash_U)).add(Y_CV.mul(z_dash_V))).getImmutable();
		final Element Q_dash_V = (xi.mul(z_dash_V)).getImmutable();

		final byte[] c_Vhash = crypto.getHash((new ListData(Arrays.asList(userTicket.P_V[index].toBytes(),
				P_dash_V.toBytes(), userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes()))).toBytes(),
				sharedMemory.Hash1);

		final BigInteger c_Vnum = (new BigInteger(1, c_Vhash)).mod(p);

		final BigInteger x_hat_U = (x_dash_U.subtract(c_Vnum.multiply(userData.x_U))).mod(p);
		final BigInteger z_hat_V = (z_dash_V.subtract(c_Vnum.multiply(z_Vnum))).mod(p);
		LOG.debug("finished generating ZK_PI_2_U");

		// collect everything that needs to be sent
		final List<byte[]> sendDataList = new ArrayList<>();
		sendDataList.addAll(Arrays.asList(userTicket.P_V[index].toBytes(), P_dash_V.toBytes(),
				userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes(), c_Vhash, x_hat_U.toByteArray(),
				z_hat_V.toByteArray(), userTicket.E_V[index].toBytes(), userTicket.F_V[index].toBytes(),
				userTicket.K_V[index].toBytes(), userTicket.s_V[index], userTicket.w_v[index].toByteArray(),
				userTicket.e_v[index].toByteArray(), userTicket.Z_V[index].toBytes()));

		// if it was the central verifier who asked then we need to add the whole
		// ticket, too
		if (ID_V.equalsIgnoreCase(Actor.CENTRAL_VERIFIER)) {
			LOG.debug("it's a trace so add the whole ticket, too!");
			userData.ticketDetails.getTicketDetails(sendDataList);
		}
		final ListData sendData = new ListData(sendDataList);
		return sendData.toBytes();

	}

	private byte[] generateVerifierID(String verifierID) {
		final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierID);
		final ListData sendData = new ListData(Arrays.asList(verifierData.ID_V.getBytes(StandardCharsets.UTF_8)));
		LOG.debug("Verifier ID = " + verifierData.ID_V);
		return sendData.toBytes();
	}

	private boolean verifyTicketDetails(byte[] data) {
		// final AnonSSOSharedMemory sharedMemory = (AnonSSOSharedMemory)
		// this.getSharedMemory();
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		final Crypto crypto = Crypto.getInstance();

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

		// only check the verifiers if we really want to...
		if (sharedMemory.validateVerifiers) {
			for (int i = 0; i < numOfVerifiers; i++) {
				// Element Y_V = sharedMemory.Y_V.get(ticketDetails.VerifierList[i]);
				final byte[] verifyD_V = crypto
						.getHash((new ListData(Arrays.asList(C_U.toBytes(), ticketDetails.VerifierList[i].getBytes())))
								.toBytes(), sharedMemory.Hash2);
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
			final Element Y_bar_I = sharedMemory.Y_bar_I;
			final Element g = sharedMemory.g.getImmutable();
			final Element g_frak = sharedMemory.g_frak.getImmutable();
			final Element h = sharedMemory.h.getImmutable();
			final Element h_tilde = sharedMemory.h_tilde.getImmutable();
			final BigInteger p = sharedMemory.p;

			for (int i = 0; i < numOfVerifiers; i++) {
				LOG.debug("Verifier: " + i + " is being checked.");

				final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.Z_V[i],
						Y_bar_I.add(g_frak.mul(ticketDetails.e_v[i])))).getImmutable();

				LOG.debug(System.currentTimeMillis() + " computed lhs: " + lhs);
				final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);

				final Element rhs = (sharedMemory.pairing
						.pairing((g.add(h.mul(ticketDetails.w_v[i]))).add(h_tilde.mul(s_Vnum)), g_frak)).getImmutable();
				LOG.debug(System.currentTimeMillis() + " computed rhs: " + rhs);

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

			final BigInteger s_PNum = (new BigInteger(1, ticketDetails.s_CV)).mod(p);
			LOG.debug("Central Verifier is being checked.");
			final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.Z_CV,
					Y_bar_I.add(g_frak.mul(ticketDetails.e_CV)))).getImmutable();
			LOG.debug("Central Verifier is still being checked. Computed lhs" + lhs);
			final Element rhs = (sharedMemory.pairing.pairing(g.add(h.mul(ticketDetails.w_CV)).add(h_tilde.mul(s_PNum)),
					g_frak)).getImmutable();
			LOG.debug("Central Verifier is still being checked. Computed rhs" + rhs);

			if (!lhs.isEqual(rhs)) {
				LOG.error("failed to verify Z_CV pairing check");
				return false;
			}

			LOG.debug("Passed Z_CV pairing verification!");
		}
		// store the ticket details
		// note that z_U was stored during the ticket request generation
		userData.C_U = C_U;
		userData.ticketDetails = ticketDetails;

		return true;
	}

	private byte[] generateTicketDetails(byte[] data) {
		final IssuerData sellerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);
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

		final Element Y_P = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER);

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
					ticketDetails.K_V[i].toBytes(), IssuerData.TICKET_TEXT.getBytes()));
			ticketDetails.s_V[i] = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
			final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);
			gcd = BigIntEuclidean.calculate(sellerData.x_I.add(ticketDetails.e_v[i]).mod(p), p);
			final BigInteger xs_plus_ev_inverse = gcd.x.mod(p);
			ticketDetails.Z_V[i] = (g.add(h.mul(ticketDetails.w_v[i])).add(h_tilde.mul(s_Vnum))).mul(xs_plus_ev_inverse)
					.getImmutable();
			ticketDetails.ticketText = IssuerData.TICKET_TEXT;

		}
		ticketDetails.w_CV = crypto.secureRandom(p);
		ticketDetails.e_CV = crypto.secureRandom(p);
		final List<byte[]> s_pDataList = new ArrayList<>();
		for (int i = 0; i < numberOfVerifiers; i++) {
			s_pDataList.add(ticketDetails.s_V[i]);
		}
		ticketDetails.s_CV = crypto.getHash((new ListData(s_pDataList)).toBytes(), sharedMemory.Hash1);
		final BigInteger s_pDataNum = new BigInteger(1, ticketDetails.s_CV).mod(p);
		gcd = BigIntEuclidean.calculate(sellerData.x_I.add(ticketDetails.e_CV).mod(p), p);
		ticketDetails.Z_CV = ((g.add(h.mul(ticketDetails.w_CV))).add(h_tilde.mul(s_pDataNum))).mul(gcd.x.mod(p));

		final List<byte[]> sendDataList = new ArrayList<>();
		sendDataList.add(C_U.toBytes());
		sendDataList.add(BigInteger.valueOf(numberOfVerifiers).toByteArray()); // need to keep track of the array size
		ticketDetails.getTicketDetails(sendDataList);
		final ListData sendData = new ListData(sendDataList);

		return sendData.toBytes();

	}

	private byte[] generateTicketRequest() {
		// final AnonSSOSharedMemory sharedMemory = (AnonSSOSharedMemory)
		// this.getSharedMemory();
		final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
		final Crypto crypto = Crypto.getInstance();

		// get some elements from sharedMemory
		LOG.debug("computing ZK_PI_1_U");
		final BigInteger p = sharedMemory.p;
		final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER).getImmutable();
		final Element xi = sharedMemory.xi.getImmutable();
		final Element g = sharedMemory.g.getImmutable();
		final Element h = sharedMemory.h.getImmutable();

		// need to include Central Verifier
		final int numberOfVerifiers = userData.VerifierList.length + 1;

		// compute some stuff for the ZKP PI_1_U
		final Element B_U = g.add(h.mul(userData.r_u)).add(userData.Y_U);
		final BigInteger v_1 = crypto.secureRandom(p);
		final BigInteger v_2 = crypto.secureRandom(p);
		final BigInteger z_u = crypto.secureRandom(p);
		// store z_U for later use...
		userData.z_u = z_u;

		final BigInteger x_dash_u = crypto.secureRandom(p);
		final BigInteger e_dash_u = crypto.secureRandom(p);
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
		final Element W_1 = ((sigma_bar_U.mul(e_dash_u.negate().mod(p))).add(h.mul(v_dash_2))).getImmutable();
		final Element W_2 = (((B_bar_U.mul(v_dash_3.negate().mod(p))).add(xi.mul(x_dash_u))).add(h.mul(v_dash)))
				.getImmutable();

		final byte[][] z_v = new byte[numberOfVerifiers][];
		final Element[] P_V = new Element[numberOfVerifiers];
		final Element[] P_dash_V = new Element[numberOfVerifiers];
		final Element[] Q_V = new Element[numberOfVerifiers];
		final Element[] Q_dash_V = new Element[numberOfVerifiers];

		for (int i = 0; i < numberOfVerifiers; i++) {
			if (i < numberOfVerifiers - 1) {
				LOG.debug("adding verifier: " + i);
				final ListData zvData = new ListData(
						Arrays.asList(z_u.toByteArray(), userData.VerifierList[i].getBytes()));
				z_v[i] = crypto.getHash(zvData.toBytes(), sharedMemory.Hash1);
				final BigInteger z_Vnum = (new BigInteger(1, z_v[i])).mod(sharedMemory.p);
				P_V[i] = userData.Y_U.add(Y_CV.mul(z_Vnum)).getImmutable();
				P_dash_V[i] = ((xi.mul(x_dash_u)).add(Y_CV.mul(z_dash[i]))).getImmutable();
				Q_V[i] = xi.mul(z_Vnum).getImmutable();
				Q_dash_V[i] = xi.mul(z_dash[i]).getImmutable();
			} else {
				LOG.debug("adding central verifier!");
				final ListData zvData = new ListData(
						Arrays.asList(z_u.toByteArray(), Actor.CENTRAL_VERIFIER.getBytes()));
				z_v[i] = crypto.getHash(zvData.toBytes(), sharedMemory.Hash1);
				final BigInteger z_Vnum = (new BigInteger(1, z_v[i])).mod(sharedMemory.p);
				P_V[i] = userData.Y_U.add(Y_CV.mul(z_Vnum)).getImmutable();
				P_dash_V[i] = ((xi.mul(x_dash_u)).add(Y_CV.mul(z_dash[i]))).getImmutable();
				Q_V[i] = xi.mul(z_Vnum).getImmutable();
				Q_dash_V[i] = xi.mul(z_dash[i]).getImmutable();
			}
		}
		LOG.debug("finished computing ZK_PI_1_U");
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

		final BigInteger e_hat_U = (e_dash_u.subtract(c_hashNum.multiply(userData.e_u))).mod(p);
		final BigInteger v_hat_2 = (v_dash_2.subtract(c_hashNum.multiply(v_2))).mod(p);
		final BigInteger v_hat_3 = (v_dash_3.subtract(c_hashNum.multiply(v_3))).mod(p);
		final BigInteger v_hat = (v_dash.subtract(c_hashNum.multiply(v))).mod(p);
		final BigInteger x_hat_u = (x_dash_u.subtract(c_hashNum.multiply(userData.x_U))).mod(p);

		final BigInteger[] z_hat_v = new BigInteger[numberOfVerifiers];
		for (int i = 0; i < numberOfVerifiers; i++) {
			final BigInteger z_VNum = (new BigInteger(1, z_v[i])).mod(p);
			z_hat_v[i] = (z_dash[i].subtract(c_hashNum.multiply(z_VNum))).mod(p);
		}

		final List<byte[]> sendDataList = new ArrayList<>();
		sendDataList.addAll(Arrays.asList(sigma_bar_U.toBytes(), sigma_tilde_U.toBytes(), B_bar_U.toBytes(),
				W_1.toBytes(), W_2.toBytes()));

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
		sendDataList.addAll(Arrays.asList(c_hash, e_hat_U.toByteArray(), v_hat_2.toByteArray(), v_hat_3.toByteArray(),
				v_hat.toByteArray(), x_hat_u.toByteArray()));

		for (int i = 0; i < numberOfVerifiers; i++) {
			sendDataList.add(z_hat_v[i].toByteArray());
		}

		final ListData sendData = new ListData(sendDataList);
		return sendData.toBytes();
	}

	private byte[] generateIssuerIdentity() {
		final IssuerData sellerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);

		// Send ID_I, Y_bar_I, Y_S_bar
		final ListData sendData = new ListData(
				Arrays.asList(sellerData.ID_I.getBytes(), sellerData.Y_I.toBytes(), sellerData.Y_bar_I.toBytes()));
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

	private byte[] generateCenVerIdentity() {
		final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);

		// Send ID_U, Y_U
		final ListData sendData = new ListData(Arrays.asList(cenVerData.ID_V.getBytes(), cenVerData.Y_V.toBytes()));
		return sendData.toBytes();
	}

	private byte[] generateIssuerCredentials(byte[] data) {

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

		centralAuthorityData.ID_I = ID_S;
		centralAuthorityData.Y_I = Y_S;
		centralAuthorityData.Y_bar_I = Y_bar_S;
		centralAuthorityData.r_I = r_S;
		centralAuthorityData.e_I = e_S;
		centralAuthorityData.sigma_I = sigma_S;

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
		// Send Z_V, e_V, r_V back
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

	private byte[] generateCenVerCredentials(byte[] data) {

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

		final Element sigma_P = (sharedMemory.g.add(sharedMemory.h.mul(r_P)).add(Y_P)).mul(gcd.x.mod(sharedMemory.p))
				.getImmutable();

		centralAuthorityData.ID_CV = ID_P;
		centralAuthorityData.Y_CV = Y_P;
		centralAuthorityData.r_CV = r_P;
		centralAuthorityData.e_CV = e_P;
		centralAuthorityData.sigma_CV = sigma_P;

		// Send sigma_s, e_s, r_s
		final ListData sendData = new ListData(Arrays.asList(sigma_P.toBytes(), r_P.toByteArray(), e_P.toByteArray()));

		return sendData.toBytes();
	}

	private boolean verifyIssuerCredentials(byte[] data) {

		final IssuerData sellerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);
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
		// final Crypto crypto = Crypto.getInstance();

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
		// get the public key of the CA
		final Element Y_A = sharedMemory.Y_A;

		LOG.debug("About to verify user credentials - computing lhs");
		final Element lhs = sharedMemory.pairing.pairing(sigma_U, Y_A.add(sharedMemory.g_frak.mul(e_u))).getImmutable();
		LOG.debug("still verifying user credentials - computing rhs");
		final Element rhs = sharedMemory.pairing
				.pairing(sharedMemory.g.add(sharedMemory.h.mul(r_u)).add(userData.Y_U), sharedMemory.g_frak)
				.getImmutable();

		if (!lhs.isEqual(rhs)) {
			LOG.error("Failed to verify user credentials");
			return false;
		}
		LOG.debug("Successfully verified user credentials");
		userData.e_u = e_u;
		userData.r_u = r_u;
		userData.sigma_U = sigma_U;
		return true;
	}

	private boolean verifyCenVerCredentials(byte[] data) {

		final CentralVerifierData cenVerData = (CentralVerifierData) sharedMemory.getData(Actor.CENTRAL_VERIFIER);
		// final Crypto crypto = Crypto.getInstance();

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

}