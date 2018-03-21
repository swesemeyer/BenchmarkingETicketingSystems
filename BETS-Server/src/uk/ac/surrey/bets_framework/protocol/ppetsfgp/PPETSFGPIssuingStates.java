/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.SellerData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.UserData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.Message.Type;
import uk.ac.surrey.bets_framework.state.State;

/**
 * Ticket issuing states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPIssuingStates {

	/**
	 * State 8.
	 */
	public static class IState08 extends State<NFCReaderCommand> {

		/**
		 * Generates the seller's proof.
		 *
		 * @return The seller's proof data.
		 */
		private byte[] generateSellerProof() {
			// Note that all elliptic curve calculations are in an additive group such that
			// * -> + and ^ -> *.
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
			final Crypto crypto = Crypto.getInstance();

			// Select random z and v.
			final BigInteger z = crypto.secureRandom(sharedMemory.p);
			final BigInteger v = crypto.secureRandom(sharedMemory.p);
			final Element Q = sellerData.delta_S.add(sharedMemory.theta.mul(z)).getImmutable();

			// Compute Z = g^z * theta^v
			final Element Z = sharedMemory.g.mul(z).add(sharedMemory.theta.mul(v)).getImmutable();

			// Compute gamma = g^z_dash * theta^v_dash where z_dash = z*c_s and
			// v_dash = v*c_s (duplicate label of gamma and Z_c_s in
			// paper).
			final BigInteger z_dash = z.multiply(sellerData.c_s);
			final BigInteger v_dash = v.multiply(sellerData.c_s);
			final Element gamma = sharedMemory.g.mul(z_dash).add(sharedMemory.theta.mul(v_dash));

			// Compute the proof PI_2_S = (M_2_S, Q, Z, gamma, Z_dash, gamma_dash,
			// omega, omega_dash, c_bar_1-3, s_bar_1-2, s_hat_1-2,
			// r_bar_1-5)
			final BigInteger z_bar = crypto.secureRandom(sharedMemory.p);
			final BigInteger v_bar = crypto.secureRandom(sharedMemory.p);
			final BigInteger z_hat = crypto.secureRandom(sharedMemory.p);
			final BigInteger v_hat = crypto.secureRandom(sharedMemory.p);
			final BigInteger x_bar_s = crypto.secureRandom(sharedMemory.p);
			final BigInteger v_bar_s = crypto.secureRandom(sharedMemory.p);
			final BigInteger c_bar_s = crypto.secureRandom(sharedMemory.p);
			final Element M_2_S = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

			// Z_dash = g^z_bar * theta^v_bar
			final Element Z_dash = sharedMemory.g.mul(z_bar).add(sharedMemory.theta.mul(v_bar));

			// gamma_dash = g^z_hat * theta^v_hat
			final Element gamma_dash = sharedMemory.g.mul(z_hat).add(sharedMemory.theta.mul(v_hat));

			// omega = e(Q, g_bar) / e(g_0, g) e(g_1,g)^H(VP_S)
			final Element omega_1 = sharedMemory.pairing.pairing(Q, sharedMemory.g_bar).getImmutable();
			final Element omega_2 = sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g).getImmutable();

			final byte[] vpsHash = crypto.getHash(sellerData.VP_S.getBytes());
			final BigInteger vpsHashNum = new BigInteger(1, vpsHash).mod(sharedMemory.p);
			LOG.debug("vpsHashNum: " + vpsHashNum);

			final Element omega_3 = sharedMemory.pairing.pairing(sharedMemory.g_n[1], sharedMemory.g).pow(vpsHashNum);

			final Element omega = omega_1.div((omega_2.mul(omega_3))).getImmutable();

			// omega_dash = e(rho, g)^x_bar_s * e(g_frak, g)^v_bar_s * e(Q,
			// g)^-c_bar_s * e(theta, g)^z_bar * e(theta, g_bar)^z_bar
			final Element omega_dash_1 = sharedMemory.pairing.pairing(sharedMemory.rho, sharedMemory.g).pow(x_bar_s)
					.getImmutable();

			final Element omega_dash_2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(v_bar_s)
					.getImmutable();

			final Element omega_dash_3 = sharedMemory.pairing.pairing(Q, sharedMemory.g)
					.pow(c_bar_s.negate().mod(sharedMemory.p)).getImmutable();

			final Element omega_dash_4 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(z_hat)
					.getImmutable();

			final Element omega_dash_5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(z_bar)
					.getImmutable();

			final Element omega_dash = omega_dash_1.mul(omega_dash_2).mul(omega_dash_3).mul(omega_dash_4).mul(omega_dash_5)
					.getImmutable();

			// Calculate hashes.
			final ListData c_bar_1Data = new ListData(Arrays.asList(M_2_S.toBytes(), Z.toBytes(), Z_dash.toBytes()));
			final byte[] c_bar_1 = crypto.getHash(c_bar_1Data.toBytes());
			final BigInteger c_bar_1Num = new BigInteger(1, c_bar_1).mod(sharedMemory.p);

			final ListData c_bar_2Data = new ListData(
					Arrays.asList(M_2_S.toBytes(), gamma.toBytes(), gamma_dash.toBytes()));
			final byte[] c_bar_2 = crypto.getHash(c_bar_2Data.toBytes());
			final BigInteger c_bar_2Num = new BigInteger(1, c_bar_2).mod(sharedMemory.p);

			final ListData c_bar_3Data = new ListData(
					Arrays.asList(M_2_S.toBytes(), omega.toBytes(), omega_dash.toBytes()));
			final byte[] c_bar_3 = crypto.getHash(c_bar_3Data.toBytes());
			final BigInteger c_bar_3Num = new BigInteger(1, c_bar_3).mod(sharedMemory.p);

			// Calculate remaining numbers.
			final BigInteger s_bar_1 = z_bar.subtract(c_bar_1Num.multiply(z)).mod(sharedMemory.p);
			final BigInteger s_bar_2 = v_bar.subtract(c_bar_1Num.multiply(v)).mod(sharedMemory.p);

			final BigInteger s_hat_1 = z_hat.subtract(c_bar_2Num.multiply(z_dash)).mod(sharedMemory.p);
			final BigInteger s_hat_2 = v_hat.subtract(c_bar_2Num.multiply(v_dash)).mod(sharedMemory.p);

			final BigInteger r_bar_1 = x_bar_s.subtract(c_bar_3Num.multiply(sellerData.x_s)).mod(sharedMemory.p);
			final BigInteger r_bar_2 = v_bar_s.subtract(c_bar_3Num.multiply(sellerData.r_s)).mod(sharedMemory.p);
			final BigInteger r_bar_3 = c_bar_s.subtract(c_bar_3Num.multiply(sellerData.c_s)).mod(sharedMemory.p);
			final BigInteger r_bar_4 = z_hat.subtract(c_bar_3Num.multiply(z_dash)).mod(sharedMemory.p);
			final BigInteger r_bar_5 = z_bar.subtract(c_bar_3Num.multiply(z)).mod(sharedMemory.p);

			// Send PI_2_S.
			final ListData sendData = new ListData(Arrays.asList(M_2_S.toBytes(), Q.toBytes(), Z.toBytes(), gamma.toBytes(),
					Z_dash.toBytes(), gamma_dash.toBytes(), omega.toBytes(), omega_dash.toBytes(), c_bar_1, c_bar_2,
					c_bar_3, s_bar_1.toByteArray(), s_bar_2.toByteArray(), s_hat_1.toByteArray(), s_hat_2.toByteArray(),
					r_bar_1.toByteArray(), r_bar_2.toByteArray(), r_bar_3.toByteArray(), r_bar_4.toByteArray(),
					r_bar_5.toByteArray()));
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
			// We are now the seller.
			((PPETSFGPSharedMemory) this.getSharedMemory()).actAs(Actor.SELLER);

			if (message.getType() == Type.SUCCESS) {
				// Generate the seller's proof and send it.
				final byte[] data = this.generateSellerProof();

				if (data != null) {
					LOG.debug("generate seller's proof complete");
					return new Action<>(Status.CONTINUE, 9, NFCReaderCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 9.
	 */
	public static class IState09 extends State<NFCReaderCommand> {

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
				// Get the user pseudonym data.
				return new Action<>(Status.CONTINUE, 10, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 10.
	 */
	public static class IState10 extends State<NFCReaderCommand> {

		/**
		 * Generate ticket serial number.
		 *
		 * @param data
		 *            The data received from the user.
		 * @return The ticket serial number.
		 */
		private byte[] generateTicketSerialNumber() {
			// Note that all elliptic curve calculations are in an additive group such that
			// * -> + and ^ -> *.
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
			final Crypto crypto = Crypto.getInstance();

			// Select random d_dash and omega_u.
			final BigInteger d_dash = crypto.secureRandom(sharedMemory.p);
			final BigInteger omega_u = crypto.secureRandom(sharedMemory.p);

			//pick a random serial number... Should probably do something slightly more clever here
			final BigInteger s_u = crypto.secureRandom(sharedMemory.p);

			//Compute psi_u = H(P_U || Price || Service || Ticket Valid_Period)
			final ListData psi_uData = new ListData(Arrays.asList(sharedMemory.stringToBytes(sellerData.U_membershipDetails),
					SellerData.TICKET_PRICE, SellerData.TICKET_SERVICE, sharedMemory.stringToBytes(sellerData.VP_T)));
			final byte[] psi_u = crypto.getHash(psi_uData.toBytes());
			final BigInteger psi_uNum = new BigInteger(1, psi_u).mod(sharedMemory.p);

			// Compute T_U = (g_0 * Y * g_1^d_dash * g_2^s_u)^(1/x_s+omega_u) using
			// the GCD approach.
			final BigIntEuclidean gcd = BigIntEuclidean.calculate(sellerData.x_s.add(omega_u).mod(sharedMemory.p),
					sharedMemory.p);
			final Element T_U = (sharedMemory.g_n[0].add(sellerData.Y).add(sharedMemory.g_n[1].mul(d_dash))
					.add(sharedMemory.g_n[2].mul(s_u)).add(sharedMemory.g_n[3].mul(psi_uNum))).mul(gcd.x.mod(sharedMemory.p)).getImmutable();

			/// Send T_U, d_dash, s_u, omega_u, psi_uNum, Y_S, Service, Price, Valid_Period.
			final ListData sendData = new ListData(Arrays.asList(T_U.toBytes(), d_dash.toByteArray(),
					 s_u.toByteArray(), omega_u.toByteArray(), psi_uNum.toByteArray(), sellerData.Y_S.toBytes(), 
					 SellerData.TICKET_SERVICE, SellerData.TICKET_PRICE, sharedMemory.stringToBytes(sellerData.VP_T)));
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
			if (message.getType() == Type.DATA) {
				// Verify the user's proof.
				if (this.verifyUserProof(message.getData())) {
					// Generate the ticket serial number and send it back.
					final byte[] data = this.generateTicketSerialNumber();

					if (data != null) {
						LOG.debug("generate ticket serial number complete");
						return new Action<>(Status.CONTINUE, 11, NFCReaderCommand.PUT, data, 0);
					}
				}
			}

			return super.getAction(message);
		}

		/**
		 * Verifies the user proof.
		 *
		 * @param data
		 *            The data received from the user.
		 * @return True if verified.
		 */
		private boolean verifyUserProof(byte[] data) {
			// Note that all elliptic curve calculations are in an additive group such that
			// * -> + and ^ -> *.
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() <= 0) { // Way too many to go and count.
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			int index = 0;
			final Element M_2_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element C = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element D = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element phi = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element Y = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			// Save off Y so that we can compute the ticket serial number later
			sellerData.Y = Y; // the user pseudonym
			final Element R = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));

			final Element[] Z_n = new Element[sharedMemory.N1()];
			final Element[] Z_dash_n = new Element[sharedMemory.N1()];
			final Element[] Z_bar_n = new Element[sharedMemory.N1()];
			final Element[] Z_bar_dash_n = new Element[sharedMemory.N1()];
			final Element[][] A_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
			final Element[][] A_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
			final Element[][] V_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
			final Element[][] V_bar_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
			final Element[][] V_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
			final Element[][] V_bar_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];

			for (int i = 0; i < sharedMemory.N1(); i++) {
				Z_n[i] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
				Z_dash_n[i] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
				Z_bar_n[i] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
				Z_bar_dash_n[i] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));

				for (int j = 0; j < sharedMemory.k; j++) {
					A_n_m[i][j] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
					A_dash_n_m[i][j] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));

					V_n_m[i][j] = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
					V_bar_n_m[i][j] = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
					V_dash_n_m[i][j] = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
					V_bar_dash_n_m[i][j] = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
				}
			}

			final Element[][] B_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];
			final Element[][] W_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];
			final Element[][] W_bar_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];

			for (int i = 0; i < sharedMemory.N2(); i++) {
				for (int j = 0; j < sharedMemory.zeta(); j++) {
					B_n_m[i][j] = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
					W_n_m[i][j] = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
					W_bar_n_m[i][j] = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
				}
			}

			final byte[] c_BAR = listData.getList().get(index++);
			final BigInteger c_BARNum = new BigInteger(1, c_BAR).mod(sharedMemory.p);
			final BigInteger c_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger x_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger d_BAR = new BigInteger(listData.getList().get(index++));
			final BigInteger r_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger alpha_BAR = new BigInteger(listData.getList().get(index++));
			final BigInteger beta_BAR = new BigInteger(listData.getList().get(index++));
			final BigInteger alpha_BAR_dash = new BigInteger(listData.getList().get(index++));
			final BigInteger beta_BAR_dash = new BigInteger(listData.getList().get(index++));

			final byte[][] e_BAR_m = new byte[sharedMemory.N1()][];
			final BigInteger[] e_BAR_mNum = new BigInteger[sharedMemory.N1()];
			final BigInteger[] gammac_BAR_n = new BigInteger[sharedMemory.N1()];
			final BigInteger[] ac_BAR_n = new BigInteger[sharedMemory.N1()];
			final BigInteger[] gammae_BAR_n = new BigInteger[sharedMemory.N1()];
			final BigInteger[] ae_BAR_n = new BigInteger[sharedMemory.N1()];
			final BigInteger[] ae_BAR_dash_n = new BigInteger[sharedMemory.N1()];

			for (int i = 0; i < sharedMemory.N1(); i++) {
				e_BAR_m[i] = listData.getList().get(index++);
				e_BAR_mNum[i] = new BigInteger(1, e_BAR_m[i]).mod(sharedMemory.p);

				gammac_BAR_n[i] = new BigInteger(listData.getList().get(index++));
				ac_BAR_n[i] = new BigInteger(listData.getList().get(index++));

				gammae_BAR_n[i] = new BigInteger(listData.getList().get(index++));
				ae_BAR_n[i] = new BigInteger(listData.getList().get(index++));
				ae_BAR_dash_n[i] = new BigInteger(listData.getList().get(index++));
			}

			final BigInteger[] e_BAR_n = new BigInteger[sharedMemory.N2()];
			final BigInteger[] e_BAR_nNum = new BigInteger[sharedMemory.N2()];
			final BigInteger[] e_BAR_dash_n = new BigInteger[sharedMemory.N2()];
			final BigInteger[] e_BAR_dash_dash_n = new BigInteger[sharedMemory.N2()];

			for (int i = 0; i < sharedMemory.N2(); i++) {
				e_BAR_n[i] = new BigInteger(listData.getList().get(index++));
				e_BAR_nNum[i] = e_BAR_dash_n[i] = new BigInteger(listData.getList().get(index++));
				e_BAR_dash_dash_n[i] = new BigInteger(listData.getList().get(index++));
			}

			final byte[][][] d_BAR_n_m = new byte[sharedMemory.N1()][sharedMemory.k][];
			final BigInteger[][] d_BAR_n_mNum = new BigInteger[sharedMemory.N1()][sharedMemory.k];
			final BigInteger[][] t_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
			final BigInteger[][] t_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
			final BigInteger[][] we_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
			final BigInteger[][] we_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
			final BigInteger[][] wd_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
			final BigInteger[][] wd_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

			for (int i = 0; i < sharedMemory.N1(); i++) {
				for (int j = 0; j < sharedMemory.k; j++) {
					d_BAR_n_m[i][j] = listData.getList().get(index++);
					// Convert the hash to a number
					d_BAR_n_mNum[i][j] = new BigInteger(1, d_BAR_n_m[i][j]).mod(sharedMemory.p);
					t_BAR_n_m[i][j] = new BigInteger(listData.getList().get(index++));
					t_BAR_dash_n_m[i][j] = new BigInteger(listData.getList().get(index++));
					we_BAR_n_m[i][j] = new BigInteger(listData.getList().get(index++));
					we_BAR_dash_n_m[i][j] = new BigInteger(listData.getList().get(index++));
					wd_BAR_n_m[i][j] = new BigInteger(listData.getList().get(index++));
					wd_BAR_dash_n_m[i][j] = new BigInteger(listData.getList().get(index++));
				}
			}
			
			//get the user policy membership and store them for later
			sellerData.U_membershipDetails=sharedMemory.stringFromBytes(listData.getList().get(index++));
		
			//get the user's validity period
			final String VP_U=sharedMemory.stringFromBytes(listData.getList().get(index++));
			
			//first check that the VP_U was used correctly in the computation of R
		    final byte[] vpuHash = crypto.getHash(VP_U.getBytes());
		    final BigInteger vpuHashNum = new BigInteger(1, vpuHash).mod(sharedMemory.p);

		    final Element checkR = sharedMemory.pairing.pairing(C, sharedMemory.g_bar)
		              .div(sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g).mul
		                      (sharedMemory.pairing.pairing(sharedMemory.g_n[1], sharedMemory.g)
		                              .pow(vpuHashNum))).getImmutable();			

		    if (!R.isEqual(checkR)) {
				LOG.error("failed to verify VP_U usuage in computing R");
				if (!sharedMemory.passVerification) {
					return false;
				}		    	
		    }
		    
		    
			// Verify c_BAR.
			final List<byte[]> c_BARVerifyList = new ArrayList<>();
			c_BARVerifyList.addAll(Arrays.asList(M_2_U.toBytes(), Y.toBytes()));

			// check Y_bar
			final Element c_BARCheck1 = (sharedMemory.xi.mul(x_BAR_u)).add(sharedMemory.g_n[1].mul(d_BAR))
					.add(Y.mul(c_BARNum)).getImmutable();

			c_BARVerifyList.add(c_BARCheck1.toBytes());

			c_BARVerifyList.add(D.toBytes());

			// check D_bar
			final Element c_BARCheck2 = sharedMemory.g.mul(alpha_BAR).add(sharedMemory.theta.mul(beta_BAR))
					.add(D.mul(c_BARNum)).getImmutable();
			c_BARVerifyList.add(c_BARCheck2.toBytes());

			c_BARVerifyList.add(phi.toBytes());

			final Element c_BARCheck3 = sharedMemory.g.mul(alpha_BAR_dash).add(sharedMemory.theta.mul(beta_BAR_dash))
					.add(phi.mul(c_BARNum));
			c_BARVerifyList.add(c_BARCheck3.toBytes());

			c_BARVerifyList.add(C.toBytes());
			c_BARVerifyList.add(R.toBytes());

			// the following computations should produce R_dash
			Element R_dash1 = sharedMemory.pairing.pairing(sharedMemory.xi, sharedMemory.g).pow(x_BAR_u).getImmutable();
			Element R_dash2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_BAR_u)
					.getImmutable();
			Element R_dash3 = sharedMemory.pairing.getGT().newOneElement();
			for (int i = 0; i < sharedMemory.N1(); i++) {
				Element value = sharedMemory.pairing.pairing(sharedMemory.g_hat_n[i], sharedMemory.g).pow(ac_BAR_n[i])
						.getImmutable();
				R_dash3 = R_dash3.mul(value);
			}
			Element R_dash4 = sharedMemory.pairing.getGT().newOneElement();
			for (int i = 0; i < sharedMemory.N2(); i++) {
				Element value = sharedMemory.pairing.pairing(sharedMemory.eta_n[i], sharedMemory.g).pow(e_BAR_dash_n[i])
						.getImmutable();
				R_dash4 = R_dash4.mul(value);
			}
			Element R_dash5 = sharedMemory.pairing.pairing(C, sharedMemory.g).pow(c_BAR_u.negate().mod(sharedMemory.p))
					.getImmutable();
			Element R_dash6 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(alpha_BAR_dash)
					.getImmutable();
			Element R_dash7 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(alpha_BAR)
					.getImmutable();
			Element R_dash8 = R.pow(c_BARNum).getImmutable();
			Element R_dash = R_dash1.mul(R_dash2).mul(R_dash3).mul(R_dash4).mul(R_dash5).mul(R_dash6).mul(R_dash7)
					.mul(R_dash8).getImmutable();

			c_BARVerifyList.add(R_dash.toBytes());

			for (int i = 0; i < sharedMemory.N1(); i++) {
				c_BARVerifyList.add(Z_n[i].toBytes());
			}

			for (int i = 0; i < sharedMemory.N1(); i++) {
				final Element c_BARCheck4 = sharedMemory.g.mul(gammac_BAR_n[i]).add(sharedMemory.h.mul(ac_BAR_n[i]))
						.add(Z_n[i].mul(c_BARNum));
				c_BARVerifyList.add(c_BARCheck4.toBytes());
			}

			for (int i = 0; i < sharedMemory.N2(); i++) {
				for (int j = 0; j < sharedMemory.zeta(); j++) {
					c_BARVerifyList.add(B_n_m[i][j].toBytes());
				}
			}

			for (int i = 0; i < sharedMemory.N2(); i++) {
				for (int j = 0; j < sharedMemory.zeta(); j++) {
					c_BARVerifyList.add(W_n_m[i][j].toBytes());
				}
			}
			for (int i = 0; i < sharedMemory.N2(); i++) {
				for (int j = 0; j < sharedMemory.zeta(); j++) {
					if (UserData.A_U_set[i].equalsIgnoreCase(sharedMemory.setPolices[i][j])) {
						Element product2 = sharedMemory.pairing.pairing(sharedMemory.eta, sharedMemory.eta_n[i])
								.pow(e_BAR_n[i]).getImmutable();
						product2 = product2.mul(sharedMemory.pairing.pairing(B_n_m[i][j], sharedMemory.eta_n[i])
								.pow(e_BAR_dash_dash_n[i])).getImmutable();
						product2 = product2.mul(W_n_m[i][j].pow(c_BARNum)).getImmutable();
						c_BARVerifyList.add(product2.toBytes());
					} else {
						// just stick some random but fixed element here as it is not used...
						c_BARVerifyList.add(sharedMemory.g.toBytes());
					}
				}
			}

			final ListData c_BARVerifyData = new ListData(c_BARVerifyList);
			final byte[] c_BARVerify = crypto.getHash(c_BARVerifyData.toBytes());

			if (!Arrays.equals(c_BAR, c_BARVerify)) {
				LOG.error("failed to verify PI_2_U: c_BAR");
				if (!sharedMemory.passVerification) {
					return false;
				}
			}

			LOG.debug("SUCCESS: verified user proof: PI_2_U: c_BAR");

			// Verify e_BAR_m.
			for (int i = 0; i < sharedMemory.N1(); i++) {
				final BigInteger lower = BigInteger.valueOf(sharedMemory.rangePolicies[i][0]);
				final BigInteger upper = BigInteger.valueOf(sharedMemory.rangePolicies[i][1]);

				final List<byte[]> e_BAR_mVerifyList = new ArrayList<>();
				e_BAR_mVerifyList.addAll(Arrays.asList(M_2_U.toBytes(), Z_n[i].toBytes()));
				Element e_BAR_mVerifyCheck1a = sharedMemory.g.mul(gammae_BAR_n[i]).getImmutable();
				Element e_BAR_mVerifyCheck1b = sharedMemory.h.mul(ae_BAR_n[i]).getImmutable();
				Element e_BAR_mVerifyCheck1c = (Z_n[i].add(sharedMemory.h.mul(lower.negate().mod(sharedMemory.p))))
						.mul(e_BAR_mNum[i]).getImmutable();
				Element e_BAR_mVerifyCheck1 = e_BAR_mVerifyCheck1a.add(e_BAR_mVerifyCheck1b).add(e_BAR_mVerifyCheck1c)
						.getImmutable();
				e_BAR_mVerifyList.add(e_BAR_mVerifyCheck1.toBytes());

				Element e_BAR_mVerifyCheck2a = sharedMemory.g.mul(gammae_BAR_n[i]).getImmutable();
				Element e_BAR_mVerifyCheck2b = sharedMemory.pairing.getG1().newZeroElement();
				for (int j = 0; j < sharedMemory.k; j++) {
					final Element e_BAR_mVerifyCheck2b_j = sharedMemory.h_bar_n[j].mul(we_BAR_n_m[i][j]).getImmutable();
					e_BAR_mVerifyCheck2b.add(e_BAR_mVerifyCheck2b_j);
				}
				final Element e_BAR_mVerifyCheck2c = (Z_n[i]
						.add(sharedMemory.h.mul(lower.negate().mod(sharedMemory.p)))).mul(e_BAR_mNum[i]).getImmutable();
				final Element e_BAR_mVerifyCheck2 = e_BAR_mVerifyCheck2a.add(e_BAR_mVerifyCheck2b)
						.add(e_BAR_mVerifyCheck2c);
				e_BAR_mVerifyList.add(e_BAR_mVerifyCheck2.toBytes());

				final BigInteger limit = BigInteger.valueOf((long) Math.pow(sharedMemory.q, sharedMemory.k));
				final Element e_BAR_mVerifyCheck3a = sharedMemory.g.mul(gammae_BAR_n[i]).getImmutable();

				Element e_BAR_mVerifyCheck3b = sharedMemory.pairing.getG1().newZeroElement().getImmutable();
				for (int j = 0; j < sharedMemory.k; j++) {
					e_BAR_mVerifyCheck3b = e_BAR_mVerifyCheck3b.add(sharedMemory.h_bar_n[j].mul(we_BAR_dash_n_m[i][j]))
							.getImmutable();
				}
				Element e_BAR_mVerifyCheck3c = sharedMemory.h.mul(limit.subtract(upper)).getImmutable();
				e_BAR_mVerifyCheck3c = e_BAR_mVerifyCheck3c.add(Z_n[i]).mul(e_BAR_mNum[i]);

				final Element e_BAR_mVerifyCheck3 = e_BAR_mVerifyCheck3a.add(e_BAR_mVerifyCheck3b)
						.add(e_BAR_mVerifyCheck3c);

				e_BAR_mVerifyList.add(e_BAR_mVerifyCheck3.toBytes());

				final ListData e_BAR_mVerifyData = new ListData(e_BAR_mVerifyList);
				final byte[] e_BAR_mVerify = crypto.getHash(e_BAR_mVerifyData.toBytes());

				if (!Arrays.equals(e_BAR_m[i], e_BAR_mVerify)) {
					LOG.error("failed to verify PI_2_U: e_BAR_n: " + i);
					if (!sharedMemory.passVerification) {
						return false;
					}
				}
			}
			LOG.debug("SUCCESS: verified PI_2_U: e_BAR_n");

			// Verify d_BAR_n_m
			for (int i = 0; i < sharedMemory.N1(); i++) {
				for (int j = 0; j < sharedMemory.k; j++) {
					final List<byte[]> d_BAR_n_mVerifyList = new ArrayList<>();
					d_BAR_n_mVerifyList.addAll(Arrays.asList(M_2_U.toBytes(), A_n_m[i][j].toBytes(),
							A_dash_n_m[i][j].toBytes(), V_n_m[i][j].toBytes(), V_dash_n_m[i][j].toBytes()));

					Element d_BAR_n_mVerifyCheck1a = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h)
							.pow(t_BAR_n_m[i][j]).getImmutable();
					Element d_BAR_n_mVerifyCheck1b = sharedMemory.pairing.pairing(A_n_m[i][j], sharedMemory.h)
							.pow(wd_BAR_n_m[i][j].negate().mod(sharedMemory.p)).getImmutable();
					Element d_BAR_n_mVerifyCheck1c = V_n_m[i][j].pow(d_BAR_n_mNum[i][j]);
					Element d_BAR_n_mVerifyCheck1 = d_BAR_n_mVerifyCheck1a.mul(d_BAR_n_mVerifyCheck1b)
							.mul(d_BAR_n_mVerifyCheck1c).getImmutable();

					d_BAR_n_mVerifyList.add(d_BAR_n_mVerifyCheck1.toBytes());

					Element d_BAR_n_mVerifyCheck2a = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h)
							.pow(t_BAR_dash_n_m[i][j]).getImmutable();
					Element d_BAR_n_mVerifyCheck2b = sharedMemory.pairing.pairing(A_dash_n_m[i][j], sharedMemory.h)
							.pow(wd_BAR_dash_n_m[i][j].negate().mod(sharedMemory.p)).getImmutable();
					Element d_BAR_n_mVerifyCheck2c = V_dash_n_m[i][j].pow(d_BAR_n_mNum[i][j]);
					Element d_BAR_n_mVerifyCheck2 = d_BAR_n_mVerifyCheck2a.mul(d_BAR_n_mVerifyCheck2b)
							.mul(d_BAR_n_mVerifyCheck2c).getImmutable();
					d_BAR_n_mVerifyList.add(d_BAR_n_mVerifyCheck2.toBytes());

					final ListData d_BAR_n_mVerifyData = new ListData(d_BAR_n_mVerifyList);
					final byte[] d_BAR_n_mVerify = crypto.getHash(d_BAR_n_mVerifyData.toBytes());

					if (!Arrays.equals(d_BAR_n_m[i][j], d_BAR_n_mVerify)) {
						LOG.error("failed to verify PI_2_U: d_BAR_n_m: " + i + ", " + j);
						if (!sharedMemory.passVerification) {
							return false;
						}
					}
				}
			}
			LOG.debug("SUCCESS: verified PI_2_U: d_BAR_n_m");

			return true;
		}
	}

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPIssuingStates.class);

}
