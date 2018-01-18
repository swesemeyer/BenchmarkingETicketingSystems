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
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.ValidatorData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.Message.Type;
import uk.ac.surrey.bets_framework.state.State;

/**
 * Ticket validation and double spend detection states of the PPETS-FGP state
 * machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPValidationStates {

	/**
	 * State 11.
	 */
	public static class VState11 extends State<NFCReaderCommand> {

		/**
		 * Generates the validator's random number.
		 *
		 * @return The validator's random number.
		 */
		private byte[] generateValidatorRandomNumber() {
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);
			final Crypto crypto = Crypto.getInstance();

			// Select random r.
			final BigInteger r = crypto.secureRandom(sharedMemory.p);

			// Store part of the transcript r, saving any previous value.
			validatorData.r_last = validatorData.r;
			validatorData.r = r;

			// Send r
			final ListData sendData = new ListData(Arrays.asList(ValidatorData.ID_V, r.toByteArray()));
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
			// We are now the validator.
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			sharedMemory.actAs(Actor.VALIDATOR);

			if (message.getType() == Type.SUCCESS) {
				LOG.info("ticket validation: " + sharedMemory.numValidations);

				// Start the timing block.
				this.startTiming(PPETSFGPSharedMemory.TIMING_NAME);

				// Generate the validator's random number and send it.
				final byte[] data = this.generateValidatorRandomNumber();

				if (data != null) {
					LOG.debug("generate validtor's random number complete");
					return new Action<>(Status.CONTINUE, 12, NFCReaderCommand.PUT, data, 0);
				}
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 12.
	 */
	public static class VState12 extends State<NFCReaderCommand> {

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
				// Get the user ticket transcript.
				return new Action<>(Status.CONTINUE, 13, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
			}

			return super.getAction(message);
		}
	}

	/**
	 * State 13.
	 */
	public static class VState13 extends State<NFCReaderCommand> {

		/**
		 * Detects if the ticket has been double spent.
		 *
		 * @return True if the ticket is double spent.
		 */
		private boolean detectDoubleSpend() {
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);

			// Here we do not (and cannot since it requires the private x_u)
			// E^r_dash/E_dash^r and Y_U, as we just compare the stored
			// ticket transcript.
			return validatorData.D.isEqual(validatorData.D_last) && !validatorData.E.isEqual(validatorData.E_last);
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
				// Verify the ticket proof
				if (this.verifyTicketProof(message.getData())) {
					// Detect double spend.
					final boolean doubleSpend = this.detectDoubleSpend();
					LOG.debug("ticket validation complete - double spend: " + doubleSpend);

					// Stop the timing block.
					this.stopTiming(PPETSFGPSharedMemory.TIMING_NAME);

					// If we have more iterations of ticket validation to do, then go back to the
					// start of validation, otherwise end.
					final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();

					if (sharedMemory.numValidations > 1) {
						sharedMemory.numValidations--;
						return new Action<>(11);
					} else {
						return new Action<>(Action.NO_STATE_CHANGE, NFCReaderCommand.CLOSE);
					}
				}
			}

			if (message.getType() == Type.SUCCESS) {
				return new Action<>(Status.END_SUCCESS, 0, null, null, 0);
			}

			return super.getAction(message);
		}

		/**
		 * Verifies the ticket proof.
		 *
		 * @param data
		 *            The data received from the user.
		 * @return True if the ticket proof is verified.
		 */
		private boolean verifyTicketProof(byte[] data) {
			final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
			final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);
			final Crypto crypto = Crypto.getInstance();

			// Decode the received data.
			final ListData listData = ListData.fromBytes(data);

			if (listData.getList().size() != 23) {
				LOG.error("wrong number of data elements: " + listData.getList().size());
				return false;
			}

			// Receive P_U, Price, Service, VP_T, M_3_U, D, Ps_U, E, F, J, J_dash, R, c,
			// s_BAR_u, x_BAR_u, s_hat_u, pi_BAR, lambda_BAR, omega_BAR_u, pi_BAR_dash,
			// d_BAR_u, psi_uNum
			// U also needs to send Y_S as the verifier won't have it otherwise

			int index = 0;
			final String P_U = sharedMemory.stringFromBytes(listData.getList().get(index++));
			final byte[] price = listData.getList().get(index++);
			final byte[] service = listData.getList().get(index++);
			final String VP_T = sharedMemory.stringFromBytes(listData.getList().get(index++));
			final Element M_3_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element D = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element Ps_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element E = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element F = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element J = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element J_dash = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
			final Element R = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
			final byte[] c = listData.getList().get(index++);
			final BigInteger s_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger x_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger s_hat_u = new BigInteger(listData.getList().get(index++));
			final BigInteger pi_BAR = new BigInteger(listData.getList().get(index++));
			final BigInteger lambda_BAR = new BigInteger(listData.getList().get(index++));
			final BigInteger omega_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger pi_BAR_dash = new BigInteger(listData.getList().get(index++));
			final BigInteger d_BAR_u = new BigInteger(listData.getList().get(index++));
			final BigInteger psi_uNum = new BigInteger(listData.getList().get(index++));
			final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(index++));

			// Verify psi_uNum
			// Compute psi_u = H(P_U || Price || Service || Ticket Valid_Period)
			final ListData check_psi_uData = new ListData(
					Arrays.asList(sharedMemory.stringToBytes(P_U), price, service, sharedMemory.stringToBytes(VP_T)));
			final byte[] check_psi_u = crypto.getHash(check_psi_uData.toBytes());
			final BigInteger check_psi_uNum = new BigInteger(1, check_psi_u).mod(sharedMemory.p);

			if (!psi_uNum.equals(check_psi_uNum)) {
				LOG.error("failed to verify psi_uNum");
				if (!sharedMemory.passVerification) {
					return false;
				}
			}

			LOG.debug("SUCCESS: verified psi_uNum");

			// Verify R

			// R = e(F,Y_S) / (e(g_0,rho) e(Y,rho) e(g_3, rho)^psi_u
			// R_bar = e(xi,rho)^x_bar_u * e(g_1,rho)^d_bar_u * e(g_2,rho)^s_bar_u *
			// e(F,rho)^-omega_bar_u * e(theta,rho)^pi_bar_dash *
			// e(theta,rho)^pi_bar
			final Element checkR_1 = sharedMemory.pairing.pairing(F, Y_S);
			final Element checkR_2 = sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.rho).getImmutable();
			final Element checkR_3 = sharedMemory.pairing.pairing(Ps_U, sharedMemory.rho).getImmutable();

			final Element checkR_4 = sharedMemory.pairing.pairing(sharedMemory.g_n[3], sharedMemory.rho).pow(psi_uNum)
					.getImmutable();

			final Element checkR = checkR_1.div(checkR_2.mul(checkR_3).mul(checkR_4)).getImmutable();

			if (!R.equals(checkR)) {
				LOG.error("failed to verify R");
				if (!sharedMemory.passVerification) {
					return false;
				}
			}

			LOG.debug("SUCCESS: verified R");

			// Verify c.
			final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);
			final List<byte[]> cVerifyList = new ArrayList<>();
			cVerifyList.addAll(Arrays.asList(M_3_U.toBytes(), D.toBytes(), Ps_U.toBytes(), E.toBytes(), J.toBytes(),
					J_dash.toBytes(), R.toBytes()));

			// Verify D_bar
			final Element cCheck1 = sharedMemory.g.mul(s_BAR_u).add(D.mul(cNum));
			cVerifyList.add(cCheck1.toBytes());

			// verify Ps_bar_U
			final Element cCheck2 = sharedMemory.xi.mul(x_BAR_u).add(sharedMemory.g_n[1].mul(d_BAR_u))
					.add(Ps_U.mul(cNum));
			cVerifyList.add(cCheck2.toBytes());

			// Verify E_bar
			final byte[] hashID_V = crypto.getHash(ValidatorData.ID_V);
			final Element elementFromHashID_V = sharedMemory.pairing.getG1()
					.newElementFromHash(hashID_V, 0, hashID_V.length).getImmutable();

			final Element cCheck3 = sharedMemory.xi.mul(x_BAR_u).add(elementFromHashID_V.mul(s_hat_u)).add(E.mul(cNum));
			cVerifyList.add(cCheck3.toBytes());

			// Verify J_bar
			final Element cCheck4 = ((sharedMemory.g.mul(pi_BAR)).add(sharedMemory.theta.mul(lambda_BAR)))
					.add(J.mul(cNum));
			cVerifyList.add(cCheck4.toBytes());

			// Verify J_bar_dash
			final Element cCheck5 = J.mul(omega_BAR_u).add(J_dash.mul(cNum));
			cVerifyList.add(cCheck5.toBytes());

			// verify R'
			final Element cCheck6_1 = sharedMemory.pairing.pairing(sharedMemory.g_n[2], sharedMemory.rho).pow(s_BAR_u);
			final Element cCheck6_2 = sharedMemory.pairing.pairing(F, sharedMemory.rho)
					.pow(omega_BAR_u.negate().mod(sharedMemory.p));
			final Element cCheck6_3 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.rho)
					.pow(pi_BAR_dash);
			final Element cCheck6_4 = sharedMemory.pairing.pairing(sharedMemory.theta, Y_S).pow(pi_BAR)
					.mul(R.pow(cNum));
			final Element cCheck6 = cCheck6_1.mul(cCheck6_2).mul(cCheck6_3).mul(cCheck6_4);
			cVerifyList.add(cCheck6.toBytes());

			final ListData cVerifyData = new ListData(cVerifyList);
			final byte[] cVerify = crypto.getHash(cVerifyData.toBytes());

			if (!Arrays.equals(c, cVerify)) {
				LOG.error("failed to verify PI_3_U: c");
				if (!sharedMemory.passVerification) {
					return false;
				}
			}
			LOG.debug("SUCCESS: Verified PI_3_U");
			// Store the transcript ((r, D, E), F, J), saving any previous value.
			// r has already been stored when generated above.
			validatorData.D_last = validatorData.D;
			validatorData.E_last = validatorData.E;
			validatorData.F_last = validatorData.F;	
			validatorData.J_last = validatorData.J;

			validatorData.D = D;
			validatorData.E = E;
			validatorData.F = F;
			validatorData.J = J;

			return true;
		}
	}

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPValidationStates.class);
}
