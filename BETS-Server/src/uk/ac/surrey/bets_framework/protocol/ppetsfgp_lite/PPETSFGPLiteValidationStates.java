/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp_lite;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.ValidatorData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Ticket validation and double spend detection states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPLiteValidationStates {

  /**
   * State 11.
   */
  public static class VState11 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
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

        // Get the user ticket transcript.
        return new Action<>(Status.CONTINUE, 12, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 12.
   */
  public static class VState12 extends State<NFCReaderCommand> {

    /**
     * Detects if the ticket has been double spent.
     *
     * @return True if the ticket is double spent.
     */
    private boolean detectDoubleSpend() {
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);

      // Check whether the previous pseudonym is the same as the current pseudonym.
      return validatorData.Y.isEqual(validatorData.Y_last);
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Verify the ticket proof.
        if (this.verifyTicketProof(message.getData())) {
          // Detect double spend.
          final boolean doubleSpend = this.detectDoubleSpend();
          LOG.debug("ticket validation complete - double spend: " + doubleSpend);

          // Stop the timing block.
          this.stopTiming(PPETSFGPSharedMemory.TIMING_NAME);

          // If we have more iterations of ticket validation to do, then go back to the start of validation, otherwise end.
          final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();

          if (sharedMemory.numValidations > 1) {
            sharedMemory.numValidations--;
            return new Action<>(11);
          }
          else {
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
     * @param data The data received from the user.
     * @return True if the ticket proof is verified.
     */
    private boolean verifyTicketProof(byte[] data) {
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
		final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);
		final Crypto crypto = Crypto.getInstance();

		// Decode the received data.
		final ListData listData = ListData.fromBytes(data);

		if (listData.getList().size() != 15) {
			LOG.error("wrong number of data elements: " + listData.getList().size());
			return false;
		}
		// Receive Trans_T = (PI^3_U, s_u, psi_u, omega_u, T_U, P_U, Price, Service, VP_T, PS_U) where
		// PI^3_U=M_3_U, Y, c, pi_BAR, lambda_BAR, Y_S (as the verifier does not have
		// Y_S)

		int index = 0;
		final Element M_3_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
		final Element Y = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
		final byte[] c = listData.getList().get(index++);
		//turn the hash into a number
		final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);
		final BigInteger pi_BAR = new BigInteger(listData.getList().get(index++));
		final BigInteger lambda_BAR = new BigInteger(listData.getList().get(index++));
		final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
		final BigInteger s_u = new BigInteger(listData.getList().get(index++));
		final BigInteger psi_uNum = new BigInteger(listData.getList().get(index++));
		final BigInteger omega_u = new BigInteger(listData.getList().get(index++));
		final Element T_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
		final String P_U = sharedMemory.stringFromBytes(listData.getList().get(index++));
		final byte[] price = listData.getList().get(index++);
		final byte[] service = listData.getList().get(index++);
		final String VP_T = sharedMemory.stringFromBytes(listData.getList().get(index++));
		final Element PS_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));

		//Verify psi_uNum
		
		// Compute check_psi_u = H(P_U || Price || Service || Ticket Valid_Period)
		final ListData check_psi_uData = new ListData(
				Arrays.asList(sharedMemory.stringToBytes(P_U), price,
						service, sharedMemory.stringToBytes(VP_T)));
		final byte[] check_psi_u = crypto.getHash(check_psi_uData.toBytes());
		final BigInteger check_psi_uNum = new BigInteger(1, check_psi_u).mod(sharedMemory.p);
		
		if (!psi_uNum.equals(check_psi_uNum)) {
			LOG.error("failed to verify psi_uNum");
			if (!sharedMemory.passVerification) {
				return false;
			}
		}
		LOG.debug("SUCCESS: verify psi_uNum");
		
		//Verify e(T_U,Y_S rho^omega_u)=?e(g_0, rho) e(PS_U, rho) e(g_2,rho)^s_u e(g_3,rho)^psi_u
		
		final Element LHS=sharedMemory.pairing.pairing(T_U, Y_S.add(sharedMemory.rho.mul(omega_u))).getImmutable();
		final Element RHS1=sharedMemory.pairing.pairing(sharedMemory.g_n[0],sharedMemory.rho).getImmutable();
		final Element RHS2=sharedMemory.pairing.pairing(PS_U,sharedMemory.rho).getImmutable();
		final Element RHS3=sharedMemory.pairing.pairing(sharedMemory.g_n[2],sharedMemory.rho).pow(s_u).getImmutable();
		final Element RHS4=sharedMemory.pairing.pairing(sharedMemory.g_n[3],sharedMemory.rho).pow(psi_uNum).getImmutable();
		final Element RHS=RHS1.mul(RHS2).mul(RHS3).mul(RHS4).getImmutable();

		if (!LHS.equals(RHS)) {
			LOG.error("failed to verify pairing check");
			if (!sharedMemory.passVerification) {
				return false;
			}
		}
		LOG.debug("SUCCESS: verify pairing check");

		// Verify c.
		
		final List<byte[]> cVerifyList = new ArrayList<>();
		cVerifyList.addAll(Arrays.asList(M_3_U.toBytes(), Y.toBytes()));

		final Element cCheck = sharedMemory.xi.mul(pi_BAR).add(sharedMemory.g_n[1].mul(lambda_BAR)).add(Y.mul(cNum))
				.getImmutable();
		cVerifyList.add(cCheck.toBytes());

		final ListData cVerifyData = new ListData(cVerifyList);
		final byte[] cVerify = crypto.getHash(cVerifyData.toBytes());

		if (!Arrays.equals(c, cVerify)) {
			LOG.error("failed to verify PI_3_U: c");
			if (!sharedMemory.passVerification) {
				return false;
			}
		}
		LOG.debug("SUCCESS: verify PI_3_U: c");

		// Store Y, saving any previous value.
		validatorData.Y_last = validatorData.Y;
		validatorData.Y = PS_U;

		return true;
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPLiteValidationStates.class);
}
