/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp_lite;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.ValidatorData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

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

      if (listData.getList().size() != 13) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      int index = 0;
      final Element T_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final byte[] time = listData.getList().get(index++);
      final byte[] service = listData.getList().get(index++);
      final byte[] price = listData.getList().get(index++);
      final byte[] validPeriod = listData.getList().get(index++);
      final Element M_3_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final Element Y = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final BigInteger omega_u = new BigInteger(listData.getList().get(index++));
      final BigInteger d_dash = new BigInteger(listData.getList().get(index++));
      final byte[] c = listData.getList().get(index++);
      final BigInteger pi_BAR = new BigInteger(listData.getList().get(index++));
      final BigInteger lambda_BAR = new BigInteger(listData.getList().get(index++));

      // Verify c.
      final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);
      final List<byte[]> cVerifyList = new ArrayList<>();
      cVerifyList.addAll(Arrays.asList(M_3_U.toBytes(), Y.toBytes()));

      final Element cCheck = sharedMemory.xi.mul(pi_BAR).add(sharedMemory.g_n[1].mul(lambda_BAR)).add(Y.mul(cNum)).getImmutable();
      cVerifyList.add(cCheck.toBytes());

      final ListData cVerifyData = new ListData(cVerifyList);
      final byte[] cVerify = crypto.getHash(cVerifyData.toBytes());

      if (!Arrays.equals(c, cVerify)) {
        LOG.error("failed to verify PI_3_U: c");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: verify PI_3_U: c" );

      // Compute s_u = H(Y || Time || Service || Price || Valid_Period)
      final ListData s_uData = new ListData(Arrays.asList(Y.toBytes(), time, service, price, validPeriod));
      final byte[] s_u = crypto.getHash(s_uData.toBytes());
      final BigInteger s_uNum = new BigInteger(1, s_u);

      // Check that e(T_U, Y_S * rho^omega_u) = e(g_0 * Y * g_1^d_dash * g_2^s_u, rho)
      final Element left = sharedMemory.pairing.pairing(T_U, Y_S.add(sharedMemory.rho.mul(omega_u))).getImmutable();
      final Element right = sharedMemory.pairing.pairing(
          sharedMemory.g_n[0].add(Y).add(sharedMemory.g_n[1].mul(d_dash)).add(sharedMemory.g_n[2].mul(s_uNum)), sharedMemory.rho);

      if (!left.isEqual(right)) {
        LOG.error("failed to verify e(T_U, Y_S * rho^omega_u)");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: verified e(T_U, Y_S * rho^omega_u)" );
      // Store Y, saving any previous value.
      validatorData.Y_last = validatorData.Y;
      validatorData.Y = Y;

      return true;
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPLiteValidationStates.class);
}
