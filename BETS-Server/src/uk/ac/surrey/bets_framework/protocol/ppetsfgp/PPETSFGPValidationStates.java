/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
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
      final ListData sendData = new ListData(Arrays.asList(r.toByteArray()));
      return sendData.toBytes();
    }

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
     * @param message The received message to process.
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

      // Here we do not (and cannot since it requires the private x_u) E^r_dash/E_dash^r and Y_U, as we just compare the stored
      // ticket transcript.
      return validatorData.D.isEqual(validatorData.D_last) && !validatorData.E.isEqual(validatorData.E_last);
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
        // Verify the ticket proof
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

      if (listData.getList().size() != 17) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      int index = 0;
      final Element M_3_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final Element D = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
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
      final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(index++));

      // Verify c.
      final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);
      final List<byte[]> cVerifyList = new ArrayList<>();
      cVerifyList.addAll(Arrays.asList(M_3_U.toBytes(), D.toBytes(), E.toBytes(), J.toBytes(), J_dash.toBytes(), R.toBytes()));

      // Verify D_bar
      final Element cCheck1 = sharedMemory.g.mul(s_BAR_u).add(D.mul(cNum));
      cVerifyList.add(cCheck1.toBytes());

      // Verify E_bar
      final Element cCheck2 = sharedMemory.xi.mul(x_BAR_u).add(sharedMemory.g_n[2].mul(s_hat_u)).add(E.mul(cNum));
      cVerifyList.add(cCheck2.toBytes());

      // Verify J_bar
      final Element cCheck3 = ((sharedMemory.g.mul(pi_BAR)).add(sharedMemory.theta.mul(lambda_BAR))).add(J.mul(cNum));
      cVerifyList.add(cCheck3.toBytes());

      // Verify J_bar_dash
      final Element cCheck4 = J.mul(omega_BAR_u).add(J_dash.mul(cNum));
      cVerifyList.add(cCheck4.toBytes());

      final Element cCheck5_1 = sharedMemory.pairing.pairing(sharedMemory.xi, sharedMemory.rho).pow(x_BAR_u);
      final Element cCheck5_2 = sharedMemory.pairing.pairing(sharedMemory.g_n[1], sharedMemory.rho).pow(d_BAR_u);
      final Element cCheck5_3 = sharedMemory.pairing.pairing(sharedMemory.g_n[2], sharedMemory.rho).pow(s_BAR_u);
      final Element cCheck5_4 = sharedMemory.pairing.pairing(F, sharedMemory.rho).pow(omega_BAR_u.negate().mod(sharedMemory.p));
      final Element cCheck5_5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.rho).pow(pi_BAR_dash);
      final Element cCheck5_6 = sharedMemory.pairing.pairing(sharedMemory.theta, Y_S).pow(pi_BAR).mul(R.pow(cNum));
      final Element cCheck5 = cCheck5_1.mul(cCheck5_2).mul(cCheck5_3).mul(cCheck5_4).mul(cCheck5_5).mul(cCheck5_6);
      cVerifyList.add(cCheck5.toBytes());

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
