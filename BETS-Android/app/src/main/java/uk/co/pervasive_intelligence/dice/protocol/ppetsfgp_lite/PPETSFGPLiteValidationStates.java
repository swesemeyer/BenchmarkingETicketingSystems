/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp_lite;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidState;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.UserData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;

/**
 * Ticket validation and double spend detection states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPLiteValidationStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPLiteValidationStates.class);

  /**
   * State 9.
   */
  public static class VState09 extends NFCAndroidState {

    /**
     * Generates the ticket transcript data.
     *
     * @return The ticket transcript response data.
     */
    private byte[] generateTicketTranscript() {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Select random pi, lambda
      final BigInteger pi = crypto.secureRandom(sharedMemory.p);
      final BigInteger lambda = crypto.secureRandom(sharedMemory.p);

      // Select random M_3_U
      final Element M_3_U = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

      // Compute Y_dash = xi^pi * g_1^lambda
      final Element Y_dash = sharedMemory.xi.mul(pi).add(sharedMemory.g_n[1].mul(lambda)).getImmutable();

      // Compute c = H(M_3_U || Y || Y_dash)
      final ListData cData = new ListData(Arrays.asList(M_3_U.toBytes(), userData.Y.toBytes(), Y_dash.toBytes()));
      final byte[] c = crypto.getHash(cData.toBytes());
      final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);

      // Compute:
      // pi_BAR = pi - c*x_u
      // lambda_BAR = lambda - c*d
      final BigInteger pi_BAR = pi.subtract(cNum.multiply(userData.x_u)).mod(sharedMemory.p);
      final BigInteger lambda_BAR = lambda.subtract(cNum.multiply(userData.d)).mod(sharedMemory.p);

      // Sends Ticket_U = (T_U, Time, Service, Price, Valid_Period), M_3_U, Y, Y_S, omega_u, c, pi_BAR, lambda_BAR
      final ListData sendData = new ListData(Arrays.asList(userData.T_U.toBytes(), userData.time, userData.service, userData
          .price, userData.validPeriod, M_3_U.toBytes(), userData.Y.toBytes(), userData.Y_S.toBytes(), userData.omega_u
          .toByteArray(), userData.d_dash.toByteArray(), c, pi_BAR.toByteArray(), lambda_BAR.toByteArray()));
      return sendData.toBytes();
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      // We are now the user.
      ((PPETSFGPSharedMemory) this.getSharedMemory()).actAs(Actor.USER);

      if (message.getType() == Message.Type.DATA) {
        // Generate the ticket transcript.
        if (message.getData() == null) {
          // Start the timing block.
          this.startTiming(PPETSFGPSharedMemory.TIMING_NAME);

          // Do the time critical stuff.
          byte[] data = this.generateTicketTranscript();

          // Stop the timing block.
          this.stopTiming(PPETSFGPSharedMemory.TIMING_NAME);

          if (data != null) {
            LOG.debug("generate ticket transcript complete");

            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);

            // Continue but allowing another ticket to be validated by staying in the current state.
            return new Action<>(Action.Status.END_SUCCESS, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
