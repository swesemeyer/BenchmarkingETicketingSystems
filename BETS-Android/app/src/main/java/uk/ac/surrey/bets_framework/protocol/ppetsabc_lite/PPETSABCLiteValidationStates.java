/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsabc_lite;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.ppetsabc.PPETSABCSharedMemory;
import uk.ac.surrey.bets_framework.protocol.ppetsabc.PPETSABCSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsabc.data.UserData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * Ticket validation and double spend detection states of the PPETS-ABC state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSABCLiteValidationStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSABCLiteValidationStates.class);

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
      final PPETSABCSharedMemory sharedMemory = (PPETSABCSharedMemory) this.getSharedMemory();
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

      // Sends Trans_T = (PI^3_U, s_u, psi_u, omega_u. T_U, P_U, Price, Service, VP_T, PS_U) where
      // PI^3_U=M_3_U, Y, c, pi_BAR, lambda_BAR, Y_S (as the verifier does not have
      // Y_S)

      final ListData sendData = new ListData(Arrays.asList(M_3_U.toBytes(), userData.Y.toBytes(), c,
              pi_BAR.toByteArray(), lambda_BAR.toByteArray(), userData.Y_S.toBytes(), userData.s_u.toByteArray(),
              userData.psi_uNum.toByteArray(), userData.omega_u.toByteArray(), userData.T_U.toBytes(),
              sharedMemory.stringToBytes(userData.P_U), userData.price,
              userData.service, sharedMemory.stringToBytes(userData.VP_T), userData.PS_U.toBytes()));
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
      ((PPETSABCSharedMemory) this.getSharedMemory()).actAs(Actor.USER);

      if (message.getType() == Message.Type.DATA) {
        // Generate the ticket transcript.
        if (message.getData() == null) {
          // Start the timing block.
          this.startTiming(PPETSABCSharedMemory.TIMING_NAME);

          // Do the time critical stuff.
          byte[] data = this.generateTicketTranscript();

          // Stop the timing block.
          this.stopTiming(PPETSABCSharedMemory.TIMING_NAME);

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
