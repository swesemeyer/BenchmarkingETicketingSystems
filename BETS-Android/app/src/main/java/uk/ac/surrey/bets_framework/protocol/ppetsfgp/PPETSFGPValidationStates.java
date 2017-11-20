/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp;

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
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.UserData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * Ticket validation and double spend detection states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPValidationStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPValidationStates.class);

  /**
   * State 9.
   */
  public static class VState09 extends NFCAndroidState {

    /**
     * Generates the ticket transcript data.
     *
     * @param data The data received from the validator.
     * @return The ticket transcript response data.
     */
    private byte[] generateTicketTranscript(byte[] data) {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 1) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      final BigInteger r = new BigInteger(listData.getList().get(0));

      // Select random pi, lambda, x_bar_u, s_bar_u, pi_bar, lambda_bar,
      // pi_bar_dash, lambda_bar_dash, omega_bar_u, d_bar_u
      final BigInteger pi = crypto.secureRandom(sharedMemory.p);
      final BigInteger lambda = crypto.secureRandom(sharedMemory.p);
      final BigInteger x_bar_u = crypto.secureRandom(sharedMemory.p);
      final BigInteger s_bar_u = crypto.secureRandom(sharedMemory.p);
      final BigInteger pi_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger pi_bar_dash = crypto.secureRandom(sharedMemory.p);
      final BigInteger lambda_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger omega_bar_u = crypto.secureRandom(sharedMemory.p);
      final BigInteger d_bar_u = crypto.secureRandom(sharedMemory.p);

      // Select random M_3_U
      final Element M_3_U = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

      // Compute:
      // D = g^s_u
      // D_bar = g^s_bar_u
      final BigInteger s_uNum = new BigInteger(1, userData.s_u).mod(sharedMemory.p);
      final Element D = sharedMemory.g.mul(s_uNum).getImmutable();
      final Element D_bar = sharedMemory.g.mul(s_bar_u).getImmutable();

      // Compute:
      // E = xi^x_u * g_s^(r*s_u)
      // E_bar = xi^x_bar_u * g_2^(r*s_bar_u)
      // F = T_U * theta^pi
      final Element E = sharedMemory.xi.mul(userData.x_u).add(sharedMemory.g_n[2].mul(r.multiply(s_uNum).mod(sharedMemory.p)))
              .getImmutable();
      final Element E_bar = sharedMemory.xi.mul(x_bar_u).add(sharedMemory.g_n[2].mul(r.multiply(s_bar_u).mod(sharedMemory.p)))
              .getImmutable();
      final Element F = userData.T_U.add(sharedMemory.theta.mul(pi)).getImmutable();

      // Compute:
      // J = g^pi * theta^lambda
      // J_bar = g^pi_bar * theta^lambda_bar
      // J_dash = J^omega_u
      // J_bar_dash = J^omega_bar_u
      final Element J = (sharedMemory.g.mul(pi).add(sharedMemory.theta.mul(lambda))).getImmutable();
      final Element J_bar = ((sharedMemory.g.mul(pi_bar)).add(sharedMemory.theta.mul(lambda_bar))).getImmutable();
      final Element J_dash = J.mul(userData.omega_u).getImmutable();
      final Element J_bar_dash = J.mul(omega_bar_u).getImmutable();

      // Compute:
      // R = e(F,Y_S) / e(g_0,rho)
      // R_bar = e(xi,rho)^x_bar_u * e(g_1,rho)^d_bar_u * e(g_2,rho)^s_bar_u *
      // e(F,rho)^-omega_bar_u * e(theta,rho)^pi_bar_dash *
      // e(theta,rho)^pi_bar
      final Element R = sharedMemory.pairing.pairing(F, userData.Y_S)
              .div(sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.rho)).getImmutable();
      final Element R_bar1 = sharedMemory.pairing.pairing(sharedMemory.xi, sharedMemory.rho).pow(x_bar_u).getImmutable();
      final Element R_bar2 = sharedMemory.pairing.pairing(sharedMemory.g_n[1], sharedMemory.rho).pow(d_bar_u).getImmutable();
      final Element R_bar3 = sharedMemory.pairing.pairing(sharedMemory.g_n[2], sharedMemory.rho).pow(s_bar_u).getImmutable();
      final Element R_bar4 = sharedMemory.pairing.pairing(F, sharedMemory.rho).pow(omega_bar_u.negate().mod(sharedMemory.p))
              .getImmutable();
      final Element R_bar5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.rho).pow(pi_bar_dash).getImmutable();
      final Element R_bar6 = sharedMemory.pairing.pairing(sharedMemory.theta, userData.Y_S).pow(pi_bar).getImmutable();
      final Element R_bar = R_bar1.mul(R_bar2).mul(R_bar3).mul(R_bar4).mul(R_bar5).mul(R_bar6).getImmutable();

      // Compute c = H(M_3_U || D || E || J || J_dash || R || D_bar || E_bar
      // || J_bar || J_bar_dash || R_dash)
      final ListData cData = new ListData(Arrays.asList(M_3_U.toBytes(), D.toBytes(), E.toBytes(), J.toBytes(), J_dash.toBytes(),
              R.toBytes(), D_bar.toBytes(), E_bar.toBytes(), J_bar.toBytes(), J_bar_dash.toBytes(), R_bar.toBytes()));
      final byte[] c = crypto.getHash(cData.toBytes());
      final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);

      // Compute:
      // s_BAR_u = s_bar_u - c*s_u
      // x_BAR_u = x_bar_u - c*x_u
      // s_hat_u = r*s_bar_u - c*r*s_u

      // d_BAR_u = d_bar_u – c*d_u
      // pi_BAR = pi_bar - c*pi
      // pi_BAR_dash = pi_bar_dash - c*pi
      // lambda_BAR = lambda_bar - c*lambda
      // omega_BAR_u = omega_bar_u - c*omega_u
      final BigInteger s_BAR_u = s_bar_u.subtract(cNum.multiply(s_uNum)).mod(sharedMemory.p);
      final BigInteger x_BAR_u = x_bar_u.subtract(cNum.multiply(userData.x_u)).mod(sharedMemory.p);
      final BigInteger s_hat_u = r.multiply(s_bar_u).subtract(cNum.multiply(r).multiply(s_uNum)).mod(sharedMemory.p);
      final BigInteger pi_BAR = pi_bar.subtract(cNum.multiply(pi)).mod(sharedMemory.p);
      final BigInteger lambda_BAR = lambda_bar.subtract(cNum.multiply(lambda)).mod(sharedMemory.p);
      final BigInteger omega_BAR_u = omega_bar_u.subtract(cNum.multiply(userData.omega_u)).mod(sharedMemory.p);
      final BigInteger pi_BAR_dash = pi_bar_dash.subtract(cNum.multiply(pi).multiply(userData.omega_u)).mod(sharedMemory.p);
      final BigInteger d_BAR_u = d_bar_u.subtract(cNum.multiply(userData.d_u)).mod(sharedMemory.p);

      // Sends M_3_U, D, E, F, J, J_dash, R, c, s_BAR_u, x_BAR_u, s_hat_u,
      // pi_BAR, lambda_BAR, omega_BAR_u, pi_BAR_dash, d_BAR_u
      final ListData sendData = new ListData(
              Arrays.asList(M_3_U.toBytes(), D.toBytes(), E.toBytes(), F.toBytes(), J.toBytes(), J_dash.toBytes(), R.toBytes(), c,
                      s_BAR_u.toByteArray(), x_BAR_u.toByteArray(), s_hat_u.toByteArray(), pi_BAR.toByteArray(), lambda_BAR.toByteArray(),
                      omega_BAR_u.toByteArray(), pi_BAR_dash.toByteArray(), d_BAR_u.toByteArray(), userData.Y_S.toBytes()));
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
        if (message.getData() != null) {
          // Start the timing block.
          this.startTiming(PPETSFGPSharedMemory.TIMING_NAME);

          // Do the time critical stuff.
          byte[] data = this.generateTicketTranscript(message.getData());

          // Stop the timing block.
          this.stopTiming(PPETSFGPSharedMemory.TIMING_NAME);

          if (data != null) {
            LOG.debug("generate ticket transcript complete");

            // Save the data for the corresponding GET.
            ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = data;
            return new Action<>(Action.Status.END_SUCCESS, 10, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 10.
   */
  public static class VState10 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Send back the delayed response if we have a GET.
        if (message.getData() == null) {
          byte[] data = ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse;
          ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = null;

          if (data != null) {
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);

            // Continue but allowing another ticket to be validated by returning to state 9.
            return new Action<>(Action.Status.END_SUCCESS, 9, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
