/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.SellerData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Registration states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPRegistrationStates {

  /**
   * State 4.
   */
  public static class RState04 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message
     *          The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);

      // Get the seller identity data.
      return new Action<>(Status.CONTINUE, 5, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 5.
   */
  public static class RState05 extends State<NFCReaderCommand> {

    /**
     * Generates the seller's credentials.
     *
     * @param data
     *          The data received from the seller.
     * @return The seller's credential data.
     */
    private byte[] generateSellerCredentials(byte[] data) {
      // Note that all elliptic curve calculations are in an additive
      // group such that * -> + and ^ -> *.
      final Crypto crypto = Crypto.getInstance();
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();

      final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 5) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      // ID_S not used.
      final Element M_1_S = sharedMemory.curveElementFromBytes(listData.getList().get(1));
      final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(2));
      final byte[] c = listData.getList().get(3);
      final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);
      final BigInteger s = new BigInteger(listData.getList().get(4));

      // Verify PI_1_S via c.
      final Element check = sharedMemory.rho.mul(s).add(Y_S.mul(cNum));
      final ListData cVerifyData = new ListData(Arrays.asList(M_1_S.toBytes(), Y_S.toBytes(), check.toBytes()));
      final byte[] cVerify = crypto.getHash(cVerifyData.toBytes());
      if (!Arrays.equals(c, cVerify)) {
        LOG.error("failed to verify PI_1_S");
        if (!sharedMemory.passVerification) {
          return null;
        }
      }
      LOG.debug("SUCCESS: passed verification of PI_1_S");
      // Select random c_s and r_s.
      final BigInteger c_s = crypto.secureRandom(sharedMemory.p).mod(sharedMemory.p);
      final BigInteger r_s = crypto.secureRandom(sharedMemory.p).mod(sharedMemory.p);

      // Compute delta_S:
      //
      // delta_s = (g_0 Ys g_frak^r_s) ^ 1/(x+c_s) is equivalent to
      // delta_s = (g_0 + Ys + r_s * g_frak) / (x+c_s).
      //
      // However, we cannot calculate 1 / (x+c_s) directly, but we can use
      // the extended GCD algorithm assuming we are working in a
      // group with order p which is prime.
      //
      // If d = (1/a) * P = k * P for some k in Z_p
      //
      // Since p is prime, the GCD of a and p is 1, and hence we can find
      // m and n such that:
      //
      // a*m + p*n = 1
      //
      // and
      //
      // d = (1/a) * P
      // = (1/a) * 1 * P
      // = (1/a) * (a*m + p*n) * P
      // = (a*m*P/a) + (P*p*n/a)
      // = m*P + k*P*p*n since (1/a) * P = k * P
      // = m*P since p*P = 0
      //
      // Therefore d = (1/a) * P = k * P = m * P and hence k = m
      //
      // We can use the extended Euclidean algorithm to compute:
      //
      // a*m + p*n = gcd(a, p) = 1
      //
      // Since (1/a) * P = m*P, and we have m from above, then we know d.

      final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x.add(c_s).mod(sharedMemory.p), sharedMemory.p);
      final CurveElement<?, ?> delta_S = (CurveElement<?, ?>) sharedMemory.g_n[0].add(Y_S).add(sharedMemory.g_frak.mul(r_s))
          .mul(gcd.x.mod(sharedMemory.p)).getImmutable();

      // Store the seller credentials for later use when we are the
      // seller.
      sharedMemory.actAs(Actor.SELLER);
      final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
      sellerData.Y_S = Y_S;
      sellerData.c_s = c_s;
      sellerData.r_s = r_s;
      sellerData.delta_S = delta_S;
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);

      // Send c_s, r_s, delta_S.
      final ListData sendData = new ListData(Arrays.asList(c_s.toByteArray(), r_s.toByteArray(), delta_S.toBytes()));
      return sendData.toBytes();

    }

    /**
     * Gets the required action given a message.
     *
     * @param message
     *          The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Generate the seller credentials and send it back.
        final byte[] data = this.generateSellerCredentials(message.getData());

        if (data != null) {
          LOG.debug("generate seller credentials complete");
          return new Action<>(Status.CONTINUE, 6, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 6.
   */
  public static class RState06 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message
     *          The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the user identity data.
        return new Action<>(Status.CONTINUE, 7, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 7.
   */
  public static class RState07 extends State<NFCReaderCommand> {

    /**
     * Generates the user's credentials.
     *
     * @param data
     *          The data received from the user.
     * @return The user's credential data.
     */
    private byte[] generateUserCredentials(byte[] data) {
      // Note that all elliptic curve calculations are in an additive
      // group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() < 11) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      int index = 0;
      final byte[] ID_U = listData.getList().get(index++);
      final Element M_1_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final Element Y_U = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      final Element R = sharedMemory.curveElementFromBytes(listData.getList().get(index++));
      // TODO: do not send the following two...
      index++; // Ignore Y_dash_U
      index++; // Ignore R_dash
      final byte[] c_1 = listData.getList().get(index++);
      final BigInteger c_1Num = new BigInteger(1, c_1).mod(sharedMemory.p);
      final byte[] c_2 = listData.getList().get(index++);
      final BigInteger c_2Num = new BigInteger(1, c_2).mod(sharedMemory.p);
      final BigInteger s_1 = new BigInteger(listData.getList().get(index++));
      final BigInteger s_2 = new BigInteger(listData.getList().get(index++));

      final BigInteger[] A_U_range = new BigInteger[sharedMemory.N1()];
      for (int i = 0; i < sharedMemory.N1(); i++) {
        A_U_range[i] = new BigInteger(listData.getList().get(index++));
      }

      final String[] A_U_set = new String[sharedMemory.N2()];
      for (int i = 0; i < sharedMemory.N2(); i++) {
        A_U_set[i] = new String(listData.getList().get(index++));
      }

      // Verify PI_1_U via c_1 and c_2.
      LOG.debug("Verifying PI_1_U c1:...");
      final Element check1 = sharedMemory.xi.mul(s_1).add(Y_U.mul(c_1Num));
      final ListData c_1VerifyData = new ListData(Arrays.asList(M_1_U.toBytes(), Y_U.toBytes(), check1.toBytes()));
      final byte[] c_1Verify = crypto.getHash(c_1VerifyData.toBytes());

      if (!Arrays.equals(c_1, c_1Verify)) {
        LOG.error("failed to verify PI_1_U: c_1");
        return null;

      }
      LOG.debug("SUCCESS: Verified PI_1_U c1:...");

      LOG.debug("Verifying PI_1_U c2:...");
      final Element check2 = sharedMemory.g_frak.mul(s_2).add(R.mul(c_2Num));
      final ListData c_2VerifyData = new ListData(Arrays.asList(M_1_U.toBytes(), R.toBytes(), check2.toBytes()));
      final byte[] c_2Verify = crypto.getHash(c_2VerifyData.toBytes());

      if (!Arrays.equals(c_2, c_2Verify)) {
    	  LOG.error("failed to verify PI_1_U: c_2");
    	  return null;

      }

      LOG.debug("SUCCESS: Verified PI_1_U c2:...");

      // Select random c_u and r_dash.
      final BigInteger c_u = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_dash = crypto.secureRandom(sharedMemory.p);

      // Compute delta_U using the same GCD approach from above.
      final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x.add(c_u).mod(sharedMemory.p), sharedMemory.p);

      Element sum1 = sharedMemory.pairing.getG1().newZeroElement();
      for (int i = 0; i < sharedMemory.N1(); i++) {
        final Element value = sharedMemory.g_hat_n[i].mul(A_U_range[i]).getImmutable();
        sum1 = sum1.add(value);
      }
      sum1 = sum1.getImmutable();

      Element sum2 = sharedMemory.pairing.getG1().newZeroElement();
      ;
      for (int i = 0; i < sharedMemory.N2(); i++) {
        final byte[] hash = crypto.getHash(A_U_set[i].getBytes());
        final BigInteger hashNum = new BigInteger(1, hash).mod(sharedMemory.p);
        final Element value = sharedMemory.eta_n[i].mul(hashNum).getImmutable();
        sum2 = sum2.add(value);
      }
      sum2 = sum2.getImmutable();

      Element delta_U = sharedMemory.g_n[0].add(Y_U).add(R).add(sharedMemory.g_frak.mul(r_dash).add(sum1).add(sum2)).getImmutable();
      delta_U = delta_U.mul(gcd.x.mod(sharedMemory.p));

      // Store ID_U, A_U, Y_U and delta_U.
      centralAuthorityData.ID_U = ID_U;
      centralAuthorityData.A_U_range = A_U_range;
      centralAuthorityData.A_U_set = A_U_set;
      centralAuthorityData.Y_U = Y_U;
      centralAuthorityData.delta_U = delta_U;

      // Send c_u, r_dash, delta_U.

      final ListData sendData = new ListData(Arrays.asList(c_u.toByteArray(), r_dash.toByteArray(), delta_U.toBytes()));
      return sendData.toBytes();

    }

    /**
     * Gets the required action given a message.
     *
     * @param message
     *          The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Generate the user credentials and send it back.
        final byte[] data = this.generateUserCredentials(message.getData());

        if (data != null) {
          LOG.debug("generate user credentials complete");
          return new Action<>(Status.CONTINUE, 8, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPRegistrationStates.class);

}
