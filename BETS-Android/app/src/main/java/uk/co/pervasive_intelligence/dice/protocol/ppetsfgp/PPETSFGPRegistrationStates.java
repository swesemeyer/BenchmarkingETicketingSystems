/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidState;
import uk.co.pervasive_intelligence.dice.protocol.data.Data;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.SellerData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.UserData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;

/**
 * Registration states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPRegistrationStates {

  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPRegistrationStates.class);

  /**
   * State 2.
   */
  public static class RState02 extends NFCAndroidState {

    /**
     * Generates the seller identity data.
     *
     * @return The seller identity response data.
     */
    private byte[] generateSellerIdentity() {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
      final Crypto crypto = Crypto.getInstance();

      final CurveElement<?, ?> rho = sharedMemory.rho;

      // Calculate Y_S. Note that x_s has already been obtained.
      sellerData.Y_S = rho.mul(sellerData.x_s).getImmutable();

      // Compute proof PI_1_S = (c, s, M_1_S, Y_S):
      final BigInteger t_s = crypto.secureRandom(sharedMemory.p);
      final Element M_1_S = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

      final CurveElement<?, ?> T_s = rho.mul(t_s);
      final ListData cData = new ListData(Arrays.asList(M_1_S.toBytes(), sellerData.Y_S.toBytes(), T_s.toBytes()));
      final byte[] c = crypto.getHash(cData.toBytes());
      final BigInteger cNum = (new BigInteger(1, c)).mod(sharedMemory.p);

      final BigInteger s = (t_s.subtract(cNum.multiply(sellerData.x_s))).mod(sharedMemory.p);

      // Send ID_S, PI_1_S (which includes Y_S).
      final ListData sendData = new ListData(
              Arrays.asList(SellerData.ID_S, M_1_S.toBytes(), sellerData.Y_S.toBytes(), c, s.toByteArray()));

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
      // Clear out shared memory as we are starting again.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.SELLER);

      if (message.getType() == Message.Type.DATA) {
        // Send back the seller identity data.
        if (message.getData() == null) {
          byte[] data = this.generateSellerIdentity();

          if (data != null) {
            LOG.debug("generate seller identity complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 3, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 3.
   */
  public static class RState03 extends NFCAndroidState {

    /**
     * Verifies the returned seller's credential data.
     *
     * @return True if the verification is successful.
     */
    private boolean verifySellerCredentials(byte[] data) {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      final BigInteger c_s = new BigInteger(listData.getList().get(0));
      final BigInteger r_s = new BigInteger(listData.getList().get(1));
      final Element delta_S = sharedMemory.curveElementFromBytes(listData.getList().get(2));

      // Verify e(delta_S, g_bar g^c_s) = e(g_0, g) e(Y_S, g) e(g, g_frac)^r_s
      final Element left = sharedMemory.pairing.pairing(delta_S, sharedMemory.g_bar.add(sharedMemory.g.mul(c_s)));
      final Element right1 = sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g);
      final Element right2 = sharedMemory.pairing.pairing(sellerData.Y_S, sharedMemory.g);
      final Element right3 = sharedMemory.pairing.pairing(sharedMemory.g, sharedMemory.g_frak).pow(r_s);

      final Element RHS = right1.mul(right2).mul(right3);
      if (!left.equals(RHS)) {
        LOG.error("invalid seller credentials");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: passed verification of seller credentials");
      // Keep the credentials.
      sellerData.c_s = c_s;
      sellerData.r_s = r_s;
      sellerData.delta_S = delta_S;
      LOG.debug("Seller.delta_S=" + sellerData.delta_S);

      return true;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Verify the seller's credentials.
        if (message.getData() != null) {
          if (this.verifySellerCredentials(message.getData())) {
            LOG.debug("verify seller credentials complete");
            return new Action<>(Action.Status.END_SUCCESS, 4, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 4.
   */
  public static class RState04 extends NFCAndroidState {

    /**
     * Generates the user identity data.
     *
     * @return The user identity response data.
     */
    private byte[] generateUserIdentity() {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Select random x_u and compute Y_U = xi^x_u
      userData.x_u = crypto.secureRandom(sharedMemory.p);
      userData.Y_U = sharedMemory.xi.mul(userData.x_u);

      // Select random r and compute R = g_frak^r
      userData.r = crypto.secureRandom(sharedMemory.p);
      LOG.debug("r: " + userData.r);
      final Element R = sharedMemory.g_frak.mul(userData.r).getImmutable();

      // Compute proof PI_1_U = (M_1_U, Y_U, R, Y_dash_U, R_dash, c_1, c_2,
      // s_1, s_2):
      final BigInteger x_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_bar = crypto.secureRandom(sharedMemory.p);
      final Element M_1_U = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

      final Element Y_dash_U = sharedMemory.xi.mul(x_bar).getImmutable();
      final Element R_dash = sharedMemory.g_frak.mul(r_bar).getImmutable();

      final ListData c_1Data = new ListData(Arrays.asList(M_1_U.toBytes(), userData.Y_U.toBytes(), Y_dash_U.toBytes()));
      final byte[] c_1 = crypto.getHash(c_1Data.toBytes());
      final BigInteger c_1Num = new BigInteger(1, c_1);

      final ListData c_2Data = new ListData(Arrays.asList(M_1_U.toBytes(), R.toBytes(), R_dash.toBytes()));
      final byte[] c_2 = crypto.getHash(c_2Data.toBytes());
      final BigInteger c_2Num = new BigInteger(1, c_2);

      final BigInteger s_1 = (x_bar.subtract(c_1Num.multiply(userData.x_u))).mod(sharedMemory.p);
      final BigInteger s_2 = r_bar.subtract(c_2Num.multiply(userData.r)).mod(sharedMemory.p);

      // Send ID_U, A_U, PI_1_U (which includes Y_U, R).
      final List<byte[]> list = new ArrayList<>();
      // TODO: do not send Y_dash_U and R_dash as they are not needed.
      list.addAll(Arrays.asList(UserData.ID_U, M_1_U.toBytes(), userData.Y_U.toBytes(), R.toBytes(), Y_dash_U.toBytes(),
              R_dash.toBytes(), c_1, c_2, s_1.toByteArray(), s_2.toByteArray()));
      for (final BigInteger attribute : UserData.A_U_range) {
        list.add(attribute.toByteArray());
      }
      for (final String attribute : UserData.A_U_set) {
        try {
          list.add(attribute.getBytes(Data.UTF8));
        }
        catch (final UnsupportedEncodingException e) {
          // Ignore.
        }
      }

      final ListData sendData = new ListData(list);
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
        // Send back the user identity data.
        if (message.getData() == null) {
          byte[] data = this.generateUserIdentity();

          if (data != null) {
            LOG.debug("generate user identity complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 5, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 5.
   */
  public static class RState05 extends NFCAndroidState {

    /**
     * Verifies the returned user's credential data.
     *
     * @return True if the verification is successful.
     */
    private boolean verifyUserCredentials(byte[] data) {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        if (!sharedMemory.passVerification) {
          return false;
        }
      }

      final BigInteger c_u = new BigInteger(listData.getList().get(0));
      final BigInteger r_dash = new BigInteger(listData.getList().get(1));
      final Element delta_U = sharedMemory.curveElementFromBytes(listData.getList().get(2));
      // Compute r_u.
      final BigInteger r_u = userData.r.add(r_dash).mod(sharedMemory.p);

      // Verify e(delta_U, g_bar g^c_u) = e(g_0, g) e(xi, g) e(g_frac, g)^r_u
      final Element left = sharedMemory.pairing.pairing(delta_U, sharedMemory.g_bar.add(sharedMemory.g.mul(c_u)));
      final Element right1 = sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g);
      // error in paper should be Y_U and not xi
      final Element right2 = sharedMemory.pairing.pairing(userData.Y_U, sharedMemory.g);
      final Element right3 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_u);
      Element product1 = sharedMemory.pairing.getGT().newOneElement().getImmutable();
      for (int i = 0; i < sharedMemory.N1(); i++) {
        final Element value = sharedMemory.pairing.pairing(sharedMemory.g_hat_n[i], sharedMemory.g).pow(UserData.A_U_range[i])
                .getImmutable();
        product1 = product1.mul(value);
      }
      product1 = product1.getImmutable();

      Element product2 = sharedMemory.pairing.getGT().newOneElement().getImmutable();
      try {
        for (int i = 0; i < sharedMemory.N2(); i++) {
          final byte[] hash = crypto.getHash(UserData.A_U_set[i].getBytes(Data.UTF8));
          final BigInteger hashNum = new BigInteger(1, hash).mod(sharedMemory.p);
          final Element value = sharedMemory.pairing.pairing(sharedMemory.eta_n[i], sharedMemory.g).pow(hashNum).getImmutable();
          product2 = product2.mul(value);
        }
      }
      catch (final UnsupportedEncodingException e) {
        // something odd happened - we terminate gracefully
        LOG.debug("UnsupportedEncodingException happened: " + e);
        return false;
      }

      // Element RHS = right1.mul(right2).mul(right3).mul(product1).mul(product2);
      final Element RHS = right1.mul(right2).mul(right3).mul(product1).mul(product2);
      if (!left.isEqual(RHS)) {
        LOG.error("invalid user credentials");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: Verified user credentials:...");
      // Keep the credentials.
      userData.c_u = c_u;
      userData.r_u = r_u;
      userData.delta_U = delta_U;
      return true;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Verify the user's credentials.
        if (message.getData() != null) {
          if (this.verifyUserCredentials(message.getData())) {
            LOG.debug("verify user credentials complete");
            return new Action<>(Action.Status.END_SUCCESS, 6, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
