/**
 *
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp;

import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.Crypto.BigIntEuclidean;
import uk.co.pervasive_intelligence.dice.protocol.data.Data;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.CentralAuthorityData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.SellerData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.UserData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.ValidatorData;

/**
 * @author swesemeyer
 *
 */
public class TestPPETSFGP_Lite {

  /** Logback logger. */
  private static final Logger LOG          = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
      .getLogger("TestEllipticCurvesMaths");
  Encoder                     base64       = Base64.getEncoder();
  Crypto                      crypto;
  PPETSFGPSharedMemory        sharedMemory = null;

  @Before
  public void setUp() throws Exception {
    // set the desired log level
    LOG.setLevel(Level.DEBUG);

    LOG.debug("Starting Setup");
    crypto = Crypto.getInstance();
    sharedMemory = new PPETSFGPSharedMemory();
    sharedMemory.passVerification = false;
    sharedMemory.rBits = 256;
    sharedMemory.qBits = 512;
    sharedMemory.clearTest();
    LOG.debug("p: " + sharedMemory.pairingParameters.getBigInteger("r"));
    LOG.debug("q: " + sharedMemory.pairingParameters.getBigInteger("q"));
    LOG.debug("Size of G1=G2=GT:" + sharedMemory.pairing.getG1().getOrder() + "=" + sharedMemory.pairing.getG2().getOrder() + "="
        + sharedMemory.pairing.getGT().getOrder());
    LOG.debug("G1=?G2:" + sharedMemory.pairing.getG1().equals(sharedMemory.pairing.getG2()));

    LOG.debug("Setting up Seller:");
    sharedMemory.actAs(Actor.SELLER);
    final BigInteger x_s = crypto.secureRandom(sharedMemory.p);
    final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
    sellerData.x_s = x_s;
    LOG.debug("Seller x_s:" + sellerData.x_s);
    LOG.debug("Setup complete:");

  }

  @Test

  public void testProtocol() {
    byte[] data;
    boolean success;
    long overall_start;
    long time_start;
    long time_end;
    long durationInMS;

    // Registration States:

    LOG.info("Going through Registration states");

    // Generate Seller Identify: RState02 (Android)
    time_start = Instant.now().toEpochMilli();
    overall_start = time_start;
    sharedMemory.actAs(Actor.SELLER);
    data = this.generateSellerIdentity();
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate Seller Identify: RState02 (Android) took (ms): " + durationInMS);

    // Generates the seller's credentials: RState05 (Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
    data = this.generateSellerCredentials(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generates the seller's credentials: RState05 (Server) took (ms): " + durationInMS);
    if (data == null) {
      fail("Seller credential creation failed");
    }

    // Verify Seller credentials: RState03 (Android)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.SELLER);
    success = this.verifySellerCredentials(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Verify Seller credentials: RState03 (Android) took (ms): " + durationInMS);
    if (!success) {
      fail("Seller credentials did not validate");
    }

    // Generate the user identity data: RState04 (Android)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.USER);
    data = this.generateUserIdentity();
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate the user identity data: RState04 (Android) took (ms): " + durationInMS);

    // Generate the user's credentials: RState07 (Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
    data = this.generateUserCredentials(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate the user's credentials: RState07 (Server) took (ms): " + durationInMS);
    if (data == null) {
      fail("user credential creation failed");
    }

    // Verify the returned user's credential data:RState05 (Android)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.USER);
    success = this.verifyUserCredentials(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Verify the returned user's credential data:RState05 took (ms): " + durationInMS);
    if (!success) {
      fail("User credentials did not validate");
    }

    LOG.info("Going through Issuing states");

    // Issuing States:

    // Generate the user proof data: IState06 (Android)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.USER);
    data = this.generateUserProof();
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate the user pseudonym data: IState06 (Android) took (ms): " + durationInMS);

    // Verify the user proof: IState10 (Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.SELLER);
    success = this.verifyUserProof(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Verify the user proof: IState10 (Server) took (ms): " + durationInMS);
    if (!success) {
      fail("user proof verification failed");
    }

    // Generate ticket serial number: IState10 (Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.SELLER);
    data = this.generateTicketSerialNumber();
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate ticket serial number: IState10 (Server) took (ms): " + durationInMS);

    // Verify the returned ticket serial number data: IState08 (Android)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.USER);
    success = this.verifyTicketSerialNumber(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Verify the returned ticket serial number data: IState08 (Android) took (ms): " + durationInMS);
    if (!success) {
      fail("ticket serial number verification failed");
    }

    LOG.info("Going through Validation states");

    // Generate the validator's random number: VState1 (Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.VALIDATOR);
    data = this.generateValidatorRandomNumber();
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate the validator's random number: VState1 (Server) took (ms): " + durationInMS);

    // Generate the ticket transcript data: VState09 (Android)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.USER);
    data = this.generateTicketTranscript(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Generate the ticket transcript data: VState09 (Android) took (ms): " + durationInMS);

    // Verifies the ticket proof: VState13 (Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.VALIDATOR);
    success = this.verifyTicketProof(data);
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Verifies the ticket proof: VState13 (Server) took (ms): " + durationInMS);
    if (!success) {
      fail("ticket proof verification failed");
    }

    // Detect if the ticket has been double spent: VState13(Server)
    time_start = Instant.now().toEpochMilli();
    sharedMemory.actAs(Actor.VALIDATOR);
    success = !this.detectDoubleSpend();
    time_end = Instant.now().toEpochMilli();
    durationInMS = time_end - time_start;
    LOG.info("Detect if the ticket has been double spent: VState13(Server) took (ms): " + durationInMS);
    if (!success) {
      fail("ticket double spend check failed");
    }

    LOG.info("Total run of the protocol with no comms overhead took (ms):" + (time_end - overall_start));
  }

  /**
   * Detects if the ticket has been double spent.
   *
   * @return True if the ticket is double spent.
   */
  private boolean detectDoubleSpend() {
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);

    // Check whether the previous pseudonym is the same as the current pseudonym.
    return validatorData.Y.isEqual(validatorData.Y_last);
  }

  /**
   * Generates the seller's credentials.
   *
   * @param data
   *          The data received from the seller.
   * @return The seller's credential data.
   */
  private byte[] generateSellerCredentials(byte[] data) {

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
   * Generates the seller identity data.
   *
   * @return The seller identity response data.
   */
  private byte[] generateSellerIdentity() {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
    // final Crypto crypto = Crypto.getInstance();

    final CurveElement<?, ?> rho = sharedMemory.rho;

    // Calculate Y_S. Note that x_2 has already been obtained.
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

  private byte[] generateSellerProof() {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
    // final Crypto crypto = Crypto.getInstance();

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

    // omega = e(Q, g_bar) / e(g_0, g)
    final Element omega = sharedMemory.pairing.pairing(Q, sharedMemory.g_bar)
        .div(sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g)).getImmutable();

    // omega_dash = e(rho, g)^x_bar_s * e(g_frak, g)^v_bar_s * e(Q,
    // g)^-c_bar_s * e(theta, g)^z_bar * e(theta, g_bar)^z_bar
    final Element omega_dash_1 = sharedMemory.pairing.pairing(sharedMemory.rho, sharedMemory.g).pow(x_bar_s).getImmutable();

    final Element omega_dash_2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(v_bar_s).getImmutable();

    final Element omega_dash_3 = sharedMemory.pairing.pairing(Q, sharedMemory.g).pow(c_bar_s.negate().mod(sharedMemory.p))
        .getImmutable();

    final Element omega_dash_4 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(z_hat).getImmutable();

    final Element omega_dash_5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(z_bar).getImmutable();

    final Element omega_dash = omega_dash_1.mul(omega_dash_2).mul(omega_dash_3).mul(omega_dash_4).mul(omega_dash_5).getImmutable();

    // Calculate hashes.
    final ListData c_bar_1Data = new ListData(Arrays.asList(M_2_S.toBytes(), Z.toBytes(), Z_dash.toBytes()));
    final byte[] c_bar_1 = crypto.getHash(c_bar_1Data.toBytes());
    final BigInteger c_bar_1Num = new BigInteger(1, c_bar_1).mod(sharedMemory.p);

    final ListData c_bar_2Data = new ListData(Arrays.asList(M_2_S.toBytes(), gamma.toBytes(), gamma_dash.toBytes()));
    final byte[] c_bar_2 = crypto.getHash(c_bar_2Data.toBytes());
    final BigInteger c_bar_2Num = new BigInteger(1, c_bar_2).mod(sharedMemory.p);

    final ListData c_bar_3Data = new ListData(Arrays.asList(M_2_S.toBytes(), omega.toBytes(), omega_dash.toBytes()));
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
        Z_dash.toBytes(), gamma_dash.toBytes(), omega.toBytes(), omega_dash.toBytes(), c_bar_1, c_bar_2, c_bar_3,
        s_bar_1.toByteArray(), s_bar_2.toByteArray(), s_hat_1.toByteArray(), s_hat_2.toByteArray(), r_bar_1.toByteArray(),
        r_bar_2.toByteArray(), r_bar_3.toByteArray(), r_bar_4.toByteArray(), r_bar_5.toByteArray()));
    return sendData.toBytes();
  }

  private byte[] generateTicketSerialNumber() {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
    final Crypto crypto = Crypto.getInstance();

    // Select random d_dash and omega_u.
    final BigInteger d_dash = crypto.secureRandom(sharedMemory.p);
    final BigInteger omega_u = crypto.secureRandom(sharedMemory.p);

    // Compute s_u = H(Y || Time || Service || Price || Valid_Period)
    final ListData s_uData = new ListData(Arrays.asList(sellerData.Y.toBytes(), SellerData.TICKET_TIME, SellerData.TICKET_SERVICE,
        SellerData.TICKET_PRICE, SellerData.TICKET_VALID_PERIOD));
    final byte[] s_u = crypto.getHash(s_uData.toBytes());
    final BigInteger s_uNum = new BigInteger(1, s_u).mod(sharedMemory.p);

    // Compute T_U = (g_0 * Y * g_1^d_dash * g_2^s_u)^(1/x_s+omega_u) using
    // the GCD approach.
    final BigIntEuclidean gcd = BigIntEuclidean.calculate(sellerData.x_s.add(omega_u).mod(sharedMemory.p), sharedMemory.p);
    final Element T_U = (sharedMemory.g_n[0].add(sellerData.Y).add(sharedMemory.g_n[1].mul(d_dash))
        .add(sharedMemory.g_n[2].mul(s_uNum))).mul(gcd.x.mod(sharedMemory.p));

    /// Send T_U, d_dash, omega_u, s_u, Y_S, Time, Service, Price, Valid_Period.
    final ListData sendData = new ListData(
        Arrays.asList(T_U.toBytes(), d_dash.toByteArray(), omega_u.toByteArray(), s_u, sellerData.Y_S.toBytes(),
            SellerData.TICKET_TIME, SellerData.TICKET_SERVICE, SellerData.TICKET_PRICE, SellerData.TICKET_VALID_PERIOD));
    return sendData.toBytes();
  }

  /**
   * Generates the ticket transcript data.
   *
   * @param data
   *          The data received from the validator.
   * @return The ticket transcript response data.
   */
  private byte[] generateTicketTranscript(byte[] data) {
    // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
    //final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
    final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
    final Crypto crypto = Crypto.getInstance();

    // Select random pi, lambda
    final BigInteger pi = crypto.secureRandom(sharedMemory.p);
    final BigInteger lambda = crypto.secureRandom(sharedMemory.p);

    // Select random M_3_U
    final Element M_3_U = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

    // Compute Y_dash = xi^pi * g_1^lambda
    final Element Y_dash = (sharedMemory.xi.mul(pi)).add(sharedMemory.g_n[1].mul(lambda)).getImmutable();


    // Compute c = H(M_3_U || Y || Y_dash)
    final ListData cData = new ListData(Arrays.asList(M_3_U.toBytes(), userData.Y.toBytes(), Y_dash.toBytes()));
    final byte[] c = crypto.getHash(cData.toBytes());
    final BigInteger cNum = new BigInteger(1, c).mod(sharedMemory.p);
    LOG.debug("cNum: "+cNum);

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
   * Generates the user's credentials.
   *
   * @param data
   *          The data received from the user.
   * @return The user's credential data.
   */
  private byte[] generateUserCredentials(byte[] data) {
    // Note that all elliptic curve calculations are in an additive
    // group such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
    final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);
    // final Crypto crypto = Crypto.getInstance();

    // Decode the received data.
    final ListData listData = ListData.fromBytes(data);

    if (listData.getList().size() < 11) {
      fail("wrong number of data elements: " + listData.getList().size());

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
      fail("failed to verify PI_1_U: c_1");

    }
    LOG.debug("SUCCESS: Verified PI_1_U c1:...");

    LOG.debug("Verifying PI_1_U c2:...");
    final Element check2 = sharedMemory.g_frak.mul(s_2).add(R.mul(c_2Num));
    final ListData c_2VerifyData = new ListData(Arrays.asList(M_1_U.toBytes(), R.toBytes(), check2.toBytes()));
    final byte[] c_2Verify = crypto.getHash(c_2VerifyData.toBytes());

    if (!Arrays.equals(c_2, c_2Verify)) {
      fail("failed to verify PI_1_U: c_2");

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
   * Generates the user identity data.
   *
   * @return The user identity response data.
   */
  private byte[] generateUserIdentity() {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
    // final Crypto crypto = Crypto.getInstance();

    // Select random x_u and compute Y_U = xi^x_u
    userData.x_u = crypto.secureRandom(sharedMemory.p);
    userData.Y_U = sharedMemory.xi.mul(userData.x_u);

    // Select random r and compute R = g_frak^r
    userData.r = crypto.secureRandom(sharedMemory.p);
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

  private byte[] generateUserProof() { // was generateUserPseudonym
    final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
    // final Crypto crypto = Crypto.getInstance();

    // Select random c_bar, d, d_bar, alpha, alpha_bar, alpha_bar_dash,
    // beta, x_bar_u,
    // r_bar_u, c_bar_u
    final BigInteger c_bar = crypto.secureRandom(sharedMemory.p);
    final BigInteger d = crypto.secureRandom(sharedMemory.p);
    final BigInteger d_bar = crypto.secureRandom(sharedMemory.p);
    final BigInteger alpha = crypto.secureRandom(sharedMemory.p);
    final BigInteger alpha_bar = crypto.secureRandom(sharedMemory.p);
    final BigInteger alpha_bar_dash = alpha.multiply(c_bar);
    final BigInteger beta = crypto.secureRandom(sharedMemory.p);
    final BigInteger beta_bar = crypto.secureRandom(sharedMemory.p);
    final BigInteger beta_bar_dash = beta.multiply(c_bar);
    final BigInteger x_bar_u = crypto.secureRandom(sharedMemory.p);
    final BigInteger r_bar_u = crypto.secureRandom(sharedMemory.p);
    final BigInteger c_bar_u = crypto.secureRandom(sharedMemory.p);

    // Select random gamma_1-N1, gamma_bar_1-N1, a_bar_1-N1, and
    // t_1-N1_0-(k-1), t_dash_1-N1_0-(k-1), t_bar_1-N1_0-(k-1),
    // t_bar_dash_1-N1_0-(k-1), w_bar_1-N1_0-(k-1), w_bar_dash_1-N1_0-(k-1)
    final BigInteger[] gamma_n = new BigInteger[sharedMemory.N1()];
    final BigInteger[] gamma_bar_n = new BigInteger[sharedMemory.N1()];
    final BigInteger[] a_bar_n = new BigInteger[sharedMemory.N1()];
    final BigInteger[][] t_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] t_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

    final BigInteger[][] t_bar_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] t_bar_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] w_bar_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] w_bar_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      gamma_n[i] = crypto.secureRandom(sharedMemory.p);
      gamma_bar_n[i] = crypto.secureRandom(sharedMemory.p);
      a_bar_n[i] = crypto.secureRandom(sharedMemory.p);

      for (int j = 0; j < sharedMemory.k; j++) {
        t_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
        t_dash_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
        t_bar_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
        t_bar_dash_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
        w_bar_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
        w_bar_dash_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
      }
    }

    // Select random e_1-N2, e_bar_1-N2, e_hat_1-N2
    final BigInteger[] e_n = new BigInteger[sharedMemory.N2()];
    final BigInteger[] e_bar_n = new BigInteger[sharedMemory.N2()];
    final BigInteger[] e_hat_n = new BigInteger[sharedMemory.N2()];
    for (int i = 0; i < sharedMemory.N2(); i++) {
      e_n[i] = crypto.secureRandom(sharedMemory.p);
      e_bar_n[i] = crypto.secureRandom(sharedMemory.p);
      e_hat_n[i] = crypto.secureRandom(sharedMemory.p);
    }

    // Select random M_2_U
    final Element M_2_U = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

    // Compute C = delta_U * theta^alpha
    final Element C = userData.delta_U.add(sharedMemory.theta.mul(alpha)).getImmutable();

    // Compute D = g^alpha * theta^beta
    final Element D = sharedMemory.g.mul(alpha).add(sharedMemory.theta.mul(beta)).getImmutable();

    // Compute phi = D^c_u=g^alpha_dash * theta^beta_dash where alpha_dash =
    // alpha*c_u and
    // beta_dash = beta*c_u
    final BigInteger alpha_dash = alpha.multiply(userData.c_u);
    final BigInteger beta_dash = beta.multiply(userData.c_u);
    // final Element phi =
    // sharedMemory.g.mul(alpha_dash).add(sharedMemory.theta.mul(beta_dash))

    final Element phi = D.mul(userData.c_u).getImmutable();
    // Compute Y = xi^x_u * g_1^d
    final Element Y = sharedMemory.xi.mul(userData.x_u).add(sharedMemory.g_n[1].mul(d)).getImmutable();

    // Compute:
    // Z_1-N1 = g^gamma_1-N1 * h^a_1-N1,
    // Z_dash_1-N1 = g^gamma_bar_1-N1 * h^a_bar_1-N1
    // Z_bar_1-N1 = g^gamma_bar_1-N1 *
    // PRODUCT_0-(k-1)(h_bar_i^w_bar_1-N1_0-(k-1))
    // Z_bar_dash_1-N1 = g^gamma_bar_1-N1 *
    // PRODUCT_0-(k-1)(h_bar_i^w_bar_dash_1-N1_0-(k-1))
    final Element[] Z_n = new Element[sharedMemory.N1()];
    final Element[] Z_dash_n = new Element[sharedMemory.N1()];
    final Element[] Z_bar_n = new Element[sharedMemory.N1()];
    final Element[] Z_bar_dash_n = new Element[sharedMemory.N1()];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      Z_n[i] = sharedMemory.g.mul(gamma_n[i]).add(sharedMemory.h.mul(UserData.A_U_range[i])).getImmutable();
      Z_dash_n[i] = sharedMemory.g.mul(gamma_bar_n[i]).add(sharedMemory.h.mul(a_bar_n[i]).getImmutable());

      Element sum1 = sharedMemory.g.mul(gamma_bar_n[i]).getImmutable();
      for (int j = 0; j < sharedMemory.k; j++) {
        final Element value = sharedMemory.h_bar_n[j].mul(w_bar_n_m[i][j]).getImmutable();
        sum1 = sum1.add(value).getImmutable();
      }
      Z_bar_n[i] = sum1.getImmutable();

      Element sum2 = sharedMemory.g.mul(gamma_bar_n[i]).getImmutable();
      for (int j = 0; j < sharedMemory.k; j++) {
        final Element value = sharedMemory.h_bar_n[j].mul(w_bar_dash_n_m[i][j]).getImmutable();
        sum2 = sum2.add(value).getImmutable();
      }
      Z_bar_dash_n[i] = sum2.getImmutable();
    }

    // Compute w_n_m and w_dash_n_m
    final int[][] w_n_m = new int[sharedMemory.N1()][sharedMemory.k];
    final int[][] w_dash_n_m = new int[sharedMemory.N1()][sharedMemory.k];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      // Calculate w_l_i member of [0, q-1], and since q = 2, w_l_i is
      // binary. Here w_l_i represents which bits are set in the
      // number A_U_range[i] - lower bound of range policy[i]
      final BigInteger lowerDiff = UserData.A_U_range[i].subtract(BigInteger.valueOf(sharedMemory.rangePolicies[i][0]));
      final String reverseLowerDiff = new StringBuilder(lowerDiff.toString(sharedMemory.q)).reverse().toString();

      // Calculate w_dash_l_i member of [0, q-1], and since q = 2,
      // w_dash_l_i is binary. Here w_dash_l_i represents which bits
      // are set in the number A_U_range[i] - upper bound of range
      // policy[i] + q^k
      final BigInteger upperDiff = UserData.A_U_range[i].subtract(BigInteger.valueOf(sharedMemory.rangePolicies[i][1]))
          .add(BigInteger.valueOf(sharedMemory.q).pow(sharedMemory.k));
      final String reverseUpperDiff = new StringBuilder(upperDiff.toString(sharedMemory.q)).reverse().toString();

      // verify
      int testLowerDiff = 0;
      int testUpperDiff = 0;
      for (int j = 0; j < sharedMemory.k; j++) {
        if (j < reverseLowerDiff.length()) {
          w_n_m[i][j] = Integer.parseInt(Character.toString(reverseLowerDiff.charAt(j)));
        }
        else {
          w_n_m[i][j] = 0;
        }
        testLowerDiff = (int) (testLowerDiff + w_n_m[i][j] * Math.pow(sharedMemory.q, j));
        if (j < reverseUpperDiff.length()) {
          w_dash_n_m[i][j] = Integer.parseInt(Character.toString(reverseUpperDiff.charAt(j)));
        }
        else {
          w_dash_n_m[i][j] = 0;
        }
        testUpperDiff = (int) (testUpperDiff + w_dash_n_m[i][j] * Math.pow(sharedMemory.q, j));
      }
    }

    // Compute:
    // A_w_1-N1_0-(k-1) = h_w_1-N1_0-(k-1)^t_1-N1_0-(k-1)
    // A_dash_w_1-N1_0-(k-1) = h_w_dash_1-N1_0-(k-1)^t_dash_1-N1_0-(k-1)
    // V_1-N1_0-(k-1) = e(h, h)^t_1-N1_0-(k-1) * e(A_w_1-N1_0-(k-1),
    // h)^-w_1-N1_0-(k-1)
    // V_bar_1-N1_0-(k-1) = e(h, h)^t_bar_1-N1_0-(k-1) * e(A_w_1-N1_0-(k-1),
    // h)^-w_bar_1-N1_0-(k-1)
    // V_dash_1-N1_0-(k-1) = e(h, h)^t_dash_1-N1_0-(k-1) *
    // e(A_dash_w_1-N1_0-(k-1), h)^-w_dash_1-N1_0-(k-1)
    // V_bar_dash_1-N1_0-(k-1) = e(h, h)^t_bar_dash_1-N1_0-(k-1) *
    // e(A_dash_w_1-N1_0-(k-1), h)^-w_bar_dash_1-N1_0-(k-1)
    final Element[][] A_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
    final Element[][] A_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
    final Element[][] V_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
    final Element[][] V_bar_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
    final Element[][] V_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
    final Element[][] V_bar_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      for (int j = 0; j < sharedMemory.k; j++) {
        A_n_m[i][j] = sharedMemory.h_n[w_n_m[i][j]].mul(t_n_m[i][j]).getImmutable();
        A_dash_n_m[i][j] = sharedMemory.h_n[w_dash_n_m[i][j]].mul(t_dash_n_m[i][j]).getImmutable();

        V_n_m[i][j] = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_n_m[i][j]).mul(sharedMemory.pairing
            .pairing(A_n_m[i][j], sharedMemory.h).pow(BigInteger.valueOf(w_n_m[i][j]).negate().mod(sharedMemory.p))).getImmutable();
        V_bar_n_m[i][j] = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_bar_n_m[i][j])
            .mul(sharedMemory.pairing.pairing(A_n_m[i][j], sharedMemory.h).pow(w_bar_n_m[i][j].negate().mod(sharedMemory.p)))
            .getImmutable();

        V_dash_n_m[i][j] = (sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_dash_n_m[i][j]))
            .mul(sharedMemory.pairing.pairing(A_dash_n_m[i][j], sharedMemory.h)
                .pow(BigInteger.valueOf(w_dash_n_m[i][j]).negate().mod(sharedMemory.p)))
            .getImmutable();
        V_bar_dash_n_m[i][j] = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_bar_dash_n_m[i][j]).mul(
            sharedMemory.pairing.pairing(A_dash_n_m[i][j], sharedMemory.h).pow(w_bar_dash_n_m[i][j].negate().mod(sharedMemory.p)))
            .getImmutable();
      }
    }

    // Compute D_bar = g^alpha_bar * theta^beta_bar
    final Element D_bar = sharedMemory.g.mul(alpha_bar).add(sharedMemory.theta.mul(beta_bar)).getImmutable();

    // Compute phi_bar = D^c_bar
    final Element phi_bar = D.mul(c_bar).getImmutable();

    // Compute Y_bar = xi^x_bar_u * g_1^d_bar
    final Element Y_bar = sharedMemory.xi.mul(x_bar_u).add(sharedMemory.g_n[1].mul(d_bar)).getImmutable();

    // Compute:
    // R = e(C,g_bar) / e(g_0,g)
    // R_dash = e(xi,g)^x_bar_u * e(g_frak,g)^r_bar_u *
    // PRODUCT_1-N1(e(g_hat,g)^a_bar_l * PRODUCT_1-N2(e(eta_i,g)^e_hat_i * e
    // (C,g)^c_bar_u * e(theta,g)^a_bar_dash * e(theta,g_bar)^alpha_bar
    final Element R = sharedMemory.pairing.pairing(C, sharedMemory.g_bar)
        .div(sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g)).getImmutable();
    final Element R_dash1 = sharedMemory.pairing.pairing(sharedMemory.xi, sharedMemory.g).pow(x_bar_u).getImmutable();
    final Element R_dash2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_bar_u).getImmutable();

    Element product1 = sharedMemory.pairing.getGT().newOneElement().getImmutable();
    for (int i = 0; i < sharedMemory.N1(); i++) {
      final Element value = sharedMemory.pairing.pairing(sharedMemory.g_hat_n[i], sharedMemory.g).pow(a_bar_n[i]);
      product1 = product1.mul(value);
    }

    Element product2 = sharedMemory.pairing.getGT().newOneElement().getImmutable();
    ;
    for (int i = 0; i < sharedMemory.N2(); i++) {
      final Element value = sharedMemory.pairing.pairing(sharedMemory.eta_n[i], sharedMemory.g).pow(e_hat_n[i]);
      product2 = product2.mul(value);
    }

    final Element R_dash3 = sharedMemory.pairing.pairing(C, sharedMemory.g).pow(c_bar_u.negate().mod(sharedMemory.p));
    final Element R_dash4 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(alpha_bar_dash);
    final Element R_dash5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(alpha_bar);

    final Element R_dash = R_dash1.mul(R_dash2).mul(product1).mul(product2).mul(R_dash3).mul(R_dash4).mul(R_dash5);

    // Compute:
    // B_1-N2_j = eta_1-N2_j^e_1-N2
    // W_1-N2_j = e(B_1-N2_j,eta_bar_1-N2)
    // W_bar_1-N2_j = e(eta,eta_1-N2)^e_bar_1-N2 *
    // e(B_1-N2_j,eta_1-N2)^e_hat_1-N2
    //
    // Note here we are only required to select one of the j set policies,
    // but for completeness, and to ensure that we measure
    // the maximum possible timing for the protocol, we have selected a
    // value for all possible set values zeta.
    final Element[][] B_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];
    final Element[][] W_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];
    final Element[][] W_bar_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];

    for (int i = 0; i < sharedMemory.N2(); i++) {
      for (int j = 0; j < sharedMemory.zeta(); j++) {
        if (UserData.A_U_set[i].equalsIgnoreCase(sharedMemory.setPolices[i][j])) {
          B_n_m[i][j] = sharedMemory.eta_n_n[i][j].mul(e_n[i]).getImmutable();
          W_n_m[i][j] = sharedMemory.pairing.pairing(B_n_m[i][j], sharedMemory.eta_bar_n[i]).getImmutable();
          Element part1 = sharedMemory.pairing.pairing(sharedMemory.eta, sharedMemory.eta_n[i]).pow(e_bar_n[i]).getImmutable();
          Element part2 = sharedMemory.pairing.pairing(B_n_m[i][j], sharedMemory.eta_n[i]).pow(e_hat_n[i]).getImmutable();
          W_bar_n_m[i][j] = part1.mul(part2).getImmutable();
        }
        else {
          // just stick some fixed element here... as they won't be used...
          B_n_m[i][j] = sharedMemory.g;
          W_n_m[i][j] = sharedMemory.g;
          W_bar_n_m[i][j] = sharedMemory.g;

        }
      }
    }

    // Calculate hash c_BAR
    final List<byte[]> c_BARList = new ArrayList<>();
    c_BARList.addAll(Arrays.asList(M_2_U.toBytes(), Y.toBytes(), Y_bar.toBytes(), D.toBytes(), D_bar.toBytes(), phi.toBytes(),
        phi_bar.toBytes(), C.toBytes(), R.toBytes(), R_dash.toBytes()));

    for (int i = 0; i < sharedMemory.N1(); i++) {
      c_BARList.add(Z_n[i].toBytes());
    }
    for (int i = 0; i < sharedMemory.N1(); i++) {
      c_BARList.add(Z_dash_n[i].toBytes());
    }

    for (int i = 0; i < sharedMemory.N2(); i++) {
      for (int j = 0; j < sharedMemory.zeta(); j++) {
        c_BARList.add(B_n_m[i][j].toBytes());
      }
    }
    for (int i = 0; i < sharedMemory.N2(); i++) {
      for (int j = 0; j < sharedMemory.zeta(); j++) {
        c_BARList.add(W_n_m[i][j].toBytes());
      }
    }

    for (int i = 0; i < sharedMemory.N2(); i++) {
      for (int j = 0; j < sharedMemory.zeta(); j++) {
        c_BARList.add(W_bar_n_m[i][j].toBytes());
      }
    }
    final ListData c_BARData = new ListData(c_BARList);
    final byte[] c_BAR = crypto.getHash(c_BARData.toBytes());
    final BigInteger c_BARNum = new BigInteger(1, c_BAR).mod(sharedMemory.p);

    // Compute:
    // x_BAR_u = x_bar_u - c_BAR * x_u
    // d_BAR = d_bar - c_BAR * d
    // r_BAR_u = r_bar_u - c_BAR * r_u
    final BigInteger x_BAR_u = x_bar_u.subtract(c_BARNum.multiply(userData.x_u)).mod(sharedMemory.p);

    final BigInteger d_BAR = d_bar.subtract(c_BARNum.multiply(d)).mod(sharedMemory.p);
    final BigInteger r_BAR_u = r_bar_u.subtract(c_BARNum.multiply(userData.r_u)).mod(sharedMemory.p);

    // Compute:
    // gammac_BAR_1-N1 = gamma_bar_1-N1 - c_BAR * gamma_1-N1
    // ac_BAR_1-N1 = a_bar_1-N1 - c_BAR * a_1-N1
    final BigInteger[] gammac_BAR_n = new BigInteger[sharedMemory.N1()];
    final BigInteger[] ac_BAR_n = new BigInteger[sharedMemory.N1()];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      gammac_BAR_n[i] = gamma_bar_n[i].subtract(c_BARNum.multiply(gamma_n[i])).mod(sharedMemory.p);
      ac_BAR_n[i] = a_bar_n[i].subtract(c_BARNum.multiply(UserData.A_U_range[i])).mod(sharedMemory.p);
    }

    // Compute:
    // e_BAR_1-N2 = e_bar_1-N2 - c_BAR * e_1-N2
    // e_BAR_dash_1-N2 = e_hat_1-N2 - c_BAR * H(I_1-N2_j)
    final BigInteger[] e_BAR_n = new BigInteger[sharedMemory.N2()];
    final BigInteger[] e_BAR_dash_n = new BigInteger[sharedMemory.N2()];
    final BigInteger[] e_BAR_dash_dash_n = new BigInteger[sharedMemory.N2()];

    try {
      for (int i = 0; i < sharedMemory.N2(); i++) {
        e_BAR_n[i] = e_bar_n[i].subtract(c_BARNum.multiply(e_n[i])).mod(sharedMemory.p);

        final byte[] hash = crypto.getHash(UserData.A_U_set[i].getBytes(Data.UTF8));
        final BigInteger hashNum = new BigInteger(1, hash).mod(sharedMemory.p);

        e_BAR_dash_n[i] = e_hat_n[i].subtract(c_BARNum.multiply(hashNum)).mod(sharedMemory.p); // needed for R' verification
        e_BAR_dash_dash_n[i] = e_hat_n[i].add(c_BARNum.multiply(hashNum)).mod(sharedMemory.p); // needed for W_bar_n_m verification
      }
    }
    catch (final UnsupportedEncodingException e) {
      // Ignore.
    }

    // Compute:
    // c_BAR_u = c_bar_u - c_BAR * c_u
    // alpha_BAR = alpha_bar - c_BAR * alpha
    // beta_BAR = beta_bar - c_BAR * beta
    // alpha_BAR_dash = alpha_bar_dash - c_BAR * alpha_dash
    // beta_BAR_dash = beta_bar_dash - c_BAR * beta_dash
    final BigInteger c_BAR_u = c_bar_u.subtract(c_BARNum.multiply(userData.c_u)).mod(sharedMemory.p);
    final BigInteger alpha_BAR = alpha_bar.subtract(c_BARNum.multiply(alpha)).mod(sharedMemory.p);
    final BigInteger beta_BAR = beta_bar.subtract(c_BARNum.multiply(beta)).mod(sharedMemory.p);
    final BigInteger alpha_BAR_dash = alpha_bar_dash.subtract(c_BARNum.multiply(alpha_dash)).mod(sharedMemory.p);
    final BigInteger beta_BAR_dash = beta_bar_dash.subtract(c_BARNum.multiply(beta_dash)).mod(sharedMemory.p);

    // Compute hashes e_BAR_1-N1
    final byte[][] e_BAR_m = new byte[sharedMemory.N1()][];
    final BigInteger[] e_BAR_mNum = new BigInteger[sharedMemory.N1()];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      final ListData data = new ListData(
          Arrays.asList(M_2_U.toBytes(), Z_n[i].toBytes(), Z_dash_n[i].toBytes(), Z_bar_n[i].toBytes(), Z_bar_dash_n[i].toBytes()));
      e_BAR_m[i] = crypto.getHash(data.toBytes());
      e_BAR_mNum[i] = new BigInteger(1, e_BAR_m[i]).mod(sharedMemory.p);
    }

    // Compute:
    // gammae_BAR_1-N1 = gamma_bar_1-N1 - e_bar_1-N1 * gamma_1-N1
    // ae_BAR_1-N1 = a_bar_1-N1 - e_BAR_1-N1 * (a_1-N1 - c_1-N1)
    // ae_BAR_dash_1-N1 = a_bar_1-N1 - e_BAR_1-N1 * (a_1-N1 - d_k + q^k)
    final BigInteger[] gammae_BAR_n = new BigInteger[sharedMemory.N1()];
    final BigInteger[] ae_BAR_n = new BigInteger[sharedMemory.N1()];
    final BigInteger[] ae_BAR_dash_n = new BigInteger[sharedMemory.N1()];
    final BigInteger limit = BigInteger.valueOf((long) Math.pow(sharedMemory.q, sharedMemory.k));

    for (int i = 0; i < sharedMemory.N1(); i++) {
      gammae_BAR_n[i] = (gamma_bar_n[i].subtract(e_BAR_mNum[i].multiply(gamma_n[i]))).mod(sharedMemory.p);

      final BigInteger lower = BigInteger.valueOf(sharedMemory.rangePolicies[i][0]);
      ae_BAR_n[i] = (a_bar_n[i].subtract(e_BAR_mNum[i].multiply(UserData.A_U_range[i].subtract(lower)))).mod(sharedMemory.p);

      final BigInteger upper = BigInteger.valueOf(sharedMemory.rangePolicies[i][1]);
      ae_BAR_dash_n[i] = a_bar_n[i].subtract(e_BAR_mNum[i].multiply(UserData.A_U_range[i].subtract(upper).add(limit)));

      // do some tests

    }

    // Compute:
    // we_BAR_1-N1_0-(k-1) = w_bar_1-N1_0-(k-1) - e_BAR_1-N1 *
    // w_1-N1_0-(k-1)
    // we_BAR_dash_1-N1_0-(k-1) = w_bar_dash_1-N1_0-(k-1) - e_BAR_1-N1 *
    // w_dash_1-N1_0-(k-1)
    final BigInteger[][] we_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] we_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      for (int j = 0; j < sharedMemory.k; j++) {
        we_BAR_n_m[i][j] = w_bar_n_m[i][j].subtract(e_BAR_mNum[i].multiply(BigInteger.valueOf(w_n_m[i][j]))).mod(sharedMemory.p);
        we_BAR_dash_n_m[i][j] = w_bar_dash_n_m[i][j].subtract(e_BAR_mNum[i].multiply(BigInteger.valueOf(w_dash_n_m[i][j])))
            .mod(sharedMemory.p);
      }
    }

    // Compute hash d_BAR_1-N1_0-(k-1)
    final byte[][][] d_BAR_n_m = new byte[sharedMemory.N1()][sharedMemory.k][];
    final BigInteger[][] d_BAR_n_mNum = new BigInteger[sharedMemory.N1()][sharedMemory.k];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      for (int j = 0; j < sharedMemory.k; j++) {
        final ListData data = new ListData(Arrays.asList(M_2_U.toBytes(), A_n_m[i][j].toBytes(), A_dash_n_m[i][j].toBytes(),
            V_n_m[i][j].toBytes(), V_dash_n_m[i][j].toBytes(), V_bar_n_m[i][j].toBytes(), V_bar_dash_n_m[i][j].toBytes()));
        d_BAR_n_m[i][j] = crypto.getHash(data.toBytes());
        d_BAR_n_mNum[i][j] = new BigInteger(1, d_BAR_n_m[i][j]).mod(sharedMemory.p);
      }
    }

    // Compute:
    // t_BAR_1-N1_0-(k-1) = t_bar_1-N1_0-(k-1) - d_BAR_1-N1_0-(k-1) *
    // t_1-N1_0-(k-1)
    // t_BAR_dash_1-N1_0-(k-1) = t_bar_dash_1-N1_0-(k-1) -
    // d_BAR_1-N1_0-(k-1) * t_dash_1-N1_0-(k-1)
    // wd_BAR_1-N1_0-(k-1) = w_bar_1-N1_0-(k-1) - d_BAR_1-N1_0-(k-1) *
    // w_1-N1_0-(k-1)
    // wd_BAR_dash_1-N1_0-(k-1) = w_bar_dash_1-N1_0-(k-1) -
    // d_BAR_1-N1_0-(k-1) * w_dash_1-N1_0-(k-1)
    final BigInteger[][] t_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] t_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] wd_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
    final BigInteger[][] wd_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

    for (int i = 0; i < sharedMemory.N1(); i++) {
      for (int j = 0; j < sharedMemory.k; j++) {
        t_BAR_n_m[i][j] = t_bar_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(t_n_m[i][j])).mod(sharedMemory.p);
        t_BAR_dash_n_m[i][j] = t_bar_dash_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(t_dash_n_m[i][j])).mod(sharedMemory.p);
        wd_BAR_n_m[i][j] = w_bar_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(BigInteger.valueOf(w_n_m[i][j])))
            .mod(sharedMemory.p);
        wd_BAR_dash_n_m[i][j] = w_bar_dash_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(BigInteger.valueOf(w_dash_n_m[i][j])))
            .mod(sharedMemory.p);
      }
    }

    // Save d, Y for later.
    userData.d = d;
    userData.Y = Y;

    // Send PI_2_U, which includes Y.
    final List<byte[]> sendDataList = new ArrayList<>();
    sendDataList.addAll(
        Arrays.asList(M_2_U.toBytes(), C.toBytes(), D.toBytes(), phi.toBytes(), Y.toBytes(), R.toBytes(), R_dash.toBytes()));

    for (int i = 0; i < sharedMemory.N1(); i++) {
      sendDataList.add(Z_n[i].toBytes());
      sendDataList.add(Z_dash_n[i].toBytes());
      sendDataList.add(Z_bar_n[i].toBytes());
      sendDataList.add(Z_bar_dash_n[i].toBytes());

      for (int j = 0; j < sharedMemory.k; j++) {
        sendDataList.add(A_n_m[i][j].toBytes());
        sendDataList.add(A_dash_n_m[i][j].toBytes());
        sendDataList.add(V_n_m[i][j].toBytes());
        sendDataList.add(V_bar_n_m[i][j].toBytes());
        sendDataList.add(V_dash_n_m[i][j].toBytes());
        sendDataList.add(V_bar_dash_n_m[i][j].toBytes());
      }
    }

    for (int i = 0; i < sharedMemory.N2(); i++) {
      for (int j = 0; j < sharedMemory.zeta(); j++) {
        sendDataList.add(B_n_m[i][j].toBytes());
        sendDataList.add(W_n_m[i][j].toBytes());
        sendDataList.add(W_bar_n_m[i][j].toBytes());
      }
    }

    sendDataList.add(c_BAR);
    sendDataList.add(c_BAR_u.toByteArray());
    sendDataList.add(x_BAR_u.toByteArray());
    sendDataList.add(d_BAR.toByteArray());
    sendDataList.add(r_BAR_u.toByteArray());
    sendDataList.add(alpha_BAR.toByteArray());
    sendDataList.add(beta_BAR.toByteArray());
    sendDataList.add(alpha_BAR_dash.toByteArray());
    sendDataList.add(beta_BAR_dash.toByteArray());

    for (int i = 0; i < sharedMemory.N1(); i++) {
      sendDataList.add(e_BAR_m[i]);

      sendDataList.add(gammac_BAR_n[i].toByteArray());
      sendDataList.add(ac_BAR_n[i].toByteArray());

      sendDataList.add(gammae_BAR_n[i].toByteArray());
      sendDataList.add(ae_BAR_n[i].toByteArray());
      sendDataList.add(ae_BAR_dash_n[i].toByteArray());
    }

    for (int i = 0; i < sharedMemory.N2(); i++) {
      sendDataList.add(e_BAR_n[i].toByteArray());
      sendDataList.add(e_BAR_dash_n[i].toByteArray());
      sendDataList.add(e_BAR_dash_dash_n[i].toByteArray());
    }

    for (int i = 0; i < sharedMemory.N1(); i++) {
      for (int j = 0; j < sharedMemory.k; j++) {
        sendDataList.add(d_BAR_n_m[i][j]);
        sendDataList.add(t_BAR_n_m[i][j].toByteArray());
        sendDataList.add(t_BAR_dash_n_m[i][j].toByteArray());
        sendDataList.add(we_BAR_n_m[i][j].toByteArray());
        sendDataList.add(we_BAR_dash_n_m[i][j].toByteArray());

        sendDataList.add(wd_BAR_n_m[i][j].toByteArray());
        sendDataList.add(wd_BAR_dash_n_m[i][j].toByteArray());
      }
    }

    final ListData sendData = new ListData(sendDataList);
    return sendData.toBytes();
  }

  /**
   * Generates the validator's random number.
   *
   * @return The validator's random number.
   */
  private byte[] generateValidatorRandomNumber() {
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final ValidatorData validatorData = (ValidatorData) sharedMemory.getData(Actor.VALIDATOR);
    // final Crypto crypto = Crypto.getInstance();

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
   * Verifies the returned seller's credential data.
   *
   * @return True if the verification is successful.
   */
  private boolean verifySellerCredentials(byte[] data) {
    // final PPETSFGPSharedMemory sharedMemory =
    // (PPETSFGPSharedMemory)this.getSharedMemory();
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

    return true;
  }

  private boolean verifySellerProof(byte[] data) {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    // final Crypto crypto = Crypto.getInstance();

    // Decode the received data.
    final ListData listData = ListData.fromBytes(data);

    if (listData.getList().size() != 20) {
      LOG.error("wrong number of data elements: " + listData.getList().size());
      return false;
    }

    final Element M_2_S = sharedMemory.curveElementFromBytes(listData.getList().get(0));

    final Element Q = sharedMemory.curveElementFromBytes(listData.getList().get(1));
    final Element Z = sharedMemory.curveElementFromBytes(listData.getList().get(2));
    final Element gamma = sharedMemory.curveElementFromBytes(listData.getList().get(3));
    // Ignore Z_dash
    // Ignore gamma_dash
    final Element omega = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(6));
    // Ignore omega_dash

    final byte[] c_bar_1 = listData.getList().get(8);
    final BigInteger c_bar_1Num = new BigInteger(1, c_bar_1).mod(sharedMemory.p);

    final byte[] c_bar_2 = listData.getList().get(9);
    final BigInteger c_bar_2Num = new BigInteger(1, c_bar_2).mod(sharedMemory.p);

    final byte[] c_bar_3 = listData.getList().get(10);
    final BigInteger c_bar_3Num = new BigInteger(1, c_bar_3).mod(sharedMemory.p);

    final BigInteger s_bar_1 = new BigInteger(listData.getList().get(11));
    final BigInteger s_bar_2 = new BigInteger(listData.getList().get(12));

    final BigInteger s_hat_1 = new BigInteger(listData.getList().get(13));
    final BigInteger s_hat_2 = new BigInteger(listData.getList().get(14));

    final BigInteger r_bar_1 = new BigInteger(listData.getList().get(15));
    final BigInteger r_bar_2 = new BigInteger(listData.getList().get(16));
    final BigInteger r_bar_3 = new BigInteger(listData.getList().get(17));
    final BigInteger r_bar_4 = new BigInteger(listData.getList().get(18));
    final BigInteger r_bar_5 = new BigInteger(listData.getList().get(19));

    // Verify c_bar_1 = H(M_2_S || Z || g^s_bar_1 * theta^s_bar_2 *
    // Z^c_bar_1)
    final Element check1 = sharedMemory.g.mul(s_bar_1).add(sharedMemory.theta.mul(s_bar_2)).add(Z.mul(c_bar_1Num));
    final ListData c_bar_1VerifyData = new ListData(Arrays.asList(M_2_S.toBytes(), Z.toBytes(), check1.toBytes()));
    final byte[] c_bar_1Verify = crypto.getHash(c_bar_1VerifyData.toBytes());

    if (!Arrays.equals(c_bar_1, c_bar_1Verify)) {
      LOG.error("failed to verify PI_2_S: c_bar_1");
      if (!sharedMemory.passVerification) {
        return false;
      }
    }
    LOG.debug("SUCCESS: passed verification of PI_2_S: c_bar_1");

    // Verify c_bar_2 = H(M_2_S || gamma || g^s_hat_1 * theta^s_hat_2 *
    // gamma^c_bar_2)
    final Element check2 = sharedMemory.g.mul(s_hat_1).add(sharedMemory.theta.mul(s_hat_2)).add(gamma.mul(c_bar_2Num));
    final ListData c_bar_2VerifyData = new ListData(Arrays.asList(M_2_S.toBytes(), gamma.toBytes(), check2.toBytes()));
    final byte[] c_bar_2Verify = crypto.getHash(c_bar_2VerifyData.toBytes());

    if (!Arrays.equals(c_bar_2, c_bar_2Verify)) {
      LOG.error("failed to verify PI_2_S: c_bar_2");
      if (!sharedMemory.passVerification) {
        return false;
      }
    }
    LOG.debug("SUCCESS: passed verification of PI_2_S: c_bar_2");
    // Verify c_bar_3 = H(M_2_S || omega || e(rho,g)^r_bar_1 *
    // e(g_frak,g)^r_bar_2 * e(Q,g)^-r_bar_3 * e(theta,g)^r_bar_4 * e
    // (theta,g_bar)^r_bar_5 * omega^c_bar_3)
    final Element check3_1 = sharedMemory.pairing.pairing(sharedMemory.rho, sharedMemory.g).pow(r_bar_1).getImmutable();
    final Element check3_2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_bar_2).getImmutable();
    final Element check3_3 = sharedMemory.pairing.pairing(Q, sharedMemory.g).pow(r_bar_3.negate().mod(sharedMemory.p))
        .getImmutable();
    final Element check3_4 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(r_bar_4).getImmutable();
    final Element check3_5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(r_bar_5).getImmutable();

    final Element check3_6 = omega.pow(c_bar_3Num).getImmutable();
    final Element check3 = check3_1.mul(check3_2).mul(check3_3).mul(check3_4).mul(check3_5).mul(check3_6).getImmutable();

    final ListData c_bar_3VerifyData = new ListData(Arrays.asList(M_2_S.toBytes(), omega.toBytes(), check3.toBytes()));
    final byte[] c_bar_3Verify = crypto.getHash(c_bar_3VerifyData.toBytes());

    if (!Arrays.equals(c_bar_3, c_bar_3Verify)) {
      LOG.error("failed to verify PI_2_S: c_bar_3");
      if (!sharedMemory.passVerification) {
        return false;
      }
    }
    LOG.debug("SUCCESS: passed verification of PI_2_S: c_bar_3");
    return true;
  }

  /**
   * Verifies the ticket proof.
   *
   * @param data
   *          The data received from the user.
   * @return True if the ticket proof is verified.
   */
  private boolean verifyTicketProof(byte[] data) {
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
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

  private boolean verifyTicketSerialNumber(byte[] data) {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
    // final Crypto crypto = Crypto.getInstance();

    // Decode the received data.
    final ListData listData = ListData.fromBytes(data);

    if (listData.getList().size() != 9) {
      LOG.error("wrong number of data elements: " + listData.getList().size());
      return false;
    }

    final Element T_U = sharedMemory.curveElementFromBytes(listData.getList().get(0));
    final BigInteger d_dash = new BigInteger(listData.getList().get(1));
    final BigInteger omega_u = new BigInteger(listData.getList().get(2));
    final byte[] s_u = listData.getList().get(3);
    final BigInteger s_uNum = new BigInteger(1, s_u);
    final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(4));
    byte[] time = listData.getList().get(5);
    byte[] service = listData.getList().get(6);
    byte[] price = listData.getList().get(7);
    byte[] validPeriod = listData.getList().get(8);

    // Compute d_u = d + d_dash
    final BigInteger d_u = userData.d.add(d_dash);

    // Check that e(T_U, Y_S * rho^omega_u) =? e(g_0,rho) * e(Y,rho) *
    // e(g_1,rho)^d_u * e(g_2,rho)^s_u
    final Element left = sharedMemory.pairing.pairing(T_U, Y_S.add(sharedMemory.rho.mul(omega_u))).getImmutable();

    final Element right1 = sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.rho).getImmutable();
    final Element right2 = sharedMemory.pairing.pairing(userData.Y_U, sharedMemory.rho).getImmutable();
    final Element right3 = sharedMemory.pairing.pairing(sharedMemory.g_n[1], sharedMemory.rho).pow(d_u).getImmutable();
    final Element right4 = sharedMemory.pairing.pairing(sharedMemory.g_n[2], sharedMemory.rho).pow(s_uNum).getImmutable();

    if (!left.isEqual(right1.mul(right2).mul(right3).mul(right4))) {
      LOG.error("failed to verify e(T_U, Y_S * rho^omega_u)");
      if (!sharedMemory.passVerification) {
        return false;
      }
    }

    // Keep the ticket Ticket_U = (d_u, d_dash, s_u, omega_u, T_U, Time, Service, Price, Valid_Period).
    userData.d_u = d_u;
    userData.d_dash = d_dash;
    userData.s_u = s_u;
    userData.omega_u = omega_u;
    userData.T_U = T_U.getImmutable();
    userData.Y_S = Y_S.getImmutable();
    userData.time = time;
    userData.service = service;
    userData.price = price;
    userData.validPeriod = validPeriod;

    LOG.debug("SUCCESS: verified Ticket serial number");

    return true;
  }

  /**
   * Verifies the returned user's credential data.
   *
   * @return True if the verification is successful.
   */
  private boolean verifyUserCredentials(byte[] data) {
    // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
    final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
    // final Crypto crypto = Crypto.getInstance();

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
   * Verifies the user proof.
   *
   * @param data
   *          The data received from the user.
   * @return True if verified.
   */
  private boolean verifyUserProof(byte[] data) {
    // Note that all elliptic curve calculations are in an additive group
    // such that * -> + and ^ -> *.
    // final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory)
    // this.getSharedMemory();
    final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);
    // final Crypto crypto = Crypto.getInstance();

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
    sellerData.Y = Y;
    final Element R = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(index++));
    index++; // Ignore R_dash

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

    // Verify c_BAR.
    final List<byte[]> c_BARVerifyList = new ArrayList<>();
    c_BARVerifyList.addAll(Arrays.asList(M_2_U.toBytes(), Y.toBytes()));

    // check Y_bar
    final Element c_BARCheck1 = (sharedMemory.xi.mul(x_BAR_u)).add(sharedMemory.g_n[1].mul(d_BAR)).add(Y.mul(c_BARNum))
        .getImmutable();

    c_BARVerifyList.add(c_BARCheck1.toBytes());

    c_BARVerifyList.add(D.toBytes());

    // check D_bar
    final Element c_BARCheck2 = sharedMemory.g.mul(alpha_BAR).add(sharedMemory.theta.mul(beta_BAR)).add(D.mul(c_BARNum))
        .getImmutable();
    c_BARVerifyList.add(c_BARCheck2.toBytes());

    c_BARVerifyList.add(phi.toBytes());

    final Element c_BARCheck3 = sharedMemory.g.mul(alpha_BAR_dash).add(sharedMemory.theta.mul(beta_BAR_dash))
        .add(phi.mul(c_BARNum));
    c_BARVerifyList.add(c_BARCheck3.toBytes());

    c_BARVerifyList.add(C.toBytes());
    c_BARVerifyList.add(R.toBytes());

    // the following computations should produce R_dash
    Element R_dash1 = sharedMemory.pairing.pairing(sharedMemory.xi, sharedMemory.g).pow(x_BAR_u).getImmutable();
    Element R_dash2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_BAR_u).getImmutable();
    Element R_dash3 = sharedMemory.pairing.getGT().newOneElement();
    for (int i = 0; i < sharedMemory.N1(); i++) {
      Element value = sharedMemory.pairing.pairing(sharedMemory.g_hat_n[i], sharedMemory.g).pow(ac_BAR_n[i]).getImmutable();
      R_dash3 = R_dash3.mul(value);
    }
    Element R_dash4 = sharedMemory.pairing.getGT().newOneElement();
    for (int i = 0; i < sharedMemory.N2(); i++) {
      Element value = sharedMemory.pairing.pairing(sharedMemory.eta_n[i], sharedMemory.g).pow(e_BAR_dash_n[i]).getImmutable();
      R_dash4 = R_dash4.mul(value);
    }
    Element R_dash5 = sharedMemory.pairing.pairing(C, sharedMemory.g).pow(c_BAR_u.negate().mod(sharedMemory.p)).getImmutable();
    Element R_dash6 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(alpha_BAR_dash).getImmutable();
    Element R_dash7 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(alpha_BAR).getImmutable();
    Element R_dash8 = R.pow(c_BARNum).getImmutable();
    Element R_dash = R_dash1.mul(R_dash2).mul(R_dash3).mul(R_dash4).mul(R_dash5).mul(R_dash6).mul(R_dash7).mul(R_dash8)
        .getImmutable();

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
          Element product2 = sharedMemory.pairing.pairing(sharedMemory.eta, sharedMemory.eta_n[i]).pow(e_BAR_n[i]).getImmutable();
          product2 = product2.mul(sharedMemory.pairing.pairing(B_n_m[i][j], sharedMemory.eta_n[i]).pow(e_BAR_dash_dash_n[i]))
              .getImmutable();
          product2 = product2.mul(W_n_m[i][j].pow(c_BARNum)).getImmutable();
          c_BARVerifyList.add(product2.toBytes());
        }
        else {
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
      Element e_BAR_mVerifyCheck1c = (Z_n[i].add(sharedMemory.h.mul(lower.negate().mod(sharedMemory.p)))).mul(e_BAR_mNum[i])
          .getImmutable();
      Element e_BAR_mVerifyCheck1 = e_BAR_mVerifyCheck1a.add(e_BAR_mVerifyCheck1b).add(e_BAR_mVerifyCheck1c).getImmutable();
      e_BAR_mVerifyList.add(e_BAR_mVerifyCheck1.toBytes());

      Element e_BAR_mVerifyCheck2a = sharedMemory.g.mul(gammae_BAR_n[i]).getImmutable();
      Element e_BAR_mVerifyCheck2b = sharedMemory.pairing.getG1().newZeroElement();
      for (int j = 0; j < sharedMemory.k; j++) {
        final Element e_BAR_mVerifyCheck2b_j = sharedMemory.h_bar_n[j].mul(we_BAR_n_m[i][j]).getImmutable();
        e_BAR_mVerifyCheck2b.add(e_BAR_mVerifyCheck2b_j);
      }
      final Element e_BAR_mVerifyCheck2c = (Z_n[i].add(sharedMemory.h.mul(lower.negate().mod(sharedMemory.p)))).mul(e_BAR_mNum[i])
          .getImmutable();
      final Element e_BAR_mVerifyCheck2 = e_BAR_mVerifyCheck2a.add(e_BAR_mVerifyCheck2b).add(e_BAR_mVerifyCheck2c);
      e_BAR_mVerifyList.add(e_BAR_mVerifyCheck2.toBytes());

      final BigInteger limit = BigInteger.valueOf((long) Math.pow(sharedMemory.q, sharedMemory.k));
      final Element e_BAR_mVerifyCheck3a = sharedMemory.g.mul(gammae_BAR_n[i]).getImmutable();

      Element e_BAR_mVerifyCheck3b = sharedMemory.pairing.getG1().newZeroElement().getImmutable();
      for (int j = 0; j < sharedMemory.k; j++) {
        e_BAR_mVerifyCheck3b = e_BAR_mVerifyCheck3b.add(sharedMemory.h_bar_n[j].mul(we_BAR_dash_n_m[i][j])).getImmutable();
      }
      Element e_BAR_mVerifyCheck3c = sharedMemory.h.mul(limit.subtract(upper)).getImmutable();
      e_BAR_mVerifyCheck3c = e_BAR_mVerifyCheck3c.add(Z_n[i]).mul(e_BAR_mNum[i]);

      final Element e_BAR_mVerifyCheck3 = e_BAR_mVerifyCheck3a.add(e_BAR_mVerifyCheck3b).add(e_BAR_mVerifyCheck3c);

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
        d_BAR_n_mVerifyList.addAll(Arrays.asList(M_2_U.toBytes(), A_n_m[i][j].toBytes(), A_dash_n_m[i][j].toBytes(),
            V_n_m[i][j].toBytes(), V_dash_n_m[i][j].toBytes()));

        Element d_BAR_n_mVerifyCheck1a = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_BAR_n_m[i][j])
            .getImmutable();
        Element d_BAR_n_mVerifyCheck1b = sharedMemory.pairing.pairing(A_n_m[i][j], sharedMemory.h)
            .pow(wd_BAR_n_m[i][j].negate().mod(sharedMemory.p)).getImmutable();
        Element d_BAR_n_mVerifyCheck1c = V_n_m[i][j].pow(d_BAR_n_mNum[i][j]);
        Element d_BAR_n_mVerifyCheck1 = d_BAR_n_mVerifyCheck1a.mul(d_BAR_n_mVerifyCheck1b).mul(d_BAR_n_mVerifyCheck1c)
            .getImmutable();

        d_BAR_n_mVerifyList.add(d_BAR_n_mVerifyCheck1.toBytes());

        Element d_BAR_n_mVerifyCheck2a = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_BAR_dash_n_m[i][j])
            .getImmutable();
        Element d_BAR_n_mVerifyCheck2b = sharedMemory.pairing.pairing(A_dash_n_m[i][j], sharedMemory.h)
            .pow(wd_BAR_dash_n_m[i][j].negate().mod(sharedMemory.p)).getImmutable();
        Element d_BAR_n_mVerifyCheck2c = V_dash_n_m[i][j].pow(d_BAR_n_mNum[i][j]);
        Element d_BAR_n_mVerifyCheck2 = d_BAR_n_mVerifyCheck2a.mul(d_BAR_n_mVerifyCheck2b).mul(d_BAR_n_mVerifyCheck2c)
            .getImmutable();
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