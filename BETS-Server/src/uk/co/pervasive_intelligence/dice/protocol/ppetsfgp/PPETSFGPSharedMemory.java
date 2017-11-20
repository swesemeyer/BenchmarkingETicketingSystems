/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.GsonUtils;
import uk.co.pervasive_intelligence.dice.Crypto.BigIntEuclidean;
import uk.co.pervasive_intelligence.dice.protocol.NFCSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.CentralAuthorityData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.SellerData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.UserData;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.ValidatorData;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class PPETSFGPSharedMemory extends NFCSharedMemory {
  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPSharedMemory.class);

  /**
   * Enum defining the different types of actor in the protocol.
   */
  public enum Actor {
    CENTRAL_AUTHORITY, SELLER, USER, VALIDATOR
  }

  /**
   * Interface defining actor data.
   */
  public interface ActorData {
  }

  /** Arbitrary bytes to act as random seed for pairing secure random so that we can re-create the pairing. */
  public static final byte[]                    PAIRING_RANDOM_SEED = PPETSFGPSharedMemory.class.getSimpleName().getBytes();

  /** Name used for timing the critical part of the protocol. */
  public static final String                    TIMING_NAME         = "Validation Timing";

  /** The current actor so that access to shared memory can be checked. */
  private transient Actor                       actor               = Actor.CENTRAL_AUTHORITY;

  /** Mapping of actor to their data. */
  private transient final Map<Actor, ActorData> actorData           = new HashMap<>();

  /** Random element eta as a generator of the group G. */
  public CurveElement<?, ?>                     eta                 = null;

  /** Elements eta_bar_1 to eta_bar_N2. */
  public CurveElement<?, ?>[]                   eta_bar_n           = null;

  /** Random elements eta_1 to eta_N2 as generators of the group G. */
  public CurveElement<?, ?>[]                   eta_n               = null;

  /** Elements eta_1_1 to eta_N2_zeta. */
  public CurveElement<?, ?>[][]                 eta_n_n             = null;

  /** Random element g as a generator of the group G. */
  public CurveElement<?, ?>                     g                   = null;

  /** Element g_bar. */
  public CurveElement<?, ?>                     g_bar               = null;

  /** Random element y_hat as a generator of the group G. */
  public CurveElement<?, ?>                     g_frak              = null;

  /** Random elements g_hat_1 to g_N1 as generators of the group G. */
  public CurveElement<?, ?>[]                   g_hat_n             = null;

  /** Random elements g_0 to g_2 as generators of the group G. */
  public CurveElement<?, ?>[]                   g_n                 = null;

  /** Random element h as a generator of the group G. */
  public CurveElement<?, ?>                     h                   = null;

  /** Element h_bar. */
  public CurveElement<?, ?>                     h_bar               = null;

  /** Elements h_bar_0 to h_bar_k-1. */
  public CurveElement<?, ?>[]                   h_bar_n             = null;

  /** Elements h_0 to h_q-1. */
  public CurveElement<?, ?>[]                   h_n                 = null;

  /**
   * Value of k such that the longest interval in the range policies is [0,
   * q^k), q member of Z_p.
   */
  public int                                    k                   = 0;

  /** How many times should validation be run? */
  public int                                    numValidations      = 2;

  /** Value of p such that p > 2q^k + 1. */
  public BigInteger                             p                   = null;

  /**
   * The bilinear group pairing: transient because we cannot serialise it and
   * instead use the parameters and random seed.
   */
  public transient Pairing                      pairing             = null;

  /** The bilinear group pairing parameters. */
  public PropertiesParameters                   pairingParameters   = null;

  /** Always pass verification steps? */
  public boolean                                passVerification    = false;

  /**
   * Value of q such that the longest interval in the range policies is [0,
   * q^k), q member of Z_p.
   */
  public int                                    q                   = 0;

  /**
   * Number of q bits in type a elliptic curve - optionally set as a
   * parameter.
   */
  public int                                    qBits               = 512;

  /**
   * Fixed set of range policies.
   * P1={0,5} AgeRange:Child
   * P2={0,3} Days:railcard for x days
   */
  public final int[][]                          rangePolicies       = new int[][] { { 0, 5 }, { 0, 3 } };

  /**
   * Number of r bits in type a elliptic curve - optionally set as a
   * parameter.
   */
  public int                                    rBits               = 256;

  /** Random element rho as a generator of the group G. */
  public CurveElement<?, ?>                     rho                 = null;

  /** Fixed set of set policies: we use arbitrary strings. */
  public transient final String[][]             setPolices          = new String[][] { { "North", "South" },
      { "Commuter", "Non-commuter" }, { "No disability", "Mobility" } };

  /** Random element theta as a generator of the group G. */
  public CurveElement<?, ?>                     theta               = null;

  /** Random element xi as a generator of the group G. */
  public CurveElement<?, ?>                     xi                  = null;

  /**
   * Deserialises the shared memory from a JSON string.
   *
   * @param json
   *          The JSON to deserialize from.
   * @return The shared memory.
   */
  public static PPETSFGPSharedMemory fromJson(String json) {
    // First we need to extract the pairing information from the JSON before
    // we deserialize.
    final JsonParser jsonParser = new JsonParser();
    final JsonObject asJson = (JsonObject) jsonParser.parse(json);

    Gson gson = new Gson();
    final PairingParameters pairingParameters = gson.fromJson(asJson.get("pairingParameters"), PropertiesParameters.class);

    // Now create the pairing and use it to get the field needed to
    // deserialize all the elements.
    final Pairing pairing = PairingFactory.getPairing(pairingParameters, new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED));

    final GsonBuilder gsonBuilder = new GsonBuilder();
    gsonBuilder.registerTypeAdapter(CurveElement.class, new GsonUtils.CurveElementSerializer());
    gsonBuilder.registerTypeAdapter(CurveElement.class, new GsonUtils.CurveElementDeserializer((CurveField<?>) pairing.getG1()));
    gson = gsonBuilder.create();

    // Deserialize and set the pairing.
    final PPETSFGPSharedMemory sharedMemory = gson.fromJson(json, PPETSFGPSharedMemory.class);
    sharedMemory.pairing = pairing;

    return sharedMemory;
  }

  /**
   * Change the current actor.
   *
   * @param actor
   *          The new actor.
   */
  public void actAs(Actor actor) {
    this.actor = actor;
  }

  /**
   * Clears out the shared memory except for those parameters set for the
   * state machine.
   */
  public void clear() {
    // Reset the shared parameters. Other parameters are kept as they are required across protocol runs.
    this.actor = Actor.CENTRAL_AUTHORITY;
    this.setBilinearGroup();

    // On the server, we only act as the central authority, seller and validator.
    this.actorData.put(Actor.CENTRAL_AUTHORITY, new CentralAuthorityData(this.p, this.N2()));
    this.actorData.put(Actor.SELLER, new SellerData());
    this.actorData.put(Actor.VALIDATOR, new ValidatorData());

    // Now complete the setup of the public parameters, which need the
    // bilinear group and private central authority data.
    this.setPublicParameters();
  }

  /**
   * Clears out the shared memory except for those parameters set for the
   * state machine. For use in the Android implementation.
   */
  public void clearAndroid() {
    // Reset the shared parameters. Other parameters are kept as they are
    // required across protocol runs.
    this.actor = Actor.CENTRAL_AUTHORITY;

    // On Android, we only act as the seller and the user, so do not
    // initialise anything else as it will be populated as we go.
    this.actorData.put(Actor.SELLER, new SellerData());
    this.actorData.put(Actor.USER, new UserData());
  }

  /**
   * Clears out the shared memory except for those parameters set for the
   * state machine needed for debugging/unit testing.
   */
  public void clearTest() {
    // Reset the shared parameters. Other parameters are kept as they are
    // required across protocol runs.
    this.actor = Actor.CENTRAL_AUTHORITY;
    this.setBilinearGroup();

    // During testing we act as everything...
    this.actorData.put(Actor.CENTRAL_AUTHORITY, new CentralAuthorityData(this.p, this.N2()));
    this.actorData.put(Actor.SELLER, new SellerData());
    this.actorData.put(Actor.VALIDATOR, new ValidatorData());
    this.actorData.put(Actor.USER, new UserData());

    // Now complete the setup of the public parameters, which need the
    // bilinear group and private central authority data.
    this.setPublicParameters();
  }

  /**
   * Convenience method to create a curve element from a byte array.
   *
   * @param bytes
   *          The bytes containing the curve element data.
   * @return The new curve element.
   */
  public Element curveElementFromBytes(byte[] bytes) {
    final CurveElement<Element, ?> element = new CurveElement<>((CurveField<?>) this.pairing.getG1());
    element.setFromBytes(bytes);

    return element.getImmutable();
  }

  /**
   * Gets the data associated with the specified actor.
   *
   * @param actor
   *          The actor to obtain data for.
   * @return The data or null if the current actor does not match the required
   *         data.
   */
  public ActorData getData(Actor actor) {
    ActorData data = null;

    if (actor == this.actor) {
      data = this.actorData.get(actor);
    }

    return data;
  }

  /**
   * Convenience method to create a GT finite element from a byte array.
   *
   * @param bytes
   *          The bytes containing the GT finite element data.
   * @return The new GT finite element.
   */
  public Element gtFiniteElementFromBytes(byte[] bytes) {
    final Element element = new GTFiniteElement(((TypeAPairing) this.pairing).getPairingMap(),
        (GTFiniteField<?>) this.pairing.getGT());
    element.setFromBytes(bytes);

    return element.getImmutable();
  }

  /**
   * @return The longest range policy interval.
   */
  private int longestRangeInterval() {
    int maxInterval = 0;

    for (final int[] policy : this.rangePolicies) {
      maxInterval = Math.max(maxInterval, Math.abs(policy[1] - policy[0]));
    }

    return maxInterval;
  }

  /**
   * @return The number of range policies.
   */
  public int N1() {
    return this.rangePolicies[0].length;
  }

  /**
   * @return The number of set policies.
   */
  public int N2() {
    return this.setPolices.length;
  }

  /**
   * Sets the bilinear group, which must be done before the central authority
   * can be initialised.
   */
  private void setBilinearGroup() {
    // Calculate q and k. We assume a value of q = 2 and that p is large,
    // and calculate k.
    this.q = 2;
    final int longestRangeInterval = this.longestRangeInterval();
    if (longestRangeInterval < this.q) {
      this.k = 1;
    }
    else {
      // No arbitrary log base function.
      this.k = (int) Math.floor(Math.log(longestRangeInterval) / Math.log(this.q)) + 1;
    }

    // Build an elliptic curve generator that will give us our p (the order r of the generator), and subsequently our bilinear group
    // pairing.
    final SecureRandom prng = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);
    final PairingParametersGenerator<?> generator = new TypeACurveGenerator(prng, this.rBits, this.qBits, false);
    this.pairingParameters = (PropertiesParameters) generator.generate();
    this.pairing = PairingFactory.getPairing(this.pairingParameters, prng);
    this.p = this.pairingParameters.getBigInteger("r");

    final BigInteger minP = BigInteger.valueOf((2 * (int) Math.pow(this.q, this.k)) + 1);
    if (this.p.compareTo(minP) <= 0) {
      throw new IllegalStateException("invalid p: " + this.p);
    }
  }

  /**
   * Sets the public parameters based upon the central authorities private
   * data.
   */
  private void setPublicParameters() {
    // Generate the required elements from the pairing. Note that CurveElement is used instead of Element for deserialization with
    // Gson.
    this.g = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.g_n = new CurveElement<?, ?>[3];
    for (int i = 0; i < this.g_n.length; i++) {
      this.g_n[i] = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    }

    this.g_hat_n = new CurveElement<?, ?>[this.N1()];
    for (int i = 0; i < this.g_hat_n.length; i++) {
      this.g_hat_n[i] = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    }

    this.g_frak = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.eta = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.xi = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.rho = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.theta = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();

    this.eta_n = new CurveElement<?, ?>[this.N2()];
    for (int i = 0; i < this.eta_n.length; i++) {
      this.eta_n[i] = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    }

    CentralAuthorityData caData=(CentralAuthorityData) this.getData(Actor.CENTRAL_AUTHORITY);
    this.g_bar = (CurveElement<?, ?>) this.g.mul(caData.x).getImmutable();
    this.h = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.h_bar = (CurveElement<?, ?>) this.h.mul(caData.y).getImmutable();
    this.h_n = new CurveElement<?, ?>[this.q];
    for (int i = 0; i < this.h_n.length; i++) {
      final BigIntEuclidean gcd = BigIntEuclidean.calculate(caData.y.add(BigInteger.valueOf(i)).mod(p), p);
      this.h_n[i] = (CurveElement<?, ?>) this.h.mul(gcd.x.mod(p)).getImmutable();
    }

    // Define h_bar_n.
    this.h_bar_n = new CurveElement<?, ?>[this.k];

    // Storing q^i as part of the loop instead of computing it afresh in each iteration should be faster.
    BigInteger powerQ = BigInteger.ONE; // q^0
    final BigInteger bigIntQ = BigInteger.valueOf(this.q);
    for (int i = 0; i < this.h_bar_n.length; i++) {
      this.h_bar_n[i] = this.h.mul(powerQ);
      powerQ = powerQ.multiply(bigIntQ);
    }

    // Calculate eta_bar_n.
    this.eta_bar_n = new CurveElement<?, ?>[this.N2()];
    for (int i = 0; i < this.eta_bar_n.length; i++) {
      this.eta_bar_n[i] = (CurveElement<?, ?>) this.eta_n[i].mul(caData.mu_n[i]).getImmutable();
    }

    // Finally we calculate eta_i_j=eta^(1/(mu_i+H(I_i_j)))

    final Crypto crypto = Crypto.getInstance();
    this.eta_n_n = new CurveElement<?, ?>[this.N2()][this.zeta()];

    for (int i = 0; i < this.N2(); i++) {
      for (int j = 0; j < this.zeta(); j++) {
        final BigInteger H_n_m_hash = (new BigInteger(1, crypto.getHash(this.setPolices[i][j].getBytes()))).mod(p);
        final BigIntEuclidean gcd = BigIntEuclidean.calculate(caData.mu_n[i].add(H_n_m_hash).mod(p), p);
        this.eta_n_n[i][j] = (CurveElement<?, ?>) this.eta.mul(gcd.x.mod(p)).getImmutable();
      }
    }
  }

  /**
   * @return Serializes the shared memory to a JSON string.
   */
  public String toJson() {
    final GsonBuilder gsonBuilder = new GsonBuilder();
    gsonBuilder.registerTypeAdapter(CurveElement.class, new GsonUtils.CurveElementSerializer());
    final Gson gson = gsonBuilder.create();

    return gson.toJson(this);
  }

  /**
   * @return The number of items in each set policy.
   */
  public int zeta() {
    return this.setPolices[0].length;
  }
}
