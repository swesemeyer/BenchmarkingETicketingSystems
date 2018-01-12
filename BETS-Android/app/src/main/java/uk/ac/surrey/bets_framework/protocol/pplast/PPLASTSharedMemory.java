package uk.ac.surrey.bets_framework.protocol.pplast;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFPairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.GsonUtils;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.pplast.data.CentralAuthorityData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.PoliceData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.SellerData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.UserData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.VerifierData;

/**
 * Created by swesemeyer on 23/10/17.
 */

public class PPLASTSharedMemory extends NFCAndroidSharedMemory {

  private static final Logger LOG = LoggerFactory.getLogger(PPLASTSharedMemory.class);

  /**
   * static class enumerating the names of the different types of actor in the protocol.
   */
  public static class Actor {
    public static final String CENTRAL_AUTHORITY = "CA";
    public static final String SELLER = "Seller1";
    public static final String USER = "User1";
    public static final String POLICE = "Police1";
    public static final String[] VERIFIERS = {"Verifier0", "Verifier1", "Verifier2", "Verifier3", "Verifier4", "Verifier5", "Verifier_Dummy"};
    public static int dummyVerifierIndx = 6;
  }

  /**
   * Interface defining actor data.
   */
  public interface ActorData {
    Element getPublicKey();
  }

  /**
   * Arbitrary bytes to act as random seed for pairing secure random so that we can re-create the pairing.
   */
  public static final byte[] PAIRING_RANDOM_SEED = PPLASTSharedMemory.class.getSimpleName().getBytes();

  /**
   * The current actor so that access to shared memory can be checked.
   */
  private transient String actor = Actor.CENTRAL_AUTHORITY;

  /**
   * Mapping of actor ID to their data.
   */
  private transient final Map<String, ActorData> actorData = new HashMap<>();

  /**
   * Random element g as a generator of the group G1.
   */
  public CurveElement<?, ?> g = null;

  /**
   * Random element h as a generator of the group G1.
   */
  public CurveElement<?, ?> h = null;

  /**
   * Random element xi as a generator of the group G1.
   */
  public CurveElement<?, ?> xi = null;

  /**
   * Random element h_bar as a generator of the group G1.
   */
  public CurveElement<?, ?> h_tilde = null;

  /**
   * Random element g_frak as a generator of the group G2.
   */
  public CurveElement<?, ?> g_frak = null;

  /**
   * Value of p such that p > 2q^k + 1.
   */
  public BigInteger p = null;

  /**
   * The bilinear group pairing: transient because we cannot serialise it and
   * instead use the parameters and random seed.
   */
  public transient Pairing pairing = null;

  /**
   * The bilinear group pairing parameters.
   */
  public PropertiesParameters pairingParameters = null;

  /**
   * Always pass verification steps?
   */
  public boolean passVerification = false;

  /**
   * Number of r bits in type a elliptic curve - optionally set as a
   * parameter.
   */
  public int rBits = 256;

  /**
   * The name of the first hash algorithm
   */
  public String Hash1 = "RIPEMD256";

  /**
   * The name of the second hash algorithm
   */
  public String Hash2 = "SHA-256";

  /**
   * The name of the third hash algorithm
   */
  public String Hash3 = "BLAKE2B-256";

  /**
   * The public key of the CA
   */

  public CurveElement<?, ?> Y_A = null;


  /**
   * The public key of the Police
   */

  public CurveElement<?, ?> Y_P = null;


  /**
   * The public key of the Seller
   */

  public CurveElement<?, ?> Y_S = null;

  /**
   * Deserialises the shared memory from a JSON string.
   *
   * @param json The JSON to deserialize from.
   * @return The shared memory.
   */
  public static PPLASTSharedMemory fromJson(String json) {
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
    gsonBuilder.registerTypeAdapter(CurveElement.class,
            new GsonUtils.CurveElementSerializer((CurveField<?>) pairing.getG1(), (CurveField<?>) pairing.getG2()));
    gsonBuilder.registerTypeAdapter(CurveElement.class,
            new GsonUtils.CurveElementDeserializer((CurveField<?>) pairing.getG1(), (CurveField<?>) pairing.getG2()));
    gson = gsonBuilder.create();

    // Deserialize and set the pairing.
    final PPLASTSharedMemory sharedMemory = gson.fromJson(json, PPLASTSharedMemory.class);
    sharedMemory.pairing = pairing;

    return sharedMemory;
  }

  /**
   * Change the current actor.
   *
   * @param actorName The new actor.
   */
  public void actAs(String actorName) {
    this.actor = actorName;
  }

  /**
   * Clears out the shared memory except for those parameters set for the
   * state machine.
   */
  public void clear() {
    // Reset the shared parameters. Other parameters are kept as they are required across protocol runs.
    this.actor = Actor.CENTRAL_AUTHORITY;
    this.setBilinearGroup();

    // Set up the public parameters, which need the bilinear group
    this.setPublicParameters();

    // On the server, we only act as the central authority, seller, verifier and the police.
    this.actorData.put(Actor.CENTRAL_AUTHORITY, new CentralAuthorityData(Actor.CENTRAL_AUTHORITY, this.p, this.g_frak));
    this.actorData.put(Actor.SELLER, new SellerData(Actor.SELLER, this.p, this.xi, this.g_frak));
    for (int i = 0; i < Actor.VERIFIERS.length; i++) {
      this.actorData.put(Actor.VERIFIERS[i], new VerifierData(Actor.VERIFIERS[i], this.p, this.xi));
    }
    this.actorData.put(Actor.POLICE, new PoliceData(Actor.POLICE, this.p, this.xi));

    this.Y_A = (CurveElement<?, ?>) this.getPublicKey(Actor.CENTRAL_AUTHORITY);
    this.Y_P = (CurveElement<?, ?>) this.getPublicKey(Actor.POLICE);

  }


  /**
   * return the public key of an actor
   */

  public Element getPublicKey(String actorName) {
    if (actorName.equalsIgnoreCase(Actor.CENTRAL_AUTHORITY)) {
      return this.Y_A;
    } else if (actorName.equalsIgnoreCase(Actor.POLICE)) {
      return this.Y_P;
    } else if (actorName.equalsIgnoreCase(Actor.SELLER)) {
      return this.Y_S;
    } else {
      LOG.debug("illegal argument!: " + actorName);
      return null;
    }
  }

  /**
   * return the trace public key of the seller
   */

  public Element getSellerTraceKey() {
    final SellerData sData = (SellerData) this.actorData.get(Actor.SELLER);
    return sData.getTraceKey();
  }


  /**
   * Clears out the shared memory except for those parameters set for the
   * state machine. For use in the Android implementation.
   */
  public void clearAndroid() {
    // Reset the shared parameters. Other parameters are kept as they are
    // required across protocol runs.
    this.actor = Actor.USER;

    // On Android, we only act as the  user, so do not
    // initialise anything else as it will be populated as we go.
    this.actorData.put(Actor.USER, new UserData(Actor.USER, this.p, this.xi));
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

    // Set up the public parameters, which need the
    // bilinear group
    this.setPublicParameters();

    // During testing we act as everything...
    this.actorData.put(Actor.CENTRAL_AUTHORITY, new CentralAuthorityData(Actor.CENTRAL_AUTHORITY, this.p, this.g_frak));
    this.actorData.put(Actor.SELLER, new SellerData(Actor.SELLER, this.p, this.xi, this.g_frak));
    for (int i = 0; i < Actor.VERIFIERS.length; i++) {
      this.actorData.put(Actor.VERIFIERS[i], new VerifierData(Actor.VERIFIERS[i], this.p, this.xi));
    }
    this.actorData.put(Actor.USER, new UserData(Actor.USER, this.p, this.xi));
    this.actorData.put(Actor.POLICE, new PoliceData(Actor.POLICE, this.p, this.xi));

  }

  /**
   * Convenience method to create a G1 curve element from a byte array.
   *
   * @param bytes The bytes containing the curve element data.
   * @return The new curve element.
   */
  public Element curveG1ElementFromBytes(byte[] bytes) {
    final CurveElement<Element, ?> element = new CurveElement<>((CurveField<?>) this.pairing.getG1());
    element.setFromBytes(bytes);

    return element.getImmutable();
  }

  /**
   * Convenience method to create a String from a byte array.
   *
   * @param bytes The bytes containing the string data.
   * @return The new String.
   */
  public String stringFromBytes(byte[] bytes) {
    final String string = new String(bytes, StandardCharsets.UTF_8);
    return string;
  }



  /**
   * Convenience method to create a G2curve element from a byte array.
   *
   * @param bytes The bytes containing the curve element data.
   * @return The new curve element.
   */
  public Element curveG2ElementFromBytes(byte[] bytes) {
    final CurveElement<Element, ?> element = new CurveElement<>((CurveField<?>) this.pairing.getG2());
    element.setFromBytes(bytes);

    return element.getImmutable();
  }


  /**
   * Gets the data associated with the specified actor.
   *
   * @param actorName The actor to obtain data for.
   * @return The data or null if the current actor does not match the required
   * data.
   */
  public ActorData getData(String actorName) {
    ActorData data = null;

    if (actor == this.actor) {
      data = this.actorData.get(actorName);
    }

    return data;
  }

  /**
   * Convenience method to create a GT finite element from a byte array.
   *
   * @param bytes The bytes containing the GT finite element data.
   * @return The new GT finite element.
   */
  public Element gtFiniteElementFromBytes(byte[] bytes) {
    final Element element = new GTFiniteElement(((TypeFPairing) this.pairing)
            .getPairingMap(),
            (GTFiniteField<?>) this.pairing.getGT());
    element.setFromBytes(bytes);

    return element.getImmutable();
  }

  /**
   * Sets the bilinear group, which must be done before the central authority
   * can be initialised.
   */
  private void setBilinearGroup() {

    // Build an elliptic curve generator that will give us our p (the order r of the generator), and subsequently our bilinear group
    // pairing.
    final SecureRandom prng = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);
    final PairingParametersGenerator<?> generator = new TypeFCurveGenerator(prng, this.rBits);
    this.pairingParameters = (PropertiesParameters) generator.generate();
    this.pairing = PairingFactory.getPairing(this.pairingParameters, prng);
    this.p = this.pairingParameters.getBigInteger("r");
    if (!Crypto.getInstance().isPrime(p)) {
      throw new IllegalStateException("p is not prime: " + this.p);
    }
    LOG.debug("size of G1: " + this.pairing.getG1().getOrder());
    LOG.debug("size of G2: " + this.pairing.getG2().getOrder());
    LOG.debug("size of GT: " + this.pairing.getGT().getOrder());
    LOG.debug("G1==G2 is " + (this.pairing.getG1() == this.pairing.getG2()));
  }

  /**
   * Sets the public parameters based upon the central authorities private
   * data.
   */
  private void setPublicParameters() {
    // Generate the required elements from the pairing. Note that CurveElement is used instead of Element for deserialization with
    // Gson.

    // create some random generators for G1
    this.g = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.h = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.h_tilde = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();
    this.xi = (CurveElement<?, ?>) this.pairing.getG1().newRandomElement().getImmutable();

    // create some random generator for G2
    this.g_frak = (CurveElement<?, ?>) this.pairing.getG2().newRandomElement().getImmutable();

  }

  /**
   * @return Serializes the shared memory to a JSON string.
   */
  public String toJson() {
    final GsonBuilder gsonBuilder = new GsonBuilder();
    gsonBuilder.registerTypeAdapter(CurveElement.class,
            new GsonUtils.CurveElementSerializer((CurveField<?>) this.pairing.getG1(), (CurveField<?>) this.pairing.getG2()));
    final Gson gson = gsonBuilder.create();

    return gson.toJson(this);
  }
}
