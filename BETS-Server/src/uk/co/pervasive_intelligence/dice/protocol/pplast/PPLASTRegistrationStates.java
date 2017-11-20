/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.pplast;

import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.Crypto.BigIntEuclidean;
import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.protocol.pplast.data.CentralAuthorityData;
import uk.co.pervasive_intelligence.dice.protocol.pplast.data.PoliceData;
import uk.co.pervasive_intelligence.dice.protocol.pplast.data.SellerData;
import uk.co.pervasive_intelligence.dice.protocol.pplast.data.VerifierData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * Registration states of the PPETS-FGP state machine protocol.
 *
 * @author Steve Wesemeyer
 */
public class PPLASTRegistrationStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPLASTRegistrationStates.class);

  /**
   * State 04:
   * As Seller: generate the seller identity
   */
  public static class RState04 extends State<NFCReaderCommand> {

    private byte[] generateSellerIdentity() {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);

      // Send ID_S, Y_S, Y_S_bar
      final ListData sendData = new ListData(
          Arrays.asList(sellerData.ID_S.getBytes(), sellerData.Y_S.toBytes(), sellerData.Y_bar_S.toBytes()));
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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.SELLER);
      if (message.getType() == Type.SUCCESS) {
        // Send the setup data.
        final byte[] data = this.generateSellerIdentity();

        if (data != null) {
          return new Action<>(Status.CONTINUE, 5, NFCReaderCommand.PUT_INTERNAL, data, 0);
        }
      }

      return super.getAction(message);
    }

  }

  /**
   * State 05:
   * As Central Authority: get the data from the seller
   */
  public static class RState05 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);

      // Get the seller identity data.
      return new Action<>(Status.CONTINUE, 6, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 06:
   * As Central Authority:
   * generate the seller credentials and send them to the seller
   */
  public static class RState06 extends State<NFCReaderCommand> {

    private byte[] generateSellerCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);
      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }
      final Element ID_S = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final Element Y_S = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));
      final Element Y_bar_S = sharedMemory.curveG2ElementFromBytes(listData.getList().get(2));

      // compute sigma_s
      final BigInteger e_S = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_S = crypto.secureRandom(sharedMemory.p);
      final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_S).mod(sharedMemory.p), sharedMemory.p);
      final Element sigma_S = (sharedMemory.g.add(sharedMemory.h.mul(r_S)).add(Y_S)).mul(gcd.x.mod(sharedMemory.p)).getImmutable();

      centralAuthorityData.ID_S = ID_S;
      centralAuthorityData.Y_S = Y_S;
      centralAuthorityData.Y_bar_S = Y_bar_S;
      centralAuthorityData.r_S = r_S;
      centralAuthorityData.e_S = e_S;
      centralAuthorityData.sigma_S = sigma_S;

      // Send sigma_s, e_s, r_s
      final ListData sendData = new ListData(Arrays.asList(sigma_S.toBytes(), r_S.toByteArray(), e_S.toByteArray()));
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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final byte[] data = this.generateSellerCredentials(message.getData());
        if (data != null) {
          return new Action<>(Status.CONTINUE, 7, NFCReaderCommand.PUT_INTERNAL, data, 0);
        }
      }
      return super.getAction(message);
    }
  }

  /**
   * State 07
   * As seller:
   * Get the data from the Central Authority
   */
  public static class RState07 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {

      // Get the seller credentials data.
      return new Action<>(Status.CONTINUE, 8, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 08
   * As seller: verify the Central Authority's data and store the seller's credentials
   */
  public static class RState08 extends State<NFCReaderCommand> {

    private boolean verifySellerCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final SellerData sellerData = (SellerData) sharedMemory.getData(Actor.SELLER);

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);
      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }
      final Element sigma_S = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final BigInteger r_S = new BigInteger(listData.getList().get(1));
      final BigInteger e_S = new BigInteger(listData.getList().get(2));

      // verify the credentials
      // get the public key of the CA
      final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);
      final Element lhs = sharedMemory.pairing.pairing(sigma_S, Y_A.add(sharedMemory.g_frak.mul(e_S))).getImmutable();
      final Element rhs = sharedMemory.pairing
          .pairing(sharedMemory.g.add(sharedMemory.h.mul(r_S)).add(sellerData.Y_S), sharedMemory.g_frak).getImmutable();

      if (!lhs.isEqual(rhs)) {
        return false;
      }

      sellerData.e_S = e_S;
      sellerData.r_S = r_S;
      sellerData.sigma_S = sigma_S;
      return true;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.SELLER);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final boolean success = this.verifySellerCredentials(message.getData());
        if (success) {
          LOG.debug("Successfully registered seller!");
          return new Action<>(9);
        }
      }
      return super.getAction(message);
    }
  }

  /**
   * State 09
   * As Central Authority: get the user's identity
   */

  public static class RState09 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {

      // Get the user's identity data.
      LOG.debug("Getting the user's identity details");
      return new Action<>(Status.CONTINUE, 10, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 10:
   * As Central Authority:
   * generate the user's credentials and send them to the user
   */
  public static class RState10 extends State<NFCReaderCommand> {

    private byte[] generateUserCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 2) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      final Element ID_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final Element Y_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));
      //store the user's public key in the sharedMemory
      sharedMemory.Y_U=(CurveElement<?, ?>)Y_U.getImmutable();

      // compute sigma_v
      final BigInteger e_U = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_U = crypto.secureRandom(sharedMemory.p);
      final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_U).mod(sharedMemory.p), sharedMemory.p);

      final Element sigma_U = (sharedMemory.g.add(sharedMemory.h.mul(r_U)).add(Y_U)).mul(gcd.x.mod(sharedMemory.p)).getImmutable();

      centralAuthorityData.ID_U = ID_U;
      centralAuthorityData.Y_U = Y_U;
      centralAuthorityData.r_U = r_U;
      centralAuthorityData.e_U = e_U;
      centralAuthorityData.sigma_U = sigma_U;

      // Send sigma_s, e_s, r_s
      final ListData sendData = new ListData(Arrays.asList(sigma_U.toBytes(), r_U.toByteArray(), e_U.toByteArray()));

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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
      if (message.getType() == Type.DATA) {
        if (message.getData() != null) {
          final byte[] data = this.generateUserCredentials(message.getData());
          LOG.debug("Generated the user's credentials");
          // Send the setup data.
          if (data != null) {
            return new Action<>(Status.CONTINUE, 11, NFCReaderCommand.PUT, data, 0);
          }
        }
      }
      return super.getAction(message);
    }
  }

  /**
   * State 11
   */
  public static class RState11 extends State<NFCReaderCommand> {

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
        LOG.debug("successfully registered user via NFC");
        return new Action<>(12);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 12:
   * As Police: generate the police identity
   */
  public static class RState12 extends State<NFCReaderCommand> {

    private byte[] generatePoliceIdentity() {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final PoliceData policeData = (PoliceData) sharedMemory.getData(Actor.POLICE);

      // Send ID_U, Y_U
      final ListData sendData = new ListData(Arrays.asList(policeData.ID_P.getBytes(), policeData.Y_P.toBytes()));
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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.POLICE);
      if (message.getType() == Type.SUCCESS) {
        // Send the setup data.
        final byte[] data = this.generatePoliceIdentity();

        if (data != null) {
          LOG.debug("sending police identity data");
          return new Action<>(Status.CONTINUE, 13, NFCReaderCommand.PUT_INTERNAL, data, 0);
        }
      }

      return super.getAction(message);
    }

  }

  /**
   * State 13:
   * As Central Authority: get the data from the police
   */
  public static class RState13 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      LOG.debug("getting police identity data");
      return new Action<>(Status.CONTINUE, 14, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 14:
   * As Central Authority:
   * generate the police credentials and send them to the police
   */
  public static class RState14 extends State<NFCReaderCommand> {

    private byte[] generatePoliceCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();

      final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 2) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      final Element ID_P = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final Element Y_P = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));

      // compute sigma_P
      final BigInteger e_P = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_P = crypto.secureRandom(sharedMemory.p);
      final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_P).mod(sharedMemory.p), sharedMemory.p);

      final Element sigma_P = (sharedMemory.g.add(sharedMemory.h.mul(r_P)).add(Y_P)).mul(gcd.x.mod(sharedMemory.p)).getImmutable();

      centralAuthorityData.ID_P = ID_P;
      centralAuthorityData.Y_P = Y_P;
      centralAuthorityData.r_P = r_P;
      centralAuthorityData.e_P = e_P;
      centralAuthorityData.sigma_P = sigma_P;

      // Send sigma_s, e_s, r_s
      final ListData sendData = new ListData(Arrays.asList(sigma_P.toBytes(), r_P.toByteArray(), e_P.toByteArray()));

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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final byte[] data = this.generatePoliceCredentials(message.getData());

        if (data != null) {
          LOG.debug("sending police credentials data");
          return new Action<>(Status.CONTINUE, 15, NFCReaderCommand.PUT_INTERNAL, data, 0);
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 15
   * As police:
   * Get the data from the Central Authority
   */
  public static class RState15 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {

      LOG.debug("getting police credential data");
      return new Action<>(Status.CONTINUE, 16, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 16
   * As police: verify the Central Authority's data and store the police's credentials
   */
  public static class RState16 extends State<NFCReaderCommand> {

    private boolean verifyPoliceCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final PoliceData policeData = (PoliceData) sharedMemory.getData(Actor.POLICE);

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      final Element sigma_P = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final BigInteger r_P = new BigInteger(listData.getList().get(1));
      final BigInteger e_P = new BigInteger(listData.getList().get(2));

      // verify the credentials

      // get the public key of the CA
      final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

      final Element lhs = sharedMemory.pairing.pairing(sigma_P, Y_A.add(sharedMemory.g_frak.mul(e_P))).getImmutable();
      final Element rhs = sharedMemory.pairing
          .pairing(sharedMemory.g.add(sharedMemory.h.mul(r_P)).add(policeData.Y_P), sharedMemory.g_frak).getImmutable();

      if (!lhs.isEqual(rhs)) {
        return false;
      }

      policeData.e_P = e_P;
      policeData.r_P = r_P;
      policeData.sigma_P = sigma_P;
      return true;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.POLICE);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final boolean success = this.verifyPoliceCredentials(message.getData());

        if (success) {
          LOG.debug("Successfully registered police details!");
          return new Action<>(17);
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 17:
   * As Verifier: generate the verifier identity
   */
  public static class RState17 extends State<NFCReaderCommand> {

    private String[] verifiers;
    private int      index;

    public RState17(String[] verifiers) {
      this.verifiers = verifiers;
      this.index = 0;
    }

    private byte[] generateVerifierIdentity() {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final VerifierData verifierData = (VerifierData) sharedMemory.getData(this.verifiers[this.index]);
      // Send ID_V, Y_V
      final ListData sendData = new ListData(Arrays.asList(verifierData.ID_V.getBytes(), verifierData.Y_V.toBytes()));
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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.VERIFIER[this.index]);
      if (message.getType() == Type.SUCCESS) {
        // Send the setup data.
        final byte[] data = this.generateVerifierIdentity();

        if (data != null) {
          LOG.debug("sending verifier identity data for " + Actor.VERIFIER[this.index]);
          this.index++;
          return new Action<>(Status.CONTINUE, 18, NFCReaderCommand.PUT_INTERNAL, data, 0);
        }
      }

      return super.getAction(message);
    }

  }

  /**
   * State 18:
   * As Central Authority: get the data from the police
   */
  public static class RState18 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      LOG.debug("getting verifier identity data");
      return new Action<>(Status.CONTINUE, 19, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 19:
   * As Central Authority:
   * generate the verifier credentials and send them to the police
   */
  public static class RState19 extends State<NFCReaderCommand> {

    private byte[] generateVerifierCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();

      final CentralAuthorityData centralAuthorityData = (CentralAuthorityData) sharedMemory.getData(Actor.CENTRAL_AUTHORITY);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 2) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      final Element ID_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final Element Y_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(1));

      // compute sigma_v
      final BigInteger e_V = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_V = crypto.secureRandom(sharedMemory.p);
      final BigIntEuclidean gcd = BigIntEuclidean.calculate(centralAuthorityData.x_a.add(e_V).mod(sharedMemory.p), sharedMemory.p);

      final Element sigma_V = (sharedMemory.g.add(sharedMemory.h.mul(r_V)).add(Y_V)).mul(gcd.x.mod(sharedMemory.p)).getImmutable();

      centralAuthorityData.ID_V = ID_V;
      centralAuthorityData.Y_V = Y_V;
      centralAuthorityData.r_V = r_V;
      centralAuthorityData.e_V = e_V;
      centralAuthorityData.sigma_V = sigma_V;

      // Send sigma_V, e_V, r_V
      final ListData sendData = new ListData(Arrays.asList(sigma_V.toBytes(), r_V.toByteArray(), e_V.toByteArray()));

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
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(Actor.CENTRAL_AUTHORITY);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final byte[] data = this.generateVerifierCredentials(message.getData());

        if (data != null) {
          LOG.debug("sending verifier credentials data");
          return new Action<>(Status.CONTINUE, 20, NFCReaderCommand.PUT_INTERNAL, data, 0);
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 20
   * As verifier:
   * Get the data from the Central Authority
   */
  public static class RState20 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {

      LOG.debug("getting verifier credential data");
      return new Action<>(Status.CONTINUE, 21, NFCReaderCommand.GET_INTERNAL, null, NFC.USE_MAXIMUM_LENGTH);
    }
  }

  /**
   * State 21
   * As verifier: verify the Central Authority's data and store the verifier's credentials
   */
  public static class RState21 extends State<NFCReaderCommand> {

    private String[] verifiers;
    private int      index;

    public RState21(String[] verifiers) {
      this.verifiers = verifiers;
      this.index = 0;
    }

    private boolean verifyVerifierCredentials(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final VerifierData verifierData = (VerifierData) sharedMemory.getData(this.verifiers[index]);

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      final Element sigma_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final BigInteger r_V = new BigInteger(listData.getList().get(1));
      final BigInteger e_V = new BigInteger(listData.getList().get(2));

      // verify the credentials

      // get the public key of the CA
      final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

      final Element lhs = sharedMemory.pairing.pairing(sigma_V, Y_A.add(sharedMemory.g_frak.mul(e_V))).getImmutable();
      final Element rhs = sharedMemory.pairing
          .pairing(sharedMemory.g.add(sharedMemory.h.mul(r_V)).add(verifierData.Y_V), sharedMemory.g_frak).getImmutable();

      if (!lhs.isEqual(rhs)) {
        return false;
      }

      verifierData.e_V = e_V;
      verifierData.r_V = r_V;
      verifierData.sigma_V = sigma_V;
      return true;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(this.verifiers[index]);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final boolean success = this.verifyVerifierCredentials(message.getData());

        if (success) {
          LOG.debug("Successfully registered verifier details for " + this.verifiers[index]);
          this.index++;
          if (this.index == this.verifiers.length) {
            return new Action<>(22);
          }
          else {
            return new Action<>(17);
          }
        }
      }
      return super.getAction(message);
    }
  }

}
