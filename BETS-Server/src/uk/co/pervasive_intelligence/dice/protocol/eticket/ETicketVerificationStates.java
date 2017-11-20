/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.eticket;

import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.data.ListData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * Ticket verification states of the e-ticket state machine protocol.
 *
 * @author Matthew Casey
 */
public class ETicketVerificationStates {

  /**
   * State 7.
   */
  public static class VState07 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the ticket from the user.
        return new Action<>(Status.CONTINUE, 8, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 8.
   */
  public static class VState08 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Verify the ticket and send back the result.
        final byte[] data = this.verifyTicket(message.getData());

        if (data != null) {
          LOG.debug("verify ticket complete");
          return new Action<>(Status.CONTINUE, 9, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }

    /**
     * Verifies the ticket.
     *
     * @param data The ticket data.
     * @return The response to the verification.
     */
    private byte[] verifyTicket(byte[] data) {
      final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      final Crypto crypto = Crypto.getInstance();
      byte[] response = null;

      // Extract out the ticket data and accumulated service cost.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 2) {
        return null;
      }

      final byte[] TStarData = listData.getList().get(0);
      sharedMemory.i = new BigInteger(listData.getList().get(1)).intValue(); // Hopefully i isn't too big for int.

      // Extract out the fields of the ticket for verification.
      final ListData listTStarData = ListData.fromBytes(TStarData);

      if (listTStarData.getList().size() != 9) {
        return null;
      }

      sharedMemory.Sn = listTStarData.getList().get(0);
      sharedMemory.Sv = listTStarData.getList().get(1);
      sharedMemory.PseuU = listTStarData.getList().get(2);
      final byte[] Tv = listTStarData.getList().get(3);
      final byte[] Ti = listTStarData.getList().get(4);
      sharedMemory.hrIn = listTStarData.getList().get(5);
      sharedMemory.hrUn = listTStarData.getList().get(6);
      final byte[] deltaTP = listTStarData.getList().get(7);
      final byte[] sigIT = listTStarData.getList().get(8);

      // 1. Verifies the ticket signature, T.Sv, T.Ti and T.Tv (these latter not checked as they are arbitrary).
      final ListData T = new ListData(Arrays.asList(sharedMemory.Sn, sharedMemory.Sv, sharedMemory.PseuU, Tv, Ti,
          sharedMemory.hrIn, sharedMemory.hrUn, deltaTP));
      final byte[] TData = T.toBytes();

      final byte[] hashT = crypto.getHash(TData);
      final byte[] hashTCheck = crypto.decrypt(sigIT, crypto.getPublicKey());

      final boolean result = (sigIT != null) && (hashT != null) && (hashTCheck != null) && (Arrays.equals(hashTCheck, hashT));

      // 2. If the verification fails, abort.
      if (!result) {
        return null;
      }

      // 3. Look for TStar in the database using T.Sn. We don't have a database, so we assume that we just use j, which will default
      // to 0 at the end of ticket purchase (see end of ETicketPurchaseStates.State06#getTicket).
      // When j = 0, hrUn = hrUn-j.

      // Extract K and rI from deltaTP.
      final byte[] kappaStar = crypto.decrypt(deltaTP, crypto.getPrivateKey());
      final ListData kappaStarData = ListData.fromBytes(kappaStar);

      if (kappaStarData.getList().size() != 2) {
        return null;
      }

      final ListData kappaData = ListData.fromBytes(kappaStarData.getList().get(0));

      if (kappaData.getList().size() != 2) {
        return null;
      }

      sharedMemory.K = kappaData.getList().get(0);
      sharedMemory.rI = new BigInteger(kappaData.getList().get(1));

      // 3a. if (i > j):
      final byte[] tau1 = new byte[] { 3, 3, 3, 3 }; // Arbitrary verification time stamp.

      if ((sharedMemory.i > sharedMemory.j) && (sharedMemory.i <= sharedMemory.n)) { // Check for i <= n added.
        // 3ai. Compute APi.
        final byte[] hK = crypto.getHash(sharedMemory.K);
        final byte[] hrIni = crypto.getHash(sharedMemory.rI.toByteArray(), sharedMemory.n - sharedMemory.i);
        sharedMemory.APi = Crypto.xor(crypto.getPRNGRandom(hK, hrIni.length), hrIni);

        // 3aii. Encrypt APi.
        final byte[] encAPi = crypto.encrypt(sharedMemory.APi, crypto.getPublicKey());

        // 3aiii. Stores APi.
        // Already done.

        // 3aiv. Assigns Vsucc and VsuccStar.
        final byte[] flag1 = new byte[] { 1 }; // Arbitrary flag.
        final ListData Vsucc = new ListData(Arrays.asList(sharedMemory.Sn, flag1, tau1, encAPi, BigInteger.valueOf(sharedMemory.j)
            .toByteArray()));
        final byte[] VsuccData = Vsucc.toBytes();

        final byte[] hashVsuccData = crypto.getHash(VsuccData);
        final byte[] sigPVsucc = crypto.encrypt(hashVsuccData, crypto.getPrivateKey());

        final ListData VsuccStarData = new ListData(Arrays.asList(VsuccData, sigPVsucc));
        final byte[] VsuccStar = VsuccStarData.toBytes();

        // 3av. Sends m2 = VsuccStar.
        response = VsuccStar;
      }
      // 3b. if (i <= j):
      else {
        LOG.info("verify ticket failed - ticket invalid: i = {}; j = {}, n = {}", sharedMemory.i, sharedMemory.j, sharedMemory.n);

        // 3bi. Compute hrIni based on hrUn.
        final byte[] hrUni = crypto.getHash(sharedMemory.hrUn, sharedMemory.j - sharedMemory.i);

        // 3bii. Assigns Vfail and VfailStar. Note data re-ordered from specification to allow consistent unpacking in the client.
        final byte[] flag0 = new byte[] { 0 }; // Arbitrary flag.
        final ListData Vfail = new ListData(Arrays.asList(sharedMemory.Sn, flag0, tau1, hrUni, BigInteger.valueOf(sharedMemory.i)
            .toByteArray()));
        final byte[] VfailData = Vfail.toBytes();

        final byte[] hashVfailData = crypto.getHash(VfailData);
        final byte[] sigPVfail = crypto.encrypt(hashVfailData, crypto.getPrivateKey());

        final ListData VfailStarData = new ListData(Arrays.asList(VfailData, sigPVfail));
        final byte[] VfailStar = VfailStarData.toBytes();

        // 3biii. Sends m2 = VfailStar.
        response = VfailStar;
      }

      return response;
    }
  }

  /**
   * State 9.
   */
  public static class VState09 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Gets the show proof response.
        return new Action<>(Status.CONTINUE, 10, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 10.
   */
  public static class VState10 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Verify the proof and send back the result.
        final byte[] data = this.verifyProof(message.getData());

        if (data != null) {
          LOG.debug("verify proof complete");

          // If we have more iterations of ticket verification to do, then go back to the start of verification, otherwise end.
          final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
          int nextState = 11;

          if (sharedMemory.j < sharedMemory.n) {
            nextState = 7;
          }

          return new Action<>(Status.CONTINUE, nextState, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }

    /**
     * Verifies the proof.
     *
     * @param data The proof data.
     * @return The response to the verification.
     */
    private byte[] verifyProof(byte[] data) {
      final ETicketSharedMemory sharedMemory = (ETicketSharedMemory) this.getSharedMemory();
      final Crypto crypto = Crypto.getInstance();

      // 1. If hrUni is not received. We have received it because, although this could happen independently of the receipt (or not)
      // of hrUni, we are running it sequentially.
      // Ignore - not doing claims.

      // 2. Obtains T.Sn and computes hrUni.
      final ListData m3Data = ListData.fromBytes(data);

      if (m3Data.getList().size() != 2) {
        return null;
      }

      final byte[] Sn = m3Data.getList().get(0);
      final byte[] AUi = m3Data.getList().get(1);
      final byte[] hrUni = Crypto.xor(AUi, crypto.getPRNGRandom(sharedMemory.K, AUi.length));

      // Make sure we have a hrUnCurrent the first time round a ticket is used.
      if (sharedMemory.hrUnCurrent == null) {
        sharedMemory.hrUnCurrent = sharedMemory.hrUn;
      }

      // 3. Verifies hrUn.
      if (!Arrays.equals(sharedMemory.hrUnCurrent, crypto.getHash(hrUni, sharedMemory.s))) {
        LOG.info("verify proof failed - ticket invalid?");
        return null;
      }

      // 4. If hrUn does not match.
      // Ignore - not doing claims.

      // 5. Generates tau2. Note no need to verify ticket expiry or tau1.
      final byte[] tau2 = new byte[] { 3, 3, 3, 3 }; // Arbitrary verification time stamp.

      // 6. Generates R and RStar with APi and tau2.
      final ListData R = new ListData(Arrays.asList(sharedMemory.APi, Sn, tau2));
      final byte[] RData = R.toBytes();

      final byte[] hashRData = crypto.getHash(RData);
      final byte[] sigPR = crypto.encrypt(hashRData, crypto.getPrivateKey());

      final ListData RStarData = new ListData(Arrays.asList(RData, sigPR));

      // 7. Stores and updates.
      sharedMemory.RStar = RStarData.toBytes();
      sharedMemory.hrUnCurrent = hrUni;
      sharedMemory.j = sharedMemory.i;

      // Sends m4 = RStarData.
      return sharedMemory.RStar;
    }
  }

  /**
   * State 11.
   */
  public static class VState11 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        if (NFC.getInstance().isOpen()) {
          return new Action<>(Action.NO_STATE_CHANGE, NFCReaderCommand.CLOSE);
        }
        else {
          return new Action<>(Status.END_SUCCESS, 0, null, null, 0);
        }
      }

      return super.getAction(message);
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ETicketVerificationStates.class);
}
