package uk.ac.surrey.bets_framework.protocol.pplast;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.pplast.data.PoliceData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.SellerData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.TicketDetails;
import uk.ac.surrey.bets_framework.protocol.pplast.data.VerifierData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

public class PPLASTVerifyingStates {

  // return new Action<>(Status.END_SUCCESS, 0, NFCReaderCommand.PUT, data, 0);
  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPLASTVerifyingStates.class);

  /**
   * State 25:
   * As Verifier: send the ID
   */
  public static class VState25 extends State<NFCReaderCommand> {

    private String[] verifiers;
    private int      index;

    public VState25(String[] verifiers) {
      LOG.debug("Verifiers: " + verifiers.length);
      this.verifiers = verifiers;
      this.index = 0;
    }

    private byte[] generateVerifierID(String verifierName) {
      LOG.debug("Acting as verifier: " + verifierName);
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      sharedMemory.actAs(verifierName);
      final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierName);
      LOG.debug("Verifier Name, ID = " + verifierName + ", " + verifierData.ID_V);
      final ListData sendData = new ListData(Arrays.asList(verifierData.ID_V.getBytes(StandardCharsets.UTF_8)));
      LOG.debug("Verifier ID = " + verifierData.ID_V);
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
      LOG.debug("reached the verifying state - meesage type is " + message.getType());
      if (message.getType() == Type.SUCCESS) {

        // Obtain the verifier ID_V and send it to the client.
        final byte[] data = this.generateVerifierID(this.verifiers[this.index]);

        if (data != null) {
          LOG.debug("sending verifier details");
          this.index++;
          return new Action<>(Status.CONTINUE, 26, NFCReaderCommand.PUT, data, 0);
        }
      }
      return super.getAction(message);
    }
  }

  /**
   * State 26
   * get the user's ticket proof
   */
  public static class VState26 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the user's ticket request data.
        return new Action<>(Status.CONTINUE, 27, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 27
   * As verifier: verify the ticket
   */
  public static class VState27 extends State<NFCReaderCommand> {

    private String[] verifiers;
    private int      index;

    public VState27(String[] verifiers) {
      this.verifiers = verifiers;
      this.index = 0;
    }

    private boolean verifyTicketProof(byte[] data, String verifierID) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final VerifierData verifierData = (VerifierData) sharedMemory.getData(verifierID);
      final Crypto crypto = Crypto.getInstance();
      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);
      if (listData.getList().size() != 14) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }
      // some constants from shared Memory
      final BigInteger p = sharedMemory.p;
      final Element xi = sharedMemory.xi.getImmutable();
      final Element g = sharedMemory.g.getImmutable();
      final Element h = sharedMemory.h.getImmutable();
      final Element h_tilde = sharedMemory.h_tilde.getImmutable();
      final Element g_frak = sharedMemory.g_frak.getImmutable();
      final Element Y_P = sharedMemory.getPublicKey(Actor.POLICE).getImmutable();
      final Element Y_S = sharedMemory.getPublicKey(Actor.SELLER).getImmutable();

      // get the elements needed for the ZKP
      int index = 0;
      final Element P_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element P_dash_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element Q_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element Q_dash_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final byte[] c_Vhash = listData.getList().get(index++);
      final BigInteger c_Vnum = (new BigInteger(1, c_Vhash)).mod(p);
      final BigInteger x_hat_U = (new BigInteger(1, listData.getList().get(index++))).mod(p);
      final BigInteger z_hat_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);

      final byte[] verifyc_Vhash = crypto.getHash(
          (new ListData(Arrays.asList(P_V.toBytes(), P_dash_V.toBytes(), Q_V.toBytes(), Q_dash_V.toBytes()))).toBytes(),
          sharedMemory.Hash1);
      if (!Arrays.equals(c_Vhash, verifyc_Vhash)) {
        LOG.debug("c_Vhash verification failed");
        return false;
      }

      LOG.debug("passed c_Vhash verification");

      final Element P_dash_Vlhs = (((xi.mul(x_hat_U)).add(Y_P.mul(z_hat_V))).add(P_V.mul(c_Vnum))).getImmutable();
      LOG.debug("P_dash_Vlhs = " + P_dash_Vlhs);
      if (!P_dash_V.isEqual(P_dash_Vlhs)) {
        LOG.debug("P_dash_V verification failed");
        return false;
      }
      LOG.debug("passed P_dash_V verification");

      final Element Q_dash_Vlhs = ((xi.mul(z_hat_V)).add(Q_V.mul(c_Vnum))).getImmutable();
      if (!Q_dash_V.isEqual(Q_dash_Vlhs)) {
        LOG.debug("Q_dash_V verification failed");
        return false;
      }

      LOG.debug("passed Q_dash_V verification. This completes the ZKP.");

      // get the elements for the remaining checks

      final Element E_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element F_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element K_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final byte[] s_Vhash = listData.getList().get(index++);
      final BigInteger s_Vnum = (new BigInteger(1, s_Vhash)).mod(p);
      final BigInteger w_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);
      final BigInteger e_V = (new BigInteger(1, listData.getList().get(index++))).mod(p);
      final Element sigma_V = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));

      final ListData s_Vdata = new ListData(Arrays.asList(P_V.toBytes(), Q_V.toBytes(), E_V.toBytes(), F_V.toBytes(), K_V.toBytes(),
          SellerData.TICKET_TEXT.getBytes()));
      final byte[] s_Vrhs = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
      if (!Arrays.equals(s_Vhash, s_Vrhs)) {
        LOG.debug("s_V hash verification failed!");
        return false;
      }
      LOG.debug("passed s_V hash verification!");

      final Element F_Vrhs = (E_V.mul(verifierData.x_V)).getImmutable();
      if (!F_V.isEqual(F_Vrhs)) {
        LOG.debug("F_V verification failed!");
        return false;
      }
      LOG.debug("passed F_V verification!");

      final Element lhs = sharedMemory.pairing.pairing(sigma_V, Y_S.add(g_frak.mul(e_V))).getImmutable();
      final Element rhs = sharedMemory.pairing.pairing(g.add(h.mul(w_V)).add(h_tilde.mul(s_Vnum)), g_frak);
      if (!lhs.isEqual(rhs)) {
        LOG.debug("pairing verification failed!");
        return false;
      }
      LOG.debug("passed pairing verification! Ticket is valid");
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
      String currentVerifier = this.verifiers[this.index];
      sharedMemory.actAs(currentVerifier);
      LOG.debug("Acting as verifier: " + currentVerifier);
      sharedMemory.actAs(currentVerifier);
      if (message.getType() == Type.DATA) {
        // check the ticket proof
        if (this.verifyTicketProof(message.getData(), currentVerifier)) {
          this.index++;
          if (this.index < this.verifiers.length) {
            // keep checking with a different identifier
            LOG.debug("there are more ticket verifiers!");
            return new Action<>(25);
          }
          else {
            LOG.debug("finished the ticket proof verification");
            return new Action<>(28);
          }
        }
      }
      return super.getAction(message);
    }
  }

  /**
   * State 28
   * get the user's ticket
   */
  public static class VState28 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {

      if (message.getType() == Type.SUCCESS) {
        // Get the user's ticket request data.
        LOG.debug("Getting the user's ticket now. This is a the police request");
        return new Action<>(Status.CONTINUE, 29, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 29
   * extract the verifier IDs from the ticket
   */
  public static class VState29 extends State<NFCReaderCommand> {

    private boolean extractVerifierIDs(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final PoliceData policeData = (PoliceData) sharedMemory.getData(Actor.POLICE);
      final Crypto crypto = Crypto.getInstance();
      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);
      if ((listData.getList().size() - 5) % 11 != 0) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }
      int numOfVerifiers = (listData.getList().size() - 4) / 11;
      TicketDetails ticketDetails = new TicketDetails(numOfVerifiers);
      ticketDetails.populateTicketDetails(sharedMemory, listData, 0);

      Element Y_U_1 = null;
      Element Y_U_2 = null;

      Y_U_1 = ticketDetails.P_V[0].div(ticketDetails.Q_V[0].mul(policeData.x_P)).getImmutable();
      for (int i = 1; i < numOfVerifiers; i = i + 2) {
        Y_U_2 = ticketDetails.P_V[i].div(ticketDetails.Q_V[i].mul(policeData.x_P)).getImmutable();
        if (!Y_U_1.equals(Y_U_2)) {
          LOG.debug("ticket verification of Y_U failed");
          return false;
        }
        else {
          Y_U_1 = Y_U_2;
        }
      }

      LOG.debug("The user has public key: " + Y_U_1);

      final Element Y_bar_S = sharedMemory.getPublicKey(Actor.SELLER).getImmutable();
      final Element g_frak = sharedMemory.g_frak.getImmutable();
      final Element g = sharedMemory.g.getImmutable();
      final Element h = sharedMemory.h.getImmutable();
      final Element h_tilde = sharedMemory.h_tilde.getImmutable();
      final BigInteger p = sharedMemory.p;

      for (int i = 0; i < numOfVerifiers; i++) {
        final byte[] verifys_V = crypto.getHash((new ListData(
            Arrays.asList(ticketDetails.P_V[i].toBytes(), ticketDetails.Q_V[i].toBytes(), ticketDetails.E_V[i].toBytes(),
                ticketDetails.F_V[i].toBytes(), ticketDetails.K_V[i].toBytes(), ticketDetails.ticketText.getBytes()))).toBytes(),
            sharedMemory.Hash1);
        if (!Arrays.equals(ticketDetails.s_V[i], verifys_V)) {
          LOG.error("failed to verify s_V[" + i + "] for verifier: " + ticketDetails.VerifierList[i]);
          return false;
        }
        final BigInteger s_Vnum = (new BigInteger(1, verifys_V)).mod(p);
        final Element lhs = sharedMemory.pairing.pairing(ticketDetails.sigma_V[i], Y_bar_S.add(g_frak.mul(ticketDetails.e_v[i])))
            .getImmutable();
        final Element rhs = sharedMemory.pairing.pairing(g.add(h.mul(ticketDetails.w_v[i])).add(h_tilde.mul(s_Vnum)), g_frak);
        if (!lhs.isEqual(rhs)) {
          LOG.debug("first pairing check failed for ID_V[" + i + "]: " + ticketDetails.VerifierList[i]);
        }

      }
      LOG.debug("passed s_V hash and corresponding pairing checks!");

      final List<byte[]> verifys_PData = new ArrayList<>();
      for (int i = 0; i < numOfVerifiers; i++) {
        verifys_PData.add(ticketDetails.s_V[i]);
      }

      if (!Arrays.equals(ticketDetails.s_P, crypto.getHash((new ListData(verifys_PData)).toBytes(), sharedMemory.Hash1))) {
        LOG.error("failed to verify s_P hash");
        return false;
      }
      LOG.debug("passed s_P hash checks!");

      final BigInteger s_PNum = (new BigInteger(1, ticketDetails.s_P)).mod(p);

      final Element lhs = (sharedMemory.pairing.pairing(ticketDetails.sigma_P, Y_bar_S.add(g_frak.mul(ticketDetails.e_P))))
          .getImmutable();
      final Element rhs = (sharedMemory.pairing.pairing(g.add(h.mul(ticketDetails.w_P)).add(h_tilde.mul(s_PNum)), g_frak))
          .getImmutable();

      if (!lhs.isEqual(rhs)) {
        LOG.error("failed to verify sigma_P pairing check");
        return false;
      }

      LOG.debug("Passed sigma_P pairing verification!");

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
      LOG.debug("Acting as police!");

      if (message.getType() == Type.DATA) {
        LOG.debug("We should have the ticket details now");
        if (message.getData() != null) {

          if (this.extractVerifierIDs(message.getData())) {
            LOG.debug("Successfully extracted all the  verifier details from the ticket");
            // Close the reader and end the protocol
            LOG.debug("Closing the reader...");
            return new Action<>(Action.NO_STATE_CHANGE, NFCReaderCommand.CLOSE);
          }
        }
      }
      LOG.debug("We should have closed the reader now - ending the protocol");
      if (message.getType() == Type.SUCCESS) {
        return new Action<>(Status.END_SUCCESS, 0, null, null, 0);
      }

      return super.getAction(message);
    }
  }
}