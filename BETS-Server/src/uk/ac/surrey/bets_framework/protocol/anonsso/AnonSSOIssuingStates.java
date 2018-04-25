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
import uk.ac.surrey.bets_framework.Crypto.BigIntEuclidean;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.NFCReaderCommand;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.pplast.data.IssuerData;
import uk.ac.surrey.bets_framework.protocol.pplast.data.TicketDetails;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message.Type;

/**
 * Ticket issuing states of the PPLAST state machine protocol.
 *
 * @author Steve Wesemeyer
 */

public class PPLASTIssuingStates {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPLASTIssuingStates.class);

  /**
   * State 22
   */
  public static class IState22 extends State<NFCReaderCommand> {

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
        return new Action<>(Status.CONTINUE, 23, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 23
   * As seller: verify user proof and issue ticket
   */
  public static class IState23 extends State<NFCReaderCommand> {

    private byte[] generateTicketDetails(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();
      final IssuerData sellerData = (IssuerData) sharedMemory.getData(Actor.ISSUER);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);
      if (listData.getList().size() <= 0) { // dependent on the number of verifiers...
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }

      // some constants from sharedMemory
      final BigInteger p = sharedMemory.p;
      final Element xi = sharedMemory.xi.getImmutable();
      final Element g = sharedMemory.g.getImmutable();
      final Element g_frak = sharedMemory.g_frak.getImmutable();
      final Element h = sharedMemory.h.getImmutable();
      final Element h_tilde = sharedMemory.h_tilde.getImmutable();

      // check the ZKP here:

      int index = 0;
      final List<byte[]> verifyc_hashData = new ArrayList<>();

      final Element sigma_bar_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element sigma_tilde_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      final Element Y_A = sharedMemory.getPublicKey(Actor.CENTRAL_AUTHORITY);

      final Element lhs = sharedMemory.pairing.pairing(sigma_bar_U, Y_A).getImmutable();
      final Element rhs = sharedMemory.pairing.pairing(sigma_tilde_U, g_frak).getImmutable();

      if (!lhs.isEqual(rhs)) {
        LOG.debug("verify user proof: simple pairing check failed");
        return null;
      }

      LOG.debug("passed simple pairing check");

      // compute the hash
      verifyc_hashData.add(sigma_bar_U.toBytes());
      verifyc_hashData.add(sigma_tilde_U.toBytes());
      final Element B_bar_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      verifyc_hashData.add(B_bar_U.toBytes());
      final Element W_1 = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      verifyc_hashData.add(W_1.toBytes());
      final Element W_2 = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
      verifyc_hashData.add(W_2.toBytes());

      final int numberOfVerifiers = new BigInteger(1, listData.getList().get(index++)).intValue();
      /** We don't do the dummy verifiers at them moment
      
      // if numberOfVerifiers is odd then add one to make an even number.
      int evenNumberOfVerifiers = numberOfVerifiers + (numberOfVerifiers % 2);
      final TicketDetails ticketDetails = new TicketDetails(evenNumberOfVerifiers);
      
      **/
      final TicketDetails ticketDetails = new TicketDetails(numberOfVerifiers);

      for (int i = 0; i < numberOfVerifiers; i++) {
        ticketDetails.VerifierList[i] = new String(listData.getList().get(index++), StandardCharsets.UTF_8);
      }

      final Element[] P_dash_V = new Element[numberOfVerifiers];
      final Element[] Q_dash_V = new Element[numberOfVerifiers];
      for (int i = 0; i < numberOfVerifiers; i++) {
        ticketDetails.P_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
        P_dash_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
        ticketDetails.Q_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
        Q_dash_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(index++));
        verifyc_hashData.add(ticketDetails.P_V[i].toBytes());
        verifyc_hashData.add(P_dash_V[i].toBytes());
        verifyc_hashData.add(ticketDetails.Q_V[i].toBytes());
        verifyc_hashData.add(Q_dash_V[i].toBytes());
      }

      final byte[] c_hash = listData.getList().get(index++);

      // check the hash value is correct
      final byte[] verifyc_hash = crypto.getHash((new ListData(verifyc_hashData)).toBytes(), sharedMemory.Hash1);
      if (!Arrays.equals(c_hash, verifyc_hash)) {
        LOG.debug("c_hash verification failed!");
        return null;
      }
      LOG.debug("Passed c_hash verification!");
      // need the BigInteger value of c_hash now
      final BigInteger c_hashNum = (new BigInteger(1, c_hash)).mod(p);

      final BigInteger e_hat_u = new BigInteger(1, listData.getList().get(index++));
      final BigInteger v_hat_2 = new BigInteger(1, listData.getList().get(index++));
      final BigInteger v_hat_3 = new BigInteger(1, listData.getList().get(index++));
      final BigInteger v_hat = new BigInteger(1, listData.getList().get(index++));
      final BigInteger x_hat_u = new BigInteger(1, listData.getList().get(index++));

      final BigInteger[] z_hat_v = new BigInteger[numberOfVerifiers];
      for (int i = 0; i < numberOfVerifiers; i++) {
        z_hat_v[i] = new BigInteger(1, listData.getList().get(index++));
      }

      // check W_1
      final Element W_1lhs = ((sigma_bar_U.mul(e_hat_u.negate().mod(p))).add(h.mul(v_hat_2)))
          .add((sigma_tilde_U.sub(B_bar_U)).mul(c_hashNum)).getImmutable();

      if (!W_1.isEqual(W_1lhs)) {
        LOG.debug("W_1 verification failed!");
        return null;
      }

      LOG.debug("passed W_1 verification!");

      // check W_2
      Element W_2lhs = (B_bar_U.mul(v_hat_3.negate().mod(p))).getImmutable();
      W_2lhs = W_2lhs.add(xi.mul(x_hat_u)).getImmutable();
      W_2lhs = W_2lhs.add(h.mul(v_hat)).getImmutable();
      W_2lhs = W_2lhs.add(g.mul(c_hashNum.negate().mod(p))).getImmutable();

      if (!W_2.isEqual(W_2lhs)) {
        LOG.debug("W_2 verification failed!");
        return null;
      }

      LOG.debug("passed W_2 verification!");

      final Element Y_P = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER);

      for (int i = 0; i < numberOfVerifiers; i++) {
        final Element P_dash_Vlhs = (xi.mul(x_hat_u)).add(Y_P.mul(z_hat_v[i])).add(ticketDetails.P_V[i].mul(c_hashNum))
            .getImmutable();
        if (!P_dash_V[i].isEqual(P_dash_Vlhs)) {
          LOG.debug("P_dash_V[" + i + "] verification failed!");
          return null;
        }
      }

      LOG.debug("passed P_dash_V verification!");

      for (int i = 0; i < numberOfVerifiers; i++) {
        final Element Q_dash_Vlhs = ((xi.mul(z_hat_v[i])).add(ticketDetails.Q_V[i].mul(c_hashNum))).getImmutable();
        if (!Q_dash_V[i].isEqual(Q_dash_Vlhs)) {
          LOG.debug("Q_dash_V[" + i + "] verification failed!");
          return null;
        }
      }
      LOG.debug("passed Q_dash_V verification!");
      
      //Creating the ticket now

      final BigInteger t_u = crypto.secureRandom(p);
      final Element C_U = xi.mul(t_u);
      LOG.debug("C_U = " + C_U);

      BigIntEuclidean gcd = null;
      boolean hasCV=false;

      for (int i = 0; i < numberOfVerifiers; i++) {
    	if (ticketDetails.VerifierList[i].equalsIgnoreCase(Actor.CENTRAL_VERIFIER)) {
    		hasCV=true;
    	}
        ticketDetails.d_v[i] = crypto.secureRandom(p);
        ticketDetails.E_V[i] = xi.mul(ticketDetails.d_v[i]).getImmutable();

        ticketDetails.w_v[i] = crypto.secureRandom(p);
        ticketDetails.e_v[i] = crypto.secureRandom(p);
        final ListData D_Vdata = new ListData(Arrays.asList(C_U.toBytes(), ticketDetails.VerifierList[i].getBytes()));
        ticketDetails.D_V[i] = crypto.getHash(D_Vdata.toBytes(), sharedMemory.Hash2);
        final Element Y_V = sharedMemory.getPublicKey(ticketDetails.VerifierList[i]);
        ticketDetails.F_V[i] = Y_V.mul(ticketDetails.d_v[i]).getImmutable();
        ticketDetails.K_V[i] = Y_V.add(Y_P.mul(ticketDetails.d_v[i])).getImmutable();
        final ListData s_Vdata = new ListData(
            Arrays.asList(ticketDetails.P_V[i].toBytes(), ticketDetails.Q_V[i].toBytes(), ticketDetails.E_V[i].toBytes(),
                ticketDetails.F_V[i].toBytes(), ticketDetails.K_V[i].toBytes(), IssuerData.TICKET_TEXT.getBytes()));
        ticketDetails.s_V[i] = crypto.getHash(s_Vdata.toBytes(), sharedMemory.Hash1);
        final BigInteger s_Vnum = (new BigInteger(1, ticketDetails.s_V[i])).mod(p);
        gcd = BigIntEuclidean.calculate(sellerData.x_I.add(ticketDetails.e_v[i]).mod(p), p);
        final BigInteger xs_plus_ev_inverse = gcd.x.mod(p);
        ticketDetails.Z_V[i] = (g.add(h.mul(ticketDetails.w_v[i])).add(h_tilde.mul(s_Vnum))).mul(xs_plus_ev_inverse)
            .getImmutable();
        ticketDetails.ticketText = IssuerData.TICKET_TEXT;

      }
      
      if (!hasCV) {
          LOG.debug("Central Verifier was not included: verification failed!");
          return null;
      }
/** remove dummy verifier for now 

      // Do we need to create a dummy verifier?
      if (numberOfVerifiers != evenNumberOfVerifiers) {
        // Yes - so give it a name and make up some stuff...
        final String ID_du = Actor.VERIFIERS[Actor.dummyVerifierIndx];
        ticketDetails.VerifierList[numberOfVerifiers] = ID_du;
        final BigInteger d_dash = crypto.secureRandom(p);
        final BigInteger w_dash = crypto.secureRandom(p);
        final BigInteger e_dash = crypto.secureRandom(p);
        // final Element D_du = sharedMemory.pairing.getG1().newRandomElement().getImmutable();
        final ListData D_duData = new ListData(Arrays.asList(C_U.toBytes(), ID_du.getBytes()));
        final byte[] D_du = crypto.getHash(D_duData.toBytes(), sharedMemory.Hash2);
        // TODO: Discuss with Jinguang
        final BigInteger z_Vdu = crypto.secureRandom(p);
        // final Element P_du = sharedMemory.pairing.getG1().newRandomElement().getImmutable();
        final Element P_du = sharedMemory.getPublicKey(Actor.USER).add(Y_CV.mul(z_Vdu));
        final Element Q_du = xi.mul(z_Vdu).getImmutable();
        final Element F_du = sharedMemory.pairing.getG1().newRandomElement().getImmutable();
        // compute the equivalent values as above but for this dummy verifier

        final Element E_du = xi.mul(d_dash).getImmutable();
        final ListData hashDataList = new ListData(Arrays.asList(ticketDetails.VerifierList[numberOfVerifiers].getBytes()));
        final byte[] hashData = crypto.getHash(hashDataList.toBytes(), sharedMemory.Hash3);
        final BigInteger hashNum = (new BigInteger(1, hashData)).mod(p);
        final Element K_du = Y_CV.mul(d_dash).add(sharedMemory.pairing.getG1().newOneElement().mul(hashNum)).getImmutable();
        final ListData s_dashList = new ListData(Arrays.asList(P_du.toBytes(), Q_du.toBytes(), E_du.toBytes(), F_du.toBytes(),
            K_du.toBytes(), IssuerData.TICKET_TEXT.getBytes()));
        final byte[] s_dash = crypto.getHash(s_dashList.toBytes(), sharedMemory.Hash1);
        final BigInteger s_dashNum = new BigInteger(1, s_dash).mod(p);
        gcd = BigIntEuclidean.calculate(sellerData.x_S.add(e_dash).mod(p), p);

        final Element sigma_du = ((g.add(h.mul(w_dash))).add(h_tilde.mul(s_dashNum))).mul(gcd.x.mod(p));

        ticketDetails.D_V[numberOfVerifiers] = D_du;
        ticketDetails.E_V[numberOfVerifiers] = E_du;
        ticketDetails.F_V[numberOfVerifiers] = F_du;
        ticketDetails.P_V[numberOfVerifiers] = P_du;
        ticketDetails.Q_V[numberOfVerifiers] = Q_du;
        ticketDetails.K_V[numberOfVerifiers] = K_du;
        ticketDetails.s_V[numberOfVerifiers] = s_dash;
        ticketDetails.sigma_V[numberOfVerifiers] = sigma_du;
        ticketDetails.w_V[numberOfVerifiers] = w_dash;
        ticketDetails.e_V[numberOfVerifiers] = e_dash;

      }
**/
      
      ticketDetails.w_CV = crypto.secureRandom(p);
      ticketDetails.e_CV = crypto.secureRandom(p);
      final List<byte[]> s_pDataList = new ArrayList<>();
      for (int i = 0; i < numberOfVerifiers; i++) {
        s_pDataList.add(ticketDetails.s_V[i]);
      }
      ticketDetails.s_CV = crypto.getHash((new ListData(s_pDataList)).toBytes(), sharedMemory.Hash1);
      final BigInteger s_pDataNum = new BigInteger(1, ticketDetails.s_CV).mod(p);
      gcd = BigIntEuclidean.calculate(sellerData.x_I.add(ticketDetails.e_CV).mod(p), p);
      ticketDetails.Z_CV = ((g.add(h.mul(ticketDetails.w_CV))).add(h_tilde.mul(s_pDataNum))).mul(gcd.x.mod(p));

      final List<byte[]> sendDataList = new ArrayList<>();
      sendDataList.add(C_U.toBytes());
      sendDataList.add(BigInteger.valueOf(numberOfVerifiers).toByteArray()); // need to keep track of the array size
      ticketDetails.getTicketDetails(sendDataList);
      final ListData sendData = new ListData(sendDataList);

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
      sharedMemory.actAs(Actor.ISSUER);
      if (message.getType() == Type.DATA) {
        // Send the setup data.
        final byte[] data = this.generateTicketDetails(message.getData());

        if (data != null) {
           LOG.debug("sending ticket details to the client");
           return new Action<>(Status.CONTINUE, 24, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }

  }
  
  /**
   * State 24
   * 
   */
  public static class IState24 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        return new Action<>(25);
      }

      return super.getAction(message);
    }
  }

}
