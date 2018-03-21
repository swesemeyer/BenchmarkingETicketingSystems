package uk.ac.surrey.bets_framework.protocol.pplast;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.pplast.data.TicketDetails;
import uk.ac.surrey.bets_framework.protocol.pplast.data.UserData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * The verifying states for PPLAST.
 * <p>
 * (c) Steve Wesemeyer 2017
 */

public class PPLASTVerifyingStates {

  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PPLASTVerifyingStates.class);

  /**
   * State 06
   * As User: generate the ticket proof for ID_V
   */
  public static class VState06 extends NFCAndroidState {

    private byte[] generateTagProof(byte[] data) {
      final PPLASTSharedMemory sharedMemory = (PPLASTSharedMemory) this.getSharedMemory();

      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);
      if (listData.getList().size() != 1) { // dependent on the number of verifiers...
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return null;
      }
      final String ID_V = new String(listData.getList().get(0), StandardCharsets.UTF_8);
      LOG.debug("Looking for ID_V = " + ID_V);

      final byte[] D_Vhash = crypto.getHash((new ListData(Arrays.asList(userData.C_U.toBytes(), ID_V.getBytes()))).toBytes(),
              sharedMemory.Hash2);

      TicketDetails userTicket = userData.ticketDetails;
      int index = userTicket.getVerifierIndex(D_Vhash);
      if (index == -1) {
        LOG.debug("Aborting as verifier not found: " + ID_V);
        return null;
      }
      // found the verifier - now proceed with ZKP PI^2_U.
      // get some constants from shared memory...
      LOG.debug("generating ZK_PI_2_U");
      final BigInteger p = sharedMemory.p;
      final Element xi = sharedMemory.xi.getImmutable();
      final Element Y_CV = sharedMemory.getPublicKey(Actor.CENTRAL_VERIFIER);

      final byte[] z_Vhash = crypto.getHash((new ListData(Arrays.asList(userData.z_u.toByteArray
                      (), ID_V.getBytes()))).toBytes(),
              sharedMemory.Hash1);
      final BigInteger z_Vnum = (new BigInteger(1, z_Vhash)).mod(p);

      final BigInteger x_dash_U = crypto.secureRandom(p);
      final BigInteger z_dash_V = crypto.secureRandom(p);

      final Element P_dash_V = ((xi.mul(x_dash_U)).add(Y_CV.mul(z_dash_V))).getImmutable();
      final Element Q_dash_V = (xi.mul(z_dash_V)).getImmutable();

      final byte[] c_Vhash = crypto.getHash((new ListData(
                      Arrays.asList(userTicket.P_V[index].toBytes(), P_dash_V.toBytes(), userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes())))
                      .toBytes(),
              sharedMemory.Hash1);

      final BigInteger c_Vnum = (new BigInteger(1, c_Vhash)).mod(p);

      final BigInteger x_hat_U = (x_dash_U.subtract(c_Vnum.multiply(userData.x_U))).mod(p);
      final BigInteger z_hat_V = (z_dash_V.subtract(c_Vnum.multiply(z_Vnum))).mod(p);
      LOG.debug("finished generating ZK_PI_2_U");

      //collect everything that needs to be sent
      final List<byte[]> sendDataList = new ArrayList<>();
      sendDataList.addAll(Arrays.asList(userTicket.P_V[index].toBytes(),P_dash_V.toBytes(),
              userTicket.Q_V[index].toBytes(), Q_dash_V.toBytes(), c_Vhash, x_hat_U.toByteArray(), z_hat_V.toByteArray(),
              userTicket.E_V[index].toBytes(), userTicket.F_V[index].toBytes(), userTicket.K_V[index].toBytes(), userTicket.s_V[index],
              userTicket.w_v[index].toByteArray(), userTicket.e_v[index].toByteArray(),
              userTicket.Z_V[index].toBytes()));

      //if it was the central verifier who asked then we need to add the whole ticket, too
      if (ID_V.equalsIgnoreCase(Actor.CENTRAL_VERIFIER)) {
        LOG.debug("it's a trace so add the whole ticket, too!");
        userData.ticketDetails.getTicketDetails(sendDataList);
      }
      final ListData sendData=new ListData(sendDataList);
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
      ((PPLASTSharedMemory) this.getSharedMemory()).actAs(PPLASTSharedMemory.Actor.USER);
      LOG.debug("Ticket Proof or Ticket Details");
      if (message.getType() == Message.Type.DATA) {
        if (message.getData() != null) {
          LOG.debug("There was some data so we are expecting a verifier ID.");
          //generate the user ticket proof
          byte[] data = this.generateTagProof(message.getData());

          if (data != null) {
            LOG.debug("generate user tag proof complete");
            ((PPLASTSharedMemory) this.getSharedMemory()).delayedResponse = data;

            //send the proof back to the verifiers
            return new Action<>(Action.Status.END_SUCCESS, 7, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }
      return super.getAction(message);

    }
  }

  /**
   * State 07
   */
  public static class VState07 extends NFCAndroidState {

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
            LOG.debug("sending the user tag proof to the verifier");
            //send the proof back and go back to the previous state in case there are more verifiers
            return new Action<>(Action.Status.END_SUCCESS, 6, NFCAndroidCommand.RESPONSE,
                    response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}