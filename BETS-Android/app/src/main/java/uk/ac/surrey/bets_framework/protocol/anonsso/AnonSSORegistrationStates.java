package uk.ac.surrey.bets_framework.protocol.anonsso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.anonsso.data.UserData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * The registration states for AnonSSO.
 * We only need to register the user. Everything else is done server-side.
 * (c) Steve Wesemeyer 2017
 */

public class AnonSSORegistrationStates {


  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AnonSSORegistrationStates.class);

  /**
   * State 02:
   * <p>
   * As user: generate the user's identity
   */
  public static class RState02 extends NFCAndroidState {

    private byte[] generateUserIdentity() {
      final AnonSSOSharedMemory sharedMemory = (AnonSSOSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      // Send ID_U, Y_U
      final ListData sendData = new ListData(Arrays.asList(userData.ID_U.getBytes(),
              userData.Y_U.toBytes()));
      LOG.debug("User public key = " + userData.Y_U);
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
      ((AnonSSOSharedMemory) this.getSharedMemory()).actAs(Actor.USER);

      if (message.getType() == Message.Type.DATA) {
        // Send back the user identity data.
        if (message.getData() == null) {
          byte[] data = this.generateUserIdentity();
          if (data != null) {
            LOG.debug("generate user identity complete");
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 3, NFCAndroidCommand.RESPONSE,
                    response, 0);
          }
        }
      }
      return super.getAction(message);
    }
  }

  /**
   * State 03
   * As user: verifiy the Central Authority's data and store the user credentials
   */

  public static class RState03 extends NFCAndroidState {

    private boolean verifyUserCredentials(byte[] data) {
      final AnonSSOSharedMemory sharedMemory = (AnonSSOSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 3) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      final Element sigma_U = sharedMemory.curveG1ElementFromBytes(listData.getList().get(0));
      final BigInteger r_u = new BigInteger(listData.getList().get(1));
      final BigInteger e_u = new BigInteger(listData.getList().get(2));

      // verify the credentials
      // get the public key of the CA
      final Element Y_A = sharedMemory.Y_A;

      LOG.debug("About to verify user credentials - computing lhs");
      final Element lhs = sharedMemory.pairing.pairing(sigma_U, Y_A.add(sharedMemory.g_frak.mul
              (e_u))).getImmutable();
      LOG.debug("still verifying user credentials - computing rhs");
      final Element rhs = sharedMemory.pairing
              .pairing(sharedMemory.g.add(sharedMemory.h.mul(r_u)).add(userData.Y_U),
                      sharedMemory.g_frak).getImmutable();

      if (!lhs.isEqual(rhs)) {
        LOG.error("Failed to verify user credentials");
        return false;
      }
      LOG.debug("Successfully verified user credentials");
      userData.e_u = e_u;
      userData.r_u = r_u;
      userData.sigma_U = sigma_U;
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
      // We are now the user.
      ((AnonSSOSharedMemory) this.getSharedMemory()).actAs(Actor.USER);

      if (message.getType() == Message.Type.DATA) {
        // Verify the user's credentials.
        if (message.getData() != null) {
          if (this.verifyUserCredentials(message.getData())) {
            LOG.debug("verified the user's credentials successfully setup complete");
            return new Action<>(Action.Status.END_SUCCESS, 4, NFCAndroidCommand.RESPONSE,
                    NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }
      return super.getAction(message);
    }
  }

}
