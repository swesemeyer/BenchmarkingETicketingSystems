/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp_lite;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPIssuingStates;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;

/**
 * Modified ticket issuing states of the PPETS-FGP Lite state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPLiteIssuingStates {

  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPLiteIssuingStates.class);

  /**
   * Modified state 6.
   */
  public static class ImState06 extends PPETSFGPIssuingStates.IState06 {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      // We are now the user.
      ((PPETSFGPSharedMemory) this.getSharedMemory()).actAs(PPETSFGPSharedMemory.Actor.USER);

      if (message.getType() == Message.Type.DATA) {
        // Generate the user pseudonym data.
        if (message.getData() == null) {
          byte[] data = this.generateUserPseudonym();

          if (data != null) {
            LOG.debug("generate user pseudonym complete");

            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 8, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}
