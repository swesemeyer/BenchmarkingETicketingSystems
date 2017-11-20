/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp_lite;

import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPIssuingStates;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;

/**
 * Modified ticket issuing states of the PPETS-FGP Lite state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSGFPLiteIssuingStates {

  /**
   * Modified state 8.
   */
  public static class ImState08 extends PPETSFGPIssuingStates.IState08 {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      // We are now the seller.
      ((PPETSFGPSharedMemory) this.getSharedMemory()).actAs(Actor.SELLER);

      if (message.getType() == Type.SUCCESS) {
        // Skip sending the seller's proof.
        return new Action<>(Status.CONTINUE, 10, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }
}
