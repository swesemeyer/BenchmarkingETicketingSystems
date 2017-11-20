/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.nfc.NFC;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderCommand;
import uk.co.pervasive_intelligence.dice.protocol.data.Data;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.protocol.ppetsfgp.data.SellerData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Action.Status;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.Message.Type;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * Setup states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPSetupStates {

  /**
   * State 0.
   */
  public static class SState00 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      // Clear out shared memory as we are starting again.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      sharedMemory.clear();

      if (message.getType() == Type.START) {
        // Open the connection.
        return new Action<>(1, NFCReaderCommand.OPEN);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 1.
   */
  public static class SState01 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Send the setup data.
        final byte[] data = this.getSetup();

        if (data != null) {
          return new Action<>(Status.CONTINUE, 2, NFCReaderCommand.PUT, data, 0);
        }
      }

      return super.getAction(message);
    }

    /**
     * Gets the setup bytes to be sent.
     *
     * @return The setup bytes to send.
     */
    private byte[] getSetup() {
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      byte[] result = null;

      try {
        result = sharedMemory.toJson().getBytes(Data.UTF8);
      }
      catch (final UnsupportedEncodingException e) {
        LOG.error("could not encode setup", e);
      }
      LOG.debug("serialised the shared Memory");
      return result;
    }
  }

  /**
   * State 2.
   */
  public static class SState02 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.SUCCESS) {
        // Get the returned setup data.
        return new Action<>(Status.CONTINUE, 3, NFCReaderCommand.GET, null, NFC.USE_MAXIMUM_LENGTH);
      }

      return super.getAction(message);
    }
  }

  /**
   * State 3.
   */
  public static class SState03 extends State<NFCReaderCommand> {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCReaderCommand> getAction(Message message) {
      if (message.getType() == Type.DATA) {
        // Process the returned setup data.
        if (this.processSetup(message.getData())) {
          LOG.error("setup complete");
          return new Action<>(4);
        }
      }

      return super.getAction(message);
    }

    /**
     * Processes the returned setup data bytes.
     *
     * @param data The received setup data.
     * @return True if processing was successful.
     */
    private boolean processSetup(byte[] data) {
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();

      // Store the seller's random x_s so that we can act as the seller in the protocol later.
      sharedMemory.actAs(Actor.SELLER);
      ((SellerData) sharedMemory.getData(Actor.SELLER)).x_s = new BigInteger(data);

      return true;
    }
  }

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPSetupStates.class);
}
