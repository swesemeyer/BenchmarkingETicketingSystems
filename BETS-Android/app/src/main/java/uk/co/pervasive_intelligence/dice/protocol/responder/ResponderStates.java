/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.responder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;

import uk.co.pervasive_intelligence.dice.APDUService;
import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.Utils;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidState;
import uk.co.pervasive_intelligence.dice.protocol.NFCSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.control.setup.ClientData;
import uk.co.pervasive_intelligence.dice.protocol.control.setup.ServerData;
import uk.co.pervasive_intelligence.dice.protocol.control.teardown.TimingsData;
import uk.co.pervasive_intelligence.dice.state.Action;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.StateMachine;

/**
 * States for the responder state machine protocol.
 *
 * @author Matthew Casey
 */
public class ResponderStates {

  /**
   * Class used to return the correct chunked request action and data.
   */
  private static class ChunkedRequest {

    /** The action for the chunked request, if any. */
    public Action<NFCAndroidCommand> action;

    /** The revised request data, if any. */
    public byte[] data;
  }

  /**
   * Abstract state.
   */
  public static class ResponderState extends NFCAndroidState {

    /**
     * Determines what APDU command has been sent.
     *
     * @param message The received message containing the APDU command as message data.
     * @return The corresponding APDU command.
     */
    protected APDUCommand getAPDUCommand(Message message) {
      // Extract the command portion of the APDU command contained in the message data.
      ByteBuffer commandBytes = ByteBuffer.wrap(message.getData(), 0, ResponderSharedMemory.COMMAND_CLA_INS_P1_P2_LENGTH);
      APDUCommand command = null;

      if (ByteBuffer.wrap(ResponderSharedMemory.COMMAND_SELECT_CLA_INS_P1_P2).equals(commandBytes)) {
        command = APDUCommand.SELECT;
      }
      else if (ByteBuffer.wrap(ResponderSharedMemory.COMMAND_GET_CLA_INS_P1_P2).equals(commandBytes)) {
        command = APDUCommand.GET;
      }
      else if (ByteBuffer.wrap(ResponderSharedMemory.COMMAND_PUT_CLA_INS_P1_P2).equals(commandBytes)) {
        command = APDUCommand.PUT;
      }

      return command;
    }

    /**
     * Extracts any optional APDU command data from a message.
     *
     * @param message The received message containing the APDU command as message data.
     * @return The corresponding APDU command data, if any.
     */
    protected byte[] getAPDUData(Message message) {
      // Extract the data portion of the APDU command contained in the message data.
      byte[] messageData = message.getData();
      int dataLength = 0;
      byte[] data = null;

      // Check if the message has any data.
      if (messageData.length > ResponderSharedMemory.COMMAND_CLA_INS_P1_P2_DATA) {
        dataLength = messageData[ResponderSharedMemory.COMMAND_CLA_INS_P1_P2_DATA] & 0xFF;
      }

      // Extract the data if there are any bytes to obtain.
      if ((dataLength > 0) && (messageData.length >= (ResponderSharedMemory.COMMAND_CLA_INS_P1_P2_LENGTH + 1 +
          dataLength))) {
        data = new byte[dataLength];
        System.arraycopy(messageData, ResponderSharedMemory.COMMAND_CLA_INS_P1_P2_DATA + 1, data, 0, dataLength);
      }

      return data;
    }

    /**
     * Determines if the current request is in chunks.  If this is in chunks, and this is not the last chunk, then an appropriate
     * action is formed and the data saved for later.  If this is the last chunk, then the previous data is concatenated.
     *
     * @param command The current command.
     * @param data    The currently received data, if any.
     * @return What needs to happen for this chunked request.
     */
    protected ChunkedRequest handleRequestChunk(APDUCommand command, byte[] data) {
      ResponderSharedMemory sharedMemory = (ResponderSharedMemory) this.getSharedMemory();
      ChunkedRequest result = new ChunkedRequest();

      // If this is a put, we need to process the response code on the end.
      if ((command == APDUCommand.PUT) && (data != null) && (data.length >= NFCAndroidSharedMemory.RESPONSE_CONTINUE.length)) {
        // Extract the response code.
        byte[] responseCode = new byte[NFCAndroidSharedMemory.RESPONSE_CONTINUE.length];
        System.arraycopy(data, data.length - NFCAndroidSharedMemory.RESPONSE_CONTINUE.length, responseCode, 0,
            NFCAndroidSharedMemory.RESPONSE_CONTINUE.length);

        // Save the data.
        int dataLength = data.length - NFCAndroidSharedMemory.RESPONSE_CONTINUE.length;

        if (dataLength > 0) {
          if (sharedMemory.requestChunked == null) {
            sharedMemory.requestChunked = new byte[dataLength];
            System.arraycopy(data, 0, sharedMemory.requestChunked, 0, dataLength);
          }
          else {
            byte[] chunked = Arrays.copyOf(sharedMemory.requestChunked, dataLength + sharedMemory.requestChunked.length);
            System.arraycopy(data, 0, chunked, sharedMemory.requestChunked.length, dataLength);
            sharedMemory.requestChunked = chunked;
          }
        }

        // If we have a response continue, save the data and send back a response OK, otherwise replace the data with the request
        // data we have accumulated.
        if ((responseCode[0] == NFCAndroidSharedMemory.RESPONSE_CONTINUE[0]) && (responseCode[1] == NFCAndroidSharedMemory
            .RESPONSE_CONTINUE[1])) {
          result.action = new Action<>(Action.Status.END_SUCCESS, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE,
              NFCAndroidSharedMemory.RESPONSE_OK, 0);
        }
        else if ((responseCode[0] == NFCAndroidSharedMemory.RESPONSE_OK[0]) && (responseCode[1] == NFCAndroidSharedMemory
            .RESPONSE_OK[1])) {
          if (sharedMemory.requestChunked != null) {
            result.data = sharedMemory.requestChunked;
            sharedMemory.requestChunked = null;
          }
        }
      }
      else {
        // Clear out any chunking.
        sharedMemory.requestChunked = null;
      }

      return result;
    }

    /**
     * Used to intercept any follow-up GET commands when sending back chunks.
     *
     * @param command The current command.
     * @param action  Optional action to copy action details from.
     * @return An action which contains the next chunk, if needed.
     */
    protected Action<NFCAndroidCommand> handleResponseChunk(APDUCommand command, Action<NFCAndroidCommand> action) {
      ResponderSharedMemory sharedMemory = (ResponderSharedMemory) this.getSharedMemory();
      Action<NFCAndroidCommand> result = null;

      // If the current chunk buffer is not empty, and this is a GET, we need to send back a chunk.
      if (command == APDUCommand.GET) {
        if (sharedMemory.responseChunked != null) {
          // Get the next chunk of data.
          int bytesLeft = sharedMemory.responseChunked.length - sharedMemory.responseChunkIndex;
          int chunkLength = Math.min(bytesLeft, NFCSharedMemory.APDU_CHUNK_SIZE);

          // If this is not the last chunk, then we need to add on our own response code for continue.
          int copyLength = chunkLength;

          if (bytesLeft > chunkLength) {
            // Take off the number bytes needed for our own response.
            copyLength -= NFCAndroidSharedMemory.RESPONSE_CONTINUE.length;
          }

          byte[] chunk = new byte[chunkLength];
          System.arraycopy(sharedMemory.responseChunked, sharedMemory.responseChunkIndex, chunk, 0, copyLength);
          sharedMemory.responseChunkIndex += copyLength;

          // Add in the response code, if needed.
          if (copyLength != chunkLength) {
            System.arraycopy(NFCAndroidSharedMemory.RESPONSE_CONTINUE, 0, chunk, copyLength, NFCAndroidSharedMemory
                .RESPONSE_CONTINUE.length);
          }

          // Build the new action from the old action, if any.
          if (action != null) {
            result = new Action<>(action.getStatus(), action.getNextState(), action.getCommand(), chunk, action
                .getCommandResponseLength());
          }
          else {
            result = new Action<>(Action.Status.END_SUCCESS, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE, chunk, 0);
          }

          // If we have finished chunking, clear up.
          if (bytesLeft <= copyLength) {
            sharedMemory.responseChunked = null;
            sharedMemory.responseChunkIndex = 0;
          }
        }
      }
      else {
        // This isn't a GET so stop any current chunking.
        sharedMemory.responseChunked = null;
        sharedMemory.responseChunkIndex = 0;
      }

      return result;
    }

    /**
     * Determines if we need to chunk any response data up for return.  If yes, the action is modified to contain the first chunk.
     *
     * @param action The action which might need chunking.
     * @return The chunked action.
     */
    protected Action<NFCAndroidCommand> responseChunk(Action<NFCAndroidCommand> action) {
      Action<NFCAndroidCommand> result = action;

      // See if we need to break up any response data into chunks.
      if ((action != null) && (action.getCommandData() != null) && (action.getCommandData().length > NFCSharedMemory
          .APDU_CHUNK_SIZE)) {
        // The response needs to be chunked.  Save off the response data.
        ResponderSharedMemory sharedMemory = (ResponderSharedMemory) this.getSharedMemory();

        sharedMemory.responseChunked = new byte[action.getCommandData().length];
        System.arraycopy(action.getCommandData(), 0, sharedMemory.responseChunked, 0, action.getCommandData().length);

        sharedMemory.responseChunkIndex = 0;

        // Create a corresponding action which is the first chunk.
        result = this.handleResponseChunk(APDUCommand.GET, action);
      }

      return result;
    }

    /**
     * The possible APDU commands sent to the app.
     */
    protected enum APDUCommand {
      SELECT, GET, PUT
    }
  }

  /**
   * State 0.
   */
  public static class ResponderState0 extends ResponderState {

    /** Logback logger. */
    private static final Logger LOG = LoggerFactory.getLogger(ResponderState0.class);

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      Action<NFCAndroidCommand> action = null;

      if (message.getType() == Message.Type.DATA) {
        APDUCommand command = this.getAPDUCommand(message);
        byte[] data = this.getAPDUData(message);
        LOG.trace("{}, {}", command, Utils.toHex(data));

        // Handle any chunked requests.
        ChunkedRequest chunkedRequest = this.handleRequestChunk(command, data);

        if (chunkedRequest != null) {
          // We either need to replace the data or send a response.
          action = chunkedRequest.action;
          data = chunkedRequest.data;
        }

        // Handle any chunked responses.
        if (action == null) {
          action = this.handleResponseChunk(command, action);
        }

        if (action == null) {
          // If it's a select, process the next command as a setup or tear down. Otherwise just inject the message data into the
          // protocol state machine, if any.
          switch (command) {
            case SELECT:
              action = new Action<>(Action.Status.END_SUCCESS, 1, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK,
                  0);
              break;

            case GET:
            case PUT:
              action = this.inject(new Message(data));
              break;

            default:
              break;
          }
        }

        // Automatically chunk up responses.
        action = this.responseChunk(action);
      }

      // Get the default action, if needed.
      if (action == null) {
        action = super.getAction(message);
      }

      return action;
    }

    /**
     * Injects a message into the protocol state machine, if any.
     *
     * @param message The message to inject.
     * @return The required action, or null if no action can be performed.
     */
    private Action<NFCAndroidCommand> inject(Message message) {
      StateMachine<?> stateMachine = ((ResponderSharedMemory) this.getSharedMemory()).stateMachine;
      Action<NFCAndroidCommand> action = null;
      LOG.info("{}", stateMachine);

      if ((stateMachine != null) && stateMachine.run(message)) {
        APDUService.sendLocalBroadcast(stateMachine.getClass().getSimpleName());

        // Extract the response from the state machine.
        action = new Action<>(Action.Status.END_SUCCESS, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE, (
            (NFCAndroidSharedMemory) stateMachine.getSharedMemory()).response, 0);
      }
      else {
        action = new Action<>(Action.Status.END_FAILURE, Action.NO_STATE_CHANGE, NFCAndroidCommand.RESPONSE,
            NFCAndroidSharedMemory.RESPONSE_FAIL, 0);
      }

      return action;
    }
  }

  /**
   * State 1.
   */
  public static class ResponderState1 extends ResponderState {

    /** Logback logger. */
    private static final Logger LOG = LoggerFactory.getLogger(ResponderState1.class);

    /**
     * Called to set up the protocol run.
     *
     * @param data The received message data to process.
     * @return True if setup was completed successfully.
     */
    private boolean setup(byte[] data) {
      boolean result = false;

      try {
        if (data != null) {
          ResponderSharedMemory sharedMemory = (ResponderSharedMemory) this.getSharedMemory();
          ServerData serverData = ServerData.fromBytes(data);

          if (serverData != null) {
            // Set the log level.
            Utils.setLogLevel(serverData.getLogLevel());

            // Save off the cryptographic information and reset everything else.
            Crypto crypto = Crypto.getInstance();
            crypto.setKeyLength(serverData.getKeyLength());
            crypto.setRemotePublicKey(serverData.getEncodedPublicKey());
            crypto.setDhParameters(serverData.getDhParameters());
            crypto.setHashParameters();
            crypto.setEncryptionParameters();
            crypto.setPrimeCertainty();
            LOG.info("using key length {}", serverData.getKeyLength());

            // Set up the required state machine using the list of available classes.
            Class<?> clazz = null;

            for (String className : sharedMemory.classes) {
              if (className.endsWith(serverData.getProtocolRun().getName())) {
                clazz = Class.forName(className);
              }
            }

            if (clazz != null) {
              sharedMemory.stateMachine = (StateMachine<?>) clazz.newInstance();
              sharedMemory.stateMachine.setParameters(serverData.getProtocolRun().getParameters());
              LOG.info("running protocol {}", serverData.getProtocolRun());
              result = sharedMemory.stateMachine != null;
            }
          }
        }
      }
      catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
        LOG.error("could not setup the protocol run", e);
      }

      return result;
    }

    /**
     * Called to tear down after a test.
     *
     * @return The timings data for the protocol state machine as a byte array, or null on failure.
     */
    private byte[] tearDown() {
      byte[] timingsResponse = null;

      // Extract the timings from the state machine.
      StateMachine<?> stateMachine = ((ResponderSharedMemory) this.getSharedMemory()).stateMachine;

      if (stateMachine != null) {
        // Extract the timings data.
        TimingsData timingsData = new TimingsData(Collections.singletonList(stateMachine.getTimings()));
        byte[] timingsBuffer = timingsData.toBytes();

        // Add on the required response code.
        timingsResponse = this.addResponseCode(timingsBuffer, NFCAndroidSharedMemory.RESPONSE_OK);
      }

      return timingsResponse;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      Action<NFCAndroidCommand> action = null;

      if (message.getType() == Message.Type.DATA) {
        APDUCommand command = this.getAPDUCommand(message);
        byte[] data = this.getAPDUData(message);
        LOG.trace("{}, {}", command, Utils.toHex(data));

        // Handle any chunked requests.
        ChunkedRequest chunkedRequest = this.handleRequestChunk(command, data);

        if (chunkedRequest != null) {
          // We either need to replace the data or send a response.
          action = chunkedRequest.action;
          data = chunkedRequest.data;
        }

        // Handle any chunked responses.
        if (action == null) {
          action = this.handleResponseChunk(command, action);
        }

        if (action == null) {
          // We are waiting for either a PUT to set the protocol, or a GET to send back results.
          switch (command) {
            case SELECT:
              // Ignore any multiple selects.
              action = new Action<>(Action.Status.END_SUCCESS, 1, NFCAndroidCommand.RESPONSE, ResponderSharedMemory
                  .RESPONSE_OK, 0);

              break;

            case PUT:
              LOG.info("setup (server)");
              APDUService.sendLocalBroadcast("Setup");
              if (this.setup(data)) {
                action = new Action<>(Action.Status.END_SUCCESS, 2, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory
                    .RESPONSE_OK, 0);
              }
              else {
                action = new Action<>(Action.Status.END_FAILURE, 0, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory
                    .RESPONSE_FAIL, 0);
              }
              break;

            case GET:
              LOG.info("tear down");
              APDUService.sendLocalBroadcast("Tear Down");
              byte[] timingsResponse = this.tearDown();

              if (timingsResponse != null) {
                action = new Action<>(Action.Status.END_SUCCESS, 0, NFCAndroidCommand.RESPONSE, timingsResponse, 0);
              }
              else {
                action = new Action<>(Action.Status.END_FAILURE, 0, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory
                    .RESPONSE_FAIL, 0);
              }
              break;

            default:
              break;
          }

          // Automatically chunk up and responses.
          action = this.responseChunk(action);
        }
      }

      // Get the default action, if needed.
      if (action == null) {
        action = super.getAction(message);
      }

      // If we have finished tera down, clear the broadcast message.
      if (action.getNextState() == 0) {
        APDUService.sendLocalBroadcast(null);
      }

      return action;
    }
  }

  /**
   * State 2.
   */
  public static class ResponderState2 extends ResponderState {

    /** Logback logger. */
    private static final Logger LOG = LoggerFactory.getLogger(ResponderState2.class);

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      Action<NFCAndroidCommand> action = null;

      if (message.getType() == Message.Type.DATA) {
        APDUCommand command = this.getAPDUCommand(message);
        byte[] data = this.getAPDUData(message);
        LOG.trace("{}, {}", command, Utils.toHex(data));

        // Handle any chunked requests.
        ChunkedRequest chunkedRequest = this.handleRequestChunk(command, data);

        if (chunkedRequest != null) {
          // We either need to replace the data or send a response.
          action = chunkedRequest.action;
          data = chunkedRequest.data;
        }

        // Handle any chunked responses.
        if (action == null) {
          action = this.handleResponseChunk(command, action);
        }

        if (action == null) {
          // We are waiting for either a PUT to set the protocol, or a GET to send back results.
          switch (command) {
            case SELECT:
              // Ignore any multiple selects.
              action = new Action<>(Action.Status.END_SUCCESS, 1, NFCAndroidCommand.RESPONSE, ResponderSharedMemory
                  .RESPONSE_OK, 0);

              break;

            case GET:
              LOG.info("setup (client)");

              // Send back the client data.
              ClientData clientData = new ClientData(Crypto.getInstance().getPublicKey().getEncoded());
              action = new Action<>(Action.Status.END_SUCCESS, 0, NFCAndroidCommand.RESPONSE, this.addResponseCode(clientData
                  .toBytes(), NFCAndroidSharedMemory.RESPONSE_OK), 0);
              break;

            case PUT:
            default:
              break;
          }

          // Automatically chunk up and responses.
          action = this.responseChunk(action);
        }
      }

      // Get the default action, if needed.
      if (action == null) {
        action = super.getAction(message);
      }

      return action;
    }
  }
}
