/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.nfc;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.plaf.jpbc.util.Arrays;
import jnasmartcardio.Smartcardio;
import uk.ac.surrey.bets_framework.Utils;
import uk.ac.surrey.bets_framework.protocol.NFCSharedMemory;

/**
 * Abstracts communication with the NFC card as a singleton. This class was built using the following specification and examples:
 *
 * <ul>
 * <li><a href="http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4.aspx">ISO7816-4</a></li>
 * <li><a
 * href="https://github.com/grundid/host-card-emulation-sample/blob/master/src/de/grundid/hcedemo/IsoDepTransceiver.java">Adrian
 * Stabiszewski's Java NFC Tools</a></li>
 * <li><a href="http://stackoverflow.com/questions/27939818/nfc-reader-and-android-phone">Stack Overflow Thread - NFC Reader and
 * Android Phone</a></li>
 * </ul>
 *
 * @author Matthew Casey
 */
@SuppressWarnings("restriction")
public class NFC {

  /** Buzzer off command data. */
  private static final int    BUZZER_OFF                            = 0x00;

  /** Buzzer on command data. */
  private static final int    BUZZER_ON                             = 0xFF;

  /** Set buzzer command APDU. */
  private static final int[]  COMMAND_BUZZER_CLA_INS_P1_P2          = new int[] { 0xFF, 0x00, 0x52, 0x00 };

  /** Set buzzer command APDU data. */
  private static final byte[] COMMAND_BUZZER_DATA                   = new byte[] { 0x00, 0x00, 0x00, 0x00 };

  /** Get data command APDU. */
  private static final int[]  COMMAND_GET_CLA_INS_P1_P2             = new int[] { 0x00, 0xCA, 0x00, 0x00 };

  /** Put data command APDU. */
  private static final int[]  COMMAND_PUT_CLA_INS_P1_P2             = new int[] { 0x00, 0xDA, 0x00, 0x00 };

  /** Select command APDU. */
  private static final int[]  COMMAND_SELECT_CLA_INS_P1_P2          = new int[] { 0x00, 0xA4, 0x04, 0x00 };

  /** Set timeout command APDU. */
  private static final int[]  COMMAND_TIMEOUT_CLA_INS_P1_P2         = new int[] { 0xFF, 0x00, 0x41, 0x00 };

  /** Set timeout command APDU data. */
  private static final byte[] COMMAND_TIMEOUT_DATA                  = new byte[] { 0x00 };

  /** Smart card device command offset. */
  private static final int    FILE_DEVICE_SMARTCARD                 = 0x310000;

  /** The singleton instance. */
  private static NFC          instance                              = null;

  /** Smart card ACR122 escape command. */
  private static final int    IOCTL_SMARTCARD_ACR122_ESCAPE_COMMAND = FILE_DEVICE_SMARTCARD + (3500 * 4);

  /** Logback logger. */
  private static final Logger LOG                                   = LoggerFactory.getLogger(NFC.class);

  /** Response continue code. */
  private static final int[]  RESPONSE_CONTINUE                     = new int[] { 0x90, 0x01 };

  /** Response continue code as an integer. */
  private static final int    RESPONSE_CONTINUE_INT                 = 0x9001;

  /** Response OK code. */
  private static final int[]  RESPONSE_OK                           = new int[] { 0x90, 0x00 };

  /** Response OK code as an integer. */
  private static final int    RESPONSE_OK_INT                       = 0x9000;

  /** The protocol to using when communicating with the terminal. */
  private static final String TERMINAL_PROTOCOL                     = "T=1";

  /** The type of card terminal required. */
  private static final String TERMINAL_TYPE                         = "PC/SC";

  /** Timeout off command data. */
  private static final int    TIMEOUT_OFF                           = 0xFF;

  /** Indicates that the maximum length for a GET should be used. */
  public static final int     USE_MAXIMUM_LENGTH                    = -1;

  /**
   * @return The singleton instance.
   */
  public static NFC getInstance() {
    // Lazy creation.
    if (instance == null) {
      instance = new NFC();
    }

    return instance;
  }

  /** The currently open connection to a card, if any. */
  private Card        card         = null;

  /** The currently open channel to the card, if any. */
  private CardChannel channel      = null;

  /** The last set of data retrieved from a get command, if any. */
  private byte[]      data         = null;

  /** The last response code received (typically evaluated as two bytes). */
  private int         responseCode = 0;

  /**
   * Default constructor.
   */
  private NFC() {
    super();
  }

  /**
   * Adds the current chunk to the previously chunked buffer.
   *
   * @param previous The previous buffer, if any.
   * @param current The chunk to add.
   * @return The complete set of chunks.
   */
  private byte[] addToChunked(byte[] previous, byte[] current) {
    byte[] chunked = null;
    int start = 0;

    if (previous == null) {
      chunked = new byte[current.length];
    }
    else {
      chunked = new byte[previous.length + current.length];
      System.arraycopy(previous, 0, chunked, 0, previous.length);
      start = previous.length;
    }

    System.arraycopy(current, 0, chunked, start, current.length);

    return chunked;
  }

  /**
   * Closes communication with the NFC terminal, closing any connected card.
   *
   * @return True.
   */
  public boolean close() {
    try {
      if (this.card != null) {
        LOG.trace("disconnecting from card {}", this.card);
        this.card.disconnect(true); // The true might need to be false as the Java implementation may have this the wrong way round.
      }
    }
    catch (final Exception e) {
      LOG.error("could not close connection to card and terminal", e);
    }
    finally {
      this.responseCode = 0;
      this.card = null;
      this.channel = null;
    }

    return true;
  }

  /**
   * Forms a command APDU from the corresponding command and data bytes.
   *
   * @param command The command bytes.
   * @param data Optional data bytes. May be null.
   * @return The command APDU.
   */
  private CommandAPDU formCommand(int[] command, byte[] data) {
    return new CommandAPDU(command[0], command[1], command[2], command[3], data);
  }

  /**
   * Forms a command APDU from the corresponding command and expected return data length.
   *
   * @param command The command bytes.
   * @param length The maximum data expected back.
   * @return The command APDU.
   */
  private CommandAPDU formCommand(int[] command, int length) {
    return new CommandAPDU(command[0], command[1], command[2], command[3], length);
  }

  /**
   * Forms a command APDU from the corresponding command and data bytes, replacing the fourth command byte with the value specified.
   *
   * @param command The command bytes.
   * @param payload The specific fourth command byte.
   * @param data Optional data bytes. May be null.
   * @return The command APDU.
   */
  private CommandAPDU formCommand(int[] command, int payload, byte[] data) {
    return new CommandAPDU(command[0], command[1], command[2], payload, data);
  }

  /**
   * Returns the data previously stored via the {@link #put_internal(byte [] data)} method
   *
   * @param length The maximum data length required. Use USE_MAXIMUM_LENGTH to use the maximum available.
   * @return True if the data was got, false otherwise. The data can be obtained via {@link #getData()}.
   */
  public boolean get_internal(int length) {
    
    this.responseCode=RESPONSE_OK_INT;
    
    if (length == 0 || this.data == null) {
      return false;
    }
    if (length >= 0 && length < this.data.length) {
      this.data = Arrays.copyOfRange(this.data, 0, length);
    }

    return true;
  }

  /**
   * Sends the get command to the card with the specified maximum data length required. If the data requires multiple chunks to be
   * returned, this method automatically handles sending multiple get commands and concatenating the results.
   *
   * @param length The maximum data length required. Use USE_MAXIMUM_LENGTH to use the maximum available.
   * @return True if the data was got, false otherwise. The data can be obtained via {@link #getData()}.
   */
  public boolean get(int length) {
    boolean result = false;

    try {
      if (this.channel != null) {
        int requestLength = length;

        if (requestLength == USE_MAXIMUM_LENGTH) {
          requestLength = NFCSharedMemory.APDU_CHUNK_SIZE;
        }

        LOG.trace("get length {}", requestLength);
        result = this.sendCommand(this.formCommand(COMMAND_GET_CLA_INS_P1_P2, requestLength));
        LOG.trace("get result {}", result);

        // Handle chunked data.
        byte[] chunked = null;

        while (result && (this.responseCode == RESPONSE_CONTINUE_INT) && (this.data != null)) {
          // Save the data to the temporary buffer for appending.
          chunked = this.addToChunked(chunked, this.data);

          LOG.trace("get chunking another {}, total {}", this.data.length, chunked.length);
          System.arraycopy(this.data, 0, chunked, chunked.length - this.data.length, this.data.length);

          // Send another get to obtain the rest of the chunks.
          LOG.trace("get length {}", requestLength);
          result = this.sendCommand(this.formCommand(COMMAND_GET_CLA_INS_P1_P2, requestLength));
          LOG.trace("get result {}", result);
        }

        // If we chunked anything, add in the last bit of data and replace the output data buffer.
        if (result && (this.responseCode == RESPONSE_OK_INT) && (chunked != null)) {
          chunked = this.addToChunked(chunked, this.data);
          this.data = chunked;
        }
      }
    }
    catch (final Exception e) {
      LOG.error("could not get data", e);
    }

    return result;
  }

  /**
   * @return The last set of data retrieved from a get command, if any.
   */
  public byte[] getData() {
    return this.data;
  }

  /**
   * @return The last response code received (typically evaluated as two bytes).
   */
  public int getResponseCode() {
    return this.responseCode;
  }

  /**
   * @return True if the NFC connection is open.
   */
  public boolean isOpen() {
    return this.card != null;
  }

  /**
   * Opens communication with the NFC terminal, waits for a card to be present and connects to it before returning. Setup of the
   * terminal is also included.
   *
   * @return True if communication was opened, false on exception.
   */
  public boolean open() {
    boolean result = false;

    // Make sure any previous connection is closed.
    this.close();

    // Connect and wait for a card.
    try {
      // Get the available terminals and connect to the first.
      final TerminalFactory factory = TerminalFactory.getInstance(TERMINAL_TYPE, null, new Smartcardio());
      final List<CardTerminal> terminals = factory.terminals().list();

      if (!terminals.isEmpty()) {
        final CardTerminal terminal = terminals.get(0);
        LOG.trace("connected to terminal {}", terminal);

        // Wait for a card to be present.
        terminal.waitForCardPresent(0);

        // Connect to the card and setup the terminal.
        if (terminal.isCardPresent()) {
          this.card = terminal.connect(TERMINAL_PROTOCOL);
          this.channel = this.card.getBasicChannel();
          result = (this.card != null) && (this.channel != null) && this.setBuzzer(this.card, false)
              && this.setTimeout(this.card, TIMEOUT_OFF);
          LOG.trace("connected to card {} ({}, {})", this.card, this.card.getProtocol(), result);
        }
      }
    }
    catch (final Exception e) {
      LOG.error("could not open connection to terminal and card", e);
    }
    finally {
      if (!result) {
        this.close();
      }
    }

    return result;
  }

  /**
   * Sends the put command to the card with the specified data.
   *
   * @param data The data to send.
   * @return True if the data was put, false otherwise.
   */
  public boolean put(byte[] data) {
    boolean result = false;

    try {
      if (this.channel != null) {
        // Chunk the data up, if needed.
        boolean finished = false;
        int chunkIndex = 0;

        while (!finished && (chunkIndex < data.length)) {
          final int chunkLength = Math.min(data.length - chunkIndex, NFCSharedMemory.APDU_CHUNK_SIZE - RESPONSE_OK.length);

          // Form the data to send.
          final byte[] buffer = new byte[chunkLength + RESPONSE_OK.length];
          System.arraycopy(data, chunkIndex, buffer, 0, chunkLength);
          chunkIndex += chunkLength;

          if (chunkIndex >= data.length) {
            buffer[chunkLength] = (byte) RESPONSE_OK[0];
            buffer[chunkLength + 1] = (byte) RESPONSE_OK[1];
            finished = true;
          }
          else {
            buffer[chunkLength] = (byte) RESPONSE_CONTINUE[0];
            buffer[chunkLength + 1] = (byte) RESPONSE_CONTINUE[1];
          }

          LOG.trace("put length {} data {}", buffer.length, Utils.toHex(buffer));
          result = this.sendCommand(this.formCommand(COMMAND_PUT_CLA_INS_P1_P2, buffer));
          LOG.trace("put result {}", result);

          if (!result) {
            finished = true;
          }
        }
      }
    }
    catch (final Exception e) {
      LOG.error("could not put data", e);
    }

    return result;
  }

  /**
   * Keeps the specified data in an internal buffer
   * bypassing the NFC card
   *
   * @param data The data to send.
   * @return True if the data was put, false otherwise.
   */
  public boolean put_internal(byte[] data) {
    this.responseCode = RESPONSE_OK_INT;
    this.data = data;
    return true;
  }

  /**
   * Sends the select command to the card to select the required AID.
   *
   * @param aid The AID to select.
   * @return True if the AID was selected, false otherwise.
   */
  public boolean select(byte[] aid) {
    boolean result = false;

    try {
      if (this.channel != null) {
        LOG.trace("put length {} data {}", aid.length, Utils.toHex(aid));
        result = this.sendCommand(this.formCommand(COMMAND_SELECT_CLA_INS_P1_P2, aid));
        LOG.trace("select result {}", result);
      }
    }
    catch (final Exception e) {
      LOG.error("could not select app", e);
    }

    return result;
  }

  /**
   * Sends a control command to set up the terminal.
   *
   * @param apdu The command to send.
   * @return True if the command was sent and executed correctly.
   * @throws CardException
   *           if there was an error executing the command.
   * @throws IllegalArgumentException
   *           if the response is incorrect.
   */
  private boolean sendCommand(CommandAPDU apdu) throws CardException, IllegalArgumentException {
    boolean result = false;
    this.responseCode = 0;

    if (this.channel != null) {
      this.data = null;
      LOG.trace("transmitting {}: {}", apdu, Utils.toHex(apdu.getBytes()));
      final ResponseAPDU response = this.channel.transmit(apdu);
      LOG.trace("response {}", Utils.toHex(response.getBytes()));
      result = ((response.getSW1() == RESPONSE_OK[0]) && (response.getSW2() == RESPONSE_OK[1]))
          || ((response.getSW1() == RESPONSE_CONTINUE[0]) && (response.getSW2() == RESPONSE_CONTINUE[1]));
      this.responseCode = response.getSW();

      if (result) {
        this.data = response.getData();
      }
    }

    return result;
  }

  /**
   * Sends a control command to set up the terminal.
   *
   * @param apdu The command to send.
   * @param responseCode The expected SW2 response code.
   * @return True if the command was sent and executed correctly with the right response code.
   * @throws CardException
   *           if there was an error executing the command.
   * @throws IllegalArgumentException
   *           if the response is incorrect.
   */
  private boolean sendControlCommand(CommandAPDU apdu, int responseCode) throws CardException, IllegalArgumentException {
    boolean result = false;
    this.responseCode = 0;

    if (this.card != null) {
      LOG.trace("transmitting control {}: {}", apdu, Utils.toHex(apdu.getBytes()));
      final byte[] responseData = this.card.transmitControlCommand(IOCTL_SMARTCARD_ACR122_ESCAPE_COMMAND, apdu.getBytes());
      final ResponseAPDU response = new ResponseAPDU(responseData);
      result = (response.getSW1() == RESPONSE_OK[0]) && (response.getSW2() == responseCode);
      this.responseCode = response.getSW();
    }

    return result;
  }

  /**
   * Sets the NFC reader's buzzer on or off.
   *
   * @param card
   *          The card attached to the reader.
   * @param on
   *          Turn the buzzer on?
   * @return True if the command was executed correctly.
   * @throws CardException
   *           if there was an error executing the command.
   * @throws IllegalArgumentException
   *           if the response is incorrect.
   */
  private boolean setBuzzer(Card card, boolean on) throws CardException, IllegalArgumentException {
    final int onOff = on ? BUZZER_ON : BUZZER_OFF;
    final boolean result = this.sendControlCommand(this.formCommand(COMMAND_BUZZER_CLA_INS_P1_P2, onOff, COMMAND_BUZZER_DATA),
        onOff);
    LOG.trace("set buzzer {}: {}", onOff, result);
    return result;
  }

  /**
   * Sets the NFC reader's timeout.
   *
   * @param card
   *          The card attached to the reader.
   * @param value
   *          0x00 means no timeout check, 0xFF means wait forever, any value in between is timeout in 5 second intervals.
   * @return True if the command was executed correctly.
   * @throws CardException
   *           if there was an error executing the command.
   * @throws IllegalArgumentException
   *           if the response is incorrect.
   */
  private boolean setTimeout(Card card, int value) throws CardException, IllegalArgumentException {
    // Note that command data is always needed, even if it is just 1 byte long:
    // http://stackoverflow.com/questions/24758072/acr122u-direct-communication-no-response
    final boolean result = this.sendControlCommand(this.formCommand(COMMAND_TIMEOUT_CLA_INS_P1_P2, value, COMMAND_TIMEOUT_DATA),
        RESPONSE_OK[1]);
    LOG.trace("set timeout {}: {}", value, result);
    return result;
  }
}
