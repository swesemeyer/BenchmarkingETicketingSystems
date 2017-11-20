/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.control.setup;

import org.bouncycastle.crypto.params.DHParameters;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import uk.ac.surrey.bets_framework.command.ProtocolRun;
import uk.ac.surrey.bets_framework.protocol.data.DataException;

/**
 * Encapsulates the setup data exchanged between the server and the client.
 *
 * @author Matthew Casey
 */
public class ServerData extends CommonData {

  /** JSON DH parameters key. */
  private static final String JSON_DH_PARAMETERS_KEY = "dhParameters";

  /** JSON key length key. */
  private static final String JSON_KEY_LENGTH        = "keyLength";

  /** JSON log level key. */
  private static final String JSON_LOG_LEVEL         = "logLevel";

  /** JSON protocol run key. */
  private static final String JSON_PROTOCOL_RUN      = "protocolRun";

  /** The DH parameters. */
  private DHParameters        dhParameters           = null;

  /** The key length for generating key pairs. */
  private int                 keyLength              = 0;

  /** Level of logging. */
  private int                 logLevel               = 0;

  /** The protocol being run. */
  private ProtocolRun         protocolRun            = null;

  /**
   * Private default constructor.
   */
  private ServerData() {
    super(null);
  }

  /**
   * Constructor requiring all fields.
   *
   * @param encodedPublicKey The public key bytes used to encrypt messages.
   * @param logLevel Level of logging.
   * @param protocolRun The protocol being run.
   * @param keyLength The key length for generating key pairs.
   * @param dhParameters The DH parameters.
   */
  public ServerData(byte[] encodedPublicKey, int logLevel, ProtocolRun protocolRun, int keyLength, DHParameters dhParameters) {
    super(encodedPublicKey);

    this.logLevel = logLevel;
    this.protocolRun = protocolRun;
    this.keyLength = keyLength;
    this.dhParameters = dhParameters;
  }

  /**
   * Creates a new object from the byte data.
   *
   * @param bytes The bytes to load from.
   * @return The corresponding data object.
   */
  public static ServerData fromBytes(byte[] bytes) {
    ServerData serverData = null;

    try {
      serverData = new ServerData();
      serverData.setFromBytes(bytes);
    }
    catch (final DataException e) {
      // Make sure we return null.
      serverData = null;
    }

    return serverData;
  }

  /**
   * Sets the fields from JSON data.
   *
   * @param json The source JSON data.
   */
  @Override
  protected void fromJson(JsonObject json) {
    final Gson gson = new Gson();
    super.fromJson(json);

    this.logLevel = json.getAsJsonPrimitive(JSON_LOG_LEVEL).getAsNumber().intValue();
    this.protocolRun = gson.fromJson(json.get(JSON_PROTOCOL_RUN), ProtocolRun.class);
    this.keyLength = json.getAsJsonPrimitive(JSON_KEY_LENGTH).getAsNumber().intValue();
    this.dhParameters = gson.fromJson(json.get(JSON_DH_PARAMETERS_KEY), DHParameters.class);
  }

  /**
   * @return The DH parameters.
   */
  public DHParameters getDhParameters() {
    return this.dhParameters;
  }

  /**
   * @return The key length for generating key pairs.
   */
  public int getKeyLength() {
    return this.keyLength;
  }

  /**
   * @return Level of logging.
   */
  public int getLogLevel() {
    return this.logLevel;
  }

  /**
   * @return The protocol being run.
   */
  public ProtocolRun getProtocolRun() {
    return this.protocolRun;
  }

  /**
   * Creates a JSON object containing the data.
   *
   * @return The corresponding JSON object.
   */
  @Override
  protected JsonObject toJson() {
    final Gson gson = new Gson();
    final JsonObject json = super.toJson();

    json.addProperty(JSON_LOG_LEVEL, this.logLevel);
    json.add(JSON_PROTOCOL_RUN, gson.toJsonTree(this.protocolRun));
    json.addProperty(JSON_KEY_LENGTH, this.keyLength);
    json.add(JSON_DH_PARAMETERS_KEY, gson.toJsonTree(this.dhParameters));

    return json;
  }
}
