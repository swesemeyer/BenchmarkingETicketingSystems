/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.data;

import java.io.UnsupportedEncodingException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

/**
 * Encapsulates the data exchanged between the server and the client.
 *
 * @author Matthew Casey
 */
public abstract class Data {

  /** Character set used for byte conversion. */
  public static final String  UTF8 = "UTF-8";

  /** Logback logger. */
  //private static final Logger LOG  = LoggerFactory.getLogger(Data.class);

  /**
   * Default constructor.
   */
  protected Data() {
    super();
  }

  /**
   * Sets the fields from JSON data.
   *
   * @param json The source JSON data.
   */
  protected abstract void fromJson(JsonObject json);

  /**
   * Sets the object's fields from a byte array.
   *
   * @param bytes The bytes to load from.
   * @throws DataException If the bytes cannot be decoded.
   */
  protected final void setFromBytes(byte[] bytes) throws DataException {
    // Convert the bytes into a UTF8 JSON string and convert into JSON (hopefully).
    try {
      final String utf8 = new String(bytes, UTF8);
      //LOG.debug("utf8="+utf8);
      final JsonObject json = new JsonParser().parse(utf8).getAsJsonObject();

      // Decode the JSON and set the fields.
      this.fromJson(json);
    }
    catch (final UnsupportedEncodingException | IllegalStateException | JsonSyntaxException e) {
      throw new DataException("could not decode bytes", e);
    }
  }

  /**
   * Converts the data into a byte array.
   *
   * @return The corresponding byte array.
   */
  public final byte[] toBytes() {
    byte[] bytes = null;

    // Convert the data into JSON.
    final JsonObject json = this.toJson();

    // Convert the JSON object into a UTF8 byte array.
    try {
      bytes = json.toString().getBytes(UTF8);
    }
    catch (final UnsupportedEncodingException e) {
      // Ignore - will be null.
    }

    return bytes;
  }

  /**
   * Creates a JSON object containing the data.
   *
   * @return The corresponding JSON object.
   */
  protected JsonObject toJson() {
    return new JsonObject();
  }
}
