/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.control.setup;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;

import uk.ac.surrey.bets_framework.protocol.data.Data;

/**
 * Encapsulates the common data exchanged between the server and the client.
 *
 * @author Matthew Casey
 */
public class CommonData extends Data {

  /** JSON encoded public key key. */
  private static final String JSON_ENCODED_PUBLIC_KEY = "encodedPublicKey";

  /** Logback logger. */
  private static final Logger LOG                     = LoggerFactory.getLogger(CommonData.class);

  /** The public key bytes used to encrypt messages. */
  private byte[]              encodedPublicKey        = null;

  /**
   * Constructor which requires the mandatory fields.
   *
   * @param encodedPublicKey The public key bytes used to encrypt messages.
   */
  public CommonData(byte[] encodedPublicKey) {
    super();

    this.encodedPublicKey = encodedPublicKey;
  }

  /**
   * Sets the fields from JSON data.
   *
   * @param json The source JSON data.
   */
  @Override
  protected void fromJson(JsonObject json) {
    try {
      final Decoder base64 = Base64.getDecoder();
      this.encodedPublicKey = base64.decode(json.get(JSON_ENCODED_PUBLIC_KEY).getAsString().getBytes(UTF8));
    }
    catch (final UnsupportedEncodingException e) {
      LOG.error("could not decode Base 64 string", e);
    }
  }

  /**
   * @return The public key bytes used to encrypt messages.
   */
  public byte[] getEncodedPublicKey() {
    return this.encodedPublicKey;
  }

  /**
   * Creates a JSON object containing the data.
   *
   * @return The corresponding JSON object.
   */
  @Override
  protected JsonObject toJson() {
    final JsonObject json = super.toJson();

    try {
      final Encoder base64 = Base64.getEncoder();
      json.addProperty(JSON_ENCODED_PUBLIC_KEY, new String(base64.encode(this.encodedPublicKey), UTF8));
    }
    catch (final UnsupportedEncodingException e) {
      LOG.error("could not encode Base 64 string", e);
    }

    return json;
  }
}
