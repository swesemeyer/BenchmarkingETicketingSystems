/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.control.setup;

import android.util.Base64;

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

  /** The public key bytes used to encrypt messages. */
  private byte[] encodedPublicKey = null;

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
    this.encodedPublicKey = Base64.decode(json.get(JSON_ENCODED_PUBLIC_KEY).getAsString(), Base64.NO_WRAP);
  }

  /**
   * Creates a JSON object containing the data.
   *
   * @return The corresponding JSON object.
   */
  @Override
  protected JsonObject toJson() {
    final JsonObject json = super.toJson();

    json.addProperty(JSON_ENCODED_PUBLIC_KEY, Base64.encodeToString(this.encodedPublicKey, Base64.NO_WRAP));

    return json;
  }

  /**
   * @return The public key bytes used to encrypt messages.
   */
  public byte[] getEncodedPublicKey() {
    return this.encodedPublicKey;
  }
}
