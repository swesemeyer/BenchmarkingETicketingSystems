/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.control.teardown;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import uk.ac.surrey.bets_framework.protocol.data.Data;
import uk.ac.surrey.bets_framework.protocol.data.DataException;
import uk.ac.surrey.bets_framework.state.Timing;

/**
 * Encapsulates the timings data exchanged between the server and the client.
 *
 * @author Matthew Casey
 */
public class TimingsData extends Data {

  /** JSON timings key. */
  private static final String             JSON_TIMINGS = "timings";

  /** The list of timings. */
  private final List<Map<String, Timing>> timings      = new ArrayList<>();

  /**
   * Private default constructor.
   */
  private TimingsData() {
    super();
  }

  /**
   * Constructor requiring the list of timings map.
   *
   * @param timings The list of timings.
   */
  public TimingsData(List<Map<String, Timing>> timings) {
    super();

    this.timings.addAll(timings);
  }

  /**
   * Creates a new object from the byte data.
   *
   * @param bytes The bytes to load from.
   * @return The corresponding data object.
   */
  public static TimingsData fromBytes(byte[] bytes) {
    TimingsData timingsData = null;

    try {
      timingsData = new TimingsData();
      timingsData.setFromBytes(bytes);
    }
    catch (final DataException e) {
      // Make sure we return null.
      timingsData = null;
    }

    return timingsData;
  }

  /**
   * Sets the fields from JSON data.
   *
   * @param json The source JSON data.
   */
  @Override
  protected void fromJson(JsonObject json) {
    final Gson gson = new Gson();
    final Type listType = new TypeToken<List<Map<String, Timing>>>() {
    }.getType();

    this.timings.clear();
    this.timings.addAll(gson.fromJson(json.get(JSON_TIMINGS), listType));
  }

  /**
   * @return An immutable list of the timings.
   */
  public List<Map<String, Timing>> getTimings() {
    return Collections.unmodifiableList(this.timings);
  }

  /**
   * Creates a JSON object containing the data.
   *
   * @return The corresponding JSON object.
   */
  @Override
  protected JsonObject toJson() {
    final JsonObject json = super.toJson();

    final Gson gson = new Gson();
    json.add(JSON_TIMINGS, gson.toJsonTree(this.timings));

    return json;
  }
}
