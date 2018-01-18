/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.data;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

/**
 * Encapsulates a generic list of bytes to be exchanged between the server and
 * the client.
 *
 * @author Matthew Casey
 */
public class ListData extends Data {

	/** JSON encoded list of bytes. */
	private static final String JSON_LIST_BYTES_KEY = "listBytes";

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(ListData.class);

	/** The list of bytes. */
	private final List<byte[]> list = new ArrayList<>();

	/**
	 * Private default constructor.
	 */
	private ListData() {
		super();
	}

	/**
	 * Constructor which requires the mandatory fields.
	 *
	 * @param list
	 *            The list of bytes.
	 */
	public ListData(List<byte[]> list) {
		super();

		this.list.addAll(list);
	}

	/**
	 * Creates a new object from the byte data.
	 *
	 * @param bytes
	 *            The bytes to load from.
	 * @return The corresponding data object.
	 */
	public static ListData fromBytes(byte[] bytes) {
		ListData listData = null;

		try {
			listData = new ListData();
			listData.setFromBytes(bytes);
		} catch (final DataException e) {
			LOG.error("could not decode the data", e);
			listData = null;
		}

		return listData;
	}

	/**
	 * Sets the fields from JSON data.
	 *
	 * @param json
	 *            The source JSON data.
	 */
	@Override
	protected void fromJson(JsonObject json) {
		final Gson gson = new Gson();
		final Type listType = new TypeToken<List<String>>() {
		}.getType();

		// Convert the list of Base 64 strings into bytes.
		final Decoder base64 = Base64.getDecoder();
		final List<String> strings = gson.fromJson(json.get(JSON_LIST_BYTES_KEY), listType);
		this.list.clear();

		for (final String string : strings) {
			this.list.add(base64.decode(string.getBytes(UTF8)));
		}

	}

	/**
	 * @return The list of bytes.
	 */
	public List<byte[]> getList() {
		return Collections.unmodifiableList(this.list);
	}

	/**
	 * Creates a JSON object containing the data.
	 *
	 * @return The corresponding JSON object.
	 */
	@Override
	protected JsonObject toJson() {
		final JsonObject json = super.toJson();

		// Convert each array in the list to Base64.
		final Encoder base64 = Base64.getEncoder();
		final List<String> strings = new ArrayList<>();

		for (final byte[] bytes : this.list) {
			strings.add(new String(base64.encode(bytes), UTF8));
		}

		final Gson gson = new Gson();
		json.add(JSON_LIST_BYTES_KEY, gson.toJsonTree(strings));

		return json;
	}
}
