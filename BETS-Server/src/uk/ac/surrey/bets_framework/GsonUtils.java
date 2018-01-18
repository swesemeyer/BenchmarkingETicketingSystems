/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import uk.ac.surrey.bets_framework.protocol.data.Data;

/**
 * Utilities for use with GSON.
 *
 * @author Matthew Casey
 */
public class GsonUtils {

	/**
	 * Deserializes an CurveElement.
	 */
	public static class CurveElementDeserializer implements JsonDeserializer<CurveElement<?, ?>> {

		/** The field associated with the curve. */
		private CurveField<?> field1 = null;
		private CurveField<?> field2 = null;

		/**
		 * Constructor.
		 *
		 * @param field
		 *            The field associated with the curve.
		 */
		public CurveElementDeserializer(CurveField<?> field1, CurveField<?> field2) {
			super();

			this.field1 = field1;
			this.field2 = field2;
		}

		/**
		 * Constructor.
		 *
		 * @param field
		 *            The field associated with the curve.
		 */
		public CurveElementDeserializer(CurveField<?> field1) {
			super();

			this.field1 = field1;
			this.field2 = null;
		}

		/**
		 * Gson invokes this call-back method during deserialization when it encounters
		 * a field of the specified type.
		 *
		 * @param json
		 *            The Json data being deserialized.
		 * @param typeOfT
		 *            The type of the Object to deserialize to.
		 * @return a deserialized object of the specified type typeOfT which is a
		 *         subclass of {@code T}.
		 * @throws JsonParseException
		 *             if json is not in the expected format of {@code typeofT}.
		 */
		@Override
		public CurveElement<?, ?> deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
				throws JsonParseException {
			final Decoder base64 = Base64.getDecoder();
			CurveElement<?, ?> curveElement = null;

			String type = json.getAsString().substring(0, 1);

			byte[] bytes = base64.decode(json.getAsString().substring(1).getBytes(Data.UTF8));

			if (type.equalsIgnoreCase("1")) {
				curveElement = new CurveElement<>(this.field1);
			} else {
				curveElement = new CurveElement<>(this.field2);
			}
			curveElement.setFromBytes(bytes);

			return (CurveElement<?, ?>) curveElement.getImmutable();
		}
	}

	/**
	 * Serializes an CurveElement.
	 */
	public static class CurveElementSerializer implements JsonSerializer<CurveElement<?, ?>> {

		/** The field associated with the curve. */
		private CurveField<?> field1 = null;
		private CurveField<?> field2 = null;

		/**
		 * Constructor.
		 *
		 * @param field
		 *            The field associated with the curve.
		 */
		public CurveElementSerializer(CurveField<?> field1, CurveField<?> field2) {
			super();

			this.field1 = field1;
			this.field2 = field2;
		}

		/**
		 * Constructor.
		 *
		 * @param field
		 *            The field associated with the curve.
		 */
		public CurveElementSerializer() {
			super();

			this.field1 = null;
			this.field2 = null;
		}

		/**
		 * Gson invokes this call-back method during serialization when it encounters a
		 * field of the specified type.
		 *
		 * @param src
		 *            the object that needs to be converted to Json.
		 * @param typeOfSrc
		 *            the actual type (fully genericized version) of the source object.
		 * @return a JsonCurveElement corresponding to the specified object.
		 */
		@Override
		public JsonElement serialize(CurveElement<?, ?> src, Type typeOfSrc, JsonSerializationContext context) {
			final Encoder base64 = Base64.getEncoder();
			JsonElement curveElement = null;
			String type = "1";
			if ((this.field2 != null) && (src.getField().equals(this.field2))) {
				type = "2";
			}
			// Get the CurveElement bytes as a string.

			curveElement = new JsonPrimitive(type + (new String(base64.encode(src.toBytes()), Data.UTF8)));

			return curveElement;
		}
	}

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(GsonUtils.class);
}
