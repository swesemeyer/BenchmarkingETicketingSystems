package uk.ac.surrey.bets_framework.icc;

import java.util.Arrays;

/**
 * Abstracts communication with an Internal Communication Channel as a
 * singleton.
 * 
 * @author Steve Wesemeyer
 */

public class ICC {

	/** The singleton instance. */
	private static ICC instance = null;

	/** The last set of data retrieved from a get command, if any. */
	private byte[] data = null;

	/** The last response code received (typically evaluated as two bytes). */
	private int responseCode = 0;

	/** Response OK code. */
	private static final int RESPONSE_OK = 0;

	/** Response ERROR code. */
	private static final int RESPONSE_ERROR = 1;
	
	  /** Indicates that the maximum length for a GET should be used. */
	  public static final int     USE_MAXIMUM_LENGTH                    = -1;

	/** boolean flag to indicate if the internal comms channel has been opened */

	private boolean isOpen = false;

	/**
	 * Default constructor.
	 */
	private ICC() {
		super();
	}

	/**
	 * @return The singleton instance.
	 */
	public static ICC getInstance() {
		// Lazy creation.
		if (instance == null) {
			instance = new ICC();
		}

		return instance;
	}

	/**
	 * Creates an internal comms channel
	 *
	 * @return True if communication was opened
	 */
	public boolean open() {
		// clear any data
		this.data = null;
		this.isOpen = true;
		this.responseCode=RESPONSE_OK;
		return true;
	}

	/**
	 * Closes communication with the NFC terminal, closing any connected card.
	 *
	 * @return True.
	 */
	public boolean close() {
		this.isOpen = false;
		this.responseCode=RESPONSE_OK;
		return true;
	}

	/**
	 * @return True if the NFC connection is open.
	 */
	public boolean isOpen() {
		this.responseCode=RESPONSE_OK;
		return this.isOpen;
	}

	/**
	 * Returns the data previously stored via the {@link #put(byte [] data)} method
	 *
	 * @param length
	 *            The maximum data length required. Use USE_MAXIMUM_LENGTH to use
	 *            the maximum available.
	 * @return True if the data was got, false otherwise. The data can be obtained
	 *         via {@link #getData()}.
	 */
	public boolean get(int length) {

		if (length == 0 || this.data == null) {
			this.responseCode = RESPONSE_ERROR;
			return false;
		}
		if (length >= 0 && length < this.data.length) {
			this.data = Arrays.copyOfRange(this.data, 0, length);
		}
		this.responseCode=RESPONSE_OK;
		return true;
	}

	/**
	 * Keeps the specified data in an internal buffer
	 *
	 * @param data
	 *            The data to send.
	 * @return True
	 */
	public boolean put(byte[] data) {
		this.data = data;
		this.responseCode=RESPONSE_OK;
		return true;
	}

	/**
	 * @return The last set of data retrieved from a get command, if any.
	 */
	public byte[] getData() {
		this.responseCode=RESPONSE_OK;
		return this.data;
	}

	/**
	 * @return the response code for this channel
	 */

	public int getResponseCode() {
		// as this channel will always succeed
		return this.responseCode;
	}
}
