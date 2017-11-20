/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.control.setup;

import uk.co.pervasive_intelligence.dice.protocol.data.DataException;

/**
 * Encapsulates the client data exchanged between the server and the client during setup.
 *
 * @author Matthew Casey
 */
public class ClientData extends CommonData {

  /**
   * Private default constructor.
   */
  private ClientData() {
    super(null);
  }

  /**
   * Constructor which requires the mandatory fields.
   *
   * @param encodedPublicKey The public key bytes used to encrypt messages.
   */
  public ClientData(byte[] encodedPublicKey) {
    super(encodedPublicKey);
  }

  /**
   * Creates a new object from the byte data.
   *
   * @param bytes The bytes to load from.
   * @return The corresponding data object.
   */
  public static ClientData fromBytes(byte[] bytes) {
    ClientData clientData = null;

    try {
      clientData = new ClientData();
      clientData.setFromBytes(bytes);
    }
    catch (final DataException e) {
      // Make sure we return null.
      clientData = null;
    }

    return clientData;
  }
}
