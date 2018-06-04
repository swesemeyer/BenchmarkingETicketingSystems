/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsabc.data;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.protocol.ppetsabc.PPETSABCSharedMemory;

import java.math.BigInteger;

/**
 * Implements user data for the PPETS-ABC NFC protocol as a state machine.
 *
 * @author Matthew Casey
 */
public class UserData implements PPETSABCSharedMemory.ActorData {

	/** The range policy attributes of U. */
	public static BigInteger[] A_U_range = {BigInteger.valueOf(3), BigInteger.valueOf(2) };

	/** The set policy attributes of U. */
	public static String[] A_U_set = {"07", "South", "Commuter", "Visually Impaired" };

	/**
	 * String capturing which range and set policies the user is a member of TODO:
	 * Need to store this differently. Will do for the prototype as it not used apart from the hash
	 */
	public String P_U = "R1-R2-S1-S2-S3-S4";

	/** The identity of U as an arbitrary array of bytes. */
	public byte[] ID_U = new byte[] { 0x01, 0x01, 0x02, 0x03 };

	/** User credentials: c_u. */
	public BigInteger c_u = null;

	/** Random d for ticket. */
	public BigInteger d = null;

	/** Ticket_U (d_dash). */
	public BigInteger d_dash = null;

	/** Ticket_U (d_u). */
	public BigInteger d_u = null;

	/** User credentials: delta_U. */
	public Element delta_U = null;

	/** Ticket_U (omega_u). */
	public BigInteger omega_u = null;

	/** Ticket price. */
	public byte[] price = null;

	/** Random r. */
	public BigInteger r = null;

	/** User credentials: r_u. */
	public BigInteger r_u = null;

	/** Ticket_U (s_u). */
	public BigInteger s_u = null;

	/** Ticket service. */
	public byte[] service = null;

	/** Ticket_U (T_U). */
	public Element T_U = null;

	/** Ticket valid period. */
	public String VP_T = null;

	/** Ticket hash content. */
	public BigInteger psi_uNum = null;

	/** Random x_u. */
	public BigInteger x_u = null;

	/** User ticket identifier. */
	public Element Y = null;

	/** Seller pseudonym */
	public Element Y_S = null;

	/** User pseudonym. */
	public Element Y_U = null;
	
	/** User pseudonym for a given ticket */
	public Element PS_U = null;

	/** some generic valid period for the user credentials */
	public String VP_U = "six months";
}
