/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.anonsso.data;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;

/**
 * Implements the central verifier data for the AnonProxy NFC protocol as a state
 * machine.
 *
 * @author Steve Wesemeyer
 */
public class CentralVerifierData extends VerifierData {

	// default constructor
	public CentralVerifierData(String ID_CV, BigInteger p, Element xi) {
		super(ID_CV, p, xi);
	}

}
