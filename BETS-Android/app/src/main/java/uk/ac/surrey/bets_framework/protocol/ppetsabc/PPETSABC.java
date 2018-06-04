/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsabc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidStateMachine;
import uk.ac.surrey.bets_framework.state.SharedMemory;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.protocol.ppetsabc.PPETSABCSharedMemory.PairingType;

/**
 * Implements the PPETS-ABC (Han, submitted) NFC protocol as a state machine.
 *
 * Han, J., Chen, L., Schneider, S.,  Treharne, H. & Wesemeyer, S(submitted).
 * "PPETS-ABC: Privacy-preserving Electronic Ticket Scheme with Attribute-based Credentials".
 *
 * @author Matthew Casey
 */
public class PPETSABC extends NFCAndroidStateMachine {

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSABC.class);

  /** The shared memory. */
  private PPETSABCSharedMemory sharedMemory = new PPETSABCSharedMemory();

  /**
   * Default constructor.
   */
  public PPETSABC() {
    super(Arrays.<State<NFCAndroidCommand>>asList(new PPETSABCSetupStates.SState00(), new PPETSABCSetupStates.SState01(), new
        PPETSABCRegistrationStates.RState02(), new PPETSABCRegistrationStates.RState03(), new PPETSABCRegistrationStates.RState04
        (), new PPETSABCRegistrationStates.RState05(), new PPETSABCIssuingStates.IState06(), new PPETSABCIssuingStates.IState07()
        , new PPETSABCIssuingStates.IState08(), new PPETSABCValidationStates.VState09(), new PPETSABCValidationStates.VState10()));
  }

  /**
   * Sets the state machine parameters, clearing out any existing parameters.
   *
   * Parameters are:
   * (boolean) always pass verification tests, e.g. false (default).
   * (int) the number of times that a ticket should be validated to provoke double spend, e.g. 2 (default).
   * (int) number of r bits to use in Type A elliptic curve, e.g. 256 (default).
   * (int) number of q bits to use in Type A elliptic curve, e.g. 512 (default).
   *
   * @param parameters The list of parameters.
   */
  @Override
  public void setParameters(List<String> parameters) {
    super.setParameters(parameters);

    // Pull out the relevant parameters into the shared memory.
    try {
      if (parameters.size() > 0) {
        this.sharedMemory.skipVerification = Boolean.parseBoolean(parameters.get(0));
      }

      if (parameters.size() > 1) {
        this.sharedMemory.numValidations = Integer.parseInt(parameters.get(1));
      }

      if (parameters.size()>2) {
        String pairingType=parameters.get(2);
        switch (pairingType) {
          case "A":
            this.sharedMemory.setPairingType(PairingType.TYPE_A);
            break;
          case "A1":
            this.sharedMemory.setPairingType(PairingType.TYPE_A1);
            //this pairing uses slightly different parameters
            //the number of primes to use
            this.sharedMemory.rBits=3;
            //the size of these primes
            this.sharedMemory.qBits=160;
            break;
          case "E":
            this.sharedMemory.setPairingType(PairingType.TYPE_E);
            break;
          default:
            throw new UnsupportedOperationException("This pairing type is not supported: "+pairingType);
        }
      }

      if (parameters.size() > 3) {
        //note for type A1 pairing this represents the number of primes to use
        this.sharedMemory.rBits = Integer.parseInt(parameters.get(3));
      }

      if (parameters.size() > 4) {
        //for type A1 pairings this represents the size of the primes
        this.sharedMemory.qBits = Integer.parseInt(parameters.get(4));
      }

      LOG.debug("ignore verfication failures:" + (this.sharedMemory.skipVerification));
      LOG.debug("bilinear group parameters (" + this.sharedMemory.rBits + ", " + this.sharedMemory.qBits + ")");
    }
    catch (final Exception e) {
      LOG.error("could not set parameters", e);
    }
  }

  /**
   * @return The shared memory for the state machine.
   */
  @Override
  public SharedMemory getSharedMemory() {
    return this.sharedMemory;
  }

  /**
   * Sets the shared memory for the state machine.
   *
   * @param sharedMemory The shared memory to set.
   */
  @Override
  public void setSharedMemory(SharedMemory sharedMemory) {
    this.sharedMemory = (PPETSABCSharedMemory) sharedMemory;
  }
}
