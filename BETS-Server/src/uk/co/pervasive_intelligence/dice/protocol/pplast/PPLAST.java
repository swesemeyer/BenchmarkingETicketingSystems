/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.pplast;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.protocol.NFCReaderStateMachine;
import uk.co.pervasive_intelligence.dice.protocol.pplast.PPLASTSharedMemory.Actor;
import uk.co.pervasive_intelligence.dice.state.SharedMemory;

/**
 * Implements the PPLAST(Han et al) NFC protocol as a state machine.
 *
 * Han, J. et al
 * "Privacy-preserving Location-aware smart ticketing" (PPLAST)
 *
 * @author Matthew Casey
 */
public class PPLAST extends NFCReaderStateMachine {

  /** Logback logger. */
  private static final Logger LOG          = LoggerFactory.getLogger(PPLAST.class);

  /** The shared memory. */
  private PPLASTSharedMemory  sharedMemory = new PPLASTSharedMemory();

  /**
   * Default constructor.
   */
  public PPLAST() {
    super(Arrays.asList(new PPLASTSetupStates.SState00(), new PPLASTSetupStates.SState01(), new PPLASTSetupStates.SState02(),
        new PPLASTSetupStates.SState03(), new PPLASTRegistrationStates.RState04(), new PPLASTRegistrationStates.RState05(),
        new PPLASTRegistrationStates.RState06(), new PPLASTRegistrationStates.RState07(), new PPLASTRegistrationStates.RState08(),
        new PPLASTRegistrationStates.RState09(), new PPLASTRegistrationStates.RState10(), new PPLASTRegistrationStates.RState11(),
        new PPLASTRegistrationStates.RState12(), new PPLASTRegistrationStates.RState13(), new PPLASTRegistrationStates.RState14(),
        new PPLASTRegistrationStates.RState15(), new PPLASTRegistrationStates.RState16(),
        new PPLASTRegistrationStates.RState17(Actor.VERIFIER), new PPLASTRegistrationStates.RState18(),
        new PPLASTRegistrationStates.RState19(), new PPLASTRegistrationStates.RState20(),
        new PPLASTRegistrationStates.RState21(Actor.VERIFIER), new PPLASTIssuingStates.IState22(),
        new PPLASTIssuingStates.IState23(),new PPLASTIssuingStates.IState24(),
        new PPLASTVerifyingStates.VState25(new String[] { Actor.VERIFIER[2], Actor.VERIFIER[5], Actor.VERIFIER[1] }),
        new PPLASTVerifyingStates.VState26(),
        new PPLASTVerifyingStates.VState27(new String[] { Actor.VERIFIER[2], Actor.VERIFIER[5], Actor.VERIFIER[1] }),
        new PPLASTVerifyingStates.VState28(),new PPLASTVerifyingStates.VState29()));
  }

  /**
   * @return The shared memory for the state machine.
   */
  @Override
  public SharedMemory getSharedMemory() {
    return this.sharedMemory;
  }

  /**
   * Sets the state machine parameters, clearing out any existing parameters.
   *
   * Parameters are:
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
        this.sharedMemory.rBits = Integer.parseInt(parameters.get(0));
      }

      LOG.debug("bilinear group parameters r = " + this.sharedMemory.rBits);
    }
    catch (final Exception e) {
      LOG.error("could not set parameters", e);
    }
  }

  /**
   * Sets the shared memory for the state machine.
   *
   * @param sharedMemory The shared memory to set.
   */
  @Override
  public void setSharedMemory(SharedMemory sharedMemory) {
    this.sharedMemory = (PPLASTSharedMemory) sharedMemory;
  }
}
