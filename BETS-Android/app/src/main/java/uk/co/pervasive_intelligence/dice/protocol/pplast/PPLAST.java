package uk.co.pervasive_intelligence.dice.protocol.pplast;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidStateMachine;
import uk.co.pervasive_intelligence.dice.state.SharedMemory;
import uk.co.pervasive_intelligence.dice.state.State;

/**
 * This implements the state machine for the PPLAST protocol
 * <p>
 * (c) Steve Wesemeyer 2017
 */

public class PPLAST extends NFCAndroidStateMachine {

  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PPLAST.class);

  /**
   * The shared memory.
   */
  private PPLASTSharedMemory sharedMemory = new PPLASTSharedMemory();

  /**
   * Default constructor.
   */
  public PPLAST() {
    super(Arrays.<State<NFCAndroidCommand>>asList(new PPLASTSetupStates.SState00(), new PPLASTSetupStates.SState01(),
            new PPLASTRegistrationStates.RState02(), new PPLASTRegistrationStates.RState03(),
            new PPLASTIssuingStates.IState04(), new PPLASTIssuingStates.IState05(),
            new PPLASTVerifyingStates.VState06(), new PPLASTVerifyingStates.VState07()));
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
   * <p>
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
    } catch (final Exception e) {
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
