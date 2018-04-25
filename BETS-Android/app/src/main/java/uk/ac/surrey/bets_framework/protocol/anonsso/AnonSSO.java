package uk.ac.surrey.bets_framework.protocol.anonsso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidStateMachine;
import uk.ac.surrey.bets_framework.state.SharedMemory;
import uk.ac.surrey.bets_framework.state.State;

/**
 * This implements the state machine for the AnonSSO protocol
 * <p>
 * (c) Steve Wesemeyer 2017
 */

public class AnonSSO extends NFCAndroidStateMachine {

  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AnonSSO.class);

  /**
   * The shared memory.
   */
  private AnonSSOSharedMemory sharedMemory = new AnonSSOSharedMemory();

  /**
   * Default constructor.
   */
  public AnonSSO() {
    super(Arrays.<State<NFCAndroidCommand>>asList(new AnonSSOSetupStates.SState00(), new AnonSSOSetupStates.SState01(),
            new AnonSSORegistrationStates.RState02(), new AnonSSORegistrationStates.RState03(),
            new AnonSSOIssuingStates.IState04(), new AnonSSOIssuingStates.IState05(),
            new AnonSSOVerifyingStates.VState06(), new AnonSSOVerifyingStates.VState07()));
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

      if (parameters.size() > 1) {
        this.sharedMemory.validateVerifiers = (1 == Integer.parseInt(parameters.get(1)));
      }
      LOG.debug("validateVerifiers = " + this.sharedMemory.validateVerifiers);
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
    this.sharedMemory = (AnonSSOSharedMemory) sharedMemory;
  }
}
