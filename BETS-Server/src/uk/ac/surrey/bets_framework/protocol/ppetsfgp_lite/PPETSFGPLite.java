/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp_lite;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.protocol.NFCReaderStateMachine;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPIssuingStates;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPRegistrationStates;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSetupStates;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory;
import uk.ac.surrey.bets_framework.state.SharedMemory;

/**
 * Implements the revised, lighter version of the PPETS-FGP (Han, unpublished) NFC protocol as a state machine.
 *
 * Han, J., Chen, L., Schneider, S. & Treharne, H. (unpublished).
 * "PPETS-FGP: Privacy-preserving Electronic Ticket Scheme with Fine-grained Pricing".
 *
 * @author Matthew Casey
 */
public class PPETSFGPLite extends NFCReaderStateMachine {

  /** Logback logger. */
  private static final Logger  LOG          = LoggerFactory.getLogger(PPETSFGPLite.class);

  /** The shared memory. */
  private PPETSFGPSharedMemory sharedMemory = new PPETSFGPSharedMemory();

  /**
   * Default constructor.
   */
  public PPETSFGPLite() {
    // Note that some states are modified from the non-lite version.
    super(Arrays.asList(new PPETSFGPSetupStates.SState00(), new PPETSFGPSetupStates.SState01(), new PPETSFGPSetupStates.SState02(),
        new PPETSFGPSetupStates.SState03(), new PPETSFGPRegistrationStates.RState04(), new PPETSFGPRegistrationStates.RState05(),
        new PPETSFGPRegistrationStates.RState06(), new PPETSFGPRegistrationStates.RState07(),
        new PPETSGFPLiteIssuingStates.ImState08(), new PPETSFGPIssuingStates.IState09(), new PPETSFGPIssuingStates.IState10(),
        new PPETSFGPLiteValidationStates.VState11(), new PPETSFGPLiteValidationStates.VState12()));
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
        this.sharedMemory.passVerification = Boolean.parseBoolean(parameters.get(0));
      }

      if (parameters.size() > 1) {
        this.sharedMemory.numValidations = Integer.parseInt(parameters.get(1));
      }

      if (parameters.size() > 2) {
        this.sharedMemory.rBits = Integer.parseInt(parameters.get(2));
      }

      if (parameters.size() > 3) {
        this.sharedMemory.qBits = Integer.parseInt(parameters.get(3));
      }
      LOG.debug("ignore verfication failures:" + (this.sharedMemory.passVerification));
      LOG.debug("bilinear group parameters (" + this.sharedMemory.rBits + ", " + this.sharedMemory.qBits + ")");
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
    this.sharedMemory = (PPETSFGPSharedMemory) sharedMemory;
  }
}
