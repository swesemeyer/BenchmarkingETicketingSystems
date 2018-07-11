/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.anonsso;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.protocol.NFCReaderStateMachine;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory.Actor;
import uk.ac.surrey.bets_framework.state.SharedMemory;
/**
 * Implements the AnonProxy(Han et al) protocol as a state machine.
 *
 * Han, J. et al "Anonymous Single-Sign-On for n designated services with traceability" (AnonProxy)
 * 
 * available at https://arxiv.org/abs/1804.07201
 *
 * @author Steve Wesemeyer
 */
public class AnonSSO extends NFCReaderStateMachine {

	/** The shared memory. */
	private AnonSSOSharedMemory sharedMemory = new AnonSSOSharedMemory();

	/**
	 * Default constructor.
	 */
	public AnonSSO() {
		super(Arrays.asList(new AnonSSOSetupStates.SState00(), new AnonSSOSetupStates.SState01(),
				new AnonSSOSetupStates.SState02(), new AnonSSOSetupStates.SState03(),
				new AnonSSORegistrationStates.RState04(), new AnonSSORegistrationStates.RState05(),
				new AnonSSORegistrationStates.RState06(), new AnonSSORegistrationStates.RState07(),
				new AnonSSORegistrationStates.RState08(), new AnonSSORegistrationStates.RState09(),
				new AnonSSORegistrationStates.RState10(), new AnonSSORegistrationStates.RState11(),
				new AnonSSORegistrationStates.RState12(), new AnonSSORegistrationStates.RState13(),
				new AnonSSORegistrationStates.RState14(), new AnonSSORegistrationStates.RState15(),
				new AnonSSORegistrationStates.RState16(), new AnonSSORegistrationStates.RState17(Actor.VERIFIERS),
				new AnonSSORegistrationStates.RState18(), new AnonSSORegistrationStates.RState19(),
				new AnonSSORegistrationStates.RState20(), new AnonSSORegistrationStates.RState21(Actor.VERIFIERS),
				new AnonSSOIssuingStates.IState22(), new AnonSSOIssuingStates.IState23(),
				new AnonSSOIssuingStates.IState24(), new AnonSSOVerifyingStates.VState25(AnonSSOSharedMemory.J_U),
				new AnonSSOVerifyingStates.VState26(), new AnonSSOVerifyingStates.VState27(AnonSSOSharedMemory.J_U),
				new AnonSSOVerifyingStates.VState28(), new AnonSSOVerifyingStates.VState29(),
				new AnonSSOVerifyingStates.VState30()));
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
	 * Parameters are: (int) number of r bits to use in Type A elliptic curve, e.g.
	 * 256 (default).
	 *
	 * @param parameters
	 *            The list of parameters.
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
		}

		catch (final Exception e) {
			LOG.error("could not set parameters", e);
		}
	}

	/**
	 * Sets the shared memory for the state machine.
	 *
	 * @param sharedMemory
	 *            The shared memory to set.
	 */
	@Override
	public void setSharedMemory(SharedMemory sharedMemory) {
		this.sharedMemory = (AnonSSOSharedMemory) sharedMemory;
	}
	
	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonSSO.class);
}
