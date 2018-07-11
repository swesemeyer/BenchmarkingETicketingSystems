/**
 * DICE Protocol evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.protocol.ICCStateMachine;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSORegistrationStates;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory.Actor;
import uk.ac.surrey.bets_framework.state.SharedMemory;
/**
 * Implements the AnonProxy(Han et al) protocol as a state machine.
 *
 * Han, J. et al "Privacy-Preserving Smart Ticketing Scheme with Proxy Verification" (AnonProxy)
 * 
 * available at ???
 *
 * @author Steve Wesemeyer
 */
public class AnonProxy extends ICCStateMachine {

	/** The shared memory. */
	private AnonProxySharedMemory sharedMemory = new AnonProxySharedMemory();

	/**
	 * Default constructor.
	 */
	public AnonProxy() {
		super(Arrays.asList(new AnonProxySetupStates.SState00(),new AnonProxySetupStates.SState01(),
				//Issuer registration states
				new AnonProxyRegistrationStates.RState02(),//put data
				new AnonProxyRegistrationStates.RState03(),//get data
				new AnonProxyRegistrationStates.RState04(),//compute credentials & put data
				new AnonProxyRegistrationStates.RState05(),//get data
				new AnonProxyRegistrationStates.RState06(),//verify credentials
				//User registration states
				new AnonProxyRegistrationStates.RState07(),//put data
				new AnonProxyRegistrationStates.RState08(),//get data
				new AnonProxyRegistrationStates.RState09(),//compute credentials & put data
				new AnonProxyRegistrationStates.RState10(),//get data
				new AnonProxyRegistrationStates.RState11(),//verify credentials
				//Verifier registration states
				new AnonProxyRegistrationStates.RState12(Actor.VERIFIERS), //put data
				new AnonProxyRegistrationStates.RState13(), //get data
				new AnonProxyRegistrationStates.RState14(), //compute credentials & put data
				new AnonProxyRegistrationStates.RState15(), //get data 
				new AnonProxyRegistrationStates.RState16(Actor.VERIFIERS) //verify credentials
				
				
				
				
				//Central verifier registration states				
				));
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
		this.sharedMemory = (AnonProxySharedMemory) sharedMemory;
	}
	
	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonProxy.class);
}
