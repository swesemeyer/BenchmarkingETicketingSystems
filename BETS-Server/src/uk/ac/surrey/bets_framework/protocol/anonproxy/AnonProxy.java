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

import uk.ac.surrey.bets_framework.icc.ICC;
import uk.ac.surrey.bets_framework.protocol.ICCCommand;
import uk.ac.surrey.bets_framework.protocol.ICCStateMachine;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSORegistrationStates;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSOSharedMemory.Actor;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.SharedMemory;
import uk.ac.surrey.bets_framework.state.State;
import uk.ac.surrey.bets_framework.state.Action.Status;

/**
 * Implements the AnonProxy(Han et al) protocol as a state machine.
 *
 * Han, J. et al "Privacy-Preserving Smart Ticketing Scheme with Proxy
 * Verification" (AnonProxy)
 * 
 * available at ???
 *
 * @author Steve Wesemeyer
 */
public class AnonProxy extends ICCStateMachine {

	/** The shared memory. */
	private AnonProxySharedMemory sharedMemory = new AnonProxySharedMemory();

	/**
	 * General GetState: gets the data and continues to the next state
	 */
	public static class GetState extends State<ICCCommand> {

		private int nextState;

		public GetState(int nextState) {
			this.nextState = nextState;
		}

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {

			// Get the issuer identity data.
			return new Action<>(Status.CONTINUE, this.nextState, ICCCommand.GET, null, ICC.USE_MAXIMUM_LENGTH);
		}
	}

	/**
	 * Default constructor.
	 */
	public AnonProxy() {
		super(Arrays.asList(new AnonProxySetupStates.SState00(),new AnonProxySetupStates.SState01(),
				//Issuer registration states
				new AnonProxyRegistrationStates.RState02(),//put issuer data
				new AnonProxy.GetState(4),//get data
				new AnonProxyRegistrationStates.RState04(),//compute issuer credentials & put data
				new AnonProxy.GetState(6),//get data,//get data
				new AnonProxyRegistrationStates.RState06(),//verify credentials
				//User registration states
				new AnonProxyRegistrationStates.RState07(),//put user data
				new AnonProxy.GetState(9),//get data
				new AnonProxyRegistrationStates.RState09(),//compute user credentials & put data
				new AnonProxy.GetState(11),//get data
				new AnonProxyRegistrationStates.RState11(),//verify credentials
				//Verifiers registration states
				new AnonProxyRegistrationStates.RState12(Actor.VERIFIERS), //put verifier data
				new AnonProxy.GetState(14), //get data
				new AnonProxyRegistrationStates.RState14(), //compute credentials & put data
				new AnonProxy.GetState(16), //get data 
				new AnonProxyRegistrationStates.RState16(Actor.VERIFIERS), //verify credentials
				//Central Verifier registration states
				new AnonProxyRegistrationStates.RState17(),//put central verifier data
				new AnonProxy.GetState(19),//get data
				new AnonProxyRegistrationStates.RState19(),//compute credentials & put data
				new AnonProxy.GetState(21),//get data
				new AnonProxyRegistrationStates.RState21(),//verify credentials
				//TicketIssuing states
				new AnonProxyIssuingStates.IState22(),//generate ticket request
				new AnonProxy.GetState(24),//get data
				new AnonProxyIssuingStates.IState24(),//compute ticket details & put data
				new AnonProxy.GetState(26),//get data
				new AnonProxyIssuingStates.IState26(),//verify credentials
				
				//Ticket Validation/Proxy Validation
   			    new AnonProxyVerifyingStates.VState27(AnonProxySharedMemory.J_U,AnonProxySharedMemory.Verifiers_for_J_U), //send ID_V
				new AnonProxy.GetState(29),//get data 
				new AnonProxyVerifyingStates.VState29(), //send Tag+Proof
				new AnonProxy.GetState(31),//get data 
				new AnonProxyVerifyingStates.VState31(AnonProxySharedMemory.J_U,AnonProxySharedMemory.Verifiers_for_J_U), //verify Tag & Proof
				new AnonProxyVerifyingStates.VState32(), //send ID_CV
				//get Data is done by GetState 28
				//send Tag, Proof and T_U is done by Vstate29
				//which then goes to GetState 33
				new AnonProxy.GetState(34),//get data 
				new AnonProxyVerifyingStates.VState34(), //verify Tag, Proof and de-anonymise user and services from T_U
				new AnonProxy.GetState(36),
				new AnonProxyVerifyingStates.VState36(),//get ID_V and ID_V' and generate rekeys
				new AnonProxy.GetState(38),
				new AnonProxyVerifyingStates.VState38()//store the rekeys and return to VState27

				
			
				
				
				
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
