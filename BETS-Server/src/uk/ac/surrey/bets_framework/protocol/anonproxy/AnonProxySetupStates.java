package uk.ac.surrey.bets_framework.protocol.anonproxy;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.surrey.bets_framework.protocol.ICCCommand;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Action.Status;
import uk.ac.surrey.bets_framework.state.Message;
import uk.ac.surrey.bets_framework.state.Message.Type;
import uk.ac.surrey.bets_framework.state.State;

public class AnonProxySetupStates {	
	
	
	/**
	 * State 0.
	 */
	public static class SState00 extends State<ICCCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			// Clear out shared memory as we are starting again.
			final AnonProxySharedMemory sharedMemory = (AnonProxySharedMemory) this.getSharedMemory();
			sharedMemory.clear();

			if (message.getType() == Type.START) {
				// Open the connection.
				return new Action<>(1, ICCCommand.OPEN);
			}

			return super.getAction(message);
		}
	}
	
	/**
	 * State 1.
	 */
	public static class SState01 extends State<ICCCommand> {

		/**
		 * Gets the required action given a message.
		 *
		 * @param message
		 *            The received message to process.
		 * @return The required action.
		 */
		@Override
		public Action<ICCCommand> getAction(Message message) {
			if (message.getType() == Type.SUCCESS) {
				LOG.info("setup complete");
				return new Action<>(2);
			}
			return super.getAction(message);
		}

	}


	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(AnonProxySetupStates.class);
}
