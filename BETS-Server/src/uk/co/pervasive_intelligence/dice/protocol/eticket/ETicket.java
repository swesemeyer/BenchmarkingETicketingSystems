/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice.protocol.eticket;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.pervasive_intelligence.dice.Crypto;
import uk.co.pervasive_intelligence.dice.protocol.NFCReaderStateMachine;
import uk.co.pervasive_intelligence.dice.state.SharedMemory;

/**
 * Implements the e-ticket protocol defined by Guasch (2013) as a state machine.
 *
 * Guasch, A.V. (2013). "Contributions to the Security and Privacy of Electronic Ticketing Systems". Ph.D Dissertation, Universitat
 * Rovira i Virgili.
 *
 * @author Matthew Casey
 */
public class ETicket extends NFCReaderStateMachine {


  /** Logback logger. */
  private static final Logger LOG          = LoggerFactory.getLogger(ETicket.class);

  /** The shared memory. */
  private ETicketSharedMemory sharedMemory = new ETicketSharedMemory();

  /**
   * Default constructor.
   */
  public ETicket() {
    super(Arrays.asList(new ETicketPseudonymStates.NState00(), new ETicketPseudonymStates.NState01(),
        new ETicketPseudonymStates.NState02(), new ETicketPurchaseStates.PState03(), new ETicketPurchaseStates.PState04(),
        new ETicketPurchaseStates.PState05(), new ETicketPurchaseStates.PState06(), new ETicketVerificationStates.VState07(),
        new ETicketVerificationStates.VState08(), new ETicketVerificationStates.VState09(),
        new ETicketVerificationStates.VState10(), new ETicketVerificationStates.VState11()));
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
   * (int) number of times ticket is to be used, e.g. 1 (default).
   * (int) cost of each service, e.g. 1 (default) or 2, ... to have each iteration cost more to cause ticket verification failure.
   * (String) encryption parameters, e.g. "RSA" (default) or "RSA/ECB/OAEPWithSHA1AndMGF1Padding"
   * (String) hash parameters, e.g. "SHA256" (default)
   * (int) prime certainty, e.g. 80% (default) or above.
   *
   * @param parameters The list of parameters.
   */
  @Override
  public void setParameters(List<String> parameters) {
    super.setParameters(parameters);

    // Pull out the relevant parameters into the shared memory.
    final Crypto crypto = Crypto.getInstance();

    try {
      if (parameters.size() > 0) {
        this.sharedMemory.n = Integer.parseInt(parameters.get(0));
      }

      if (parameters.size() > 1) {
        this.sharedMemory.s = Integer.parseInt(parameters.get(1));
      }

      if (parameters.size() > 2) {
        crypto.setEncryptionParameters(parameters.get(2));
      }

      if (parameters.size() > 3) {
        crypto.setHashParameters(parameters.get(3));
      }

      if (parameters.size() > 4) {
        crypto.setPrimeCertainty(Integer.parseInt(parameters.get(4)));
      }
    }
    catch (final Exception e) {
      LOG.error("could not set parameters", e);
    }

    // Make sure we have DH parameters defined.
    if (crypto.getDhParameters() == null) {
      throw new IllegalArgumentException("DH parameters must be defined");
    }
  }

  /**
   * Sets the shared memory for the state machine.
   *
   * @param sharedMemory The shared memory to set.
   */
  @Override
  public void setSharedMemory(SharedMemory sharedMemory) {
    this.sharedMemory = (ETicketSharedMemory) sharedMemory;
  }
}
