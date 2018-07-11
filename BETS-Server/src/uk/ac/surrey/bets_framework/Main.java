/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.crypto.params.DHParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.supercsv.cellprocessor.constraint.LMinMax;
import org.supercsv.cellprocessor.ift.CellProcessor;
import org.supercsv.io.CsvListWriter;
import org.supercsv.io.ICsvListWriter;
import org.supercsv.prefs.CsvPreference;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.google.gson.Gson;

import uk.ac.surrey.bets_framework.command.JCommanderFactory;
import uk.ac.surrey.bets_framework.command.ProtocolRun;
import uk.ac.surrey.bets_framework.icc.ICC;
import uk.ac.surrey.bets_framework.nfc.NFC;
import uk.ac.surrey.bets_framework.protocol.control.setup.ServerData;
import uk.ac.surrey.bets_framework.protocol.control.setup.Setup;
import uk.ac.surrey.bets_framework.protocol.control.teardown.TearDown;
import uk.ac.surrey.bets_framework.state.StateMachine;
import uk.ac.surrey.bets_framework.state.Timing;

/**
 * Main entry point for NFC reader application.
 *
 * @author Matthew Casey
 */
public class Main {

	/** Suffix to timing count used for CSV headers. */
	private static final String CSV_DATA = "-DataSize";

	/** Suffix to timing count used for CSV headers. */
	private static final String CSV_COUNT = "-Count";

	/** Suffix to timing iteration used for CSV headers. */
	private static final String CSV_ITERATION = "Iteration";

	/** Suffix to timing time used for CSV headers. */
	private static final String CSV_TIME = "-Time";

	/** Pause between iterations in milliseconds. */
	private static final long ITERATION_PAUSE = 500L;

	/** Protocol run default key length. */
	private static final int KEY_LENGTH_DEFAULT = 1024;

	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(Main.class);

	/** Logback default log level. */
	private static final int LOG_LEVEL_DEFAULT = 6;

	/** The name of the client timing output file, if any. */
	@Parameter(names = { "--client-output",
			"-c" }, description = "Optionally output the client protocol timings to a CSV file")
	private String clientOutput = null;

	/** Help command line parameter. */
	@Parameter(names = { "--help", "-h" }, description = "Display usage", help = true)
	private boolean help = false;

	/** Protocol run command line parameters. */
	@Parameter(names = { "--input-dh", "-i" }, description = "Load DH parameters from file")
	private String inputDH = null;

	/** The key length to use in protocol runs. */
	@Parameter(names = { "--key-length", "-k" }, description = "Key length")
	private int keyLength = KEY_LENGTH_DEFAULT;

	/** Log level command line parameter. */
	@Parameter(names = { "--log-level",
			"-l" }, description = "Level of logging: 0 off, 1 error, 2, warn, 3 info, 4 debug, 5 trace, 6 all")
	private int logLevel = LOG_LEVEL_DEFAULT;

	/** Protocol run command line parameters. */
	@Parameter(names = { "--output-dh", "-o" }, description = "Save DH parameters to file")
	private String outputDH = null;

	/** Protocol run command line parameters. */
	@Parameter(names = { "--run", "-r" }, description = "Run a protocol (:iterations:parameter1:parameter2:...)")
	private ProtocolRun protocolRun = null;

	/** The name of the server timing output file, if any. */
	@Parameter(names = { "--server-output",
			"-s" }, description = "Optionally output the server protocol timings to a CSV file")
	private String serverOutput = null;

	/** The name of the server setup timing output file, if any. */
	@Parameter(names = { "--setup-output",
			"-u" }, description = "Optionally output the server setup timings to a CSV file")
	private String setupOutput = null;

	/** The name of the server tear down timing output file, if any. */
	@Parameter(names = { "--tear-down-output",
			"-d" }, description = "Optionally output the server tear down timings to a CSV file")
	private String tearDownOutput = null;

	/** Flag to indicate that the protocol should use Diffie-Hellman. */
	@Parameter(names = { "--use-dh", "-e" }, description = "Use DH parameters")
	private boolean useDH = false;

	/** use ICC state machine instead of NFC */
	@Parameter(names = { "--use-comms" }, description = "Optionally specify the channel to use - default is NFC")
	private String commsChannel = "NFC";

	/**
	 * Default constructor.
	 */
	public Main() {
		super();

		// These are needed only because Eclipse's clean up will try to make the fields
		// final because they are set by JCommander, and
		// not explicitly.
		this.protocolRun = null;
		this.logLevel = LOG_LEVEL_DEFAULT;
		this.keyLength = KEY_LENGTH_DEFAULT;
		this.help = false;
		this.serverOutput = null;
		this.clientOutput = null;
		this.setupOutput = null;
		this.tearDownOutput = null;
		this.inputDH = null;
		this.outputDH = null;
		this.useDH = false;
	}

	/**
	 * Main entry point for program when run from the command line.
	 *
	 * @param args
	 *            Command arguments.
	 */
	public static void main(String[] args) {
		// Process the command line arguments.
		final Main main = new Main();
		final JCommander jCommander = new JCommander(main);
		jCommander.setProgramName(Main.class.getSimpleName());
		jCommander.addConverterFactory(new JCommanderFactory());

		try {
			jCommander.parse(args);

			// Display usage, if required.
			if (main.help) {
				jCommander.usage();
			} else {
				// Run the code.
				main.run();
			}
		} catch (final ParameterException e) {
			jCommander.usage();
		} catch (final Exception e) {
			LOG.error("failed to run", e);
		} finally {
			// Make sure the comms channel is reset.
			if (main.commsChannel.equalsIgnoreCase("NFC")) {
				NFC.getInstance().close();
			} else if (main.commsChannel.equals("ICC")) {
				ICC.getInstance().close();
			}
		}
	}

	/**
	 * Inputs DH parameters from file.
	 *
	 * @param filename
	 *            The file to load the DH parameters from.
	 * @return The loaded DH parameters, or null on error.
	 */
	private DHParameters inputDHParameters(String filename) {
		DHParameters dhParameters = null;

		try {
			final Gson gson = new Gson();
			final byte[] bytes = Files.readAllBytes(Paths.get(filename));
			dhParameters = gson.fromJson(new String(bytes), DHParameters.class);
		} catch (final IOException e) {
			LOG.error("could not load DH parameters from file {}", filename, e);
		}

		return dhParameters;
	}

	/**
	 * Outputs the timing CSV file header and returns the associated cell
	 * processors.
	 *
	 * @param csvWriter
	 *            The CSV writer for the file.
	 * @param names
	 *            The names of the fields for the header.
	 * @return The cell processors for each field.
	 * @throws IOException
	 *             If there was a problem writing the header.
	 */
	private CellProcessor[] outputCSVHeader(ICsvListWriter csvWriter, final List<String> names) throws IOException {
		final List<String> header = new ArrayList<>();
		final List<CellProcessor> processors = new ArrayList<>();

		// Add in the iteration number.
		header.add(CSV_ITERATION);
		processors.add(new LMinMax(1L, LMinMax.MAX_LONG));

		// Add in three fields per timing: the time, the count and the number of bytes
		// processed
		for (final String name : names) {
			header.add(name + CSV_TIME);
			processors.add(new LMinMax(LMinMax.MIN_LONG, LMinMax.MAX_LONG));

			header.add(name + CSV_COUNT);
			processors.add(new LMinMax(LMinMax.MIN_LONG, LMinMax.MAX_LONG));

			header.add(name + CSV_DATA);
			processors.add(new LMinMax(LMinMax.MIN_LONG, LMinMax.MAX_LONG));
		}

		// Write the header.
		csvWriter.writeHeader(header.toArray(new String[0]));

		// Return the cell processors for each field.
		return processors.toArray(new CellProcessor[0]);
	}

	/**
	 * Outputs a timings CSV row to file.
	 *
	 * @param csvWriter
	 *            The CSV writer for the file.
	 * @param names
	 *            The names of the fields to get the order correct.
	 * @param cellProcessors
	 *            The cell processors used to output the CSV fields.
	 * @param iteration
	 *            The current iteration number.
	 * @param timings
	 *            The timings to be output.
	 * @throws IOException
	 *             If there was a problem writing the timings.
	 */
	private void outputCSVTimings(ICsvListWriter csvWriter, final List<String> names, CellProcessor[] cellProcessors,
			int iteration, final Map<String, Timing> timings) throws IOException {
		final List<Long> values = new ArrayList<>();

		// Add one to the iteration number to make it start at one
		// rather than zero.
		values.add((long) iteration + 1);

		// Add in three fields per timing: the time, the count, the amount of data sent
		for (final String name : names) {
			final Timing timing = timings.get(name);
			values.add(timing.getTime());
			values.add(timing.getCount());
			values.add(timing.getDataSize());

		}

		csvWriter.write(values);
	}

	/**
	 * Outputs the cryptographic DH parameters to file.
	 *
	 * @param filename
	 *            The name of the file to write to.
	 * @param dhParameters
	 *            The DH parameters to output.
	 */
	private void outputDHParameters(String filename, DHParameters dhParameters) {
		try {
			final Gson gson = new Gson();
			Files.write(Paths.get(filename), gson.toJson(dhParameters).getBytes());
		} catch (final IOException e) {
			LOG.error("could not save generated DH parameters to file {}", filename, e);
		}
	}

	/**
	 * returns a list of timer names in the order in which the timers were created
	 * 
	 * @param timings
	 *            the list of timings to be output
	 * @return the list of names in the order in which the timers were created
	 */

	private List<String> orderedTimerNames(List<Map<String, Timing>> timings) {
		TreeMap<String, String> sortedTimerNames = new TreeMap<String, String>();
		Map<String, Timing> tmpMap = timings.get(0);

		for (String name : tmpMap.keySet()) {
			sortedTimerNames.put(tmpMap.get(name).getCreationTime() + name, name);
		}
		return new ArrayList<String>(sortedTimerNames.values());
	}

	/**
	 * Outputs a list of timings to a CSV file.
	 *
	 * @param timings
	 *            The list of timings to be output.
	 * @param filename
	 *            The output filename.
	 */
	private void outputTimings(List<Map<String, Timing>> timings, String filename) {
		ICsvListWriter csvWriter = null;

		if (timings.size() > 0) {
			try {
				// Open the output CSV file.
				csvWriter = new CsvListWriter(new FileWriter(filename), CsvPreference.STANDARD_PREFERENCE);

				// Get the list of names in sorted order for consistency. We hope they match for
				// each protocol run.
				// final List<String> names = new ArrayList<>(timings.get(0).keySet());
				// Collections.sort(names);

				final List<String> names = this.orderedTimerNames(timings);

				// Output the header.
				final CellProcessor[] cellProcessors = this.outputCSVHeader(csvWriter, names);

				// Add each iterations timings to the file.
				for (int i = 0; i < timings.size(); i++) {
					this.outputCSVTimings(csvWriter, names, cellProcessors, i, timings.get(i));
				}
			} catch (final IOException e) {
				LOG.error("could not open timing output file {}", filename, e);
			} finally {
				if (csvWriter != null) {
					try {
						csvWriter.close();
					} catch (final IOException e) {
						LOG.error("could not close timing output file {}", filename, e);
					}
				}
			}
		}
	}

	/**
	 * Runs the code.
	 */
	private void run() {
		// Set the log level from the command line parameter.
		Utils.setLogLevel(this.logLevel);

		// Set up the cryptographic parameters.
		final Crypto crypto = Crypto.getInstance();

		LOG.info("using key length {}", this.keyLength);
		crypto.setKeyLength(this.keyLength);

		// Optionally load DH parameters from file.
		if (this.inputDH != null) {
			LOG.info("loading DH parameters from {}", this.inputDH);
			crypto.setDhParameters(this.inputDHParameters(this.inputDH));
		}

		// Generate the DH parameters, if needed.
		if (this.useDH && (crypto.getDhParameters() == null)) {
			LOG.info("generating DH parameters");
			crypto.generateDHParameters();
		}

		// Optionally save the DH parameters to file.
		if ((this.outputDH != null) && (crypto.getDhParameters() != null)) {
			LOG.info("saving DH parameters to {}", this.outputDH);
			this.outputDHParameters(this.outputDH, crypto.getDhParameters());
		}

		// Define the server data for the client.
		final ServerData serverData = new ServerData(crypto.getPublicKey().getEncoded(), this.logLevel,
				this.protocolRun, this.keyLength, crypto.getDhParameters());

		// Warm up the encryption so that loading of the encryption provider does not
		// slow things down.
		crypto.decrypt(crypto.encrypt(new byte[] { 1, 2, 3, 4 }, crypto.getPublicKey()), crypto.getPrivateKey());

		// Run the protocol the required number of times.
		final Class<?> clazz = Utils.getClass(this.getClass().getPackage().getName(), this.protocolRun.getName());
		final List<Map<String, Timing>> serverTimings = new ArrayList<>();
		final List<Map<String, Timing>> clientTimings = new ArrayList<>();
		final List<Map<String, Timing>> setupTimings = new ArrayList<>();
		final List<Map<String, Timing>> tearDownTimings = new ArrayList<>();

		if (clazz != null) {
			LOG.info("running protocol {}", this.protocolRun);

			try {
				for (int i = 1; i <= this.protocolRun.getIteration(); i++) {
					if (this.commsChannel.equalsIgnoreCase("NFC")) {
						// Setup the client.
						LOG.info("{}: setup", i);
						final Setup setup = new Setup(serverData);

						// Sometimes setup just fails to get through to the Android device. Try running
						// for a fixed number of times until success.
						if (!setup.run()) {
							throw new IllegalStateException("could not setup client");
						}

						// Save off the setup timings.
						setupTimings.add(setup.getTimings());
					}
					// Run the protocol for this iteration.
					LOG.info("{}: {}", i, this.protocolRun.getName());
					final StateMachine<?> protocol = (StateMachine<?>) clazz.newInstance();
					protocol.setParameters(this.protocolRun.getParameters());
					final boolean result = protocol.run();

					if (result) {
						LOG.info("{}: {} success", i, this.protocolRun.getName());
					} else {
						LOG.error("{}: {} failed", i, this.protocolRun.getName());
					}

					// Save off the server timings.
					serverTimings.add(protocol.getTimings());
					if (this.commsChannel.equalsIgnoreCase("NFC")) {
						// Tear down the client.
						LOG.info("{}: tear down", i);
						final TearDown tearDown = new TearDown();

						if (tearDown.run()) {
							// Save off the client timings.
							clientTimings.addAll(tearDown.getClientTimings());
						} else {
							throw new IllegalStateException("could not tear down client");
						}

						// Save off the tear down timings.
						tearDownTimings.add(tearDown.getTimings());
					}
					// Pause a short while as the NFC stuff seems quite erratic.
					try {
						Thread.sleep(ITERATION_PAUSE);
					} catch (final InterruptedException e) {
						// Ignore.
					}
				}
			} catch (final InstantiationException | IllegalAccessException | ClassCastException e) {
				LOG.error("could not create protocol {}", this.protocolRun.getName(), e);
			} catch (final IllegalStateException e) {
				LOG.error("could not setup or tear down client", e);
			}
		} else {
			LOG.error("could not find protocol {}", this.protocolRun.getName());
		}

		// Optionally output the server timing data.
		if (this.serverOutput != null) {
			this.outputTimings(serverTimings, this.serverOutput);
		}

		// Optionally output the client timing data.
		if (this.clientOutput != null) {
			this.outputTimings(clientTimings, this.clientOutput);
		}

		// Optionally output the server setup timing data.
		if (this.setupOutput != null) {
			this.outputTimings(setupTimings, this.setupOutput);
		}

		// Optionally output the server tear down timing data.
		if (this.tearDownOutput != null) {
			this.outputTimings(tearDownTimings, this.tearDownOutput);
		}
	}
}
