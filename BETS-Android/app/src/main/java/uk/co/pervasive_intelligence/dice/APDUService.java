/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice;

import android.content.Context;
import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import dalvik.system.DexFile;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidCommand;
import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;
import uk.co.pervasive_intelligence.dice.protocol.responder.Responder;
import uk.co.pervasive_intelligence.dice.state.Message;
import uk.co.pervasive_intelligence.dice.state.StateMachine;

/**
 * Launch activity for NFC application.
 *
 * @author Matthew Casey
 */
public class APDUService extends HostApduService {

  /** The app broadcast action. */
  public static final String BROADCAST_ACTION = "uk.co.pervasive_intelligence.dice.protocol.responder.BROADCAST";

  /** The app broadcast action message in the intent. */
  public static final String BROADCAST_ACTION_MESSAGE = "MESSAGE";

  /** Logback logger. */
  private static final Logger LOG = LoggerFactory.getLogger(APDUService.class);

  /** A weak reference to the context so that broadcast messages can be sent statically. */
  private static WeakReference<Context> weakContext = null;

  /** The state machine handling the protocol. */
  private StateMachine<NFCAndroidCommand> stateMachine = null;

  /**
   * Allows a local broadcast message to be sent statically.  This assumes that the static weak reference to the context is
   * maintained.
   *
   * @param message The message payload to sent.
   */
  public static void sendLocalBroadcast(String message) {
    // Get the context.
    if (weakContext != null) {
      Context context = weakContext.get();

      if (context != null) {
        Intent intent = new Intent();
        intent.setAction(BROADCAST_ACTION);

        if (message != null) {
          intent.putExtra(BROADCAST_ACTION_MESSAGE, message);
        }

        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
      }
    }
  }

  /**
   * Gets the list of available classes in Android for the current package.
   */
  private List<String> getAvailableClasses() {
    List<String> classes = new ArrayList<>();

    try {
      // Scan through the Dex file for the package. See:
      // http://stackoverflow.com/questions/15446036/find-all-classes-in-a-package-in-android
      DexFile dexFile = new DexFile(this.getPackageCodePath());
      Enumeration<String> classNames = dexFile.entries();

      while (classNames.hasMoreElements()) {
        String className = classNames.nextElement();

        if (className.contains(APDUService.class.getPackage().getName())) {
          classes.add(className);
        }
      }
    }
    catch (IOException e) {
      LOG.error("cannot get list of classes", e);
    }

    return classes;
  }

  /**
   * Called by the system when the service is first created.  Do not call this method directly.
   */
  @Override
  public void onCreate() {
    LOG.trace("onCreate");
    super.onCreate();

    weakContext = new WeakReference<Context>(this);
  }

  /**
   * Called by the system every time a client explicitly starts the service by calling
   * {@link Context#startService}, providing the arguments it supplied and a
   * unique integer token representing the start request.  Do not call this method directly.
   *
   * <p>For backwards compatibility, the default implementation calls
   * {@link #onStart} and returns either {@link #START_STICKY}
   * or {@link #START_STICKY_COMPATIBILITY}.
   *
   * <p>If you need your application to run on platform versions prior to API
   * level 5, you can use the following model to handle the older {@link #onStart}
   * callback in that case.  The <code>handleCommand</code> method is implemented by
   * you as appropriate:
   *
   * {@sample development/samples/ApiDemos/src/com/example/android/apis/app/ForegroundService.java
   * start_compatibility}
   *
   * <p class="caution">Note that the system calls this on your
   * service's main thread.  A service's main thread is the same
   * thread where UI operations take place for Activities running in the
   * same process.  You should always avoid stalling the main
   * thread's event loop.  When doing long-running operations,
   * network calls, or heavy disk I/O, you should kick off a new
   * thread, or use {@link AsyncTask}.</p>
   *
   * @param intent  The Intent supplied to {@link Context#startService},
   *                as given.  This may be null if the service is being restarted after
   *                its process has gone away, and it had previously returned anything
   *                except {@link #START_STICKY_COMPATIBILITY}.
   * @param flags   Additional data about this start request.  Currently either
   *                0, {@link #START_FLAG_REDELIVERY}, or {@link #START_FLAG_RETRY}.
   * @param startId A unique integer representing this specific request to
   *                start.  Use with {@link #stopSelfResult(int)}.
   * @return The return value indicates what semantics the system should
   * use for the service's current started state.  It may be one of the
   * constants associated with the {@link #START_CONTINUATION_MASK} bits.
   * @see #stopSelfResult(int)
   */
  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    LOG.trace("onStartCommand {}, {}, {}", intent, flags, startId);
    return super.onStartCommand(intent, flags, startId);
  }

  /**
   * Called by the system to notify a Service that it is no longer used and is being removed.  The
   * service should clean up any resources it holds (threads, registered
   * receivers, etc) at this point.  Upon return, there will be no more calls
   * in to this Service object and it is effectively dead.  Do not call this method directly.
   */
  @Override
  public void onDestroy() {
    LOG.trace("onDestroy");
    super.onDestroy();
  }

  @Override
  public void onLowMemory() {
    LOG.trace("onLowMemory");
    super.onLowMemory();
  }

  /**
   * <p>This method will be called when a command APDU has been received from a remote device. A response APDU can be provided
   * directly by returning a byte-array in this method. Note that in general response APDUs must be sent as quickly as possible,
   * given the fact that the user is likely holding his device over an NFC reader when this method is called.
   *
   * <p class="note">If there are multiple services that have registered for the same AIDs in their meta-data entry, you will only
   * get called if the user has explicitly selected your service, either as a default or just for the next tap.
   *
   * <p class="note">This method is running on the main thread of your application. If you cannot return a response APDU
   * immediately, return null and use the {@link #sendResponseApdu(byte[])} method later.
   *
   * @param commandAPDU The APDU that was received from the remote device.
   * @param extras      A bundle containing extra data. May be null.
   * @return a byte-array containing the response APDU, or null if no response APDU can be sent at this point.
   */
  @Override
  public byte[] processCommandApdu(byte[] commandAPDU, Bundle extras) {
    LOG.trace("processing APDU {}", Utils.toHex(commandAPDU));

    // This method will only be called if the registered AID has been selected by the server. We inject the message into the
    // state machine for processing.
    Message message = new Message(commandAPDU);
    byte[] result = null;

    // Create the state machine, if it does not exist.
    if (this.stateMachine == null) {
      this.stateMachine = new Responder(this.getAvailableClasses());
    }

    if (this.stateMachine.run(message)) {
      // Extract the response from the state machine.
      result = ((NFCAndroidSharedMemory) this.stateMachine.getSharedMemory()).response;
    }

    if (result == null) {
      result = NFCAndroidSharedMemory.RESPONSE_FUNCTION_NOT_SUPPORTED;
      sendLocalBroadcast(null);
    }

    LOG.trace("result {}", Utils.toHex(result));
    return result;
  }

  /**
   * This method will be called in two possible scenarios:
   * <li>The NFC link has been deactivated or lost.
   * <li>A different AID has been selected and was resolved to a different service component.
   *
   * @param reason Either {@link #DEACTIVATION_LINK_LOSS} or {@link #DEACTIVATION_DESELECTED}
   */
  @Override
  public void onDeactivated(int reason) {
    LOG.trace("onDeactivated {}", reason);
  }
}
