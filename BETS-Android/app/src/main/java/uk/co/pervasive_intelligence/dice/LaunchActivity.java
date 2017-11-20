/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.co.pervasive_intelligence.dice;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

/**
 * Launch activity for NFC application.
 *
 * @author Matthew Casey
 */
public class LaunchActivity extends AppCompatActivity {

  /** The broadcast receiver. */
  private ProcessingBroadcastReceiver receiver = new ProcessingBroadcastReceiver();

  /**
   * Called when the activity is starting.
   *
   * @param savedInstanceState If the activity is being re-initialized after previously being shut down then this Bundle contains
   *                           the data it most recently supplied in {@link #onSaveInstanceState}.  <b><i>Note: Otherwise it is
   *                           null.</i></b>
   */
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_launch);

    // Register for local broadcasts.
    IntentFilter filter = new IntentFilter(APDUService.BROADCAST_ACTION);
    LocalBroadcastManager.getInstance(this).registerReceiver(this.receiver, filter);

  }

  /**
   * Perform any final cleanup before an activity is destroyed.
   */
  @Override
  protected void onDestroy() {
    // Unregister the broadcast receiver.
    LocalBroadcastManager.getInstance(this).unregisterReceiver(this.receiver);

    super.onDestroy();
  }

  /**
   * Used to receive broadcast messages.
   */
  private class ProcessingBroadcastReceiver extends BroadcastReceiver {

    /**
     * This method is called when the BroadcastReceiver is receiving an Intent broadcast.
     *
     * @param context The Context in which the receiver is running.
     * @param intent  The Intent being received.
     */
    @Override
    public void onReceive(Context context, Intent intent) {
      TextView textView = (TextView) LaunchActivity.this.findViewById(R.id.processingTextView);

      if (textView != null) {
        String message = intent.getStringExtra(APDUService.BROADCAST_ACTION_MESSAGE);

        if (message != null) {
          textView.setText(LaunchActivity.this.getResources().getString(R.string.processingText, message));
        }
        else {
          textView.setText(R.string.noProcessingText);
        }
      }
    }
  }
}
