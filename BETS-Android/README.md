# NFC App #

This repository contains the Android code which can be run to evaluate experiments on cryptographic protocols used during e-ticket purchasing and usage. This app interacts with the program built from the NFC Reader repository on a PC with an ACR122 NFC device connected.

## Setup ##

* Download this repository
* Open the repository in Android Studio
* Launch the app on a connected device that has NFC enabled
* Place the device on the NFC reader

Note that the first time the device is placed on the NFC reader, NFC communications may fail.  Simply re-run the PC-based NFC reader software.

## Running ##

All control of the protocol is maintained by the PC-based NFC reader software.  This will:

* Set up this app at each iteration of a protocol run, including which protocol should be run and its parameters
* Run the protocol
* Tear down this app after each protocol run, retrieving the timing results

The above is then automatically repeated for each required iteration of the protocol run.

## Enhancements ##

Currently, an activity is installed and will open when the app is run.  The activity only shows which protocol is being processed and could be removed.

All NFC communications are chunked into 32 bytes (plus protocol).  This is because the communications become unstable with a larger number of bytes in each packet sent.  This makes protocol runs slow and the number of bytes possible to transmit should be increased if possible.

We also use the Java-based JPBC library ( http://gas.dia.unisa.it/projects/jpbc/) for the bilinear maps used in the protocols which is very slow (at least on the Samsung Galaxy J3 used for testing). 
It should be possible to migrate that to the "pure" C-based version (https://crypto.stanford.edu/pbc/) to speed up the computations on the Android device.
