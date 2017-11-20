package uk.co.pervasive_intelligence.dice.protocol.eticket;

import java.math.BigInteger;

import uk.co.pervasive_intelligence.dice.protocol.NFCAndroidSharedMemory;

/**
 * The implementation of the state machine's shared memory.
 */
public class ETicketSharedMemory extends NFCAndroidSharedMemory {

  /** Get service, 5) A1: random value power mod thing. */
  public BigInteger A1 = null;

  /** Get service, 6) A2: random value power mod thing. */
  public BigInteger A2 = null;

  /** Verify ticket, 3ai) APi: part of verification time stamp. */
  public byte[] APi = null;

  /** Get server, 3) HU: random value power mod thing. */
  public BigInteger HU = null;

  /** Get challenge, 3) HUc: challenge. */
  public BigInteger HUc = null;

  /** Solve challenge, 4) K: hash of w1. */
  public byte[] K = null;

  /** Verify pseudonym, 1) PseuU = sigT: verified pseudonym for user. */
  public byte[] PseuU = null;

  /** Verify Proof, 7) RStar: signed verification response. */
  public byte[] RStar = null;

  /** Get ticket, 7) Sn: unique serial number. */
  public byte[] Sn = null;

  /** Get service, 1) Sv: desired service. */
  public byte[] Sv = null;

  /** Get ticket, 12) TStar: signed ticket. */
  public byte[] TStar = null;

  /** Get service, 4) a1: random value. */
  public BigInteger a1 = null;

  /** Get service, 4) a2: random value. */
  public BigInteger a2 = null;

  /** Get challenge, 1) c: random value power mod thing. */
  public BigInteger c = null;

  /** Get ticket, 8) hrIn: hash chain n of rI. */
  public byte[] hrIn = null;

  /** Validation confirmation, 4) hrIn: the current hrIn taking into account usage. */
  public byte[] hrInCurrent = null;

  /** Get service, 2) hrUn: hash chain n of rU. */
  public byte[] hrUn = null;

  /** Verify proof, 7) hrUnCurrent: the current hrUn taking into account usage. */
  public byte[] hrUnCurrent = null;

  /** Authenticate user, 2) hyU: hash of yU. */
  public byte[] hyU = null;

  /** Show ticket, 1) i: requested accumulated ticket cost. */
  public int i = 0;

  /** Receive ticket, 5) j: number of journeys. */
  public int j = 0;

  /** Get service, 2) n: number of times e-ticket can be used. */
  public int n = 1;

  /** Get ticket, 7) rI: random value. */
  public BigInteger rI = null;

  /** Get service, 2) rU: random value. */
  public BigInteger rU = null;

  /** Show ticket, 1) s: service cost. */
  public int s = 1;

  /** Solve challenge, 1) w1: challenge response. */
  public BigInteger w1 = null;

  /** Solve challenge, 2) w2: challenge response. */
  public BigInteger w2 = null;

  /** Authenticate user, 1) yU: random value. */
  public BigInteger xU = null;

  /** Authenticate user, 1) yU: random value power mod thing. */
  public BigInteger yU = null;

  /** Get challenge, 2) yUc: challenge. */
  public BigInteger yUc = null;

  /**
   * Clears out the shared memory except for those parameters set for the state machine.
   */
  public void clear() {
    this.a1 = null;
    this.A1 = null;
    this.a2 = null;
    this.A2 = null;
    this.APi = null;
    this.c = null;
    this.hrIn = null;
    this.hrInCurrent = null;
    this.hrUn = null;
    this.hrUnCurrent = null;
    this.HU = null;
    this.HUc = null;
    this.hyU = null;
    this.i = 0;
    this.j = 0;
    this.K = null;
    // Not n
    this.PseuU = null;
    this.rI = null;
    this.RStar = null;
    this.rU = null;
    // Not s
    this.Sn = null;
    this.Sv = null;
    this.TStar = null;
    this.w1 = null;
    this.w2 = null;
    this.xU = null;
    this.yU = null;
    this.yUc = null;
  }
}