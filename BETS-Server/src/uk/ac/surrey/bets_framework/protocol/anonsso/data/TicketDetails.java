/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.pplast.data;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.pplast.PPLASTSharedMemory;

/** 
 * store the ticket information for the PPLAST NFC protocol implementation
 * 
 * @author Steve Wesemeyer
 *
 */
public class TicketDetails {

  public String[]     VerifierList   = null;
  public BigInteger[] d_v            = null;
  public BigInteger[] w_v            = null;
  public BigInteger[] e_v            = null;
  public Element[]    P_V            = null;
  public Element[]    Q_V            = null;
  public byte[][]     D_V            = null;
  public Element[]    E_V            = null;
  public Element[]    F_V            = null;
  public Element[]    K_V            = null;
  public byte[][]     s_V            = null;
  public Element[]    Z_V        	 = null;
  public byte[]       s_CV            = null;
  public BigInteger   w_CV            = null;
  public BigInteger   e_CV            = null;
  public Element      Z_CV        = null;
  public int          numOfVerifiers = -1;
  public String       ticketText     = null;

  public TicketDetails(int numOfVerifiers) {

    this.numOfVerifiers = numOfVerifiers;

    this.VerifierList = new String[numOfVerifiers];
    this.d_v = new BigInteger[numOfVerifiers];
    this.w_v = new BigInteger[numOfVerifiers];
    this.e_v = new BigInteger[numOfVerifiers];
    this.P_V = new Element[numOfVerifiers];
    this.Q_V = new Element[numOfVerifiers];
    this.D_V = new byte[numOfVerifiers][];
    this.E_V = new Element[numOfVerifiers];
    this.F_V = new Element[numOfVerifiers];
    this.K_V = new Element[numOfVerifiers];
    this.s_V = new byte[numOfVerifiers][];
    this.Z_V = new Element[numOfVerifiers];

  }

  public void getTicketDetails(List<byte[]> sendDataList) {
    for (int i = 0; i < this.numOfVerifiers; i++) {
      sendDataList.add(this.VerifierList[i].getBytes(StandardCharsets.UTF_8));
      sendDataList.add(this.D_V[i]);
      sendDataList.add(this.P_V[i].toBytes());
      sendDataList.add(this.Q_V[i].toBytes());
      sendDataList.add(this.E_V[i].toBytes());
      sendDataList.add(this.F_V[i].toBytes());
      sendDataList.add(this.K_V[i].toBytes());
      sendDataList.add(this.s_V[i]);
      sendDataList.add(this.w_v[i].toByteArray());
      sendDataList.add(this.e_v[i].toByteArray());
      sendDataList.add(this.Z_V[i].toBytes());
    }
    sendDataList.add(this.s_CV);
    sendDataList.add(this.w_CV.toByteArray());
    sendDataList.add(this.e_CV.toByteArray());
    sendDataList.add(this.Z_CV.toBytes());
    sendDataList.add(this.ticketText.getBytes(StandardCharsets.UTF_8));
  }

  public int populateTicketDetails(PPLASTSharedMemory sharedMemory, ListData listData, int indx) {

    for (int i = 0; i < numOfVerifiers; i++) {
      this.VerifierList[i] = new String(listData.getList().get(indx++), StandardCharsets.UTF_8);
      this.D_V[i] = listData.getList().get(indx++);
      this.P_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
      this.Q_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
      this.E_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
      this.F_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
      this.K_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
      this.s_V[i] = listData.getList().get(indx++);
      this.w_v[i] = new BigInteger(1, listData.getList().get(indx++));
      this.e_v[i] = new BigInteger(1, listData.getList().get(indx++));
      this.Z_V[i] = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
    }
    this.s_CV = listData.getList().get(indx++);
    this.w_CV = new BigInteger(1, listData.getList().get(indx++));
    this.e_CV = new BigInteger(1, listData.getList().get(indx++));
    this.Z_CV = sharedMemory.curveG1ElementFromBytes(listData.getList().get(indx++));
    this.ticketText=new String (listData.getList().get(indx++),StandardCharsets.UTF_8);
    return indx;
  }

  public int getVerifierIndex(byte[] D_Vhash) {
    int index = -1;
    for (int i = 0; i < numOfVerifiers; i++) {
      if (Arrays.equals(D_Vhash, this.D_V[i])) {
        return i;
      }
    }
    return index;

  }
}
