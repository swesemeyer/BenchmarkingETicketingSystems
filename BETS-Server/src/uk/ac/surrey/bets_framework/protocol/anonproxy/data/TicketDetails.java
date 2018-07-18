/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017-2018.
 */
package uk.ac.surrey.bets_framework.protocol.anonproxy.data;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.protocol.anonproxy.AnonProxySharedMemory;
import uk.ac.surrey.bets_framework.protocol.anonsso.AnonSSO;
import uk.ac.surrey.bets_framework.protocol.data.ListData;

/**
 * store the ticket information for the AnonProxy protocol implementation
 * 
 * @author Steve Wesemeyer
 *
 */
public class TicketDetails {
	
	/** Logback logger. */
	private static final Logger LOG = LoggerFactory.getLogger(TicketDetails.class);
	
	
	public String ticket_Text_1=null;
	public String ticket_Text_2=null;
	public String[] VerifierList = null;
	public BigInteger[] t_v = null;
	public BigInteger[] w_v = null;
	public BigInteger[] z_v = null;
	public Element[] P_V = null;
	public Element[] Q_V = null;
	public Element[] D_V = null;
	public Element[] E_V_1 = null;
	public Element[] E_V_2 = null;
	public Element[] E_V_3 = null;
	public Element[] T_V=null;
	public byte[][] s_V = null;
	public Element[] Z_V = null;
	public byte[] s_CV = null;
	public BigInteger w_cv = null;
	public BigInteger z_cv = null;
	public Element Z_CV = null;
	public int numOfVerifiers = -1;

	public TicketDetails(int numOfVerifiers) {
		
		this.ticket_Text_1="travel time";
		this.ticket_Text_2="ticket type, etc";

		this.numOfVerifiers = numOfVerifiers;

		this.VerifierList = new String[numOfVerifiers];
		this.t_v = new BigInteger[numOfVerifiers];
		this.w_v = new BigInteger[numOfVerifiers];
		this.z_v = new BigInteger[numOfVerifiers];
		this.P_V = new Element[numOfVerifiers];
		this.Q_V = new Element[numOfVerifiers];
		this.D_V = new Element[numOfVerifiers];
		this.E_V_1 = new Element[numOfVerifiers];
		this.E_V_2 = new Element[numOfVerifiers];
		this.E_V_3 = new Element[numOfVerifiers];
		this.T_V = new Element[numOfVerifiers];
		this.s_V = new byte[numOfVerifiers][];
		this.Z_V = new Element[numOfVerifiers];

	}

	public void getTicketDetails(List<byte[]> sendDataList) {
		for (int i = 0; i < this.numOfVerifiers; i++) {
			sendDataList.add(this.VerifierList[i].getBytes(StandardCharsets.UTF_8));
			sendDataList.add(this.D_V[i].toBytes());
			sendDataList.add(this.P_V[i].toBytes());
			sendDataList.add(this.Q_V[i].toBytes());
			sendDataList.add(this.E_V_1[i].toBytes());
			sendDataList.add(this.E_V_2[i].toBytes());
			sendDataList.add(this.E_V_3[i].toBytes());
			sendDataList.add(this.T_V[i].toBytes());
			sendDataList.add(this.s_V[i]);
			sendDataList.add(this.z_v[i].toByteArray());
			sendDataList.add(this.w_v[i].toByteArray());
			sendDataList.add(this.Z_V[i].toBytes());
		}
		sendDataList.add(this.s_CV);
		sendDataList.add(this.w_cv.toByteArray());
		sendDataList.add(this.z_cv.toByteArray());
		sendDataList.add(this.Z_CV.toBytes());
		sendDataList.add(this.ticket_Text_1.getBytes(StandardCharsets.UTF_8));
		sendDataList.add(this.ticket_Text_2.getBytes(StandardCharsets.UTF_8));
	}

	public int populateTicketDetails(AnonProxySharedMemory sharedMemory, ListData listData, int indx) {

		for (int i = 0; i < numOfVerifiers; i++) {
			this.VerifierList[i] = new String(listData.getList().get(indx++), StandardCharsets.UTF_8);
			this.D_V[i] = sharedMemory.G2ElementFromBytes(listData.getList().get(indx++));
			this.P_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
			this.Q_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
			this.E_V_1[i] = sharedMemory.GTElementFromBytes(listData.getList().get(indx++));
			this.E_V_2[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
			this.E_V_3[i] = sharedMemory.G2ElementFromBytes(listData.getList().get(indx++));
			this.T_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
			this.s_V[i] = listData.getList().get(indx++);
			this.z_v[i] = new BigInteger(1, listData.getList().get(indx++));
			this.w_v[i] = new BigInteger(1, listData.getList().get(indx++));
			this.Z_V[i] = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
		}
		this.s_CV = listData.getList().get(indx++);
		this.w_cv = new BigInteger(1, listData.getList().get(indx++));
		this.z_cv = new BigInteger(1, listData.getList().get(indx++));
		this.Z_CV = sharedMemory.G1ElementFromBytes(listData.getList().get(indx++));
		this.ticket_Text_1 = new String(listData.getList().get(indx++), StandardCharsets.UTF_8);
		this.ticket_Text_1 = new String(listData.getList().get(indx++), StandardCharsets.UTF_8);
		return indx;
	}

	public int getVerifierIndex(Element D_V) {
		LOG.debug("Looking for: "+D_V);
		
		int index = -1;
		for (int i = 0; i < numOfVerifiers; i++) {
			LOG.debug("verifier["+i+"]= "+this.D_V[i]);
			if (D_V.isEqual(this.D_V[i])) {
				return i;
			}
		}
		return index;

	}
}
