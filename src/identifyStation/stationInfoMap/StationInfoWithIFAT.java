package identifyStation.stationInfoMap;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import ifat.Signature;
import structure.IEEE80211ManagementFrame;

/**
 * 用于区分终端所需要用到的信息,加入了IFAT签名
 * 序列号，MAC地址集合，IFAT签名
 * @author longlong
 *
 */
public class StationInfoWithIFAT {

	private ArrayList<IEEE80211ManagementFrame> frameList;
	private int lastSeq;
	//区分后的MAC地址集 
	private Set<String> MACs;
	private Signature sig;
	
	public StationInfoWithIFAT(ArrayList<IEEE80211ManagementFrame> burst) {
		this.frameList = new ArrayList<>();
		this.MACs = new HashSet<>();
		
		ArrayList<Long> frameArr = new ArrayList<>();
		for (int i = 1; i < burst.size(); i++) {
			frameArr.add(burst.get(i).getTimestamp()-burst.get(i-1).getTimestamp());
		}
		//将burst中的最后一帧的序列号set为lastSeq  ？？？？为什么要这样呢？？？？
		setLastSeq(burst.get(burst.size()-1).getSeq_num());
		sig = new Signature(frameArr);
		frameList.addAll(burst);
		MACs.add(burst.get(0).getSr_mac());
		
	}
	
	public void setLastSeq(int seq) { this.lastSeq = seq; }
	public int getLastSeq() { return this.lastSeq; }
	
	public void addBurst(ArrayList<IEEE80211ManagementFrame> burst) {
		this.frameList.addAll(burst);
	}
	
	public void updateSignature(ArrayList<Long> ifat_burst) {
		this.sig.updateSig(ifat_burst);
	}
	
	
	@Override
	public String toString() {
		String re = "本终端共发出 " + this.frameList.size() + " 个probe request帧";
		re = "本终端所使用到的mac地址有";
		for (String mac : this.MACs) {
			re += mac + " ";
		}
		return re;
	}
	
	public Signature getSig() {
		return this.sig;
	}
	
	public Set<String> getMACSet() {
		return this.MACs;
	}
	
	public ArrayList<IEEE80211ManagementFrame> getFrameList() {
		return this.frameList;
	}
			
}
