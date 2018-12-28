package longll;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import structure.IEEE80211ManagementFrame;

public class IFATBurst {
	private ArrayList<IEEE80211ManagementFrame> packet_seq;
	private Map<Long, ArrayList<Long>> bin_set;
	private Signature signature;
	
	private ArrayList<Long> IFAT;
	
	private int validFrameNum;
	
	public IFATBurst() {}
	
	public IFATBurst(ArrayList<IEEE80211ManagementFrame> packet_seq) {
		this.packet_seq = packet_seq;
		this.bin_set = new HashMap<>();
		this.signature = new Signature();
		this.IFAT = new ArrayList<>();
	}
	
	
	
	//当存在丢帧的情况时，将其补齐
	public void paddingBurst() {
		IEEE80211ManagementFrame last = packet_seq.get(0);
		for (int i = 1; i < packet_seq.size(); i++) {
			IEEE80211ManagementFrame now = packet_seq.get(i);
			long diff = now.getMacTimestamp() - last.getMacTimestamp();
			int count = now.getSeq_num() - last.getSeq_num();
			
			if (count != 1 && count > 0) {
				//不连续的话，则补齐
				for (int j = 0; j < count; j++) {
					IFAT.add(diff/count);
				}
			} else if (count == 1) {
				IFAT.add(diff);
			} else {
				//count <= 0
				System.out.println("seq is wrong, the seq num are "+last.getSeq_num() + "~"+now.getSeq_num());
				return;
			}
			last = now;
		}
	}
	
	public double calSimilarity() {
		double r = 0;
		
		return r;
	}

	public ArrayList<Long> getIFATList() {
		return this.IFAT;
	}
}


