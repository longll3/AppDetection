package longll;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jfree.ui.RefineryUtilities;

import DrawFigure.BarChart;
import structure.IEEE80211ManagementFrame;
import util.DataUtils;

public class IFATG_identify {
	private ArrayList<IEEE80211ManagementFrame> packet_seq;
	private Map<Long, ArrayList<Long>> bin_set;
	private Signature signature;
	
	private int validFrameNum;
	
	private static int BIN_SIZE = 10000; //以10000us(10ms)为单位create bin
	
	public IFATG_identify(ArrayList<IEEE80211ManagementFrame> packet_seq) {
		bin_set =new HashMap<>();
		this.packet_seq = packet_seq;
		validFrameNum = 0;
		signature = new Signature();
		validFrameNum = 0;
	}
	
	public IFATG_identify() {
		super();
	}
	
	public void initial(ArrayList<IEEE80211ManagementFrame> packet_seq) {
		bin_set =new HashMap<>();
		this.packet_seq = packet_seq;
		validFrameNum = 0;
		signature = new Signature();
		validFrameNum = 0;
	}

	/**
	 * 相同mac地址的属于一个burst
	 * @return
	 */
	public Set<ArrayList<IEEE80211ManagementFrame>> groupInBurstSet() {
		Set<ArrayList<IEEE80211ManagementFrame>> burstSet = new HashSet<ArrayList<IEEE80211ManagementFrame>>();
		IEEE80211ManagementFrame last = packet_seq.get(0);
		ArrayList<IEEE80211ManagementFrame> arr = new ArrayList<>();
		arr.add(last);
		
		for (int i = 1; i < this.packet_seq.size(); i++) {
			IEEE80211ManagementFrame now = packet_seq.get(i);
			if (last.getSr_mac().equals(now.getSr_mac())) {
				arr.add(now);
			} else {
				burstSet.add(arr);
				arr = new ArrayList<>();
				arr.add(now);				
			}
			last = now;
		}
		
		return burstSet;
	}

	public void groupInBins() {
		
		int lastIndex = 0;
		validFrameNum = 0;
		signature.setMac(packet_seq.get(0).getSr_mac());
		
		for (int i = 1; i < packet_seq.size(); i++) {
			if (packet_seq.get(i).getSeq_num() == packet_seq.get(lastIndex).getSeq_num() + 1) {
				//consecutive frames
				long timeDifference = packet_seq.get(i).getTimestamp() - packet_seq.get(lastIndex).getTimestamp();
				long key = timeDifference/BIN_SIZE;
				if (!bin_set.containsKey(key)) {
					//not in the bin set
					ArrayList<Long> timeDiffList = new ArrayList<>();
					timeDiffList.add(timeDifference);
					
					bin_set.put(key, timeDiffList);
				} else {
					//already in the bin set
					bin_set.get(key).add(timeDifference);
				}
				
				validFrameNum++;
			}
			
			lastIndex = i;
			
		}
	}
	
	public void generateSignature() {
		groupInBins();
		
		Set<Long> keys = bin_set.keySet();
        Long[] key_array = keys.toArray(new Long[0]);
        
        for (int i = 0; i < key_array.length; i++) {
        		int sum = 0;
        		int count = 0;
        		for (int j = 0; j < bin_set.get(key_array[i]).size(); j++) {
        			sum += bin_set.get(key_array[i]).get(j);
        			count++;
        		}
        		
        		signature.getMean().put(key_array[i], (double)sum/count);
        		signature.getPercentege().put(key_array[i], (double)count/validFrameNum);
        }
	}
	
	/**
	 * 计算与已知的签名之间的距离
	 * @param Signature toCompare 已知的签名
	 * @return double 签名之间的距离 
	 */
	public double getDistanceFrom(Signature toCompare) {
		double distance = 0.0;
		
		//since HashMap mean and percentage have the same key set, the size of them are same
		Set<Long> keys_m = toCompare.getMean().keySet();
		for (Long i : keys_m) {
			double subtraction_m;
			double absolute_p;
			double sum_p;
			if (this.signature.getMean().containsKey(i)) {
				subtraction_m = DataUtils.getAbsoluteValue(toCompare.getMean().get(i), this.signature.getMean().get(i));
			} else {
				subtraction_m = toCompare.getMean().get(i);
			}
			
			if (this.signature.getPercentege().containsKey(i)) {
				absolute_p = DataUtils.getAbsoluteValue(toCompare.getPercentege().get(i), this.signature.getPercentege().get(i));
				sum_p = toCompare.getPercentege().get(i) + this.signature.getPercentege().get(i);
			} else {
				absolute_p = toCompare.getPercentege().get(i);
				sum_p = toCompare.getPercentege().get(i);
			}
			
			distance += absolute_p*sum_p;
//			distance += (sum_p / 2 * subtraction_m);
			
		}
		
		return distance;
	}


	public Signature getSignature() {
		return signature;
	}

	
	public void setSignature(Signature signature) {
		this.signature = signature;
	}
	
	public static void drawBarchart(Signature sig1, Signature sig2) {
		BarChart barChart1 = new BarChart("IFAT attack", "签名比较", sig1, sig2, 0, "IFAT均值", "bin大小");
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true ); 
		
		BarChart barChart2 = new BarChart("IFAT attack", "签名比较", sig1, sig2, 1, "bin中帧数百分比", "bin大小");
		barChart2.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart2.setVisible( true ); 
	}
	
}


