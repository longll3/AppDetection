package ifat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Signature {
//	private int size; //有的设备有两种size的burst
	private Map<Integer, Long[]> sig; //
	
	private Map<Integer, Double> burstSizeDistribution; //key, burst大小，value，该大小的burst所占的比例
	
//	private int mean;
	private int mode; //burst size的众数
	private int min; //burst size的最小值
	private int max; //burst size的最大值

	public Signature(Set<ArrayList<Long>> burstSet) {
		Map<Integer, Integer> burstSizeCount = new HashMap<>();
		burstSizeDistribution = new HashMap<>();
		sig = new HashMap<>();
		for (ArrayList<Long> burst: burstSet) {
			if (burstSizeCount.containsKey(burst.size())) {
				int temp = burstSizeCount.get(burst.size());
				burstSizeCount.put(burst.size(), temp+1);
			} else {
				burstSizeCount.put(burst.size(), 1);
			}
		}
		
		Set<Integer> keys = burstSizeCount.keySet();
		this.max = 0;
		this.min = Integer.MAX_VALUE;
		double maxRate = 0.0;
		for (Integer key: keys) {
			double rate = (double)burstSizeCount.get(key)/burstSet.size();
			
//			if (rate > 0.10) {
				if (rate > maxRate) {
					maxRate = rate;
					this.mode = key;
				}
				if (key > this.max) this.max = key;
				if (key < this.min) this.min = key;
				
				//只留下大小占比超过20%的burst
				this.burstSizeDistribution.put(key, rate);
//			}
		}
		
		for (ArrayList<Long> burst: burstSet) {
			if (burstSizeDistribution.containsKey(burst.size())) {
				if (sig.containsKey(burst.size())) {
					Long[] temp = sig.get(burst.size());
					for (int i = 0; i < temp.length; i++) {
						temp[i] += burst.get(i);
					}
				} else {
					sig.put(burst.size(), burst.toArray(new Long[0]));
				}
			}
		}
		
		Set<Integer> sizeKeys = burstSizeDistribution.keySet();
		for(Integer size: sizeKeys) {
			Long[] temp = sig.get(size);
			for (int i = 0; i < temp.length; i++) {
				temp[i] /= burstSizeCount.get(size);
			}
		}
		
		
		
	}

	public Map<Integer, Long[]> getSig() {
		return sig;
	}

	public void setSig(Map<Integer, Long[]> sig) {
		this.sig = sig;
	}

	public Map<Integer, Double> getBurstSizeDistribution() {
		return burstSizeDistribution;
	}

	public void setBurstSizeDistribution(Map<Integer, Double> burstSizeDistribution) {
		this.burstSizeDistribution = burstSizeDistribution;
	}

	

	public int getMode() {
		return mode;
	}

	public void setMode(int mode) {
		this.mode = mode;
	}

	public int getMin() {
		return min;
	}

	public void setMin(int min) {
		this.min = min;
	}

	public int getMax() {
		return max;
	}

	public void setMax(int max) {
		this.max = max;
	}
	

	
}
