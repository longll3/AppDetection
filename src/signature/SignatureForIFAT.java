package signature;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


public class SignatureForIFAT {
//	private int size; //有的设备有两种size的burst
	
	private Map<Integer, Double[]> sig; //key，burst大小，value，对应burst大小下的平均IFAT
	private Map<Integer, Long[]> IFATSum; //key，burst大小，value，对应burst大小下的IFAT总和的序列
	private Map<Integer, Double> burstSizeDistribution; //key, burst大小，value，该大小的burst所占的比例
	private Map<Integer, Integer> burstSizeCount; //key, burst的大小，value， 该burst的大小出现的次数
	
	private int burstNum; // burst种类记数
	
//	private int mean;
	private int mode; //burst size的众数
	private int min; //burst size的最小值
	private int max; //burst size的最大值

	public SignatureForIFAT(ArrayList<Long> burst) {
		this.burstSizeCount = new HashMap<>();
		this.burstSizeDistribution = new HashMap<>();
		this.sig = new HashMap<>();
		this.IFATSum = new HashMap<>();
		
		int size = burst.size();;
		mode = size;
		min = size;
		max = size;
		burstNum = 1;
		
		if (burst.size() < 2) {
			System.err.println("burst size is < 2");
		}
		
		Long[] a = burst.toArray(new Long[0]);
		int s = burst.size();
		IFATSum.put(s, a);
		burstSizeCount.put(size, 1);
	
		Double[] p = new Double[size];
		for (int i = 0; i < size; i++ ) {
			p[i] =  (double) IFATSum.get(size)[i] /burstSizeCount.get(size);
		}
		sig.put(size, p);
		burstSizeDistribution.put(size, 1.0);
	
		
		
	}
	
	//新添加一个burst，对signature进行更新
	public void updateSig(ArrayList<Long> burst) {
		int burstSize = burst.size();
		Set<Integer> sigSetKey = burstSizeDistribution.keySet();
		burstNum++;
		for (Integer key: sigSetKey) {
			double p = 0.0;
			if (key == burstSize) {
				p = (burstSizeDistribution.get(key)+1) / (burstNum);
			} else {
				p = (burstSizeDistribution.get(key)) / (burstNum);
			}
			burstSizeDistribution.put(key, p);
		}
		
		if (burstSizeCount.containsKey(burstSize)) {
			int temp = burstSizeCount.get(burstSize);
			temp++;
			burstSizeCount.put(burstSize, temp);
			
			Long[] ifat = this.IFATSum.get(burst.size());
			for (int i = 0; i < ifat.length; i++) {
				ifat[i] += burst.get(i);
			}
			
			Double[] meanIfat = this.sig.get(burstSize);
			for (int i = 0; i < meanIfat.length; i++) {
				meanIfat[i] =(double)ifat[i]/temp;
			}
			
			System.out.println("sig 更新完毕");
			
		} else {
			burstSizeCount.put(burstSize, 1);
			IFATSum.put(burstSize, burst.toArray(new Long[0]));
			
			Double[] p = new Double[burstSize];
			for (int i = 0; i < burstSize; i++ ) {
				p[i] =  (double) burst.get(i);
			}
			sig.put(burstSize, p);
		}
		
		
		
		
		
	}
	
	public SignatureForIFAT(Set<ArrayList<Long>> burstSet) {
		this.burstNum = burstSet.size();
		this.burstSizeCount = new HashMap<>();
		burstSizeDistribution = new HashMap<>();
		sig = new HashMap<>();
		this.IFATSum = new HashMap<>();
		//将每个burst的大小统计到burstSizeCount中，key：burst的大小，value：该大小的burst出现的次数
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
				if (IFATSum.containsKey(burst.size())) {
					Long[] temp = IFATSum.get(burst.size());
					for (int i = 0; i < temp.length; i++) {
						temp[i] += burst.get(i);
					}
				} else {
					IFATSum.put(burst.size(), burst.toArray(new Long[0]));
				}
			}
		}
		
		
		Set<Integer> sizeKeys = burstSizeDistribution.keySet();
		for(Integer size: sizeKeys) {
			Long[] temp = IFATSum.get(size);
			Double[] meanArr = new Double[size];
			for (int i = 0; i < temp.length; i++) {
				meanArr[i] = (double) temp[i] / burstSizeCount.get(size);
				
			}
			this.sig.put(size, meanArr);
		}
		
		
		
	}

	public Map<Integer, Double[]> getSig() {
		return sig;
	}

	public void setSig(Map<Integer, Double[]> sig) {
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
