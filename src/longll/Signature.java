package longll;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Signature {
	private String mac;
	private Map<Long, Double> percentege;
	private Map<Long, Double> mean;
	
	
	
	public Map<Long, Double> getPercentege() {
		return percentege;
	}
	public void setPercentege(Map<Long, Double> percentege) {
		this.percentege = percentege;
	}
	public Map<Long, Double> getMean() {
		return mean;
	}
	public void setMean(Map<Long, Double> mean) {
		this.mean = mean;
	}
	public String getMac() {
		return mac;
	}
	public void setMac(String mac) {
		this.mac = mac;
	}
	
	public Signature() {
		this.mac = "";
		this.mean = new HashMap<>();
		this.percentege = new HashMap<>();
		// TODO Auto-generated constructor stub
	}
	public Signature(String mac, Map<Long, Double> percentege, Map<Long, Double> mean) {
		super();
		this.mac = mac;
		this.percentege = percentege;
		this.mean = mean;
	}
	
	
	
}
