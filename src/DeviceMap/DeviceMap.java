package DeviceMap;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import parser.IEEE80211Parser;

/**
 * 统计各个设备的信息元素的种类以及个数
 * @author longlong
 *
 */
public enum DeviceMap {
	IPHONE7("iPhone7 Plus"), IPHONE6S("iPhone6s"), MATE7_1("1号华为 Mate 7"), MATE7_2("2号华为 Mate 7"), HONOR10("华为荣耀10"), MI4("小米4"), MI6("小米6");
	
	private Map<ArrayList<Integer>, Integer> infoElements;
	private String deviceName;
	
	private DeviceMap(String deviceName) {
		this.deviceName = deviceName;
		this.infoElements = new HashMap();
	}

	public String getDeviceName() {
		return deviceName;
	}

	public void setDeviceName(String deviceName) {
		this.deviceName = deviceName;
	}
	
	@Override
	public String toString() {
		String re1 = "设备:"+this.deviceName+", 所有的IE的种类为"+this.infoElements.size()+ ", 检查帧总数为: ";
		
		String re2 = "";
		Set<ArrayList<Integer>> keys = this.infoElements.keySet();
		int all = 0;
		for(ArrayList<Integer> item : keys) {
			re2 += "[";
//			System.out.print("[");
			for (Integer type : item) {
//				System.out.print(type+",");
				re2 += type + ",";
			}
			re2 += "]";
//			System.out.print("]");
			re2  += ", 该种信息元素的个数为 " + this.infoElements.get(item)+"\n";
			all += this.infoElements.get(item);
//			System.out.println(", 该种信息元素的个数为 " + this.IE.get(item)+"  ");
		}
		re1 += all+"\n";
//		System.out.println();
		return re1+re2;
		
	}
	
	public void setInfoElem(Map<ArrayList<Integer>,Integer> infoList) {
		this.infoElements = infoList;
	}
	
	public static void main(String[] agrs) throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/";
		String file = "mate72_1.pcap";
		
		IEEE80211Parser parser = new IEEE80211Parser(new File(path+file));
		parser.openInfoElementsFlag();
		parser.parse();
//		this.deviceInfoElements.put(1, value)
		DeviceMap.MATE7_2.setInfoElem(parser.getInfoElem());
		System.out.println(DeviceMap.MATE7_2);
	}
	
}
