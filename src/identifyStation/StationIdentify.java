package identifyStation;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

import DeviceMap.DeviceMap;
import parser.IEEE80211Parser;

public class StationIdentify {
	private IEEE80211Parser parser; //解析文件工具
	
	//存放当前捕捉到的终端集合，key为终端的编号，value为终端的mac地址集合
	private Map<Integer, ArrayList<String>> stationMap;
	
	
	public StationIdentify() {
		
	}
	
	/**
	 * 利用已有的数据为已知设备简历信息元素以及序列号签名
	 * 
	 * 没用！！！！
	 */
	public void generateDataBase() throws IOException {
		
		String path = "/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/";
		String file = "mate72_1.pcap";
		
		this.parser = new IEEE80211Parser(new File(path+file));
		parser.openInfoElementsFlag();
		DeviceMap.MATE7_2.setInfoElem(parser.getInfoElem());
		System.out.println(DeviceMap.MATE7_2);
		
		
		parser.setFile(new File(path+"mate71-all.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"mate9-all.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"mi6-1.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"honor10-2.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"iphon6s_1.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"iphone7-1.pcap"));
		parser.printIE();
		
	}
	
	
	
}
