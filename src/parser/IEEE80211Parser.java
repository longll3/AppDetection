package parser;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import structure.IEEE80211ManagementFrame;
import structure.PcapDataHeader;
import structure.PcapFileHeader;
import structure.PcapStruct;
import structure.RadioTapHeader;
import util.DataUtils;

/**
 * 解析文件之后会有一个IEEE80211ManagementFrame的ArrayList,包含文件中每一帧的信息。
 * 具体通过probe request帧识别子品牌时使用ProcessByDTW类进行进一步分析。
 * 在区分终端时使用StationIdentity类进行下一步分析。
 * @author longlong
 *
 */
public class IEEE80211Parser {
	
	private File pcapFile;
	private PcapStruct pcapStruct;
	private Map<ArrayList<Integer>, Integer> IE; //key：信息元素合集
	
	private Map<ArrayList<Integer>, String> HTSet;
	
	private ArrayList<IEEE80211ManagementFrame> timeArray;
	
	private boolean flag = false; //用于是否开启IE统计
	
	private final static int fileHeaderLength = 24;
	private final static int pcapDataHeaderLength = 16;
	
	public IEEE80211Parser() {
		super();
		
	}
	
	public IEEE80211Parser(File file) {
		this.pcapFile = file;
		
	}
	
	public void setFile(File f) {
		this.pcapFile = f;
	}
	
	public ArrayList<IEEE80211ManagementFrame> getTimeArray() {
		return timeArray;
	}
	
	/**
	 * 
	 * @throws IOException
	 */
	public void parse() throws IOException {
		this.timeArray = new ArrayList<>();
		this.pcapStruct = new PcapStruct();
		this.IE = new HashMap();
		this.HTSet = new HashMap();
		
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(pcapFile);
			
			byte file_header[] = new byte[fileHeaderLength];
			int m = fis.read(file_header);
			if (m > 0) {
				PcapFileHeader fileHeader = parseFileHeader(file_header);
				
				if (fileHeader == null) {
					System.out.println("fileHeader null");
					return;
				}
				
				pcapStruct.setFileHeader(fileHeader);
				
				byte data_header[] = new byte[pcapDataHeaderLength];
				m = fis.read(data_header);
				
				while (m > 0) {
					PcapDataHeader dataHeader = parseDataHeader(data_header);
					pcapStruct.getDataHeaders().add(dataHeader);
					
					byte content[] = new byte[dataHeader.getCaplen()];
					m = fis.read(content);
					
					boolean isDone = parseContent(content);
					if (isDone) {
						break;
					} else {
						m = fis.read(data_header);
					}
					
				}
				
			}
		} finally {
			fis.close();
		}
		return;
	}
	
	/**
	 * 读取pcap文件头
	 * @param file_header
	 * @return
	 * @throws IOException
	 */
	public PcapFileHeader parseFileHeader(byte[] file_header) throws IOException {
        PcapFileHeader fileHeader = new PcapFileHeader();
        byte[] buff_4 = new byte[4];    // 4 字节的数组
        byte[] buff_2 = new byte[2];    // 2 字节的数组

        int offset = 0;
        for (int i = 0; i < 4; i ++) {
            buff_4[i] = file_header[i + offset];
        }
        offset += 4;
        int magic = DataUtils.byteArrayToInt(buff_4);
        fileHeader.setMagic(magic);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = file_header[i + offset];
        }
        offset += 2;
        short magorVersion = DataUtils.byteArrayToShort(buff_2);
        fileHeader.setMagorVersion(magorVersion);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = file_header[i + offset];
        }
        offset += 2;
        short minorVersion = DataUtils.byteArrayToShort(buff_2);
        fileHeader.setMinorVersion(minorVersion);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = file_header[i + offset];
        }
        offset += 4;
        int timezone = DataUtils.byteArrayToInt(buff_4);
        fileHeader.setTimezone(timezone);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = file_header[i + offset];
        }
        offset += 4;
        int sigflags = DataUtils.byteArrayToInt(buff_4);
        fileHeader.setSigflags(sigflags);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = file_header[i + offset];
        }
        offset += 4;
        int snaplen = DataUtils.byteArrayToInt(buff_4);
        fileHeader.setSnaplen(snaplen);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = file_header[i + offset];
        }
        offset += 4;
        int linktype = DataUtils.byteArrayToInt(buff_4);
        fileHeader.setLinktype(linktype);

//      LogUtils.printObjInfo(fileHeader);

        return fileHeader;
    }
	
	/**
	 * 读取数据包头
	 * @param data_header
	 * @return
	 */
	public PcapDataHeader parseDataHeader(byte[] data_header){
        byte[] buff_4 = new byte[4];
        PcapDataHeader dataHeader = new PcapDataHeader();
        int offset = 0;
        for (int i = 0; i < 4; i ++) {
            buff_4[i] = data_header[i + offset];
        }
        offset += 4;
        int timeS = DataUtils.byteArrayToInt(buff_4);
        dataHeader.setTimeS(timeS);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = data_header[i + offset];
        }
        offset += 4;
        int timeMs = DataUtils.byteArrayToInt(buff_4);
        dataHeader.setTimeMs(timeMs);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = data_header[i + offset];
        }
        offset += 4;
        // 得先逆序在转为 int
        DataUtils.reverseByteArray(buff_4);
        int caplen = DataUtils.byteArrayToInt(buff_4);
        dataHeader.setCaplen(caplen);
//      LogUtils.printObj("数据包实际长度", dataHeader.getCaplen());

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = data_header[i + offset];
        }
        offset += 4;
//              int len = DataUtils.byteArrayToInt(buff_4);
        DataUtils.reverseByteArray(buff_4);
        int len = DataUtils.byteArrayToInt(buff_4);
        dataHeader.setLen(len);

//      LogUtils.printObjInfo(dataHeader);

        return dataHeader;
    }
	
	/**
	 * 解析真正的数据（不包括pcap头）
	 */
	private boolean parseContent(byte[] content) {
		
		RadioTapHeader radioTapHeader = new RadioTapHeader();
		
		int offset = 0;
		radioTapHeader.setRevision(content[offset++]);
		radioTapHeader.setPad(content[offset++]);
		
		byte[] buff_2 = new byte[2];
		for (int i = 1, j = 0; i >= 0; i--, j++) {
            buff_2[j] = content[i + offset];
        }
		short radiotap_length = DataUtils.byteArrayToShort(buff_2);
		radioTapHeader.setHeader_length(radiotap_length);
		
		if (radiotap_length == 25) {
			offset = 8;
		} else if (radiotap_length == 36 || radiotap_length == 38) {
			//hetao phone
			offset = 16;
		}
//		offset = 8;
//		offset = 16; //hetao phone
		byte[] buff_8 = new byte[8];
		for(int i = 0, j = 7; i < 8; i++, j--) {
			buff_8[i] = content[offset+j];
		}
		
		//获取时间戳TFS
		long timestamp = DataUtils.byteArrayToLong(buff_8);
		
		offset = radiotap_length + 4; //第5个字节开始是destination address
		String dst_mac = DataUtils.byteArray2HexString(content, offset, offset+6);
		
		offset += 6;
		String sr_mac = DataUtils.byteArray2HexString(content, offset, offset+6);
		offset += 6;
		
		int seq_num;
		offset = radioTapHeader.getHeader_length() + 22;
		
		seq_num = getSqeNum(content, offset);
		
		//the length of probe request part is 24 bytes 
		int probeRequestLength = 24;
		
		ArrayList<Integer> IEArray = new ArrayList<>(); //probe request帧的信息元素种类的编码
		Map<Integer, byte[]> IEs = new HashMap<>();
		
		parseInformationElements(content, probeRequestLength+radioTapHeader.getHeader_length(), IEArray, IEs);
		
		if (IEs.containsKey(45)) {
			this.HTSet.put(IEArray, DataUtils.byte2HexStr(IEs.get(45), 0, 2));
		}
		
		timeArray.add(new IEEE80211ManagementFrame(timestamp, sr_mac, dst_mac, seq_num, IEs, IEArray));
//		System.out.println(timestamp);
		
		if (this.flag) {
		
			if (this.IE.containsKey(IEArray)) this.IE.put(IEArray, this.IE.get(IEArray)+1);
			else this.IE.put(IEArray, 1);
		}
		
		return false;
		
	}
	
	public static int getSqeNum(byte content[], int start) {
		int seq_num = 0;
		
//		System.out.println(String.format("%02X", content[start]));
//		System.out.println(String.format("%02X", content[start+1]));
		
		byte seq1 = content[start];
		byte seq2 = content[start+1];
		
		int low_bit = (seq1 >> 4) & 0x000f; // >> 右移，相当于*2         >>> 无符号右移，忽略符号位，空位以0补齐
		seq2 &= 0xff;
		
		int high_bit = (int) seq2;
		
		seq_num += (high_bit << 4) & 0x0ff0; // << 左移，相当于乘以2
		seq_num += low_bit;
		
		return seq_num;
	}

	public static void parseInformationElements(byte content[], int start, ArrayList<Integer> IEArray, Map<Integer, byte[]> IEs) {
		
		int length;
		while (start < content.length-4) {
			int IE = DataUtils.byteToInt(content[start++]);
			IEArray.add(IE);
			length = DataUtils.byteToInt(content[start++]);
			byte[] values = (Arrays.copyOfRange(content, start, start+length));
			
			IEs.put(IE, values);
			
			start += length;
		}
		
		return;
		
	}
	
	public void openInfoElementsFlag() {
		this.flag = true;
	}
	
	public void printIE() throws IOException {
		this.parse();
		
		System.out.println("设备"+this.pcapFile.getName()+"\n"+"所有的IE的种类为"+this.IE.size());
		Set<ArrayList<Integer>> keys = this.IE.keySet();
		
		for(ArrayList<Integer> item : keys) {
			System.out.print("[");
			for (Integer type : item) {
				System.out.print(type+",");
			}
			System.out.print("]， ");
			
			System.out.print("含有该信息元素种类的帧数为 " + this.IE.get(item)+",  ");
			if (item.contains(45)) {
				System.out.print("HT Cap Info: " + this.HTSet.get(item));
			}
			
			System.out.println();
		}
		System.out.println();
		
//		System.out.println("HT Capabilities Info 信息元素总共存在的值有 "+ this.HTSet.size()+" 种，分别是：");
//		for (String HT: this.HTSet) {
//			System.out.println(HT+", ");
//		}
		
	}
	
	public Map<ArrayList<Integer>, Integer> getInfoElem() {
		return this.IE;
	}
	
}
