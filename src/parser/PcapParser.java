package parser;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import structure.EthernetDataFrame;
import structure.IPHeader;
import structure.PcapDataHeader;
import structure.PcapFileHeader;
import structure.PcapStruct;
import structure.ProtocolData;
import structure.ProtocolType;
import structure.TCPHeader;
import structure.UDPHeader;
import util.DataUtils;

/**
 * 文件解析工具类
 * @author longlong
 *
 */
public class PcapParser {
	
	private File pcap;
//	private String savePath;

	private PcapStruct struct;
	private ProtocolData protocolData;
	private IPHeader ipHeader;
	private TCPHeader tcpHeader;
	private UDPHeader udpHeader;
	
	private List<String[]> datas = new ArrayList<String[]>();
	private List<String> filenames = new ArrayList<String>();
	
	private byte[] file_header = new byte[24];
	private byte[] data_header = new byte[16];
	private byte[] content;
//	private byte[] ip_content;
//	private byte[] tcp_content;
//	private byte[] udp_content;
	
	private int data_offset = 0;			// 数据负载信息所在开始位置
	private byte[] data_content;			// 数据包的数据负载
	
	public PcapParser (File pcap) {
//	public PcapParser (File pcap, File outDir) {
		this.pcap = pcap;
//		this.savePath = outDir.getAbsolutePath();
	}
	
	public boolean parse() throws IOException {
//		boolean rs = true;
		struct = new PcapStruct();
		List<PcapDataHeader> dataHeaders = new ArrayList<PcapDataHeader>();
		FileInputStream fis = null;
		
		try {
			fis = new FileInputStream(pcap);
			//读取头24个字节
			int m = fis.read(file_header);
			if (m > 0) {

				PcapFileHeader fileHeader = parseFileHeader(file_header);
				
				if (fileHeader == null) {
//					rs = false;
					System.out.println("fileHeader null");
					return false;
//					LogUtils.printObj("fileHeader", "null");
					
				}
				struct.setFileHeader(fileHeader);

				while (m > 0) {
					//读取pcap数据包包头
					m = fis.read(data_header);
					PcapDataHeader dataHeader = parseDataHeader(data_header);
					dataHeaders.add(dataHeader);

					content = new byte[dataHeader.getCaplen()];
//					LogUtils.printObj("content.length", content.length);
					m = fis.read(content);

					protocolData = new ProtocolData();
					boolean isDone = parseContent();
					if (isDone) {
						break;
					}

//					createFiles(protocolData);
					
//					LogUtils.printObjInfo(protocolData);
//					LogUtils.printObj("--------------------------------------");
				}

//				rs = true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
//			FileUtils.closeStream(fis, null);
			fis.close();
		}
		struct.setDataHeaders(dataHeaders);

		return true;
	}

	
	/**
	 * 解析真正的数据（不包括pcap头）
	 */
	private boolean parseContent() {
		// 1. 读取以太网数据帧
		readEthernetFrame(content);
		// 2. 读取 IP
		ipHeader = readIPHeader(content);
		if (ipHeader == null) {							// 当 ip 为 null 时解析完毕
			return true;
		}

		int offset = 14;							// 以太网数据帧长度
		offset += 20;

		// 3. 根据 protocol 类型进行分析
		String protocol = ipHeader.getProtocol() + "";
		if (ProtocolType.TCP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.TCP);
			tcpHeader = readTCPHeader(content, offset);
			
			int lenght = content.length;
			
//			Byte[] tcpContent = new Byte[lenght-data_offset];
			
			System.err.println(lenght-data_offset);
//			System.out.println(DataUtils.bytesToString(content, data_offset, lenght));
			System.out.println(DataUtils.byte2HexStr(content, data_offset, lenght));
			String hexString = DataUtils.bytesToHexString(content, data_offset, lenght-data_offset);
			System.out.println(DataUtils.hexStr2Str(hexString));
			System.out.println(DataUtils.bytesToString(content, data_offset, lenght));
			
		} else if (ProtocolType.UDP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.UDP);
			udpHeader = readUDPHeader(content, offset);
		} else {
//			LogUtils.printObj("这是其他协议的数据包");
			System.out.println("这是其他协议的数据包");
		}

		return false;
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
        //      int len = DataUtils.byteArrayToInt(buff_4);
        DataUtils.reverseByteArray(buff_4);
        int len = DataUtils.byteArrayToInt(buff_4);
        dataHeader.setLen(len);

//      LogUtils.printObjInfo(dataHeader);

        return dataHeader;
    }
	
	/**
	 * 读取pcap数据帧，就是以太网数据帧，14个字节
	 * @param content
	 */
	public void readEthernetFrame(byte[] content) {
        EthernetDataFrame dataFrame = new EthernetDataFrame();
        
        //第13-14字节表示帧ß类型
        int offset = 12;
        byte[] buff_2 = new byte[2];
        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        short frameType = DataUtils.byteArrayToShort(buff_2);
        dataFrame.setFrameType(frameType);

//      LogUtils.printObjInfo(dataFrame);
    }

	/**
	 * 读取IP头
	 * @param content
	 * @return
	 */
	private IPHeader readIPHeader(byte[] content) {
		//前14个字节是以太网帧头
        int offset = 14;
        IPHeader ip = new IPHeader();

        byte[] buff_2 = new byte[2];
        byte[] buff_4 = new byte[4];

        //这里不会越界吗？？？
        byte varHLen = content[offset ++];              // offset = 15
//      LogUtils.printByteToBinaryStr("varHLen", varHLen);
        if (varHLen == 0) {
            return null;
        }

        ip.setVarHLen(varHLen);

        byte tos = content[offset ++];                  // offset = 16
        ip.setTos(tos);

        for (int i = 0; i < 2; i ++) {      
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 18
        short totalLen = DataUtils.byteArrayToShort(buff_2);
        ip.setTotalLen(totalLen);

        for (int i = 0; i < 2; i ++) {          
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 20
        short id = DataUtils.byteArrayToShort(buff_2);
        ip.setId(id);

        for (int i = 0; i < 2; i ++) {                  
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 22
        short flagSegment = DataUtils.byteArrayToShort(buff_2);
        ip.setFlagSegment(flagSegment);

        byte ttl = content[offset ++];                  // offset = 23
        ip.setTtl(ttl);

        byte protocol = content[offset ++];             // offset = 24
        ip.setProtocol(protocol);

        for (int i = 0; i < 2; i ++) {                  
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 26
        short checkSum = DataUtils.byteArrayToShort(buff_2);
        ip.setCheckSum(checkSum);

        for (int i = 0; i < 4; i ++) {                  
            buff_4[i] = content[i + offset];
        }
        offset += 4;                                    // offset = 30
        int srcIP = DataUtils.byteArrayToInt(buff_4);
        ip.setSrcIP(srcIP);

        // 拼接出 SourceIP
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            builder.append((int) (buff_4[i] & 0xff));
            builder.append(".");
        }
        //减去最后append的一个.
        builder.deleteCharAt(builder.length() - 1);
        String sourceIP = builder.toString();
        protocolData.setSrcIP(sourceIP);

        for (int i = 0; i < 4; i ++) {      
            buff_4[i] = content[i + offset];
        }
        offset += 4;                                    // offset = 34
        int dstIP = DataUtils.byteArrayToInt(buff_4);
        ip.setDstIP(dstIP);

        // 拼接出 DestinationIP
        builder = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            builder.append((int) (buff_4[i] & 0xff));
            builder.append(".");
        }
        //减去最后append的一个.
        builder.deleteCharAt(builder.length() - 1);
        String destinationIP = builder.toString();
        protocolData.setDesIP(destinationIP);

//      LogUtils.printObjInfo(ip);

        return ip;
    }
	
	
	/**
	 * 读取TCP头
	 * @param content2
	 * @param offset
	 * @return
	 */
	private TCPHeader readTCPHeader(byte[] content2, int offset) {
		int offsetCopy = offset;
        byte[] buff_2 = new byte[2];
        byte[] buff_4 = new byte[4];

        TCPHeader tcp = new TCPHeader();

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
//          LogUtils.printByteToBinaryStr("TCP: buff_2[" + i + "]", buff_2[i]);
        }
        offset += 2;                                    // offset = 36
        short srcPort = DataUtils.byteArrayToShort(buff_2);
        tcp.setSrcPort(srcPort);

        String sourcePort = validateData(srcPort);
        protocolData.setSrcPort(sourcePort);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 38
        short dstPort = DataUtils.byteArrayToShort(buff_2);
        tcp.setDstPort(dstPort);

        String desPort = validateData(dstPort);
        protocolData.setDesPort(desPort);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = content[i + offset];
        }
        offset += 4;                                    // offset = 42
        int seqNum = DataUtils.byteArrayToInt(buff_4);
        tcp.setSeqNum(seqNum);

        for (int i = 0; i < 4; i ++) {
            buff_4[i] = content[i + offset];
        }
        offset += 4;                                    // offset = 46
        int ackNum = DataUtils.byteArrayToInt(buff_4);
        tcp.setAckNum(ackNum);

        byte headerLen = content[offset ++];           // offset = 47
        tcp.setHeaderLen(headerLen);

        byte flags = content[offset ++];                // offset = 48
        tcp.setFlags(flags);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 50
        short window = DataUtils.byteArrayToShort(buff_2);
        tcp.setWindow(window);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 52
        short checkSum = DataUtils.byteArrayToShort(buff_2);
        tcp.setCheckSum(checkSum);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 54
        short urgentPointer = DataUtils.byteArrayToShort(buff_2);
        tcp.setUrgentPointer(urgentPointer);

//      LogUtils.printObj("tcp.offset", offset);
        
        data_offset = offsetCopy + tcp.getLengthOfHeader();
        
//      LogUtils.printObjInfo(tcp);

        return tcp;
    }
	
	
	/**
	 * 读取UDP头
	 * @param content
	 * @param offset
	 * @return
	 */
	private UDPHeader readUDPHeader(byte[] content, int offset) {
        byte[] buff_2 = new byte[2];

        UDPHeader udp = new UDPHeader();
        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
//          LogUtils.printByteToBinaryStr("UDP: buff_2[" + i + "]", buff_2[i]);
        }
        offset += 2;                                    // offset = 36
        short srcPort = DataUtils.byteArrayToShort(buff_2);
        udp.setSrcPort(srcPort);

        String sourcePort = validateData(srcPort);
        protocolData.setSrcPort(sourcePort);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 38
        short dstPort = DataUtils.byteArrayToShort(buff_2);
        udp.setDstPort(dstPort);

        String desPort = validateData(dstPort);
        protocolData.setDesPort(desPort);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 40
        short length = DataUtils.byteArrayToShort(buff_2);
        udp.setLength(length);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 42
        short checkSum = DataUtils.byteArrayToShort(buff_2);
        udp.setCheckSum(checkSum);

//      LogUtils.printObj("udp.offset", offset );
//      LogUtils.printObjInfo(udp);
        data_offset = offset;

        return udp;
    }
	
	/**
	 * 修正端口号为负值的导致转换为十进制数据出错
	 * @param data
	 * @return
	 */
	private String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}
}


