/**
 * 
 */
package parser;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import structure.EthernetDataFrame;
import structure.IPHeader;
import structure.PcapDataHeader;
import structure.PcapFileHeader;
import structure.PcapStruct;
import structure.ProtocolType;
import structure.TCPHeader;
import structure.UDPHeader;

import util.DataUtils;

/**
 * @author longlong
 *
 */
public class PcapFileParser {
	private File pcapFile;
	private PcapStruct pcapStruct;
	private InformationMinning tcpDataMining;
	private String SrcIP;
	
	private final static int fileHeaderLength = 24;
	private final static int pcapDataHeaderLength = 16;
	private final static int ethernetHeadLenght = 14;
	private final static int ipHeaderLength = 20;
	
	
	
	public PcapFileParser(File file, String srcIP) {
		this.pcapFile = file;
		this.pcapStruct = new PcapStruct();
		this.tcpDataMining = new InformationMinning();
		this.SrcIP = srcIP;
	}
	
	public void parse() throws IOException {
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
	 * 解析真正的数据（不包括pcap头）
	 */
	private boolean parseContent(byte[] content) {
		readEthernetFrame(content);
		
		IPHeader ipHeader = readIPHeader(content);
		
		
		if (ipHeader == null) {
			//read the end of the file
			return true;
		}
		
		//不是目标原地址，则不分析该包，跳过
		if (!ipHeader.getSrcIPString().equals(SrcIP)) return false;
		
		int offset = ethernetHeadLenght + ipHeaderLength;
		
		String protocol = ipHeader.getProtocol() + "";
		if (ProtocolType.TCP.getType().equals(protocol)) {
			TCPHeader tcpHeader = readTCPHeader(content, offset);
			
			System.out.println(content.length - tcpHeader.getData_offset());
			//tcp recall function
//			System.out.println(DataUtils.bytesToString(content, tcpHeader.getData_offset(), content.length));
			
			if (!tcpDataMining.ifFoundAllInfo()) {
				tcpDataMining.find(DataUtils.bytesToString(content, tcpHeader.getData_offset(), content.length), ipHeader.getDstIPString());
			}
			
			
			
		} else if (ProtocolType.UDP.getType().equals(protocol)) {
			UDPHeader udpHeader = readUDPHeader(content, offset);
			
			System.out.println("this is udp package");
			System.out.println(DataUtils.bytesToString(content, udpHeader.getData_offset(), content.length));
			
		} else {
			System.out.println("这是其他协议类型的数据包");
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
	private void readEthernetFrame(byte[] content) {
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
        ip.setSrcIPString(sourceIP);
//        protocolData.setSrcIP(sourceIP);

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
//        protocolData.setDesIP(destinationIP);
        ip.setDstIPString(destinationIP);

//      LogUtils.printObjInfo(ip);

        return ip;
    }

	/**
	 * 读取TCP头
	 * @param content2
	 * @param offset
	 * @return
	 */
	private TCPHeader readTCPHeader(byte[] content, int offset) {
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

//        String sourcePort = validateData(srcPort);
//        protocolData.setSrcPort(sourcePort);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 38
        short dstPort = DataUtils.byteArrayToShort(buff_2);
        tcp.setDstPort(dstPort);

//        String desPort = validateData(dstPort);
//        protocolData.setDesPort(desPort);

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
        
        tcp.setData_offset(offsetCopy + tcp.getLengthOfHeader());
        
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

//        String sourcePort = validateData(srcPort);
        
//        protocolData.setSrcPort(sourcePort);

        for (int i = 0; i < 2; i ++) {
            buff_2[i] = content[i + offset];
        }
        offset += 2;                                    // offset = 38
        short dstPort = DataUtils.byteArrayToShort(buff_2);
        udp.setDstPort(dstPort);

//        String desPort = validateData(dstPort);
//        protocolData.setDesPort(desPort);

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
        udp.setData_offset(offset);

        return udp;
    }
	
	public Map<String, String> getInfo() {
		return tcpDataMining.infoMap;
	}

}
