/**
 * 
 */
package structure;

import com.sun.tracing.dtrace.ProviderAttributes;

import util.DataUtils;

/**
 * TCP包头，20字节
 * @author longlong
 *
 */
public class TCPHeader {
	/**
     * 源端口（2 字节）
     */
    private short srcPort;

    /**
     * 目的端口（2 字节）
     */
    private short dstPort;

    /**
     * Sequence Number：发送数据包中的第一个字节的序列号（4 字节）
     */
    private int seqNum;

    /**
     * 确认序列号（4 字节）
     * 表示接收方期望收到发送方下一个报文段的第一个字节数据的编号。
     */
    private int ackNum;

    /**
     * 数据报头的长度(4 bit) + 保留(4 bit) = 1 byte
     * 由于TCP首部包含一个长度可变的选项部分，所以需要这么一个值来指定这个TCP报文段到底有多长。
     * 或者可以这么理解：就是表示TCP报文段中数据部分在整个TCP报文段中的位置。该字段的单位是32位字，即：4个字节。
     */
    private byte headerLen;

    /**
     * 标识TCP不同的控制消息(1 字节)
     */
    private byte flags;

    /**
     * 接收缓冲区的空闲空间，用来告诉TCP连接对端自己能够接收的最大数据长度（2 字节）
     */
    private short window;

    /**
     * 校验和（2 字节）
     */
    private short checkSum;

    /**
     * 紧急指针（2 字节）
     */
    private short urgentPointer;
    
    /**
     * tcp包中数据部分的位置偏移（即tcp的真实头部大小，包括可选部分的长度）
     */
    private int data_offset;
    
    

    public int getData_offset() {
		return data_offset;
	}

	public void setData_offset(int data_offset) {
		this.data_offset = data_offset;
	}

	public String getSrcPortString() {
		return DataUtils.validateData(this.srcPort);
	}


	public String getDstPortString() {
		return DataUtils.validateData(this.dstPort);
	}


	public short getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(short srcPort) {
        this.srcPort = srcPort;
    }

    public short getDstPort() {
        return dstPort;
    }

    public void setDstPort(short dstPort) {
        this.dstPort = dstPort;
    }

    public int getSeqNum() {
        return seqNum;
    }

    public void setSeqNum(int seqNum) {
        this.seqNum = seqNum;
    }

    public int getAckNum() {
        return ackNum;
    }

    public void setAckNum(int ackNum) {
        this.ackNum = ackNum;
    }

    public byte getHeaderLen() {
        return headerLen;
    }
    
    public int getLengthOfHeader() {
    		int headLen =  (this.headerLen >> 4);
        headLen = headLen & 0x0f;
        //单位是4字节
        return headLen*4;
    }

    public void setHeaderLen(byte headerLen) {
        this.headerLen = headerLen;
    }

    public byte getFlags() {
        return flags;
    }

    public void setFlags(byte flags) {
        this.flags = flags;
    }

    public short getWindow() {
        return window;
    }

    public void setWindow(short window) {
        this.window = window;
    }

    public short getCheckSum() {
        return checkSum;
    }

    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }

    public short getUrgentPointer() {
        return urgentPointer;
    }

    public void setUrgentPointer(short urgentPointer) {
        this.urgentPointer = urgentPointer;
    }

    public TCPHeader() {}

    @Override
    public String toString() {
        return "TCPHeader [srcPort=" + srcPort
                + ", dstPort=" + dstPort
                + ", seqNum=" + seqNum
                + ", ackNum=" + ackNum
                + ", headerLen=" + headerLen
                + ", flags=" + DataUtils.byteToHexString(flags)
                + ", window=" + window
                + ", checkSum=" + DataUtils.shortToHexString(checkSum)
                + ", urgentPointer=" + urgentPointer
                + "]";
    }

}
