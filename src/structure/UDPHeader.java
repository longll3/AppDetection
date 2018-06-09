/**
 * 
 */
package structure;

import util.DataUtils;

/**
 * UDP包头，由4个域组成，每个域各占用2个字节
 * @author longlong
 *
 */
public class UDPHeader {
	private short srcPort;          // 源端口
    private short dstPort;          // 目的端口
    private short length;           // 数据包长
    private short checkSum;     // 校验和
    
    //数据包中数据起始位置
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
    public short getLength() {
        return length;
    }
    public void setLength(short length) {
        this.length = length;
    }
    public short getCheckSum() {
        return checkSum;
    }
    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }

    public UDPHeader() {}

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return "UDPHeader [srcPort=" + srcPort
                + ", dstPort=" + dstPort
                + ", length=" + length
                + ", checkSum=" + DataUtils.shortToHexString(checkSum)
                + "]";
    }
}
