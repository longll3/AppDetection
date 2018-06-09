/**
 * 
 */
package structure;

import util.DataUtils;

/**
 * IP数据报头
 * @author longlong
 *
 */
public class IPHeader {
	/**
     * 协议版本号(4 bit)及包头长度(4bit) =（1 字节）
     * 版本号(Version):一般的值为0100（IPv4），0110（IPv6）
     * IP包头最小长度为20字节
     * 包头长度：固定部分的长度（20字节）和可变部分的长度之和。
     * 		   共占4位。
     * 		   最大为1111，即10进制的15，代表IP报头的最大长度可以为15个32bits（4字节），
     *         也就是最长可为15*4=60字节，除去固定部分的长度20字节，可变部分的长度最大为40字节。
     */
    private byte varHLen;

    /**
     * Type of  Service：服务类型，（1 字节）
     */
    private byte tos;

    /**
     * 总长度（2 字节）
     * IP报文的总长度。报头的长度和数据部分的长度之和。
     */
    private short totalLen;

    /**
     * 标识（2 字节）
     * 唯一的标识主机发送的每一分数据报。通常每发送一个报文，它的值加一。
     * 当IP报文长度超过传输网络的MTU（最大传输单元）时必须分片，
     * 这个标识字段的值被复制到所有数据分片的标识字段中，
     * 使得这些分片在达到最终目的地时可以依照标识字段的内容重新组成原先的数据。
     */
    private short id;

    /**
     * 标志与偏移量（2 字节）
     * 标志：共3位。R、DF、MF三位。
     * 		目前只有后两位有效，DF位：为1表示不分片，为0表示分片。
     * 		MF：为1表示“更多的片”，为0表示这是最后一片。
     * 偏移量：本分片在原先数据报文中相对首位的偏移位。（需要再乘以8）
     */
    private short flagSegment;

    /**
     * Time to Live：生存周期（1 字节）
     * IP报文所允许通过的路由器的最大数量。
     * 每经过一个路由器，TTL减1，当为0时，路由器将该数据报丢弃。
     * TTL 字段是由发送端初始设置一个 8 bit字段.推荐的初始值由分配数字 RFC 指定，当前值为 64。
     * 发送 ICMP 回显应答时经常把 TTL 设为最大值 255。
     */
    private byte ttl;

    /**
     * 协议类型（1 字节）
     * 指出IP报文携带的数据使用的是那种协议，以便目的主机的IP层能知道要将数据报上交到哪个进程（不同的协议有专门不同的进程处理）。
     * 和端口号类似，此处采用协议号，TCP的协议号为6，UDP的协议号为17。ICMP的协议号为1，IGMP的协议号为2.
     */
    private byte protocol;

    /**
     * 头部校验和（2 字节
     * 计算IP头部的校验和，检查IP报头的完整性。
     */
    private short checkSum;

    /**
     * 源 IP（4 字节）
     */
    private int srcIP;

    /**
     * 目的 IP（4 字节）
     */
    private int dstIP;
    
    //正常形式的IP地址：***.***.***.***
    private String srcIPString;
    private String dstIPString;
    
    

    public String getSrcIPString() {
		return srcIPString;
	}

	public void setSrcIPString(String srcIPString) {
		this.srcIPString = srcIPString;
	}

	public String getDstIPString() {
		return dstIPString;
	}

	public void setDstIPString(String dstIPString) {
		this.dstIPString = dstIPString;
	}

	public byte getVarHLen() {
        return varHLen;
    }

    public void setVarHLen(byte varHLen) {
        this.varHLen = varHLen;
    }

    public byte getTos() {
        return tos;
    }

    public void setTos(byte tos) {
        this.tos = tos;
    }

    public short getTotalLen() {
        return totalLen;
    }

    public void setTotalLen(short totalLen) {
        this.totalLen = totalLen;
    }

    public short getId() {
        return id;
    }

    public void setId(short id) {
        this.id = id;
    }

    public short getFlagSegment() {
        return flagSegment;
    }

    public void setFlagSegment(short flagSegment) {
        this.flagSegment = flagSegment;
    }

    public byte getTtl() {
        return ttl;
    }

    public void setTtl(byte ttl) {
        this.ttl = ttl;
    }

    public byte getProtocol() {
        return protocol;
    }

    public void setProtocol(byte protocol) {
        this.protocol = protocol;
    }

    public short getCheckSum() {
        return checkSum;
    }

    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }

    public int getSrcIP() {
        return srcIP;
    }

    public void setSrcIP(int srcIP) {
        this.srcIP = srcIP;
    }

    public int getDstIP() {
        return dstIP;
    }

    public void setDstIP(int dstIP) {
        this.dstIP = dstIP;
    }

    public IPHeader() { }

    @Override
    public String toString() {
        return "IPHeader [varHLen=" + DataUtils.byteToHexString(varHLen)
                + ", tos=" + DataUtils.byteToHexString(tos)
                + ", totalLen=" + totalLen
                + ", id=" + DataUtils.shortToHexString(id)
                + ", flagSegment=" + DataUtils.shortToHexString(flagSegment)
                + ", ttl=" + ttl
                + ", protocol=" + protocol
                + ", checkSum=" + DataUtils.shortToHexString(checkSum)
                + ", srcIP=" + DataUtils.intToHexString(srcIP)
                + ", dstIP=" + DataUtils.intToHexString(dstIP)
                + "]";
    }
    
}
