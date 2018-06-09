/**
 * 
 */
package structure;

import util.DataUtils;

/**
 * pcap文件中的数据帧头：以太网帧，14字节，可以不做处理，直接跳过
 * @author longlong
 *
 */
public class EthernetDataFrame {
	/**
     * 目的 MAC 地址：6 byte
     */
    private byte[] desMac;

    /**
     * 源 MAC 地址：6 byte
     */
    private byte[] srcMac;

    /**
     * 数据帧类型:2 字节
     */
    private short frameType;

    public byte[] getDesMac() {
        return desMac;
    }

    public void setDesMac(byte[] desMac) {
        this.desMac = desMac;
    }

    public byte[] getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(byte[] srcMac) {
        this.srcMac = srcMac;
    }

    public short getFrameType() {
        return frameType;
    }

    public void setFrameType(short frameType) {
        this.frameType = frameType;
    }

    public EthernetDataFrame() {}

    /**
     * 按照 Wireshark 的格式显示信息
     */
    @Override
    public String toString() {
        // frameType 以 十六进制显示
        return "PcapDataFrame [frameType=" + DataUtils.shortToHexString(frameType) + "]";
    }
}
