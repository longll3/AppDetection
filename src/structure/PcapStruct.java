/**
 * 
 */
package structure;

import java.util.ArrayList;
import java.util.List;

/**
 * pcap 结构
 * @author longlong
 * @private_variable private PcapFileHeader fileHeader;
   					private List<PcapDataHeader> dataHeaders;
 *
 */
public class PcapStruct {
	private PcapFileHeader fileHeader;
    private List<PcapDataHeader> dataHeaders;

    public PcapFileHeader getFileHeader() {
        return fileHeader;
    }
    public void setFileHeader(PcapFileHeader fileHeader) {
        this.fileHeader = fileHeader;
    }
    public List<PcapDataHeader> getDataHeaders() {
        return dataHeaders;
    }
    public void setDataHeaders(List<PcapDataHeader> dataHeaders) {
        this.dataHeaders = dataHeaders;
    }

    public PcapStruct() {
    		this.fileHeader = null;
    		this.dataHeaders = new ArrayList<PcapDataHeader>();
    }

}
