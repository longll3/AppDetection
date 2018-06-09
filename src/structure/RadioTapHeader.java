package structure;

/**
 * radiotap 的头。共8字节
 * @author longlong
 *
 */
public class RadioTapHeader {
	
	private byte revision;
	private byte pad;
	private short header_length; //包括radiotap header头部和数据两部分的长度
	private int it_present; // it_present表示radiotap数据的位掩码
	
	
	
	public RadioTapHeader() {
		super();
		// TODO Auto-generated constructor stub
	}
	public byte getRevision() {
		return revision;
	}
	public void setRevision(byte revision) {
		this.revision = revision;
	}
	public byte getPad() {
		return pad;
	}
	public void setPad(byte pad) {
		this.pad = pad;
	}
	public short getHeader_length() {
		return header_length;
	}
	public void setHeader_length(short header_length) {
		this.header_length = header_length;
	}
	public int getIt_present() {
		return it_present;
	}
	public void setIt_present(int it_present) {
		this.it_present = it_present;
	}
	
	

	
}
