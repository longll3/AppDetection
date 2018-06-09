/**
 * 
 */
package parser;

import java.util.HashMap;
import java.util.Map;

/**
 * 查看TCP数据包中是否有需要的信息
 * @author longlong
 *
 */
public class InformationMinning {
//	private String content;
	
	Map<String, String> infoMap;
	
//	private String IMEI;
	private boolean ifGetIMEI;
	
//	private String telephoneNumber;
	private boolean ifGetTelephoneNumber;
	
//	private String longitude;
//	private String latitude;
	private boolean ifGetLon;
	private boolean ifGetLat;
	
	private final static String tcpFlagforIMEI[] = {"utm_content=", "msid=", "pragma-mtid:", "wm_did="};
	private final static String httpFlagforIMEI[] = {"User-Agent:"};
	private final static String tcpFlagforPhoneNumber[] = {"h_cookie_phone=", "grap_cookie_phone_ab="};
	private final static String tcpFlagforLatidue = "&wm_actual_latitude=";
	private final static String tcpFlagforLongitude = "&wm_actual_longitude=";
	
	private final static int IMEILength = 15;
	private final static int TelephoneNumberLength = 11;
	
	//经纬度的长度不一定，没有定长
//	private final static int LocationLength = 8；
	
	
	public InformationMinning() {
//		this.IMEI = null;
		this.ifGetIMEI = false;
//		this.telephoneNumber = null;
		this.ifGetTelephoneNumber = false;
//		this.longitude = null;
//		this.latitude = null;
		this.ifGetLon = false;
		this.ifGetLat = false;
		
		this.infoMap = new HashMap<String, String>();
	}
	
	public boolean ifFoundAllInfo() {
		if (this.ifGetIMEI && this.ifGetLon && ifGetLat && this.ifGetTelephoneNumber) return true;
		else return false;
	}
	
	/**
	 * 从content中找到IMEI号、手机号、经纬度信息
	 * @param content 数据包
	 * @param dstIP 数据包的目标IP
	 */
	public void find(String content, String dstIP) {
		
		if (content.length() == 0) return;
		if (ifFoundAllInfo()) return;
		
		
		if(!ifGetIMEI) {
			if (dstIP.equals("36.110.144.110") || dstIP.equals("36.110.144.127") ||
					dstIP.equals("113.113.64.39") || dstIP.equals("203.76.217.1") ||
					dstIP.equals("103.75.152.3") || dstIP.equals("103.37.142.131") ||
					dstIP.equals("125.90.58.150") || dstIP.equals("103.37.152.53") ||
					dstIP.equals("103.37.152.41") || dstIP.equals("103.37.152.1")) {
				for (int i = 0; i < tcpFlagforIMEI.length; i++) {
					int start = content.indexOf(tcpFlagforIMEI[i]) + tcpFlagforIMEI[i].length();
					
					//start > -1 + tcpFlag[i].length()+1 => start > tcpFlag[i].length()
					if (start > (tcpFlagforIMEI[i].length())) {
						infoMap.put("IMEI",	content.substring(start, start+IMEILength));
//						this.IMEI = content.substring(start, start+IMEILength);
						this.ifGetIMEI = true;
						break;
					}
				}
			} else if ((dstIP.equals("113.113.64.36") || dstIP.equals("113.113.64.37") ||
					dstIP.equals("14.21.76.30") || dstIP.equals("117.27.142.27") ||
					dstIP.equals("113.105.155.198") )) {
				int start = content.indexOf(httpFlagforIMEI[0]) + httpFlagforIMEI[0].length();
				int end = content.indexOf("\r\n", start);
				
				//当httpFlag【0】是最后一个参数时，该参数值的末尾 有时 不会有换行符“\r\n”
				if (! (end > 0)) end = content.length();
				
				String userAgent = content.substring(start, end);
				
				String temp[] = userAgent.split(" ");
				if (temp.length > 2) {
					String temp2[] = temp[2].split("-");
					infoMap.put("IMEI",	temp2[7]);
//					this.IMEI = temp2[7];
					this.ifGetIMEI = true;
					
				}
				
			}
		}
			
		if (!ifGetTelephoneNumber) {
			if (dstIP.equals("103.37.152.53") || dstIP.equals("103.37.152.41")) {
				for (int i = 0; i < tcpFlagforPhoneNumber.length; i++) {
					int start = content.indexOf(tcpFlagforPhoneNumber[i]) + tcpFlagforPhoneNumber[i].length();
						
					if (start > tcpFlagforPhoneNumber[i].length()) {
						//this.telephoneNumber = content.substring(start, start+TelephoneNumberLength);
						this.infoMap.put("TelePhone Number", content.substring(start, start+TelephoneNumberLength));
						this.ifGetTelephoneNumber = true;
						break;
					}
				}
			}
		}
			
		if (!ifGetLon || !ifGetLat) {
			if (dstIP.equals("36.110.144.127")) {
				int startForLat = content.indexOf(tcpFlagforLatidue) + tcpFlagforLatidue.length();
				
				if (startForLat > tcpFlagforLatidue.length()) {
					int end = content.indexOf("&", startForLat);
					this.infoMap.put("latitude", content.substring(startForLat, end));
					this.ifGetLat = true;
					//this.latitude = content.substring(startForLat, end);
				}
				
				int startForLong = content.indexOf(tcpFlagforLongitude) + tcpFlagforLongitude.length();
				
				if (startForLong > tcpFlagforLongitude.length()) {
					int end = content.indexOf("&", startForLong);
					this.infoMap.put("longitude", content.substring(startForLong, end));
					this.ifGetLon = true;
//					this.longitude = content.substring(startForLong, end);
				}
				
				
			}
		}
			
			
			
		
//		int start = content.indexOf("Host:") + 6;
//		int end = str.indexOf("\r\n", start);
//		int end = content.indexOf("\r\n", start);
//		
//		//当host是最后一个参数时，该参数值的末尾 有时 不会有换行符“\r\n”
//		if (! (end > 0)) end = content.length();
		
//		return content.substring(start, end);
		
	}
	
	
	public boolean ifFoundIMEI() {
		return this.ifGetIMEI;
	}

	public boolean ifFoundNumber() {
		return this.ifGetTelephoneNumber;
	}
	
	public boolean ifFoundLocation() {
		return (this.ifGetLat && this.ifGetLon);
	}
	
	
	

}
