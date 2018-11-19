package util;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class DataUtils {
	
	private final static char[] mChars = "0123456789ABCDEF".toCharArray();  
    private final static String mHexStr = "0123456789ABCDEF";
	
	/**
	 * short 转 16 进制字符串
	 * @param s
	 * @return
	 */
	public static String shortToHexString (short s) {
		String hex = intToHexString(s);
		int len = hex.length();
		if (len > 4) {	// 此时 short 值为负值，高位会补 1，变成 ffffed5c，因此截去符号位
			hex = hex.substring(4);
		} 

		len = hex.length();
		if (len < 4) {	// 若小于 4，则高位补 0
			int n = 4 - len;
			for (int i = 0; i < n; i ++) {
				hex = "0" + hex;
			}
		}

		return "0x" + hex;
	}
	
	/** Convert byte[] to hex string.
	 * @param src byte[] data   
	 * @return hex string   
	 */      
	public static String bytesToHexString(byte[] src , int offset, int length){   
	    StringBuilder stringBuilder = new StringBuilder("");   
	    if (src == null || src.length <= 0) {   
	        return null;   
	    }   
	    for (int i = offset, j = 0; j < length; j++, i++) {   
	        int v = src[i] & 0xFF;   
	        String hv = Integer.toHexString(v);   
	        if (hv.length() < 2) {   
	            stringBuilder.append(0);   
	        }   
	        stringBuilder.append(hv);   
	    }   
	    return stringBuilder.toString();   
	}
	
	/**
	 * byte 转为 16 进制字符串
	 * @param b
	 * @return
	 */
	public static String byteToHexString (byte b) {
		return intToHexString(byteToInt(b));
	}
	
	/**
	 * 将 int 转为 16 进制字符串
	 * @param data
	 * @return
	 */
	public static String intToHexString (int data) {
		return Integer.toHexString(data);
	}
	
	
	
	/**
	 * byte 转 int
	 * @param b
	 * @return
	 */
	public static int byteToInt (byte b) {
		return (b & 0xff);
	}

	/**
	 * 一维字节数组转 int 值(4 字节)
	 * @param b
	 * @return
	 */
	public static int byteArrayToInt(byte[] b){
		return byteArrayToUnsignedInt(b, 0);
//		return byteArrayToInt(b, 0);
	}

	/**
	 * 一维字节数组转 int 值(4 字节)
	 * @param b
	 * @param offset
	 * @return
	 */
	public static int byteArrayToUnsignedInt(byte[] bytes, int offset){
		int value= 0;
		//由高位到低位
		for (int i = 0; i < 4; i++) {
			int shift= (4 - 1 - i) * 8;
			value +=(bytes[i] & 0x000000FF) << shift;//往高位游
		}

		return value&0x0FFFFFFFF;
	}

	/**
	 * 一维字节数组转 int 值(4 字节)
	 * @param b
	 * @param offset
	 * @return
	 */
	public static int byteArrayToInt(byte[] bytes, int offset){
		int value= 0;
		//由高位到低位
		for (int i = 0; i < 4; i++) {
			int shift= (4 - 1 - i) * 8;
			value +=(bytes[i] & 0x00FF) << shift;//往高位游
		}

		return value;
	}
	
	/**
	 * 一维字节数组转 long 值(8 字节)
	 * @param b
	 * @return
	 */
	public static long byteArrayToLong(byte[] bytes){
		long value= 0;
		//由高位到低位
		for (int i = 0; i < 8; i++) {
			bytes[i] &= 0xff;
			int temp = bytes[i] & 0x00ff;
 			int shift= (8 - 1 - i) * 8;
 			
			value += ((long)temp << shift);//往高位游
		}
		
//		System.out.println(value);
		return value;
	}
	
	/**
	 * 一维字节数组转 short 值(2 字节)
	 * @param b
	 * @return
	 */
	public static short byteArrayToShort(byte[] b){
		return byteArrayToShort(b, 0);
	}

	/**
	 * 一维字节数组转 short 值(2 字节)
	 * @param b
	 * @param offset
	 * @return
	 */
	public static short byteArrayToShort(byte[] b,int offset){
		return (short) (((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff)); 
	}
	
	/**
	 * 将一维的字节数组逆序
	 * @param arr
	 */
	public static void reverseByteArray(byte[] arr){
		byte temp;
		int n = arr.length;
		for(int i = 0; i < n / 2; i++){
			temp = arr[i];
			arr[i] = arr[n - 1 - i];
			arr[n - 1 - i] = temp;
		}
	}
	
	/**
	 * 将二进制的数字字符串转为十进制
	 * @param str
	 */
	public static int binaryToDecimal (String str) {
		String[] strs = str.split("");
		List<Integer> datas = new ArrayList<Integer>();
		for (String s : strs) {
			datas.add(Integer.valueOf(s));
		}
		int size = datas.size();

		int values = 0;
		if (size <= 16) {
			for (int i = 0; i < size; i ++) {
				values += (datas.get(i) * ((int) Math.pow(2, size - i - 1)));
			}
		} else {	// 这种情况是该数值为负值，前面补 1
			// 只留下最后 16 位数
			int offset = size - 16;
			for (int i = 0; i < 16; i ++) {
				values += (datas.get(i + offset) * ((int) Math.pow(2, 16 - i - 1)));
			}
		}

		return values;
	}
	
	/**
	 * convert byte[] to string
	 * 
	 */
	public static String bytesToString(byte[] src, int start, int end) {
		String res = null;
		try {
			res = new String(Arrays.copyOfRange(src, start, end), "ascii"); 
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}

	
	/**  
     * 十六进制字符串转换成 ASCII字符串 
     * @param str String Byte字符串 
     * @return String 对应的字符串 
     */    
    public static String hexStr2Str(String hexStr){    
        hexStr = hexStr.toString().trim().replace(" ", "").toUpperCase(Locale.US);  
        char[] hexs = hexStr.toCharArray();    
        byte[] bytes = new byte[hexStr.length() / 2];    
        int iTmp = 0x00;;    
  
        for (int i = 0; i < bytes.length; i++){    
            iTmp = mHexStr.indexOf(hexs[2 * i]) << 4;    
            iTmp |= mHexStr.indexOf(hexs[2 * i + 1]);    
            bytes[i] = (byte) (iTmp & 0xFF);    
        }    
        return new String(bytes);    
    }  
      
    /** 
     * bytes转换成十六进制字符串 
     * @param b byte[] byte数组 
     * @param iLen int 取前N位处理 N=iLen 
     * @return String 每个Byte值之间空格分隔 
     */  
    public static String byte2HexStr(byte[] b, int start, int end){  
        StringBuilder sb = new StringBuilder();  
        for (int n=start; n<end; n++){  
            sb.append(mChars[(b[n] & 0xFF) >> 4]);  
            sb.append(mChars[b[n] & 0x0F]);  
            sb.append(' ');  
        }  
        return sb.toString().trim().toUpperCase(Locale.US);  
    }
    
    public static String byteArray2HexString(byte bytes[], int start, int end) {
    		StringBuilder sb = new StringBuilder();
	    for (int i = start; i < end; i++) {
	        sb.append(String.format("%02X", bytes[i]));
	    }
	    return sb.toString();
    }
    
	/**
	 * 修正端口号为负值的导致转换为十进制数据出错
	 * @param data
	 * @return
	 */
	public static String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}
	
	public static double getAbsoluteValue(double a, double b) {
		if (a > b) return a - b;
		else return b - a;
	}
}
