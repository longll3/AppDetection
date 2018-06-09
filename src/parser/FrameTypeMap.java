package parser;

import java.util.HashMap;
import java.util.Map;

public class FrameTypeMap {

	public static Map<String, String> frames = new HashMap<String, String >();
	
	static {
		frames.put("80", "beacon");
		frames.put("08", "data");
		frames.put("40", "probe request");
		frames.put("50", "probe response");
	}
	
}
