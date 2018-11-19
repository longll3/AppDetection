package signature;

import java.util.*;

public class SignatureForIE {

	private Set<Map<Integer, byte[]>> IEs = new HashSet<>();

	public SignatureForIE() {}


	public SignatureForIE(Map<Integer, byte[]> IE) {
		this.IEs.add(extractSignature(IE));
	}



	public static Map<Integer, byte[]> extractSignature(Map<Integer, byte[]> IE) {

		Map<Integer, byte[]> element = new HashMap<>();
		for (Map.Entry<Integer, byte[]> entry : IE.entrySet()) {
			if (entry.getKey() == 0) {
				//ignore ssid information
				continue;
			}

			if (entry.getKey() == 221) {
				//ignore vendor information
				continue;
			}
			element.put(entry.getKey(), entry.getValue());
		}
		return element;
	}




	public void updateSignature(Map<Integer, byte[]> IEs) {
		Map<Integer, byte[]> ie = extractSignature(IEs);
		if (isBelongTo(ie)) return;
		else this.IEs.add(ie);
	}



	/**
	 * @param a 被比较的
	 * @param b 签名中的IE
	 * @return
	 */
	private boolean checkIE(Map<Integer, byte[]> a, Map<Integer, byte[]> b) {
		//比较IE中的每个元素，是否相等
		Set<Integer> keys = a.keySet();
		for (Integer key : keys) {
			//跳过SSID的比较（该信息元素太个性化）
			if (key == 0) continue;

			if (b.containsKey(key)) {
				byte[] compare = b.get(key);
				byte[] to = a.get(key);

				if (compare.length != to.length) {
					return false;
				} else {
					for (int i = 0; i < compare.length; i++) {
						if (compare[i] != to[i]) {

							return false;
						}
					}
				}

			} else {
				return false;
			}
		}

		return true;
	}



	public boolean isBelongTo(Map<Integer, byte[]> IEs) {

		for (Map<Integer, byte[]> IE : this.IEs) {
			//有相等的IE就返回true
			if (checkIE(extractSignature(IEs), IE)) {
				return true;
			}

		}

		return false;
	}






}
