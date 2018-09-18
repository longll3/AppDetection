package signature;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SignatureForIE {
	private Set<Map<Integer, byte[]>> IEs = new HashSet<>();

	public SignatureForIE() {}

	public void updateSignature(Map<Integer, byte[]> IEs) {
		if (isBelongTo(IEs)) return;
		else this.IEs.add(IEs);
	}

	/**
	 * @param a 被比较的
	 * @param b 签名中的IE
	 * @return
	 */
	public boolean checkIE(Map<Integer, byte[]> a, Map<Integer, byte[]> b) {
		//比较IE中的每个元素，是否相等
		Set<Integer> keys = a.keySet();
		for (Integer key : keys) {
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

	/**
	 * 仅比较所含IE种类是否相同
	 * @param IEs
	 * @return
	 */
	public boolean isBelongTo(Map<Integer, byte[]> IEs) {

		for (Map<Integer, byte[]> IE : this.IEs) {

			if (checkIE(IEs, IE)) {
				return true;
			}

		}

		return false;
	}

	
}
