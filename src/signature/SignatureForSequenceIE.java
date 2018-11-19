package signature;

import java.util.*;

public class SignatureForSequenceIE extends SignatureForIE {

    //这里的map应该用LinkedHashMap，因为IE的出现顺序也是重要的
    private Set<LinkedHashMap<Integer, byte[]>> IEs = new HashSet<>();

    public static LinkedHashMap<Integer, byte[]> extractSignature(LinkedHashMap<Integer, byte[]> IE) {
        LinkedHashMap<Integer, byte[]> el = new LinkedHashMap<>();
        Iterator<Map.Entry<Integer, byte[]>> ite = IE.entrySet().iterator();

        while (ite.hasNext()) {
            Map.Entry<Integer, byte[]> entry = ite.next();
            if (entry.getKey() == 0 || entry.getKey() == 221) continue;
            el.put(entry.getKey(), entry.getValue());
        }

        return el;

    }

    public void updateSignature(LinkedHashMap<Integer, byte[]> IEs) {
        LinkedHashMap<Integer, byte[]> ie = extractSignature(IEs);
        if (isBelongTo(ie)) return;
        else this.IEs.add(ie);
    }

    /**
     *
     * @param a 被比较的
     * @param b 签名中的IE
     * @description IE出现的顺序也是重要的，因此使用LinkedHashMap，并使用Iterator的方式遍历（与加入顺序相同）
     * @return
     */
    private boolean checkIE(LinkedHashMap<Integer, byte[]> a, LinkedHashMap<Integer, byte[]> b) {
        Iterator<Map.Entry<Integer, byte[]>> iteratorA = a.entrySet().iterator();
        Iterator<Map.Entry<Integer, byte[]>> iteratorB = b.entrySet().iterator();

        while (iteratorA.hasNext()) {
            if (iteratorB.hasNext()) {
                Map.Entry entryA = iteratorA.next();
                Map.Entry entryB = iteratorB.next();

                if (entryA.getKey() != entryB.getKey() ) {
                    return false;
                }

                byte[] valueA = (byte[]) entryA.getValue();
                byte[] valueB = (byte[]) entryB.getValue();

                if (valueA.length != valueB.length) return false;

                for(int i = 0; i < valueA.length; i++) {
                    if (valueA[i] != valueB[i]) {
                        return false;
                    }
                }
            } else {
                //IE数量不一致
                return false;
            }
        }

        if (!iteratorA.hasNext() && !iteratorB.hasNext()) {
            return true;
        } else {
            return false;
        }
    }

    public SignatureForSequenceIE() { }

    public SignatureForSequenceIE(LinkedHashMap<Integer, byte[]> IE) {
        this.IEs.add(IE);
    }

    public boolean isBelongTo(LinkedHashMap<Integer, byte[]> IEs) {
        for (LinkedHashMap<Integer, byte[]> IE : this.IEs) {
            //有相等的IE就返回true
            if (checkIE(extractSignature(IEs), IE)) {
                return true;
            }

        }

        return false;

    }
}
