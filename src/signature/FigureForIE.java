package signature;

import java.util.ArrayList;
import java.util.Map;

public class FigureForIE implements Figure {

    Map<Integer, byte[]> IEs;
    ArrayList<Integer> keySequence;

    public FigureForIE(Map<Integer, byte[]> IEs, ArrayList<Integer> IESeq) {
        this.IEs = IEs;
        this.keySequence = IESeq;
    }

    @Override
    public Map<Integer, byte[]> getIEMap() {
        return IEs;
    }

    @Override
    public Double[] getIFATList() {
        System.err.println("it's a FiureForIE class");
        return new Double[0];
    }
}
