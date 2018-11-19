package signature;

import java.util.Map;

public class FigureForIFAT implements Figure {

    Double[] IFATArr;


    public FigureForIFAT(Double[] arr) {
        this.IFATArr = arr;
    }

    @Override
    public Map<Integer, byte[]> getIEMap() {
        System.err.println("it's a FigureForIFAT");
        return null;
    }

    @Override
    public Double[] getIFATList() {
        return IFATArr;
    }
}
