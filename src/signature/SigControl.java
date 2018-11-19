package signature;

import java.util.Map;

public interface SigControl {

    void updateSignature(Figure fig);

    boolean isBelongToTheType(Figure fig);

    Map extractSignature(Figure fig);




}
