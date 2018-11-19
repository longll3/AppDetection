package process;

import java.io.IOException;

public interface Processor {

    public void generatesSignature() throws IOException;

    public void process() throws IOException;
}
