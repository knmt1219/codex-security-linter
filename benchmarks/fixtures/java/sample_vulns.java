import java.beans.XMLDecoder;
import java.io.InputStream;
import java.sql.Statement;

public class SampleVulns {
    public void execute(String cmd, InputStream in, Statement stmt, String accountId) throws Exception {
        Runtime.getRuntime().exec(cmd);
        XMLDecoder decoder = new XMLDecoder(in);
        stmt.executeQuery("SELECT * FROM users WHERE id = " + accountId);
    }
}
