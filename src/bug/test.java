package bug;

// Random functions for testing.

import java.util.ArrayList;

import burp.impl.HttpService;
import burp.impl.RequestResponse;

public class test {

    /**
     * Create an return an arraylist of n Bugs.
     * @param n Number of Bugs to return.
     * @return An arraylist containing n Bugs.
     */
    public static ArrayList<Bug> makeBugs(int n) {
        ArrayList<Bug> iss = new ArrayList<Bug>();
        for (int i = 0; i < n; i++) {
            String num = Integer.toString(i);
            // Create httpService
            HttpService srv = new HttpService("host"+num, 443, "https");
            RequestResponse reqResp = new RequestResponse.Builder(
                    ("request"+num).getBytes(), ("response"+num).getBytes(), srv
                )
                .build();
            Bug tmpBug = new Bug.Builder("name"+num).severity("severity"+num)
                .host("host"+num).path("path"+num).description("description"+num)
                .remediation("remediation"+num)
                .requestResponse(reqResp)
                .build();
            iss.add(tmpBug);
        }
        return iss;
    }

    /**
     * Create an BugTable with n Bugs.
     * @param n Number of Bugs to include in the table.
     * @return An BugTable with n Bugs.
     */
    public static BugTable makeBugTable(int n) {
        ArrayList<Bug> bugs = makeBugs(n);
        BugTable ist = new BugTable(bugs);
        return ist;
    }
}