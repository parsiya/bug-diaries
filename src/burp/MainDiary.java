/**
 * Extension constants.
 */

package burp;

import gui.MainPanel;
import bug.Bug;
import bug.BugTable;

import burp.impl.HttpService;

import java.net.MalformedURLException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.swing.JFileChooser;
import java.awt.Component;
import javax.swing.filechooser.FileNameExtensionFilter;


public class MainDiary {
    // Globals
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    // public static BugFrame bugFrame;
    public static MainPanel mainPanel;
    public static BugTable table;

    // Extension text
    public static String extensionName = "The Bug Diaries - Burp Bugs for All";
    public static String tabName = "Bug Diaries";

    // Useful "constants"
    // Seems like this is not working when passed to setRequest and setResponse
    // of IMessageEditors.
    public static byte[] emptyBytes = "".getBytes();

    // Default bug to populate the panels.
    public static Bug defaultBug =
        new Bug.Builder("Name").severity("High").host("Host").path("Path")
            .description("Description").remediation("Remediation").build();

    // Table columns
    public static String[] columnStrings = new String[] {
        "Name", "Severity", "Host", "Path"
    };

    public static Class[] classes = new Class[] {
        java.lang.String.class, java.lang.String.class,
        java.lang.String.class, java.lang.String.class
    };

    // Severity levels
    // These are case-sensitive.
    public static String[] severities = new String[] {
        "High", "Medium", "Low", "Information"
    };

    // Confidence levels
    public static String[] confidence = new String[] {
        "Certain", "Firm", "Tentative"
    };

    /**
     * Prints the String s to standard output.
     * @param s The String to be printed.
     */
    public static void print(String s) {
        callbacks.printOutput(s);
    }

    /**
     * Prints the String s to standard error.
     * @param s The String to be printed.
     */
    public static void printError(String s) {
        callbacks.printError(s);
    }

    /**
     * Returns an exception's stacktrace.
     * @param e The exception.
     * @return A String with the exception's stacktrace.
     */
    public static String getStackTraceString(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    /**
     * Prints the exception's stacktrace to stderr.
     * @param e The exception.
     */
    public static void printStackTraceString(Exception e) {
        printError(getStackTraceString(e));
    }

    /**
     * Attempts to salvage and return an HttpService from a URL string.
     * @param u URL string to be parsed.
     * @return HttpService object with hopefully correct values.
     */
    public static HttpService salvageURL(String u) {

        int port = 443; // Default port
        String protocol = "https"; // Default protocol.
        u = u.toLowerCase();
        // 1. Try to convert the string to a java.net.URL.
        try {
            java.net.URL url = new java.net.URL(u);
            // If port is not present in u, getPort() returns -1.
            if (url.getPort() == -1) {
                // Check the protocol and assign the port manually.
                switch (url.getProtocol()) {
                case "http":
                    port = 80;
                    break;
                case "https":
                    port = 443;
                    break;
                }
            }
            return new HttpService(url.getHost(), port, url.getProtocol());
        } catch (MalformedURLException e) {
            // Do nothing if it goes wrong and continue.
            // printStackTraceString(e);
        }

        // 2. Do some funky homebrew salvaging.
        // Check if it contains "://" if so, everything before "://" is protocol
        // This might give us protocols that are not correct, but we will deal
        // with it later.
        int indexProtocol = u.indexOf("://");
        if (indexProtocol != -1) {
            // Grab everything before "://" and put it in protocol.
            protocol = u.substring(0, indexProtocol);
            u = u.substring(indexProtocol + 3);
        }
        // Check for ":"
        int indexPort = u.indexOf(":");
        if (indexPort != -1) {
            // Grab everything between : and / (if any) and hope it's a number.
            String portString = "";
            if (u.contains("/")) {
                portString = u.substring(indexPort + 1, u.indexOf("/"));
            } else {
                portString = u.substring(indexPort + 1);
            }
            // Try to convert port to an int.
            try {
                port = Integer.parseInt(portString);
                // Putting this after the function that might cause exception
                // means it will only get completed if the above was successful.
                // Am I a genius or what? /s
                u = u.substring(0, indexPort);
            } catch (NumberFormatException e) {
                // If it's not a number, stay with 0.
                printStackTraceString(e);
            }
        }
        // Remove the trailing forwardslash here.
        // TODO: This might remove everything so we need to be careful.
        if (u.contains("/")) {
            u = u.substring(0, u.indexOf("/"));
        }
        // Anything here should hopefully be host.
        return new HttpService(u, port, protocol);
    }

    public static String getToolName(int flag) {
        java.util.Map<Integer, String> toolMap = new java.util.HashMap<Integer, String>();

        // Populate the map.
        toolMap.put(1, "Suite");
        toolMap.put(2, "Target");
        toolMap.put(4, "Proxy");
        toolMap.put(8, "Spider");
        toolMap.put(16, "Scannner");
        toolMap.put(32, "Intruder");
        toolMap.put(64, "Repeater");
        toolMap.put(128, "Sequencer");
        toolMap.put(256, "Decoder");
        toolMap.put(512, "Comparer");
        toolMap.put(1024, "Extender");

        return toolMap.get(flag);
    }

    public static String getResourceFile(String name) throws IOException {
        InputStream in = BurpExtender.class.getResourceAsStream(name); 
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        
        StringBuffer buf = new StringBuffer();
        String tmpStr = "";


        while((tmpStr = reader.readLine()) != null) {
            buf.append(tmpStr);
        }
        in.close();
        return buf.toString();
    }

    /**
     * Select a file for saving using a JFileChooser swing component.
     * @param parent The parent component.
     * @param startingPath Starting directory for the explorer.
     * @param title The title of the filechooser.
     * @param extension The extension to filter with. E.g., "json".
     * @return The selected file as a {@link File} object
     */
    public static File saveFile(Component parent, String startingPath,
        String title, String extension) {

            JFileChooser fc = new JFileChooser();
            // If starting path is set, use it.
            if (startingPath.length() != 0) {
                fc.setCurrentDirectory(new File(startingPath));
            }
            // If title is set, use it.
            if (title.length() != 0) {
                fc.setDialogTitle(title);
            }
            // If extension is set, create the file filter.
            if (extension.length() != 0) {
                // "JSON Files (*.json)"
                String extFilterString = String.format("%s Files (*.%s)",
                    extension.toUpperCase(), extension.toLowerCase());
                String[] extFilterList = new String[] {extFilterString};
                FileNameExtensionFilter ff =
                    new FileNameExtensionFilter(extFilterString, extFilterList);
                fc.addChoosableFileFilter(ff);
            }
            // Only choose files.
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            // Show the dialog and store the return value.
            int retVal = fc.showSaveDialog(parent);
            // If the dialog was cancelled, return null.
            if (retVal != JFileChooser.APPROVE_OPTION) {
                return null;
            }
            return fc.getSelectedFile();
        }

        /**
         * Select a file for opening using a JFileChooser.
         * @param parent The parent component.
         * @param startingPath The starting directory.
         * @param title The title of the dialog.
         * @param extension The extension to filter with. E.g., "json".
         * @return The selected file as a {@link File} object.
         */
        public static File openFile(Component parent, String startingPath, String title,
        String extension) {

            JFileChooser fc = new JFileChooser();
            // If starting path is set, use it.
            if (startingPath.length() != 0) {
                fc.setCurrentDirectory(new File(startingPath));
            }
            // If title is set, use it.
            if (title.length() != 0) {
                fc.setDialogTitle(title);
            }
            // If extension is set, create the file filter.
            if (extension.length() != 0) {
                // "JSON Files (*.json)"
                String extFilterString = String.format("%s Files (*.%s)",
                    extension.toUpperCase(), extension.toLowerCase());
                String[] extFilterList = new String[] {extFilterString};
                FileNameExtensionFilter ff =
                    new FileNameExtensionFilter(extFilterString, extFilterList);
                fc.addChoosableFileFilter(ff);
            }
            // Only choose files.
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            // Show the dialog and store the return value.
            int retVal = fc.showOpenDialog(parent);
            // If the dialog was cancelled, return null.
            if (retVal != JFileChooser.APPROVE_OPTION) {
                return null;
            }
            return fc.getSelectedFile();
        }

        public static void writeFile(File f, String data) throws IOException {
            try(FileWriter fw = new FileWriter(f)) {
                fw.write(data);
            }
        }
    
        public static String readFile(File f) throws IOException {
            return Files.readString(Paths.get(f.getAbsolutePath()));
        }

}
