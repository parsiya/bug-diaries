/**
 * Main extension file.
 */

package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

// import gui.BugFrame;
import gui.MainPanel;
import gui.NewBugFrame;
import bug.test;
import bug.Bug;

import burp.impl.RequestResponse;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        MainDiary.callbacks = callbacks;
        MainDiary.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(MainDiary.extensionName);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // Start test
                // Add some bugs to the table.

                try {
                    ArrayList<Bug> iss = test.makeBugs(3);
                    // for (Bug bug : iss) {
                    // MainDiary.printOutput(bug.toString());
                    // }
                    MainDiary.mainPanel = new MainPanel(iss);
                } catch (Exception e) {
                    MainDiary.print(e.toString());
                }
                // End test
                callbacks.registerContextMenuFactory(BurpExtender.this);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return MainDiary.tabName;
    }

    @Override
    public Component getUiComponent() {
        return MainDiary.mainPanel.panel;
    }

    /**
     * Implement IContextMenuFactory
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        JMenuItem menu1 = new JMenuItem("Make Custom Bug");
        menu1.addActionListener(event -> {
            MainDiary.print("Clicked context menu item");
            // Get the first selected message.
            // TODO: Get selectedIssues if we have right-clicked a Burp Issue tab.
            RequestResponse reqResp = new RequestResponse(invocation.getSelectedMessages()[0]);
            Bug newBug = MainDiary.defaultBug;
            // Assign host, path and port from reqResp.
            newBug.host = reqResp.getHttpService().getHost();
            newBug.path = MainDiary.callbacks.getHelpers().analyzeRequest(reqResp).getUrl().getFile();
            newBug.requestResponse = reqResp;
            String title = "New Bug From " + MainDiary.getToolName(invocation.getToolFlag());
            NewBugFrame nbi = new NewBugFrame(this.getUiComponent(), title, newBug);
            nbi.display();
        });


        ArrayList<JMenuItem> menuArray = new ArrayList<JMenuItem>();

        menuArray.add(menu1);
        return menuArray;
    }
}