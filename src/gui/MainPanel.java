package gui;

import javax.swing.*;

// Needed for Gson.
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;

import java.awt.Color;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.awt.event.ActionEvent;
import java.util.ArrayList;

import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

import burp.MainDiary;
import static burp.MainDiary.print;
import static burp.MainDiary.defaultBug;

import bug.BugTable;
import bug.Bug;

public class MainPanel implements IMessageEditorController {

    // Non-GUI variables
    private static burp.IBurpExtenderCallbacks callbacks;
    private BugTable bugTable;

    // panel is public
    public JSplitPane panel;

    /**
     * Creates new form MainPanel
     */
    public MainPanel() {
        initComponents();
    }

    /**
     * Creates a new form MainPanel where the bugs table is populated.
     * 
     * @param table Table with bugs.
     */
    public MainPanel(BugTable table) {
        initComponents();
        // This doesn't seem to be working.
        bugTable = table;
        MainDiary.table = bugTable;
    }

    /**
     * Creates a new form MainPanel where the bugs table is populated.
     * 
     * @param bugs ArrayList<Bug> containing the bugs.
     */
    public MainPanel(ArrayList<Bug> bugs) {
        initComponents();
        bugTable.populate(bugs);
        MainDiary.table = bugTable;
    }

    /**
     * Loads the main panel with the details of bug.
     * 
     * @param bug Bug whose details will be displayed in the panel.
     */
    public void loadPanel(Bug bug) {
        textName.setText(bug.name);
        textHost.setText(bug.host);
        textPath.setText(bug.path);
        textAreaDescription.setText(bug.description);
        textAreaRemediation.setText(bug.remediation);
        textSeverity.setText(bug.severity);
        // requestResponse might not be populated.
        if (bug.requestResponse != null) {
            panelRequest.setMessage(bug.getRequest(), true);
            panelResponse.setMessage(bug.getResponse(), false);
        } else {
            panelRequest.setMessage("".getBytes(), true);
            panelResponse.setMessage("".getBytes(), false);
        }
    }

    /**
     * Implementing IMessageEditorController
     */

    @Override
    public IHttpService getHttpService() {
        return bugTable.getSelectedBug().requestResponse.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return bugTable.getSelectedBug().getRequest();
    }

    @Override
    public byte[] getResponse() {
        return bugTable.getSelectedBug().getResponse();
    }

    /**
     * Sets up the GUI.
     */
    private void initComponents() {
        callbacks = MainDiary.callbacks;

        jScrollPane1 = new JScrollPane();
        jPanel1 = new JPanel();
        labelName = new JLabel("Name");
        textName = new JTextField();
        labelSeverity = new JLabel("Severity");
        textSeverity = new JTextField();
        labelHost = new JLabel("Host");
        labelPath = new JLabel("Path");
        textHost = new JTextField();
        textPath = new JTextField();
        tabBug = new JTabbedPane();
        textAreaDescription = new JTextArea();
        textAreaRemediation = new JTextArea();

        // JScrollPanes to hold the two jTextAreas
        // put the textareas in JScrollPanes
        jsPaneDescription = new JScrollPane(textAreaDescription);
        jsPaneRemediation = new JScrollPane(textAreaRemediation);
        panelRequest = callbacks.createMessageEditor(this, false);
        panelResponse = callbacks.createMessageEditor(this, false);

        // Buttons and their actions.
        buttonNewBug = new JButton("New Bug");
        // Add the action as an anonymous class.
        buttonNewBug.addActionListener(event -> {
            print("New Bug button pressed!");
            try {
                NewBugFrame nbf = new NewBugFrame(
                    MainDiary.mainPanel.panel, "Add New Bug", defaultBug
                );
                nbf.display();
            } catch (Exception e) {
                MainDiary.printStackTraceString(e);
            }
        });

        buttonDeleteBug = new JButton("Delete Bug");
        buttonDeleteBug.setToolTipText("The only good bug is a dead bug!");
        buttonDeleteBug.addActionListener(event -> {
            print("The only good bug is a dead bug!");
            // Get selected index and remove it.
            bugTable.removeBug(bugTable.getTableSelectedRow());
        });

        buttonImport = new JButton("Import");
        buttonImport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                print("Import clicked!");
                // Use the last used directory if it was saved.
                String lastDir = callbacks.loadExtensionSetting("lastDir");
                if (lastDir == null) {
                    lastDir = "";
                }
                java.io.File openFile = MainDiary.openFile(
                    MainDiary.mainPanel.panel,
                    lastDir,
                    "Select file to import",
                    "json"
                );
                String importStr = "";
                try {
                    // Read the file.
                    importStr = MainDiary.readFile(openFile);
                } catch (Exception e) {
                    MainDiary.printStackTraceString(e);
                    return;
                }
                // Create an array of Bugs from the imported JSON file.
                Type listType = new TypeToken<ArrayList<Bug>>() {}.getType();
                ArrayList<Bug> importedBugs = new Gson().fromJson(importStr, listType);
                print("Got bugs, importing them.");
                // Populate the table.
                bugTable.populate(importedBugs);
                // Update the last used directory.
                lastDir = openFile.getParent();
                if (lastDir.length() != 0) {
                    callbacks.saveExtensionSetting("lastDir", lastDir);
                }
                print(String.format(
                        "Import complete! Imported %d bugs from %s.",
                        importedBugs.size(),
                        openFile.getAbsolutePath()
                    )
                );
            }
        });

        buttonExport = new JButton("Export");
        buttonExport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {

                print("Export clicked!");
                // Convert all bugs to JSON.
                String jsoned = new Gson().toJson(bugTable.getBugs());
                // To prettyprint use this Gson object.
                // Gson gson = new GsonBuilder().setPrettyPrinting().create();
                // Use the last used directory if it was saved.
                String lastDir = callbacks.loadExtensionSetting("lastDir");
                if (lastDir == null) {
                    lastDir = "";
                }
                // Open a save file dialog.
                java.io.File saveFile = MainDiary.saveFile(
                    MainDiary.mainPanel.panel,
                    lastDir,
                    "Select export file",
                    "json"
                );
                // Write the file.
                try {
                    MainDiary.writeFile(saveFile, jsoned);
                } catch (IOException e) {
                    print("Export Failed!");
                    MainDiary.printStackTraceString(e);
                    return;
                }
                lastDir = saveFile.getParent();
                callbacks.saveExtensionSetting("lastDir", lastDir);
                print(String.format(
                        "Export complete! Exported %d bugs to %s.",
                        bugTable.getModel().getRowCount(),
                        saveFile.getAbsolutePath()
                    )
                );
            }
        });

        bugTable = new BugTable();
        // Wrap the table in a scrollpane.
        jScrollPane1.setViewportView(bugTable);

        // Top panel with the table.
        jPanel1.setBorder(BorderFactory.createLineBorder(new Color(0, 0, 0)));

        // Create the labels and textfields
        textName.setEditable(false);
        textName.setBackground(Color.LIGHT_GRAY);

        textSeverity.setEditable(false);
        textSeverity.setBackground(Color.LIGHT_GRAY);

        textHost.setEditable(false);
        textHost.setBackground(Color.LIGHT_GRAY);

        textPath.setEditable(false);
        textPath.setBackground(Color.LIGHT_GRAY);

        // Description textarea
        textAreaDescription.setEditable(false);
        textAreaDescription.setLineWrap(true);
        textAreaDescription.setWrapStyleWord(true);
        tabBug.addTab("Description", jsPaneDescription);

        // Remediation textarea
        textAreaRemediation.setEditable(false);
        textAreaRemediation.setLineWrap(true);
        textAreaRemediation.setWrapStyleWord(true);
        tabBug.addTab("Remediation", jsPaneRemediation);

        // Request tab
        // panelRequest.setMessage("", true);
        tabBug.addTab("Request", panelRequest.getComponent());

        // Response tab
        // panelResponse.setMessage("", false);
        tabBug.addTab("Response", panelResponse.getComponent());

        // GUI CODE - DO NOT TOUCH.
        // jpanel1 is the bottom panel.
        GroupLayout jPanel1Layout = new GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
                // GroupLayout.Alignment.CENTER centers the group, in this form it
                // centers the buttons
                jPanel1Layout.createParallelGroup(GroupLayout.Alignment.CENTER).addGroup(jPanel1Layout
                        .createSequentialGroup().addContainerGap()
                        .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                                .addComponent(labelHost).addComponent(labelName))
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                .addGroup(jPanel1Layout.createSequentialGroup().addComponent(textName)
                                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                        .addComponent(labelSeverity)
                                                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                        .addComponent(textSeverity, GroupLayout.PREFERRED_SIZE, 186,
                                                                GroupLayout.PREFERRED_SIZE))
                                                .addGroup(jPanel1Layout.createSequentialGroup()
                                                        .addComponent(textHost, GroupLayout.PREFERRED_SIZE, 330,
                                                                GroupLayout.PREFERRED_SIZE)
                                                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                        .addComponent(labelPath)
                                                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                        .addComponent(textPath))))
                                .addComponent(tabBug))
                        .addContainerGap())
                        .addGroup(jPanel1Layout.createSequentialGroup().addComponent(buttonNewBug)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(buttonDeleteBug)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(buttonImport)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(buttonExport)));

        // Link the size of buttons together.
        jPanel1Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, buttonDeleteBug, buttonExport, buttonImport,
                buttonNewBug);

        jPanel1Layout.setVerticalGroup(jPanel1Layout.createParallelGroup().addGroup(jPanel1Layout
                .createSequentialGroup().addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(labelName)
                        .addComponent(textName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                GroupLayout.PREFERRED_SIZE)
                        .addComponent(labelSeverity).addComponent(textSeverity, GroupLayout.PREFERRED_SIZE,
                                GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(textHost, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                GroupLayout.PREFERRED_SIZE)
                        .addComponent(labelPath)
                        .addComponent(textPath, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                GroupLayout.PREFERRED_SIZE)
                        .addComponent(labelHost))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED).addComponent(tabBug)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup().addComponent(buttonNewBug).addComponent(buttonDeleteBug)
                        .addComponent(buttonImport).addComponent(buttonExport))
                .addContainerGap()));

        // Create the main panel.
        panel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // Set the top component.
        panel.setLeftComponent(jScrollPane1);
        panel.setRightComponent(jPanel1);
        panel.setDividerLocation(150);
        // END OF GUI CODE
    }

    // GUI variables declaration
    private JScrollPane jScrollPane1;
    private JPanel jPanel1;
    private JLabel labelName;
    private JTextField textName;
    private JLabel labelSeverity;
    private JTextField textSeverity;
    private JLabel labelHost;
    private JLabel labelPath;
    private JTextField textHost;
    private JTextField textPath;
    private JTabbedPane tabBug;
    private JTextArea textAreaDescription;
    private JTextArea textAreaRemediation;
    private JScrollPane jsPaneDescription;
    private JScrollPane jsPaneRemediation;
    private IMessageEditor panelRequest;
    private IMessageEditor panelResponse;
    private JButton buttonNewBug;
    private JButton buttonDeleteBug;
    private JButton buttonImport;
    private JButton buttonExport;
    // End of variables declaration
}