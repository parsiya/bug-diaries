package gui;

import javax.swing.*;
import java.awt.Component;
import java.awt.event.ActionEvent;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.MainDiary;

import bug.Bug;
import bug.Template;

/**
 * BugFrame is the parent frame for new/edit bug frames
 */
public class BugFrame implements IMessageEditorController {

    // Variables
    protected static IBurpExtenderCallbacks callbacks;
    protected Component parent;
    public JFrame frm;
    // Holds the currently displayed bug.
    protected Bug currentBug;

    /**
     * Creates new a form BugFrame
     */
    public BugFrame() {
        initComponents();
    }

    /**
     * Creates a new BugFrame and assigns the parent
     * 
     * @param parentFrame The parent component.
     */
    public BugFrame(Component parentFrame) {
        initComponents();
        parent = parentFrame;
    }

    /**
     * Creates a new BugFrame and assigns the parent and title
     * 
     * @param parentFrame The parent component.
     * @param title       Frame's title.
     */
    public BugFrame(Component parentFrame, String title) {
        initComponents();
        parent = parentFrame;
        frm.setTitle(title);
    }

    /**
     * Creates a new BugFrame and assigns the parent and title. Loads bug into the
     * frame.
     * 
     * @param parentFrame The parent component.
     * @param title       Frame's title. @
     */
    public BugFrame(Component parentFrame, String title, Bug bug) {
        initComponents();
        parent = parentFrame;
        frm.setTitle(title);
        setBug(bug); // Maybe we need to do (currentBug = bug;) here too.
    }

    public void display() {
        try {
            frm.pack();
            // frm.setLocationRelativeTo(MainDiary.mainPanel.panel);
            frm.setLocationRelativeTo(parent);
            frm.setVisible(true);
        } catch (Exception e) {
            MainDiary.print(e.toString());
        }
    }

    /**
     * Loads a bug into the frame.
     * 
     * @param bug The bug to be loaded.
     */
    public void setBug(Bug bug) {

        currentBug = bug;

        textName.setText(bug.name);
        textHost.setText(bug.host);
        textPath.setText(bug.path);
        textAreaDescription.setText(bug.description);
        textAreaRemediation.setText(bug.remediation);
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
     * Get the current {@link Bug} from the frame.
     * 
     * @return The Bug currently displayed in the frame.
     */
    protected Bug getBug() {
        Bug selectedBug = new Bug.Builder(textName.getText()).severity(comboSeverity.getSelectedItem().toString())
                .host(textHost.getText()).path(textPath.getText()).description(textAreaDescription.getText())
                .remediation(textAreaRemediation.getText())
                // TODO: We have to account for modified requestResponse.
                .requestResponse(currentBug.requestResponse).build();
        return selectedBug;
    }

    /**
     * Save button action. Must be overriden by child classes.
     */
    protected void saveAction(ActionEvent event) {
        // Do nothing.
    }

    /**
     * Loads defaultBug into the frame == resetting the frame.
     */
    private void resetAction() {
        setBug(MainDiary.defaultBug);
    }

    /**
     * Hides the form when the cancel button is pressed.
     */
    private void cancelAction() {
        // Seems like this resets the form so we do not need to call dispose().
        frm.setVisible(false);
    }

    @Override
    public IHttpService getHttpService() {
        return currentBug.requestResponse.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentBug.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentBug.getResponse();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     */
    private void initComponents() {

        callbacks = MainDiary.callbacks;

        frm = new JFrame();

        // Enabling this will close Burp when the dialog is closed.
        // setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        // Name
        labelName = new JLabel("Name");
        textName = new JTextField();
        // Severity
        labelSeverity = new JLabel();
        comboSeverity = new JComboBox<>();
        comboSeverity.setModel(new DefaultComboBoxModel<String>(MainDiary.severities));
        // Host
        labelHost = new JLabel("Host");
        textHost = new JTextField();
        // Path
        labelPath = new JLabel("Path");
        textPath = new JTextField();
        // Template
        labelTemplate = new JLabel("Template");
        comboTemplate = new JComboBox<Template>();

        // Description textarea
        textAreaDescription = new JTextArea();
        // Set values for the textarea
        textAreaDescription.setLineWrap(true);
        textAreaDescription.setWrapStyleWord(true);

        // Remediation textarea
        textAreaRemediation = new JTextArea();
        textAreaRemediation.setLineWrap(true);
        textAreaRemediation.setWrapStyleWord(true);

        // Put the textareas into jscrollpanes
        jsPaneDescription = new JScrollPane(textAreaDescription);
        jsPaneRemediation = new JScrollPane(textAreaRemediation);

        // Request IMessageEditor
        panelRequest = callbacks.createMessageEditor(this, true);
        panelResponse = callbacks.createMessageEditor(this, true);


        // Add the textareas and message editors to a tabbed pane
        tabBug = new JTabbedPane();
        tabBug.addTab("Description", jsPaneDescription);
        tabBug.addTab("Remediation", jsPaneRemediation);
        tabBug.addTab("Request", panelRequest.getComponent());
        tabBug.addTab("Response", panelResponse.getComponent());

        // Buttons
        buttonSave = new JButton("Save");
        buttonSave.addActionListener(event -> saveAction(event));

        buttonReset = new JButton("Reset");
        buttonReset.addActionListener(event -> resetAction());

        buttonCancel = new JButton("Cancel");
        buttonCancel.addActionListener(event -> cancelAction());

        // GUI CODE - DO NOT TOUCH.
        GroupLayout layout = new GroupLayout(frm.getContentPane());
        frm.getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER).addGroup(layout
                .createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(layout
                        .createSequentialGroup().addContainerGap()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(labelTemplate)
                                .addComponent(labelHost).addComponent(labelName))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(layout
                                .createSequentialGroup().addComponent(textName)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(labelSeverity)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(comboSeverity,
                                        GroupLayout.PREFERRED_SIZE, 125, GroupLayout.PREFERRED_SIZE))
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(textHost, GroupLayout.PREFERRED_SIZE, 266,
                                                GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(labelPath)
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(textPath))
                                .addComponent(comboTemplate, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                        .addGroup(layout.createSequentialGroup().addContainerGap().addComponent(tabBug)))
                .addContainerGap())
                .addGroup(layout.createSequentialGroup().addComponent(buttonSave)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(buttonReset)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(buttonCancel)));

        // Link the size of buttons together.
        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, buttonSave, buttonReset, buttonCancel);

        layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup().addContainerGap()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(labelName)
                                .addComponent(textName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                        GroupLayout.PREFERRED_SIZE)
                                .addComponent(labelSeverity).addComponent(comboSeverity, GroupLayout.PREFERRED_SIZE,
                                        GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(labelHost)
                                .addComponent(textHost, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                        GroupLayout.PREFERRED_SIZE)
                                .addComponent(labelPath).addComponent(textPath, GroupLayout.PREFERRED_SIZE,
                                        GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(labelTemplate)
                                .addComponent(comboTemplate, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                        GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(tabBug, GroupLayout.PREFERRED_SIZE, 363, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(buttonSave)
                                .addComponent(buttonReset).addComponent(buttonCancel))
                        .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

        // frm.pack();
        // Moved pack to display().
        // END OF GUI CODE
    }

    // Variables declaration
    // private ones should not be modified by subclasses.
    // protected ones can be overriden.
    private JButton buttonCancel;
    private JButton buttonReset;
    // Must be protected so subclasses can change the action.
    private JButton buttonSave;
    protected JComboBox<String> comboSeverity;
    // TODO: Change the type when we add templates to comboTemplate.
    // Subclasses must be able to hide this.
    protected JComboBox<Template> comboTemplate;
    // Subclasses must be able to hide this.
    protected JLabel labelTemplate;
    private JScrollPane jsPaneDescription;
    private JScrollPane jsPaneRemediation;
    private JLabel labelHost;
    private JLabel labelName;
    private JLabel labelPath;
    private JLabel labelSeverity;
    protected IMessageEditor panelRequest;
    protected IMessageEditor panelResponse;
    private JTabbedPane tabBug;
    protected JTextArea textAreaDescription;
    protected JTextArea textAreaRemediation;
    protected JTextField textHost;
    protected JTextField textName;
    protected JTextField textPath;
    // End of variables
}
