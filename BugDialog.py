# Base frame for creating and editing issues.

from javax.swing import (LayoutStyle, JTextField, JTabbedPane, WindowConstants,
                         JTextField, JButton, JSplitPane, JComboBox, JLabel,
                         JDialog, GroupLayout, JTextArea, BorderFactory, 
                         JScrollPane)
from Issue import Issue
from java.awt.event import ComponentListener


class DialogListener(ComponentListener):
    """ComponentListener for the frame."""

    def __init__(self, dialog):
        """DialogListener constructor to save a reference to the dialog."""
        self.dialog = dialog

    def componentHidden(self, event):
        """Invoked when the dialog is hidden."""
        # inheriting classes should implement this.
        # issue = self.dialog.issue
        pass

    def componentMoved(self, event):
        pass

    def componentResized(self, event):
        pass

    def componentShown(self, event):
        pass


class BugDialog(JDialog):
    """Represents the dialog."""

    # default issue to populate the panel with
    defaultIssue = Issue(
        name="Name",
        severity="Critical",
        host="Host",
        path="Path",
        description="Description",
        remediation="",
        request="",
        response=""
    )

    def loadPanel(self, issue):
        # type: (Issue) -> ()
        """Populates the panel with issue."""
        if issue is None:
            return
        
        # check if the input is the correct object
        assert isinstance(issue, Issue)

        # set textfields and textareas
        # selectionStart=0 selects the text in the textfield when it is in focus
        self.textName.text = issue.name
        self.textName.selectionStart = 0
        self.textHost.text = issue.host
        self.textHost.selectionStart = 0
        self.textPath.text = issue.path
        self.textPath.selectionStart = 0
        self.textAreaDescription.text = issue.description
        self.textAreaDescription.selectionStart = 0
        self.textAreaRemediation.text = issue.remediation
        self.textAreaRemediation.selectionStart = 0
        # severity combobox
        # this is case-sensitive apparently
        self.comboSeverity.setSelectedItem(issue.severity)
        # request and response tabs
        self.panelRequest.setMessage(issue.getRequest(), True)
        self.panelResponse.setMessage(issue.getResponse(), False)
        # reset the template combobox (only applicable to NewIssueDialog)
        self.comboTemplate.setSelectedIndex(-1)
    
    def loadTemplateIntoPanel(self, issue):
        # type: (Issue) -> ()
        """Populates the panel with the template issue.
        Does not overwrite:
        name (append), host, path, severity, request and response."""
        if issue is None:
            return
        
        # check if the input is the correct object
        assert isinstance(issue, Issue)

        # set textfields and textareas
        # selectionStart=0 selects the text in the textfield when it is in focus
        self.textName.text += " - " + issue.name
        self.textName.selectionStart = 0
        # self.textHost.text = issue.host
        # self.textHost.selectionStart = 0
        # self.textPath.text = issue.path
        # self.textPath.selectionStart = 0
        self.textAreaDescription.text = issue.description
        self.textAreaDescription.selectionStart = 0
        self.textAreaRemediation.text = issue.remediation
        self.textAreaRemediation.selectionStart = 0
        # severity combobox
        # this is case-sensitive apparently
        # self.comboSeverity.setSelectedItem(issue.severity)
        # request and response tabs
        # self.panelRequest.setMessage(issue.getRequest(), True)
        # self.panelResponse.setMessage(issue.getResponse(), False)
        # reset the template combobox (only applicable to NewIssueDialog)
        self.comboTemplate.setSelectedIndex(-1)

    def cancelButtonAction(self, event):
        """Close the dialog when the cancel button is clicked."""
        self.dispose()

    def resetButtonAction(self, event):
        """Reset the dialog."""
        self.loadPanel(self.defaultIssue)

    # Inheriting forms should implement this
    def saveButtonAction(self, event):
        """Save the current issue.
        Inheriting classes must implement this."""
        pass
    
    def __init__(self, callbacks, issue=defaultIssue, title="", modality=""):
        """Constructor, populates the dialog."""
        # set the title
        self.setTitle(title)
        # store the issue
        self.issue = issue

        from javax.swing import JFrame
        self.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);

        if modality is not "":
            from java.awt.Dialog import ModalityType
            modality = modality.lower()
            # application blocks us from clicking anything else in Burp
            if modality == "application":
                self.setModalityType(ModalityType.APPLICATION_MODAL)
            if modality == "document":
                self.setModalityType(ModalityType.DOCUMENT_MODAL)
            if modality == "modeless":
                self.setModalityType(ModalityType.DOCUMENT_MODAL)
            if modality == "toolkit":
                self.setModalityType(ModalityType.DOCUMENT_MODAL)

        # assert isinstance(callbacks, IBurpExtenderCallbacks)
        # starting converted code from NetBeans
        self.labelPath = JLabel("Path")
        self.labelSeverity = JLabel("Severity")
        self.tabIssue = JTabbedPane()
        self.textAreaDescription = JTextArea()
        self.textAreaRemediation = JTextArea()
        # JScrollPanes to hold the two jTextAreas
        # put the textareas in JScrollPanes
        self.jsPaneDescription = JScrollPane(self.textAreaDescription)
        self.jsPaneRemediation = JScrollPane(self.textAreaRemediation)
        self.panelRequest = callbacks.createMessageEditor(None, True)
        self.panelResponse = callbacks.createMessageEditor(None, True)
        self.textName = JTextField()
        self.textHost = JTextField()
        self.textPath = JTextField()
        self.labelHost = JLabel("Host")
        self.labelName = JLabel("Name")

        # buttons
        self.buttonSave = JButton("Save",
                                  actionPerformed=self.saveButtonAction)
        self.buttonCancel = JButton("Cancel",
                                    actionPerformed=self.cancelButtonAction)
        self.buttonReset = JButton("Reset",
                                   actionPerformed=self.resetButtonAction)

        # description and remediation textareas
        from java.awt import Dimension
        self.textAreaDescription.setPreferredSize(Dimension(400,500))
        self.textAreaDescription.setLineWrap(True)
        self.textAreaDescription.setWrapStyleWord(True)
        self.textAreaRemediation.setLineWrap(True)
        self.textAreaRemediation.setWrapStyleWord(True)
        self.tabIssue.addTab("Description", self.jsPaneDescription)
        self.tabIssue.addTab("Remediation", self.jsPaneRemediation)
        # request and response tabs
        # request tab
        self.panelRequest.setMessage("", True)
        self.tabIssue.addTab("Request", self.panelRequest.getComponent())
        # response tab
        self.panelResponse.setMessage("", False)
        self.tabIssue.addTab("Response", self.panelResponse.getComponent())
        # template
        self.labelTemplate = JLabel("Template")
        self.comboTemplate = JComboBox()
        
        # TODO: Populate this from outside using a config file from the
        # constructor? or perhaps the extension config 
        self.comboSeverity = JComboBox(["Critical", "High", "Medium", "Low",
        "Info"])
        self.comboSeverity.setSelectedIndex(-1)

        # add componentlistener
        dlgListener = DialogListener(self)
        self.addComponentListener(dlgListener)

        if issue is None:
            issue = self.defaultIssue
        # load the issue into the edit dialog.
        self.loadPanel(issue)

        # "here be dragons" GUI code
        layout = GroupLayout(self.getContentPane())
        self.getContentPane().setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                        .addGroup(layout.createSequentialGroup()
                                    .addContainerGap()
                                    .addGroup(layout.createParallelGroup()
                                        .addGroup(layout.createSequentialGroup()
                                            .addGroup(layout.createParallelGroup()
                                                .addComponent(self.labelTemplate)
                                                .addComponent(self.labelHost)
                                                .addComponent(self.labelName))
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                            .addGroup(layout.createParallelGroup()
                                                .addGroup(layout.createSequentialGroup()
                                                    .addComponent(self.comboTemplate))
                                                .addGroup(layout.createSequentialGroup()
                                                    .addComponent(self.textHost, GroupLayout.PREFERRED_SIZE, 212, GroupLayout.PREFERRED_SIZE)
                                                    .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                    .addComponent(self.labelPath)
                                                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                    .addComponent(self.textPath))
                                                .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                                    .addComponent(self.textName, GroupLayout.PREFERRED_SIZE, 620, GroupLayout.PREFERRED_SIZE)
                                                    .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                    .addComponent(self.labelSeverity)
                                                    .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                    .addComponent(self.comboSeverity, GroupLayout.PREFERRED_SIZE, 182, GroupLayout.PREFERRED_SIZE))))
                                        .addComponent(self.tabIssue)))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(self.buttonSave, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.buttonReset, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.buttonCancel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
                        )
                    .addContainerGap())
        )

        # link size of buttons together
        from javax.swing import SwingConstants
        layout.linkSize(SwingConstants.HORIZONTAL, [self.buttonCancel, self.buttonSave, self.buttonReset])

        layout.setVerticalGroup(
            layout.createParallelGroup()
                .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(self.labelName)
                        .addComponent(self.textName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self.labelSeverity)
                        .addComponent(self.comboSeverity, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(self.textHost, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self.labelPath)
                        .addComponent(self.textPath, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self.labelHost))
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(self.comboTemplate, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self.labelTemplate))
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(self.tabIssue)
                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(layout.createParallelGroup()
                        .addComponent(self.buttonSave)
                        .addComponent(self.buttonReset)
                        .addComponent(self.buttonCancel))
                    .addContainerGap())
        )
        # end of converted code from NetBeans

        # set the template label and combobox to invisible
        self.labelTemplate.setVisible(False)
        self.comboTemplate.setVisible(False)

    def display(self, parent):
        """packs and shows the frame."""
        self.pack()
        # setlocation must be AFTER pack
        # source: https://stackoverflow.com/a/22615038
        self.dlgParent = parent
        self.setLocationRelativeTo(self.dlgParent.panel)
        # self.show()
        self.setVisible(True)

    def loadTemplate(self):
        """Reads the template file and populates the combobox for NewIssueDialog.
        """
        templateFile = "data\\templates-cwe-1200.json"
        fi = open(templateFile, "r")
        from Utils import dictToIssue
        import json
        templateIssues = json.load(fi, object_hook=dictToIssue)
        self.templateIssues = templateIssues
        # templateNames = [t.name for t in self.templateIssues]
        for t in self.templateIssues:
            self.comboTemplate.addItem(t)