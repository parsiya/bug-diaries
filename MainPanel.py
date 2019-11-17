# The converted GUI from NetBeans.

from javax.swing import (JScrollPane, JTable, JPanel, JTextField, JLabel,
                         JTabbedPane, table, BorderFactory, GroupLayout,
                         LayoutStyle, JFrame, JTextArea, JSplitPane, JButton)
from Issue import Issue

class MainPanel():
    """Represents the converted frame from NetBeans."""

    defaultIssue = Issue(
        name="Issue Type/Name",
        severity="Critical",
        host="Issue Host",
        path="Issue Path",
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
        self.textName.text = issue.name
        self.textHost.text = issue.host
        self.textPath.text = issue.path
        self.textAreaDescription.text = issue.description
        self.textAreaRemediation.text = issue.remediation
        self.textSeverity.text = issue.severity
        # request and response tabs
        self.panelRequest.setMessage(issue.getRequest(), True)
        self.panelResponse.setMessage(issue.getResponse(), False)


    # button actions
    def newIssueAction(self, event):
        """Pops up a frame to add a new issue."""
        from NewIssueDialog import NewIssueDialog
        frm = NewIssueDialog(self.callbacks, "New Issue")
        frm.display(self)

    def gotNewIssue(self, issue):
        """got a new issue"""
        self.tableIssue.addRow(issue)
    
    def editIssue(self, index, issue):
        """Issue has been edited."""
        self.tableIssue.editRow(index, issue)
    
    def deleteIssueAction(self, event):
        """Delete the currently selected issue."""
        # this is the button
        # btn = event.getSource()
        row = self.tableIssue.getTableSelectedRow()
        # YOLO
        self.tableIssue.deleteRow(row)
        # it works!

    def exportAction(self, event):
        """Export everything in the table to a file."""
        lastDir = ""
        try:
            # load the last used directory
            # this will probably change as we will use a base64 encoded json as the complete config?
            lastDir = self.callbacks.loadExtensionSetting("lastDir")
        except:
            # if there is not a last used directory in the settings, continue
            pass

        from Utils import saveFileDialog, writeFile
        selectedFile, usedDirectory = saveFileDialog(parent=self.panel,
            startingDir=lastDir, title="Export Issues", extension="json")
        
        if selectedFile is not None:
            # write to the file
            writeFile(selectedFile.getAbsolutePath(),
                      self.tableIssue.exportIssues())
        
        if usedDirectory is not None:
            # overwrite the last used directory
            self.callbacks.saveExtensionSetting("lastDir", usedDirectory)

    def importAction(self, event):
        """Import a file to the table."""
        lastDir = ""
        try:
            # load the last used directory
            # this will probably change as we will use a base64 encoded json as the complete config?
            lastDir = self.callbacks.loadExtensionSetting("lastDir")
        except:
            # if there is not a last used directory in the settings, continue
            pass
        
        from Utils import openFileDialog, dictToIssue
        selectedFile, usedDirectory = openFileDialog(parent=self.panel,
            startingDir=lastDir, title="Import Issues", extension="json")
        
        # save the last directory
        self.callbacks.saveExtensionSetting("lastDir", usedDirectory)
        import json
        fi = open(selectedFile.getAbsolutePath(), "r")
        # read the file and create a list of Issues
        newIssues = json.load(fi, object_hook=dictToIssue)
        # clear the table
        self.tableIssue.clear()
        # add the issues to the table
        # for iss in newIssues:
        #     self.tableIssue.addRow(iss)
        self.tableIssue.populate(newIssues)

    # mostly converted generated code
    def __init__(self, callbacks, table=None):

        self.callbacks = callbacks
        self.jScrollPane1 = JScrollPane()
        self.jPanel1 = JPanel()
        self.labelName = JLabel("Issue Type/Name")
        self.textName = JTextField()
        self.labelSeverity = JLabel("Severity")
        self.textSeverity = JTextField()
        self.labelHost = JLabel("Host")
        self.labelPath = JLabel("Path")
        self.textHost = JTextField()
        self.textPath = JTextField()
        self.tabIssue = JTabbedPane()
        self.textAreaDescription = JTextArea()
        self.textAreaRemediation = JTextArea()
        self.panelRequest = self.callbacks.createMessageEditor(None, False)
        self.panelResponse = self.callbacks.createMessageEditor(None, False)

        self.loadPanel(self.defaultIssue)

        # buttons
        self.buttonNewIssue = JButton("New Issue",
                                      actionPerformed=self.newIssueAction)
        self.buttonDeleteIssue = JButton("Delete Issue",
                                         actionPerformed=self.deleteIssueAction)
        self.buttonImport = JButton("Import", actionPerformed=self.importAction)
        self.buttonExport = JButton("Export", actionPerformed=self.exportAction)

        if table is not None:
            self.tableIssue = table
        else:
            from IssueTable import IssueTable
            self.tableIssue = IssueTable()

        # wrap the table in a scrollpane
        self.jScrollPane1.setViewportView(self.tableIssue)

        # top panel containing the table
        from java.awt import Color
        self.jPanel1.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)))

        # create the labels and textfields
        self.textName.editable = False
        self.textName.setBackground(Color.LIGHT_GRAY)

        self.textSeverity.editable = False
        self.textSeverity.setBackground(Color.LIGHT_GRAY)

        self.textHost.editable = False
        self.textHost.setBackground(Color.LIGHT_GRAY)

        self.textPath.editable = False
        self.textPath.setBackground(Color.LIGHT_GRAY)

        # description textarea
        self.textAreaDescription.editable = False
        self.tabIssue.addTab("Description", self.textAreaDescription)

        # remediation textarea
        self.textAreaRemediation.editable = False
        self.tabIssue.addTab("Remediation", self.textAreaRemediation)

        # request tab
        self.panelRequest.setMessage("", True)
        self.tabIssue.addTab("Request", self.panelRequest.getComponent())

        # response tab
        self.panelResponse.setMessage("", False)
        self.tabIssue.addTab("Response", self.panelResponse.getComponent())

        # from java.lang import Short
        # jpanel1 is the bottom panel
        jPanel1Layout = GroupLayout(self.jPanel1)
        self.jPanel1.setLayout(jPanel1Layout)
        jPanel1Layout.setHorizontalGroup(
            # GroupLayout.Alignment.CENTER centers the group, in this case it
            # centers the buttons
            jPanel1Layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                .addGroup(jPanel1Layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                              .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                                        .addComponent(self.labelHost)
                                                        .addComponent(self.labelName))
                                              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                              .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                                        .addComponent(self.textName)
                                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                        .addComponent(self.labelSeverity)
                                                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                        .addComponent(self.textSeverity, GroupLayout.PREFERRED_SIZE, 186, GroupLayout.PREFERRED_SIZE))
                                                        .addGroup(jPanel1Layout.createSequentialGroup()
                                                                  .addComponent(self.textHost, GroupLayout.PREFERRED_SIZE, 330, GroupLayout.PREFERRED_SIZE)
                                                                  .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                                  .addComponent(self.labelPath)
                                                                  .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                                  .addComponent(self.textPath))))
                                    .addComponent(self.tabIssue))
                          .addContainerGap())
                .addGroup(jPanel1Layout.createSequentialGroup()
                          .addComponent(self.buttonNewIssue)
                          .addComponent(self.buttonDeleteIssue)
                          .addComponent(self.buttonImport)
                          .addComponent(self.buttonExport))
        )

        # link size of buttons
        from javax.swing import SwingConstants
        jPanel1Layout.linkSize(SwingConstants.HORIZONTAL, [self.buttonDeleteIssue, self.buttonExport, self.buttonImport, self.buttonNewIssue])

        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup()
                .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(self.labelName)
                                .addComponent(self.textName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.labelSeverity)
                                .addComponent(self.textSeverity, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(self.textHost, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.labelPath)
                                .addComponent(self.textPath, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.labelHost))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.tabIssue)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup()
                                .addComponent(self.buttonNewIssue)
                                .addComponent(self.buttonDeleteIssue)
                                .addComponent(self.buttonImport)
                                .addComponent(self.buttonExport))
                        .addContainerGap())
        )

        # create the main panel
        self.panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # set the top component
        self.panel.leftComponent = self.jScrollPane1
        self.panel.rightComponent = self.jPanel1
        self.panel.setDividerLocation(150)

    # end of converted code


# create "global" panel
burpPanel = None
