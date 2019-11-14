# The converted GUI from NetBeans.

from javax.swing import (JScrollPane, JTable, JPanel, JTextField, JLabel,
                         JTabbedPane, table, BorderFactory, GroupLayout,
                         LayoutStyle, JFrame, JTextArea, JSplitPane, JButton)


class MainPanel():
    """Represents the converted frame from NetBeans."""

    # button actions
    def newIssueAction(self, event):
        """Pops up a frame."""
        # print str(event)
        from EditDialog import EditDialog
        # modality="application" blocks all of Burp which may or may not be a
        # good thing for your usecase.
        # it helps if you want to make sure the dialog is closed before the user
        # continues but messes up if users want to copy/paste from Burp into the
        # dialog.
        frm = EditDialog(self.callbacks, title="New Issue")
        frm.display(self)

    def gotNewIssue(self, issue):
        """got a new issue"""
        # print str(issue)
        self.jTable1.addRow(issue)
    
    def deleteIssueAction(self, event):
        """Delete the currently selected issue."""
        # this is the button
        # btn = event.getSource()
        # print "self.jTable1.selectedRow(): " + str(self.jTable1.getTableSelectedRow())
        # print "self.jTable1.getModel().issues(self.jTable1.getTableSelectedRow()): " + str(self.jTable1.getModel().issues[self.jTable1.getTableSelectedRow()])
        # seems like this is working
        # let's try and delete something
        row = self.jTable1.getTableSelectedRow()
        # YOLO
        self.jTable1.deleteRow(row)
        # it works!

    def exportAction(self, event):
        """Export everything in the table to a file."""
        print self.jTable1.exportIssues()

    # mostly converted generated code
    def __init__(self, callbacks, table=None):

        self.callbacks = callbacks
        self.jScrollPane1 = JScrollPane()
        self.jPanel1 = JPanel()
        self.labelName = JLabel("Issue Type/Name")
        self.textName = JTextField("Issue Type/Name")
        self.labelSeverity = JLabel("Severity")
        self.textSeverity = JTextField("Severity")
        self.labelHost = JLabel("Host")
        self.labelPath = JLabel("Path")
        self.textHost = JTextField("Issue Host")
        self.textPath = JTextField("Issue Path")
        self.tabIssue = JTabbedPane()
        self.textAreaDescription = JTextArea()
        self.textAreaRemediation = JTextArea()
        self.panelRequest = self.callbacks.createMessageEditor(None, False)
        self.panelResponse = self.callbacks.createMessageEditor(None, False)

        # buttons
        self.buttonNewIssue = JButton("New Issue",
                                      actionPerformed=self.newIssueAction)
        self.buttonDeleteIssue = JButton("Delete Issue",
                                         actionPerformed=self.deleteIssueAction)
        self.buttonImport = JButton("Import")
        self.buttonExport = JButton("Export", actionPerformed=self.exportAction)

        if table is not None:
            self.jTable1 = table
        else:
            from IssueTable import IssueTable
            self.jTable1 = IssueTable()

        # wrap the table in a scrollpane
        self.jScrollPane1.setViewportView(self.jTable1)

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
