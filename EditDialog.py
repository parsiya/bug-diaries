# Frame to edit issues.

from javax.swing import (JPanel, JLabel, JTextField, JTabbedPane, JPanel,
                         JTextField, JButton, JSplitPane, BorderFactory,
                         GroupLayout, JTextArea, JComboBox, LayoutStyle,
                         JDialog, WindowConstants)
from java.lang import Short

from burp import IBurpExtenderCallbacks


class EditDialog(JDialog):
    """Represents the dialog used to edit issues or add new ones."""

    def cancelButtonAction(self, event):
        """Close the dialog when the cancel button is clicked."""
        self.dispose()

    def resetButtonAction(self, event):
        """Reset the dialog."""
        self.revalidate()
        # self.dispose()
        # selt.setVisible(True)


    def __init__(self, callbacks, title="", modality="", issue=None):
        """Constructor to populate the dialog with the new issue."""
        self.setTitle(title)

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

        assert isinstance(callbacks, IBurpExtenderCallbacks)
        # starting converted code from NetBeans
        self.labelPath = JLabel("Path")
        self.labelSeverity = JLabel("Severity")
        self.tabIssue = JTabbedPane()
        self.textAreaDescription = JTextArea()
        self.textAreaRemediation = JTextArea()
        self.panelRequest = callbacks.createMessageEditor(None, False)
        self.panelResponse = callbacks.createMessageEditor(None, False)
        self.textName = JTextField("Issue Type/Name")
        self.textHost = JTextField("Issue Host")
        self.textPath = JTextField("Issue Path")
        self.labelHost = JLabel("Host")
        self.labelName = JLabel("Issue Type/Name")

        # buttons
        self.buttonSave = JButton("Save")
        self.buttonCancel = JButton("Cancel",
                                    actionPerformed=self.cancelButtonAction)
        self.buttonReset = JButton("Reset",
                                   actionPerformed=self.resetButtonAction)

        # description textarea
        from java.awt import Dimension
        self.textAreaDescription.setPreferredSize(Dimension(400,500))
        self.tabIssue.addTab("Description", self.textAreaDescription)
        self.tabIssue.addTab("Remediation", self.textAreaRemediation)

        # request and response tabs
        # request tab
        self.panelRequest.setMessage("", True)
        self.tabIssue.addTab("Request", self.panelRequest.getComponent())

        # response tab
        self.panelResponse.setMessage("", False)
        self.tabIssue.addTab("Response", self.panelResponse.getComponent())

        self.comboSeverity = JComboBox(["Critical", "High", "Medium", "Low",
                                        "Info"])

        # "here be dragons" GUI code
        layout = GroupLayout(self.getContentPane())
        self.getContentPane().setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                .addGroup(layout.createSequentialGroup()
                          .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                    .addGroup(layout.createSequentialGroup()
                                              .addContainerGap()
                                              .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                        .addGroup(layout.createSequentialGroup()
                                                                  .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                                                            .addComponent(self.labelHost)
                                                                            .addComponent(self.labelName))
                                                                  .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                                  .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
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

    def display(self, parent):
        """packs and shows the frame."""
        self.pack()
        # setlocation must be AFTER pack
        # source: https://stackoverflow.com/a/22615038
        self.setLocationRelativeTo(parent)
        # self.show()
        self.setVisible(True)
