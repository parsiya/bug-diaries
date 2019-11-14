# Frame to edit issues.

from javax.swing import (JPanel, JLabel, JTextField, JTabbedPane, JPanel,
                         JTextField, JButton, JSplitPane, BorderFactory,
                         GroupLayout, JTextArea, JComboBox, LayoutStyle,
                         JFrame, WindowConstants)
from java.lang import Short

from burp import IBurpExtenderCallbacks


class EditFrame(JFrame):
    """Represents the frame used to edit issues or add new ones."""
    def __init__(self, callbacks, issue=None):
        """Constructor to populate a frame with the new issue."""

        assert isinstance(callbacks, IBurpExtenderCallbacks)

        # starting converted code from NetBeans
        self.buttonSave = JButton("Save")
        self.buttonCancel = JButton("Cancel")
        self.labelPath = JLabel("Path")
        self.labelSeverity = JLabel("Severity")
        self.tabIssue = JTabbedPane()
        self.textAreaDescription = JPanel()
        self.textAreaRemediation = JPanel()
        self.panelRequest = callbacks.createMessageEditor(None, False)
        self.panelResponse = callbacks.createMessageEditor(None, False)
        self.textName = JTextField("Issue Type/Name")
        self.textHost = JTextField("Issue Host")
        self.textPath = JTextField("Issue Path")
        self.labelHost = JLabel("Host")
        self.labelName = JLabel("Issue Type/Name")
        self.buttonReset = JButton()

        # if this is enabled, closing the jframe will close Burp
        # self.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE)

        # self.buttonSave.addActionListener(new java.awt.event.ActionListener() {
        #     public void actionPerformed(java.awt.event.ActionEvent evt) {
        #     buttonSaveActionPerformed(evt)
        # }
        # })


        # description textarea
        textAreaDescriptionLayout = GroupLayout(self.textAreaDescription)
        self.textAreaDescription.setLayout(textAreaDescriptionLayout)
        # is this needed?
        textAreaDescriptionLayout.setHorizontalGroup(
            textAreaDescriptionLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 951, Short.MAX_VALUE)
        )
        textAreaDescriptionLayout.setVerticalGroup(
            textAreaDescriptionLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 441, Short.MAX_VALUE)
        )
        self.tabIssue.addTab("Description", self.textAreaDescription)

        textAreaRemediationLayout = GroupLayout(self.textAreaRemediation)
        self.textAreaRemediation.setLayout(textAreaRemediationLayout)
        # is this needed?
        textAreaRemediationLayout.setHorizontalGroup(
            textAreaRemediationLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 951, Short.MAX_VALUE)
        )
        textAreaRemediationLayout.setVerticalGroup(
            textAreaRemediationLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 441, Short.MAX_VALUE)
        )
        self.tabIssue.addTab("Remediation", self.textAreaRemediation)

        # self.textName.addActionListener(new java.awt.event.ActionListener() {
        #     public void actionPerformed(java.awt.event.ActionEvent evt) {
        #     textNameActionPerformed(evt)
        # }
        # })

        # request and response tabs
        # request tab
        self.panelRequest.setMessage("", True)
        self.tabIssue.addTab("Request", self.panelRequest.getComponent())

        # response tab
        self.panelResponse.setMessage("", False)
        self.tabIssue.addTab("Response", self.panelResponse.getComponent())
        
        self.buttonReset.setText("Reset")
        # buttonReset.addActionListener(new java.awt.event.ActionListener() {
        #     public void actionPerformed(java.awt.event.ActionEvent evt) {
        #     buttonResetActionPerformed(evt)
        # }
        # })

        self.comboSeverity = JComboBox(["Critical", "High", "Medium", "Low",
                                        "Info"])

        layout = GroupLayout(self.getContentPane())
        self.getContentPane().setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                          .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
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
                                              .addGap(280, 280, 280)
                                              .addComponent(self.buttonSave, GroupLayout.PREFERRED_SIZE, 128, GroupLayout.PREFERRED_SIZE)
                                              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                              .addComponent(self.buttonReset, GroupLayout.PREFERRED_SIZE, 128, GroupLayout.PREFERRED_SIZE)
                                              .addGap(13, 13, 13)
                                              .addComponent(self.buttonCancel, GroupLayout.PREFERRED_SIZE, 128, GroupLayout.PREFERRED_SIZE)
                                              .addGap(0, 0, Short.MAX_VALUE)))
                          .addContainerGap())
        )

        # link size of buttons
        from javax.swing import SwingConstants
        layout.linkSize(SwingConstants.HORIZONTAL, [self.buttonCancel, self.buttonSave, self.buttonReset])

        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
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
                          .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                              .addComponent(self.buttonCancel)
                                              .addComponent(self.buttonSave)
                                              .addComponent(self.buttonReset)))
                          .addContainerGap())
        )
        # end of converted code from NetBeans

    def display(self):
        """packs and shows the frame."""
        self.pack()
        self.show()