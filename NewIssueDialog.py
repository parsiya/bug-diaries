# Frame to create a new issue.

from Issue import Issue

from BugDialog import BugDialog
class NewIssueDialog(BugDialog):
    """Represents the dialog used to create a new issue."""

    def saveButtonAction(self, event):
        """Save the new issue."""
        ist = Issue(name=self.textName.text, host=self.textHost.text,
                    path=self.textPath.text,
                    description=self.textAreaDescription.text,
                    remediation=self.textAreaRemediation.text,
                    severity=str(self.comboSeverity.getSelectedItem()),
                    request=self.panelRequest.getMessage(),
                    response=self.panelResponse.getMessage())
        self.issue = ist
        self.setVisible(False)
    
    def componentHidden(self, event):
        """Invoked when the dialog is hidden."""
        issue = self.issue
        self.dlgParent.gotNewIssue(issue)
    
    def __init__(self, callbacks, title="", modality=""):
        """Constructor to populate the dialog with the new issue."""
        # call the BugDialog constructor.
        BugDialog.__init__(self, callbacks, title, modality)

        # set the save button action
        self.buttonSave.actionPerformed = self.saveButtonAction

        # override the componentHidden method of ComponentListener
        self.componentListeners[0].componentHidden = self.componentHidden
