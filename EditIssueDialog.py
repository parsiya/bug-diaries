# Frame to edit an issue.

from java.awt.event import ComponentListener
from Issue import Issue
from BugDialog import BugDialog


class EditIssueDialog(BugDialog):
    """Represents the dialog used to edit an issue."""

    def saveButtonAction(self, event):
        """Save the edited issue."""
        ist = Issue(name=self.textName.text, host=self.textHost.text,
                    path=self.textPath.text,
                    description=self.textAreaDescription.text,
                    remediation=self.textAreaRemediation.text,
                    severity=str(self.comboSeverity.getSelectedItem()),
                    request=self.panelRequest.getMessage(),
                    response=self.panelResponse.getMessage())
        self.issue = ist
        # pass the index
        self.issue.index = self.index
        self.setVisible(False)
    
    def componentHidden(self, event):
        """Invoked when the dialog is hidden."""
        issue = self.issue
        # get the index
        index = issue.index
        # delete the index attribute
        delattr(issue, 'index')
        # replace the old issue with the new one
        self.dlgParent.editIssue(index, issue)
    
    def __init__(self, callbacks, issue, title="", modality=""):
        """Constructor to populate the dialog with the selected issue."""
        # pass the index
        # let's see if it's needed later.
        self.index = issue.index
        # pass the issue from the constructor.
        BugDialog.__init__(self, callbacks, issue, title, modality)
        # add the save button action
        self.buttonSave.actionPerformed = self.saveButtonAction
        # override the componentHidden method of ComponentListener
        self.componentListeners[0].componentHidden = self.componentHidden

        # hide the reset button.
        self.buttonReset.setVisible(False)

        print "self.issue.reqResp: "
        print self.issue.reqResp
