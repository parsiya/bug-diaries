# Frame to create a new issue.

from Issue import Issue
from RequestResponse import RequestResponse
from BugDialog import BugDialog


from java.awt.event import ActionListener
class ComboListener(ActionListener):
    """ActionListener for the template combobox."""
    def __init__(self, parent):
        self.myParent = parent

    def actionPerformed(self, event):
        """Invoked when the selection on the template combobox is changed."""
        src = event.getSource()
        selected = src.getSelectedItem()
        self.myParent.loadTemplateIntoPanel(selected)

class NewIssueDialog(BugDialog):
    """Represents the dialog used to create a new issue."""

    def saveButtonAction(self, event):
        """Save the new issue."""
        tmpReqResp = RequestResponse(
            request=self.panelRequest.getMessage(),
            response=self.panelResponse.getMessage()
        )
        ist = Issue(name=self.textName.text, host=self.textHost.text,
                    path=self.textPath.text,
                    description=self.textAreaDescription.text,
                    remediation=self.textAreaRemediation.text,
                    severity=str(self.comboSeverity.getSelectedItem()),
                    reqResp=tmpReqResp)
        self.issue = ist
        self.setVisible(False)
    
    def componentHidden(self, event):
        """Invoked when the dialog is hidden."""
        # this is also triggered when the window is closed by clicking on [X]
        # how can we detect how the window was closed?
        issue = self.issue
        self.dlgParent.gotNewIssue(issue)
   
    def __init__(self, callbacks, issue=None, title="", modality=""):
        """Constructor to populate the dialog with the new issue."""
        # call the BugDialog constructor.
        if issue is not None:
            BugDialog.__init__(self, callbacks=callbacks, issue=issue,
                title=title, modality=modality)
        else:
            BugDialog.__init__(self, callbacks=callbacks, title=title,
                modality=modality)

        # set the save button action
        self.buttonSave.actionPerformed = self.saveButtonAction

        # override the componentHidden method of ComponentListener
        self.componentListeners[0].componentHidden = self.componentHidden

        # populate the template combobox
        self.loadTemplate()
        # set the actionPerformed
        listener = ComboListener(self)
        self.comboTemplate.addActionListener(listener)
        # enable the template label and combobox
        self.labelTemplate.setVisible(True)
        self.comboTemplate.setVisible(True)

        # add reqResp
        # self.reqResp = issue.reqResp
