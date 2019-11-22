# Update the panel with selected row's data.

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

from burp import IBurpExtender
# needed for tab
from burp import ITab, IContextMenuFactory
from Issue import Issue
from RequestResponse import RequestResponse
from java.awt.event import ActionListener

class ContextMenuListener(ActionListener):
    """ActionListener for the Burp context menu."""
    def __init__(self, invocation):
        self.invocation = invocation

    def actionPerformed(self, event):
        """Invoked when the context menu item is selected."""
        from MainPanel import burpPanel
        burpPanel.newIssueFromBurp(self.invocation)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    # implement IBurpExtender

    # set everything up
    def registerExtenderCallbacks(self, callbacks):

        # get helpers - not needed here.
        self.callbacks = callbacks

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass

        # set our extension name
        callbacks.setExtensionName("Bug Diaries")

        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)
        # register the context menu
        callbacks.registerContextMenuFactory(self)

    # implement ITab
    # https://portswigger.net/burp/extender/api/burp/ITab.html
    # two methods must be implemented.

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "Bug Diaries"

    def getUiComponent(self):
        """Burp uses this method to obtain the component that should be used as
        the contents of the custom tab when it is displayed.
        Returns a awt.Component.
        """
        # GUI happens here
        # setting up the table
        # initial data in the table
        tableData = [
            # [3, "Issue3", "Severity3", "Host3", "Path3"],
            ["Issue0", "Severity0", "Host0", "Path0", "Description0",
             "Remediation0", "Request0", "Response0"],
            # [2, "Issue2", "Severity2", "Host2", "Path2"],
        ]
        from IssueTable import IssueTable
        issues = list()
        for it in tableData:
            tmpIssue = Issue(name=it[0], severity=it[1],host=it[2],
                path=it[3], description=it[4], remediation=it[5],
                reqResp=RequestResponse(request=it[6], response=it[7]))
            issues.append(tmpIssue)

        table = IssueTable(issues)
        import MainPanel
        MainPanel.burpPanel = MainPanel.MainPanel(self.callbacks, table)
        return MainPanel.burpPanel.panel
    
    # implement IContextMenuFactory
    # https://portswigger.net/burp/extender/api/burp/IContextMenuFactory.html
    def createMenuItems(self, invocation):
        """Called when a context menu is invoked in Burp."""
        from javax.swing import JMenuItem
        customMenuItem = JMenuItem("Create Custom Issue")
        contextMenuListener = ContextMenuListener(invocation)
        customMenuItem.addActionListener(contextMenuListener)

        from java.util import ArrayList
        menuArray = ArrayList()
        menuArray.add(customMenuItem)

        return menuArray

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass
