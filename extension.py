# Update the panel with selected row's data.

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

from burp import IBurpExtender
# needed for tab
from burp import ITab


class BurpExtender(IBurpExtender, ITab):
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
        callbacks.setExtensionName("08-BugDiaries")

        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)

    # implement ITab
    # https://portswigger.net/burp/extender/api/burp/ITab.html
    # two methods must be implemented.

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "08-BugDiaries"

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
        from Issue import Issue
        issues = list()
        for it in tableData:
            tmpIssue = Issue(name=it[0], severity=it[1],host=it[2],
                             path=it[3], description=it[4], remediation=it[5],
                             request=it[6], response=it[7])
            issues.append(tmpIssue)

        table = IssueTable(issues)
        import MainPanel
        MainPanel.burpPanel = MainPanel.MainPanel(self.callbacks, table)
        # from EditFrame import EditFrame
        # edf = EditFrame(self.callbacks)
        # edf.display()
        # return edf

        return MainPanel.burpPanel.panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass