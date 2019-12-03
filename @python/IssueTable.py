# Represents a custom Issue table.

from javax.swing import JTable
from javax.swing.table import AbstractTableModel
from java.awt.event import MouseListener

from Issue import Issue
import java.lang
import json


class IssueTableModel(AbstractTableModel):
    """Represents the extension's custom issue table. Extends the
    AbstractTableModel to make it readonly."""
    # column names
    columnNames = ["Issue Type/Name", "Severity", "Host", "Path"]
    # column classes

    columnClasses = [java.lang.String, java.lang.String, java.lang.String,
                     java.lang.String]

    issueList = list()

    def __init__(self, initialIssues=None):
        """Create an issue table model and populate it (if applicable)."""
        if initialIssues is not None:
            self.issues = initialIssues
        else:
            # list to hold all the issues
            # if this does not work use an ArrayList
            # from java.util import ArrayList
            # issues = ArrayList() - issues.add(whatever)
            self.issues = list()

    def getColumnCount(self):
        # type: () -> int
        """Returns the number of columns in the table model."""
        return len(self.columnNames)

    def getRowCount(self):
        # type: () -> int
        """Returns the number of rows in the table model."""
        return len(self.issues)

    def getValueAt(self, row, column):
        # type: (int, int) -> object
        """Returns the value at the specified row and column."""
        if row < self.getRowCount() and column < self.getColumnCount():
            # is this going to come back and bite us in the back because we
            # are ignoring the hidden fields?
            issue = self.issues[row]
            # print "inside getValueAt - " + "row: " + str(row) + " - column: " + str(column)
            assert isinstance(issue, Issue)
            if column == 0:
                return issue.name
            if column == 1:
                return issue.severity
            if column == 2:
                return issue.host
            if column == 3:
                return issue.path
            return None

    # interface implemented, adding utility methods

    def getColumnName(self, index):
        # type: (int) -> str
        """Returns the name of the table column."""
        if 0 <= index < self.getColumnCount():
            return self.columnNames[index]
        else:
            return "Invalid Column Index: " + str(index)

    def getColumnClass(self, index):
        # type: (int) -> object
        """Returns the class of the table column."""
        if 0 <= index < len(self.columnClasses):
            return self.columnClasses[index]
        return java.lang.Object

    def isCellEditable(self, row, column):
        # type: (int, int) -> bool
        """Returns True if cells are editable."""
        # make all rows and columns uneditable.
        return False

    def getIssue(self, index):
        # type: (int) -> Issue
        """Returns the issue object at index."""
        if 0 <= index < len(self.issues):
            return self.issues[index]
        # this is going to come and bite me in the back, isn't it?
        return self.issues[0]

    # # is this needed for a readonly table?
    # def setValueAt(self, value, row, column):
    #     # type: (object, int, int) -> ()
    #     """Sets the table cell at [row, count]."""
    #     if row < self.getRowCount() and column < self.getColumnCount():
    #         # is this going to come back and bite us in the back because we
    #         # are ignoring the hidden fields?
    #         issue = self.issues[row]
    #         # assert isinstance(issue, Issue)
    #         if column == 0:
    #             issue.index = value
    #         if column == 1:
    #             issue.name = value
    #         if column == 2:
    #             issue.severity = value
    #         if column == 3:
    #             issue.host = value
    #         if column == 4:
    #             issue.path = value
    #         # otherwise do nothing

    def addIssue(self, issue):
        # type: (Issue) -> ()
        """Adds the issue to the list of issues."""
        # is issue is None == we have clicked "cancel" on the form
        if issue is None:
            return
        self.issues.append(issue)
        # alert the table that something has changed.
        # this is not ideal because we can just tell the table that some row
        # have changed but this works for now.
        self.fireTableDataChanged()

    def deleteIssue(self, index):
        # type: (int) -> ()
        """Removes the issue at index from the list of issues."""
        if 0 <= index < len(self.issues):
            del self.issues[index]
            self.fireTableDataChanged()
        else:
            print "deleteIssue called with invalid index: " + str(index)
        # otherwise do nothing.
    
    def editIssue(self, index, issue):
        # type: (int, Issue) -> ()
        """Edits the issue at index with issue."""
        if issue is not None:
            if 0 <= index < len(self.issues):
                self.issues[index] = issue
                self.fireTableDataChanged()
            else:
                print "editIssue called with invalid index: " + str(index)
        else:
            print "editIssue called with None issue"

    def issuesToJSON(self):
        # type: () -> (str)
        """Returns a JSON array of all issues."""
        from RequestResponse import ComplexEncoder
        # for iss in self.issues:
        return json.dumps([iss.customJSON() for iss in self.issues],
                               cls=ComplexEncoder, indent=2)
        # return json.dumps([iss.__dict__ for iss in self.issues], indent=2)
    
    def clear(self):
        # type: () -> ()
        """Clears the table model."""
        # list.clear() was introduced in Python 3.3, not available here.
        # self.issues.clear()
        self.issues = list()
        self.fireTableDataChanged()
        
    def populate(self, issues):
        # type (list(Issue)) -> ()
        """Populates self.issues with issues and erases existing data."""
        self.issues = issues
        self.fireTableDataChanged()

class IssueTableMouseListener(MouseListener):
    """Custom mouse listener to differentiate between single and double-clicks.
    """
    def getClickedRow(self, event):
        """Returns the clicked row."""
        tbl = event.getSource()
        mdl = tbl.getModel()
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        assert isinstance(mdl, IssueTableModel)
        return mdl.getIssue(row)

    def mousePressed(self, event):
        # print "mouse pressed", event.getClickCount()
        pass

    def mouseReleased(self, event):
        # print "mouse released", event.getClickCount()
        pass

    # event.getClickCount() returns the number of clicks.
    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            rowData = self.getClickedRow(event)
            assert isinstance(rowData, Issue)

            # let's see if we can modify the panel
            # import burpPanel to modify it
            from MainPanel import burpPanel, MainPanel
            assert isinstance(burpPanel, MainPanel)
            if rowData is not None:
                burpPanel.loadPanel(rowData)

        if event.getClickCount() == 2:
            # open the dialog to edit
            # print "double-click"
            tbl = event.getSource()
            currentIssue = self.getClickedRow(event)
            from EditIssueDialog import EditIssueDialog
            from MainPanel import burpPanel
            # add a new attribute to currentIssue to hold the index
            currentIssue.index = tbl.getTableSelectedRow()
            frm = EditIssueDialog(burpPanel.callbacks,
                             title="Edit " + currentIssue.name,
                             issue=currentIssue)
            frm.display(burpPanel)

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class IssueTable(JTable):
    """Issue table."""

    def __init__(self, issues=None):
        # set the table model
        model = IssueTableModel(issues)
        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        # disable the reordering of columns
        self.getTableHeader().setReorderingAllowed(False)
        # assign panel to a field
        self.addMouseListener(IssueTableMouseListener())
        self.model = self.getModel()

    def addRow(self, issue):
        """Add a new row to the tablemodel."""
        self.model.addIssue(issue)

    # solution to resize column width automagically
    # https://stackoverflow.com/a/17627497

    def getTableSelectedRow(self):
        # type: () -> (int)
        """Get the currently selected row.
        getSelectedRow() and selectedRow are already defined in JTable so I had
        to make one to adjust for the view sorting etc."""
        row = self.convertRowIndexToModel(self.getSelectedRow())
        return row

    def deleteRow(self, index):
        from MainPanel import burpPanel
        # type: (int) -> ()
        """Deletes the row at index."""
        if index is not None:
            self.model.deleteIssue(index)
        # if table is not empty, select the last row
        lastRow = self.model.getRowCount() - 1
        if lastRow >= 0:
            # select the last row
            self.setRowSelectionInterval(lastRow, lastRow)
            # update the panel
            burpPanel.loadPanel(self.model.getIssue(lastRow))
        else:
            # table is now empty
            # update the panel with the default text
            burpPanel.loadPanel(burpPanel.defaultIssue)
    
    def editRow(self, index, issue):
        """Edits the row at index."""
        self.model.editIssue(index, issue)
    
    def exportIssues(self):
        # type: () -> (str)
        """Returns a JSON array of all issues."""
        return self.model.issuesToJSON()
    
    def clear(self):
        # type: () -> ()
        """Clears the table and removes all issues."""
        self.model.clear()
    
    def populate(self, issues):
        # type: (list(Issue)) -> ()
        """Populates in the table with the issues and removes existing data."""
        self.model.populate(issues)
