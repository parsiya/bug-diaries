package bug;

import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;
import javax.swing.JTable;
import javax.swing.KeyStroke;

import java.util.ArrayList;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import burp.MainDiary;
import gui.EditBugFrame;


/**
 * BugTable displays the bugs in the GUI.
 */
public class BugTable extends JTable implements MouseListener {

    // Fields
    private BugTableModel model;

    /**
     * Create a new empty BugTable.
     */
    public BugTable() {
        model = new BugTableModel();
        initTable();
    }

    /**
     * Create a new BugTable and populate it.
     * @param bugs ArrayList of Bugs that will populate the table.
     */
    public BugTable(ArrayList<Bug> bugs) {
        model = new BugTableModel(bugs);
        initTable();     
    }

    /**
     * Initialize the table.
     */
    private void initTable() {
        setAutoCreateRowSorter(true);
        setModel(model);
        // Add the class as MouseListener.
        addMouseListener(this);

        // Add keybinding for DELETE. It should delete the selected row.
        getInputMap().put(KeyStroke.getKeyStroke("DELETE"), "DeleteSelectedBug");
        getActionMap().put("DeleteSelectedBug", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                removeSelectedBug();
            }
        });
    }

    /**
     * Returns the currently selected row. Mainly to get the correct row
     * regardless of the view. Without this, clicking on the table after it's
     * been sorted returns the wrong row.
     * @return Selected row's index as int.
     */
    public int getTableSelectedRow() {
        return convertRowIndexToModel(getSelectedRow());
    }

    /**
     * Returns the Bug at index.
     * @param index The index of the Bug.
     * @return The Bug at index.
     */
    public Bug getBug(int index) {
        return model.get(index);
    }

    /**
     * Returns the currently selected Bug in the table.
     * @return Bug that is selected in the table.
     */
    public Bug getSelectedBug() {
        return getBug(getTableSelectedRow());
    }
    
    /**
     * Adds a new bug to the table. Does not check for duplicates.
     * @param bug The Bug to tbe added.
     */
    public void addBug(Bug bug) {
        model.add(bug);
    }

    /**
     * Removes the bug at index from the table.
     * @param index Index of the Bug to be removed.
     */
    public void removeBug(int index) {
        model.remove(index);
        // If the table is not empty select the last row.
        int lastRow = model.getRowCount() - 1;
        if (lastRow >= 0) {
            setRowSelectionInterval(lastRow, lastRow);
        }
    }

    /**
     * Removes the currently selected bug from the table.
     */
    public void removeSelectedBug() {
        removeBug(getTableSelectedRow());
    }

    /**
     * Replaces the Bug at index with bug.
     * @param index Index of the old bug.
     * @param bug New bug.
     */
    public void editBug(int index, Bug bug) {
        model.edit(index, bug);
    }

    /**
     * Clears the table. Use wisely.
     */
    public void clear() {
        model.clear();
    }

    /**
     * Populates the table with bugs.
     * Note: <b>This overwrites the current bugs in the table</b>.
     * @param bugs New bugs for the table.
     */
    public void populate(ArrayList<Bug> bugs) {
        model.populate(bugs);
    }

    /**
     * Returns all Bugs in the table.
     * @return An ArrayList<Bug> containing all Bugs in the table.
     */
    public ArrayList<Bug> getBugs() {
        return model.getAll();
    }

    // Implementing MouseListener.
    // This way we can add the class as its own MouseListener.
    @Override
    public void mouseClicked(MouseEvent e) {
        // Listen for mouse events here.
        Bug clickedBug = getSelectedBug();
        switch (e.getClickCount()) {
            case 1:
                // Single click.
                MainDiary.mainPanel.loadPanel(clickedBug);
                break;
            case 2:
                // Double click.
                // Create the frame title.
                String title = "Editing " + clickedBug.name;
                // Create a new EditBugFrame.
                EditBugFrame ebg = new EditBugFrame(MainDiary.mainPanel.panel,
                    title, clickedBug);
                ebg.display();
                break;
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {}

    @Override
    public void mouseReleased(MouseEvent e) {}

    @Override
    public void mouseEntered(MouseEvent e) {}

    @Override
    public void mouseExited(MouseEvent e) {}

    // Finished implementing MouseListener.
}
