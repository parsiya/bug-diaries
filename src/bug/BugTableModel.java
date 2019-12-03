package bug;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

import burp.MainDiary;

/**
 * Represents the extension's custom bug table. Extends the AbstractTableModel
 * to make it readonly.
 */
public class BugTableModel extends AbstractTableModel{

    // Fields
    private String[] columnNames;
    private Class[] columnClasses;
    private ArrayList<Bug> bugs;

    /**
     * Creates a new BugTable.
     */
    public BugTableModel() {
        initTableModel();       
    }

    /**
     * Creates and populates a new BugTable.
     * @param bugs ArrayList of Bugs that will populate the model.
     */
    public BugTableModel(ArrayList<Bug> bugs) {
        initTableModel();
        populate(bugs);
    }

    /**
     * Initializes a new BugTable.
     */
    private void initTableModel() {
        // Set columns.
        columnNames = MainDiary.columnStrings;
        columnClasses = MainDiary.classes;
        // Create the underlying Bug list.
        bugs = new ArrayList<Bug>();
    }

    // Implementing AbstractTableModel.

    @Override
    public int getColumnCount() {
        // Returns the number of columns in the tablemodel.
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        // Returns the number of rows in the tablemodel.
        return bugs.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        // Returns the value at the specified row and column.
        Bug selected = bugs.get(rowIndex);
        switch (columnIndex) {
            // No need for break; here because we are returning.
            case 0:
                return selected.name;
            case 1:
                return selected.severity;
            case 2:
                return selected.host;
            case 3:
                return selected.path;
        }
        // Golang error handling lol.
        String err = String.format("invalid column index %d", columnIndex);
        return err;
    }

    // AbstractTableModel implemented.

    @Override
    public String getColumnName(int column) {
        // Returns the column name.
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // Returns the column class.
        return columnClasses[columnIndex];
    }

    // Seems like the AbstractTableModel returns false by default, in that case
    // this is not needed.
    // @Override
    // public boolean isCellEditable(int rowIndex, int columnIndex) {
    //     // Returns true if the cell is editable.
    //     // BugTable is readonly so this function returns false.
    //     return false;
    // }

    /**
     * Returns true if an index is invalid.
     * @param index The index that is checked for validity.
     * @return true if the index is invalid and false if valid.
     */
    private boolean invalidIndex(int index) {
        return ((index < 0) || (index >= getRowCount()));
    }

    /**
     * Returns the {@link Bug} at index.
     * @param index The index of the target bug.
     * @return {@link Bug} at index.
     * @exception IndexOutOfBoundsException if index is invalid.
     */
    public Bug get(int index) throws IndexOutOfBoundsException {
        if (invalidIndex(index)){
            throw new IndexOutOfBoundsException();
        }
        return bugs.get(index);
    }

    /**
     * Returns all items in the tablemodel.
     * @return An ArrayList<Bug> containing all items in the tablemodel.
     */
    public ArrayList<Bug> getAll() {
        return bugs;
    }

    /**
     * Adds bug to the tablemodel.
     * @param bug The bug to be added.
     */
    public void add(Bug bug) {
        bugs.add(bug);
        fireTableDataChanged();
    }
    
    /**
     * Deletes the bug at index.
     * @param index The index of the bug that is deleted.
     * @exception IndexOutOfBoundsException if index is invalid.
     * @throws IndexOutOfBoundsException
     */
    public void remove(int index) throws IndexOutOfBoundsException {
        if (invalidIndex(index)) {
            throw new IndexOutOfBoundsException();
        }
        bugs.remove(index);
        fireTableDataChanged();
    }

    /**
     * Replaces the item at index with bug.
     * @param index The index of the item to be replaced.
     * @param bug The replacement bug.
     * @throws IndexOutOfBoundsException
     */
    public void edit(int index, Bug bug) throws IndexOutOfBoundsException {
        if (invalidIndex(index)) {
            throw new IndexOutOfBoundsException();
        }
        bugs.set(index, bug);
        fireTableDataChanged();
    }

    /**
     * Deletes all bugs. Use wisely.
     */
    public void clear() {
        bugs.clear();
        fireTableDataChanged();
    }

    /**
     * Replaces the current items in the model with bugs.
     * Note: <b>This overwrites the current bugs in the model.</b>
     * @param newBugs New bugs to populate the model with.
     */
    public void populate(ArrayList<Bug> newBugs) {
        clear();
        bugs.addAll(newBugs);
        fireTableDataChanged();
    }

}