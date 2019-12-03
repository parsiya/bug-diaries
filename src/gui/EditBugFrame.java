package gui;

import java.awt.Component;
import java.awt.event.ActionEvent;

import bug.Bug;
import burp.MainDiary;

public class EditBugFrame extends BugFrame {

    // This is used to store the index.
    private int selectedIndex;

    public EditBugFrame() {
        customizeFrame();
    }

    /**
     * Creates a new fram to edit the bug.
     * @param parentFrame Parent frame that has invoked this dialog.
     * @param title
     * @param bug
     * @param selectedRow
     */
    public EditBugFrame(Component parentFrame, String title, Bug bug) {
        super(parentFrame, title, bug);
        customizeFrame();
    }

    /**
     * Customize the inherited class
     */
    private void customizeFrame() {
        // Hide the template stuff.
        labelTemplate.setVisible(false);
        comboTemplate.setVisible(false);
        // pack() happens in display() so no need to do it here.
        // Otherwise we have to because we have hidden some GUI components.

        // If we If we access the selectedIndex when "Save" is pressed, we might
        // have an issue if another row has been selected after the frame has
        // been spawned and before "Save" is clicked.
        selectedIndex = MainDiary.table.getTableSelectedRow();
    }

    @Override
    protected void saveAction(ActionEvent event) {
        // Action to perform when saveButton is clicked.
        // Object eventSource = event.getSource(); // source is the JButton object.
        // TODO: Update theBug.requestResponse here.
        Bug theBug = getBug();

        // We already have the selected index when the frame was spawned.
        MainDiary.table.editBug(selectedIndex, theBug);
        frm.setVisible(false);
    }
    
}