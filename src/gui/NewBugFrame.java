package gui;

import java.util.ArrayList;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;

import javax.swing.DefaultComboBoxModel;

// Needed for Gson.
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;

import bug.Bug;
import bug.Template;

import burp.MainDiary;
import static burp.MainDiary.print;

import burp.impl.HttpService;
import burp.impl.RequestResponse;

/**
 * NewBugFrame is the frame to add a new bug
 */
public class NewBugFrame extends BugFrame {

    /**
     * Creates a frame to add a new bug
     */
    public NewBugFrame() {
        customizeFrame();
    }

    /**
     * Creates a frame to add a new bug
     * 
     * @param parentFrame The parent component
     * @param title       The frame's title
     */
    public NewBugFrame(Component parentFrame, String title) {
        super(parentFrame, title);
        customizeFrame();
    }

    /**
     * Creates a frame to add a new bug with some fields populated. Mostly this will
     * be used to add a bug via the context menu.
     * 
     * @param parentFrame The parent component
     * @param title       The Frame's title
     * @param bug         The bug to be loaded into the frame
     */
    public NewBugFrame(Component parentFrame, String title, Bug bug) {
        super(parentFrame, title, bug);
        customizeFrame();
    }

    /**
     * Customize the inherited class
     */
    private void customizeFrame() {
        populateTemplate();
        // Select the current text in text fields, so we can just tab between
        // them and enter new text without having to clear the current text.
        textName.setSelectionStart(0);
        textHost.setSelectionStart(0);
        textPath.setSelectionStart(0);
        textAreaDescription.setSelectionStart(0);
        textAreaRemediation.setSelectionStart(0);
    }

    /**
     * Get the current {@link Bug} from the frame.
     * 
     * @return The Bug currently displayed in the frame.
     */
    @Override
    protected Bug getBug() {
        // If we are creating a new bug without using the contextmenu, the
        // currentBug.requestReponse is null.
        HttpService srv;
        if (currentBug.requestResponse == null) {
            // New bug without using the context menu.
            // Try and create an HttpService from the URL in the Host field.
            srv = MainDiary.salvageURL(textHost.getText().toLowerCase());
        } else {
            srv = currentBug.requestResponse.getHttpService();
        }

        // Create a RequestResponse object from the service and the data in the
        // request and response IMessageEditors.
        RequestResponse reqResp = new RequestResponse.Builder(panelRequest.getMessage(), panelResponse.getMessage(),
                srv).build();
        // Create and return the current bug.
        Bug selectedBug = new Bug.Builder(textName.getText()).severity(comboSeverity.getSelectedItem().toString())
                .host(textHost.getText()).path(textPath.getText()).description(textAreaDescription.getText())
                .remediation(textAreaRemediation.getText()).requestResponse(reqResp).build();
        return selectedBug;
    }

    @Override
    protected void saveAction(ActionEvent event) {
        // Action to perform when saveButton is clicked.
        // MainDiary.printOutput("Inside NewBugFrame saveAction");
        // Object eventSource = event.getSource(); // source == JButton.
        // print(eventSource.toString());
        // print(event.getActionCommand()); --> "Save"
        // print(event.paramString()); -->
        // "ACTION_PERFORMED,cmd=Save,when=1574981399452,modifiers=Button1"
        Bug theBug = getBug();
        print("Adding the following bug");
        print(theBug.toString());
        MainDiary.table.addBug(theBug);
        frm.setVisible(false);
    }

    /**
     * Populate the template combobox
     */
    private void populateTemplate() {

        String cwe = "";
        try {
            cwe = MainDiary.getResourceFile("/cwe-1200.json");
        } catch (Exception e) {
            MainDiary.printStackTraceString(e);
        }
        // Convert the json string from the file into an array of Templates.
        Type listType = new TypeToken<ArrayList<Template>>() {}.getType();
        ArrayList<Template> templates = new Gson().fromJson(cwe, listType);
        // VS Code is giving us a warning here but it works for the most part.
        comboTemplate.setModel(new DefaultComboBoxModel(templates.toArray()));
        // What happens when combobox's selection changes.
        comboTemplate.addItemListener(e -> loadTemplate(e));
    }

    /**
     * What's executed when the combobox selection changes.
     * @param e ItemEvent from the combobox.
     */
    private void loadTemplate(ItemEvent e) {
        // This is fired twice, when previous item is deselected and when the
        // new item is selected. Here we check and act only on selection.
        if (e.getStateChange() == ItemEvent.SELECTED) {
            // TODO: Check for exceptions here?
            Template selectedTemplate = (Template) comboTemplate.getSelectedItem();
            textName.setText(textName.getText() + " - " + selectedTemplate.getName());
            textAreaDescription.setText(selectedTemplate.getDescription());
            textAreaRemediation.setText(selectedTemplate.getRemediation());
        }
    }
}