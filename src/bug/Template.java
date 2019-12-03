package bug;

/**
 * Template represents a template item. A template can be added to a
 * {@link Bug}.
 */
public class Template {

    private String name, description, remediation;

    public Template() {}

    public Template(String name, String description, String remediation) {
        this.name = name;
        this.description = description;
        this.remediation = remediation;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRemediation() {
        return remediation;
    }

    public void setRemediation(String remediation) {
        this.remediation = remediation;
    }

    /**
     * toString() is used to display the object in the combobox.
     */
    public String toString() {
        return name;
    }
}