package bug;

import burp.impl.RequestResponse;

import com.google.gson.Gson;

/**
 * Each Bug represents one finding.
 */
public class Bug {

    // Fields
    // Public because getters and setters suck.
    public String name;
    public String severity;
    public String host;
    public String path;
    public String description;
    public String remediation;
    public RequestResponse requestResponse;

    /**
     * Builder pattern for Bug
     */
    public static class Builder {
        // Required parameters
        private final String name;
        // Optional parameters
        private String severity = "";
        private String host = "";
        private String path = "";
        private String description = "";
        private String remediation = "";
        // private IHttpRequestResponse requestResponse = null;
        private RequestResponse requestResponse = null;

        public Builder(String val) {
            name = val;
        }

        public Builder severity(String val) {
            severity = val;
            return this;
        }

        public Builder host(String val) {
            host = val;
            return this;
        }

        public Builder path(String val) {
            path = val;
            return this;
        }

        public Builder description(String val) {
            description = val;
            return this;
        }

        public Builder remediation(String val) {
            remediation = val;
            return this;
        }

        public Builder requestResponse(RequestResponse val) {
            requestResponse = val;
            return this;
        }

        public Bug build() {
            return new Bug(this);
        }
    }

    /**
     * Constructor used in the builder.
     */
    private Bug(Builder builder) {
        name = builder.name;
        severity = builder.severity;
        host = builder.host;
        path = builder.path;
        description = builder.description;
        remediation = builder.remediation;
        requestResponse = builder.requestResponse;
    }
    // Now we can do
    // Bug myBug = new Bug.Builder("bugname").host("host").path("path")
    //             .severity("severity").description("description")
    //             .remediation("remediation").build();

    /**
     * Creates an empty {@link Bug}.
     */
    public Bug() {}

    /**
     * Returns the request of the Bug.
     * @return byte[] containing the Bug's request.
     */
    public byte[] getRequest() {
        return requestResponse.getRequest();
    }

    /**
     * Sets the Bug's request.
     * @param request byte[] containing the request.
     */
    public void setRequest(byte[] request) {
        requestResponse.setRequest(request);
    }
    
    /**
     * Returns the response of the Bug.
     * @return byte[] containing the Bug's response.
     */
    public byte[] getResponse() {
        return requestResponse.getResponse();
    }

    /**
     * Sets the Bug's response.
     * @param response byte[] containing the response.
     */
    public void setResponse(byte[] response) {
        requestResponse.setResponse(response);
    }

    /**
     * Returns the bug as a JSON string.
     */
    public String toString() {
        return new Gson().toJson(this);
    }
}
