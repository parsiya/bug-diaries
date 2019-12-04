package bug;

import burp.impl.RequestResponse;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.MalformedURLException;
import java.net.URL;

import com.google.gson.Gson;

/**
 * Each Bug represents one finding.
 */
public class Bug implements IScanIssue {

    // Fields
    // Public because getters and setters suck.
    public String name;
    public String severity;
    public String host;
    public String path;
    public String description; // issueDetail in IScanIssue
    public String remediation; // remediationDetail in IScanIssue
    public RequestResponse requestResponse;
    public String confidence;
    public String issueBackground = "";
    public String remediationBackground = "";
    // See at the bottom of the list "Extension generated issue"
    public int issueType = 0x08000000;

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
        private RequestResponse requestResponse = null;
        private String confidence ="";
        private String issueBackground = "";
        private String remediationBackground = "";

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

        public Builder confidence(String val) {
            confidence = val;
            return this;
        }

        public Builder issueBackground(String val) {
            issueBackground = val;
            return this;
        }

        public Builder remediationBackground(String val) {
            remediationBackground = val;
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
        confidence = builder.confidence;
        issueBackground = builder.issueBackground;
        remediationBackground = builder.remediationBackground;
    }
    // Now we can do
    // Bug myBug = new Bug.Builder("bugname").host("host").path("path")
    // .severity("severity").description("description")
    // .remediation("remediation").issueBackground("issuebackground")
    // .remediationBackground("remediationbackground")
    // .build();

    /**
     * Creates an empty {@link Bug}.
     */
    public Bug() {
    }

    /**
     * Returns the request of the Bug.
     * 
     * @return byte[] containing the Bug's request.
     */
    public byte[] getRequest() {
        return requestResponse.getRequest();
    }

    /**
     * Sets the Bug's request.
     * 
     * @param request byte[] containing the request.
     */
    public void setRequest(byte[] request) {
        requestResponse.setRequest(request);
    }

    /**
     * Returns the response of the Bug.
     * 
     * @return byte[] containing the Bug's response.
     */
    public byte[] getResponse() {
        return requestResponse.getResponse();
    }

    /**
     * Sets the Bug's response.
     * 
     * @param response byte[] cotaining the response.
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

    @Override
    public URL getUrl() {
        try {
            return requestResponse.getHttpService().getURL();
        } catch (MalformedURLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        // TODO: This will be bad later.
        return null;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return description;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new RequestResponse[] { requestResponse };
    }

    @Override
    public IHttpService getHttpService() {
        return requestResponse.getHttpService();
    }
}
