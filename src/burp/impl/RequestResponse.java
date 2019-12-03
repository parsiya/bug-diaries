package burp.impl;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * RequestResponse implements Burp's IHttpRequestResponse interface.
 * https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
 */
public class RequestResponse implements IHttpRequestResponse {

    // Variables
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private HttpService service; // Should we change this to IHttpService?

    /**
     * Creates a {@link RequestResponse} from an {@link IHttpRequestResponse}.
     * @param reqResp 
     */
    public RequestResponse(IHttpRequestResponse reqResp) {
        this.request = reqResp.getRequest();
        this.response = reqResp.getResponse();
        this.comment = reqResp.getComment();
        this.highlight = reqResp.getHighlight();
        this.service = new HttpService(reqResp.getHttpService());
    }

    // Create a builder pattern constructor for RequestResponse.

    public static class Builder {
        // Required parameters
        private final byte[] request;
        private final byte[] response;
        private final HttpService service;
        // Optional parameters
        private String comment = "";
        private String highlight = "";

        public Builder(byte[] req, byte[] resp, HttpService srv) {
            request = req;
            response = resp;
            service = srv;
        }

        public Builder comment(String cmt) {
            comment = cmt;
            return this;
        }

        public Builder highlight(String hlt) {
            highlight = hlt;
            return this;
        }

        public RequestResponse build() {
            return new RequestResponse(this);
        }
    }

    /**
     * Constructor used in the builder.
     */
    private RequestResponse(Builder builder) {
        request = builder.request;
        response = builder.response;
        service = builder.service;
        comment = builder.comment;
        highlight = builder.highlight;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String cmt) {
        comment = cmt;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        highlight = color;
    }

    @Override
    public HttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        service = new HttpService(httpService);
    }

}