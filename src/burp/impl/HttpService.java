// Implementing burp's IHttpService interface.

package burp.impl;

import java.net.MalformedURLException;
import java.net.URL;

import burp.IHttpService;

/**
 * Implementing https://portswigger.net/burp/extender/api/burp/IHttpService.html
 */
public class HttpService implements IHttpService {

    // Protocol constants
    public static final String HTTP_PROTOCOL = "http";
    public static final String HTTPS_PROTOCOL = "https";

    // Variables
    private String host;
    private int port;
    private String protocol;

    /**
     * Creates a new HttpService object from host, port and protocol.
     * 
     * @param host     Service's host as a String.
     * @param port     Service's port as an int.
     * @param protocol Service's protocol. "http" and "https" are supported.
     */
    public HttpService(String host, int port, String protocol) {
        this.host = host;
        this.port = port;
        this.protocol = protocol;
    }

    /**
     * Converts a Burp's HttpService object to our implementation.
     * 
     * @param service HttpService object to be converted.
     */
    public HttpService(IHttpService service) {
        host = service.getHost();
        port = service.getPort();
        protocol = service.getProtocol();
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    /**
     * Stringer for HttpService.
     * @return A String containing a somewhat correct URL.
     */
    public String toString() {
        
        return String.format("%s://%s:%d", getProtocol(), getHost(), getPort());
    }

    /**
     * Gets a java.net.URL object from the HttpService.
     * This should work if it's populated.
     */
    public URL getURL() throws MalformedURLException {
        return new URL(toString());
    }
}