# Class implementing the IHttpService interface.
# https://portswigger.net/burp/extender/api/burp/IHttpService.html

class HttpService():
    """Implements Burp's IHttpService interface."""

    def __init__(self, host="", port=0, protocol=""):
        # type: (str, int, str) -> (HttpService)
        """Initialize a new HttpService object."""
        self.host = host
        self.port = port
        self.protocol = protocol
    
    def getHost(self):
        # type: () -> (str)
        """Returns the hostname or IP address for the service."""
        return self.host
    
    def getPort(self):
        # type: () -> (int)
        """Returns the port number for the service."""
        return self.port
    
    def getProtocol(self):
        # type: () -> (str)
        """Returns the protocol for the service. Expected values are "http" or
        "https"."""
        return self.protocol
    
    def JSON(self):
        # type: () -> (str)
        """Returns the HttpService in JSON."""
        import json
        return json.dumps(self.__dict__, indent=2)
    
    def __str__(self):
        # type: () -> (str)
        """Stringer for the HttpService object."""
        return str(self.JSON())
    
    def __repr__(self):
        return self.__str__()


# Class implementing the IHttpRequestResponse interface.
# https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html

class RequestResponse():
    """Implements Burp's IHttpRequestResponse interface."""

    def __init__(self, request=None, response=None, httpService=None,
                 highlight="", comment=""):
        # type: (bytearray, bytearray, HttpService, str, str) -> (RequestResponse)
        """Initialize a new RequestResponse object."""
        self.request = request
        self.response = response
        self.httpService = httpService
        self.highlight = highlight
        self.comment = comment
    
    def getComment(self):
        # type: () -> (str)
        """Returns the user-annotated comment for this item, if applicable."""
        return self.comment
    
    def setComment(self, comment):
        # type: (str) -> ()
        """Updates the user-annotated comment for this item."""
        self.comment = comment

    def getHighlight(self):
        # type: () -> (str)
        """Returns the user-annotated highlight for this item, if applicable."""
        return self.highlight
    
    def setHighlight(self, highlight):
        # type: (str) -> ()
        """Updates the user-annotated highlight for this item."""
        self.highlight = highlight
    
    def getHttpService(self):
        # type: () -> (HttpService)
        """Returns the HTTP service for this request / response."""
        return self.httpService
    
    def setHttpService(self, httpService):
        # type: (HttpService) -> ()
        """Updates the HTTP service for this request / response."""
        self.httpService = httpService
    
    def getRequest(self):
        # type: () -> (bytearray)
        """Returns the request message."""
        return self.request
    
    def setRequest(self, request):
        # type: (bytearray) -> ()
        """Updates the request message."""
        self.request = request
    
    def getResponse(self):
        # type: () -> (bytearray)
        """Returns the response message."""
        return self.response

    def setResponse(self, response):
        # type: (bytearray) -> ()
        """Updates the response message."""
        self.response = response
    
    def JSON(self):
        # type: () -> (str)
        """Returns the RequestResponse in JSON."""
        import json
        return json.dumps(self.__dict__, indent=2)
    
    def __str__(self):
        # type: () -> (str)
        """Stringer for the RequestResponse object."""
        return str(self.JSON())
    
    def __repr__(self):
        return self.__str__()

# this cannot be part of the class and is needed for the import later.
def dictToRequestResponse(d):
    """Returns a RequestResponse from a dictionary."""
    if d is None:
        return None
    reqResp = RequestResponse()
    reqResp.__dict__.update(d)
    return reqResp
