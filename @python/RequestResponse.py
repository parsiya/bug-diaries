# Class implementing the IHttpService interface.
# https://portswigger.net/burp/extender/api/burp/IHttpService.html

import json

class ComplexEncoder(json.JSONEncoder):
    """Encoder class for (hopefully) serializing these nested objects to JSON.
    """
    def default(self, obj):
        if hasattr(obj,'customJSON'):
            return obj.customJSON()
        else:
            return json.JSONEncoder.default(self, obj)


from burp import IHttpService
class HttpService(IHttpService):
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
        return json.dumps(self.__dict__, indent=2)
    
    def __str__(self):
        # type: () -> (str)
        """Stringer for the HttpService object."""
        return str(self.JSON())
    
    def __repr__(self):
        return self.__str__()
    
    def customJSON(self):
        return dict(
            host = self.host,
            port = self.port,
            protocol = self.protocol
        ) 

from base64 import b64decode, b64encode
# Class implementing the IHttpRequestResponse interface.
# https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html

from burp import IHttpRequestResponse
class RequestResponse(IHttpRequestResponse):
    """Implements Burp's IHttpRequestResponse interface."""

    def __init__(self, request=None, response=None, httpService=None,
                 highlight="", comment=""):
        # type: (bytearray, bytearray, HttpService, str, str) -> (RequestResponse)
        """Initialize a new RequestResponse object."""
        self.setRequest(request)
        self.setResponse(response)
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
        return b64decode(self.request)
    
    def setRequest(self, request):
        # type: (bytearray) -> ()
        """Updates the request message."""
        if request is not None:
            self.request = b64encode(request)
        else:
            self.request = b64encode("")
    
    def getResponse(self):
        # type: () -> (bytearray)
        """Returns the response message."""
        return b64decode(self.response)

    def setResponse(self, response):
        # type: (bytearray) -> ()
        """Updates the response message."""
        if response is not None:
            self.response = b64encode(response)
        else:
            self.response = b64encode("")
    
    def JSON(self):
        # type: () -> (str)
        """Returns the RequestResponse in JSON."""
        return json.dumps(self.__dict__, cls=ComplexEncoder, indent=2)
    
    def __str__(self):
        # type: () -> (str)
        """Stringer for the RequestResponse object."""
        return str(self.JSON())
    
    def __repr__(self):
        return self.__str__()
    
    def customJSON(self):
        return dict(
            # request = self.getRequest(),
            request = self.request,
            # response = self.getResponse(),
            response = self.response,
            httpService = self.httpService,
            highlight = self.highlight,
            comment = self.comment
        )
    
    def fromIHttpRequestResponse(self, iHttpReqResp):
        # type: (IHttpRequestResponse) -> ()
        """Converts a Burp IHttpRequestResponse object to RequestResponse."""
        myService = HttpService(
            host=iHttpReqResp.getHttpService().getHost(),
            port=iHttpReqResp.getHttpService().getPort(),
            protocol=iHttpReqResp.getHttpService().getProtocol()
        )
        self.setRequest(iHttpReqResp.getRequest())
        self.setResponse(iHttpReqResp.getResponse())
        self.httpService = myService
        self.highlight = iHttpReqResp.getHighlight()
        self.comment = iHttpReqResp.getComment()
    
# this cannot be part of the class and is needed for the import later.
def dictToRequestResponse(d):
    """Returns a RequestResponse from a dictionary."""
    if d is None:
        return None
    reqResp = RequestResponse()
    reqResp.__dict__.update(d)
    return reqResp
