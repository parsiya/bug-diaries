# Each Issue contains the information for one finding.
from base64 import b64decode, b64encode
from RequestResponse import RequestResponse

class Issue():
    """Issue represents one finding."""
    # issue name.
    name = ""  # type: str
    # severity: could be an enum but we will use a string to support custom
    # values.
    severity = ""  # type: str
    # host - might be better to merge it with path.
    host = ""  # type: str
    path = ""  # type: str
    description = ""  # type: str
    remediation = ""  # type: str
    reqResp = "" # type: RequestResponse

    def getRequest(self):
        # type: () -> (bytearray)
        return self.reqResp.getRequest()

    def setRequest(self, req):
        # type: (bytearray) -> ()
        self.reqResp.setRequest(req)

    def getResponse(self):
        # type: () -> (bytearray)
        return self.reqResp.getResponse()

    def setResponse(self, resp):
        # type: (bytearray) -> ()
        self.reqResp.setResponse(resp)

    def __init__(self, name="", severity="", host="", path="",
                 description="", remediation="", reqResp=None):
        """Create the issue."""
        self.name = name
        self.severity = severity
        self.host = host
        self.path = path
        self.description = description
        self.remediation = remediation
        self.reqResp = reqResp

    def JSON(self):
        # type: () -> (str)
        """Returns the Issue in JSON."""
        import json
        # TODO: Change indent to 2?
        # TODO: Also make it configurable in the extension config
        # json.dumps(self.__dict__) without the indent, it returns an error
        # that it's not serializable
        return json.dumps(self.__dict__, indent=2)
    
    def customJSON(self):
        return dict(
            name = self.name,
            severity = self.severity,
            host = self.host,
            path = self.path,
            description = self.description,
            remediation = self.remediation,
            reqResp = self.reqResp
        )

    # def __str__(self):
    #     # type: () -> (str)
    #     """Stringer for the Issue object."""
    #     return str(self.JSON())

    # toString() does not work.
    # https://stackoverflow.com/a/6950800
    def __repr__(self):
        # type: () -> (str)
        """Override toString() to return the name for JCombobox."""
        return self.name