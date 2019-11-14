# Each Issue contains the information for one finding.
from base64 import b64decode, b64encode

class Issue():
    """Issue represents one finding."""
    # issue name/type.
    name = ""  # type: str
    # severity: could be an enum but we will use a string to support custom
    # values.
    severity = ""  # type: str
    # host - might be better to merge it with path.
    host = ""  # type: str
    path = ""  # type: str
    description = ""  # type: str
    remediation = ""  # type: str
    # request and response will be stored as base64 encoded strings.
    request = ""  # type: str
    response = ""  # type: str

    def getRequest(self):
        # type: () -> bytearray
        """Base64 decode the request and return the results."""
        return b64decode(self.request)

    def setRequest(self, req):
        # type: (bytearray) -> None
        """Base64 encode the request and store it."""
        self.request = b64encode(req)

    def getResponse(self):
        # type: () -> bytearray
        """Base64 decode the response and return the results."""
        return b64decode(self.response)

    def setResponse(self, resp):
        # type: (bytearray) -> None
        """Base64 encode the response and store it."""
        self.response = b64encode(resp)

    def __init__(self, name="", severity="", host="", path="",
                 description="", remediation="", request="", response=""):
        """Create the issue."""
        self.name = name
        self.severity = severity
        self.host = host
        self.path = path
        self.description = description
        self.remediation = remediation
        self.setRequest(request)
        self.setResponse(response)

    def JSON(self):
        """Returns the Issue in JSON."""
        import json
        # TODO: Change indent to 2?
        # TODO: Also make it configurable in the extension config
        # json.dumps(self.__dict__) without the indent, it returns an error
        # that it's not serializable
        return json.dumps(self.__dict__, indent=4)

    def __str__(self):
        """Stringer for the Issue object."""
        return str(self.JSON())
