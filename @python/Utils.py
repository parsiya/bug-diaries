# Utilities module.
# Move any utils not tied to other places here.

from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File

def saveFileDialog(parent, startingDir=None, title=None, extension=None):
    # type: (java.awt.Component, str, str, str) -> (java.io.File, str)
    """Creates a fileChooser.showSaveDialog and returns the selected file.
    
    Args:
    
    * parent (java.awt.Component): Parent component.
    * startingDir (str): Starting directory.
    * title (str): Title of the dialog.
    * fileFilter (str): Extension (without the dot) of the file to look for. E.g., "json"
    
    Returns java.io.File and a string containing the last used directory."""

    fileChooser = JFileChooser()
    if startingDir is not None:
        startingPath = File(startingDir)
        fileChooser.setCurrentDirectory(startingPath)
    if title is not None:
        fileChooser.dialogTitle = title

    # FileNameExtensionFilter
    # https://docs.oracle.com/javase/8/docs/api/javax/swing/filechooser/FileNameExtensionFilter.html
    if extension is not None:
        extensionFilterString = "%s Files (*.%s)" % (extension.upper(), extension)
        extensionFilterList = [extension]
        fil = FileNameExtensionFilter(extensionFilterString, extensionFilterList)
        fileChooser.fileFilter = fil
        fileChooser.addChoosableFileFilter(fil)

    fileChooser.fileSelectionMode = JFileChooser.FILES_ONLY
    returnVal = fileChooser.showSaveDialog(parent)
    if returnVal != JFileChooser.APPROVE_OPTION:
        # export cancelled or there was an error
        return None, ""

    # store the used directory
    lastDir = fileChooser.getCurrentDirectory().toString()
    # get file path
    selectedFile = fileChooser.getSelectedFile()
    return selectedFile, lastDir

def openFileDialog(parent, startingDir=None, title=None, extension=None):
    # type: (java.awt.Component, str, str, str) -> (java.io.File, str)
    """Creates a fileChooser.showOpenDialog and returns the selected file.
    
    Args:
    
    * parent (java.awt.Component): Parent component.
    * startingDir (str): Starting directory.
    * title (str): Title of the dialog.
    * fileFilter (str): Extension (without the dot) of the file to look for. E.g., "json"
    
    Returns java.io.File and a string containing the last used directory."""

    fileChooser = JFileChooser()
    if startingDir is not None:
        startingPath = File(startingDir)
        fileChooser.setCurrentDirectory(startingPath)
    if title is not None:
        fileChooser.dialogTitle = title

    # FileNameExtensionFilter
    # https://docs.oracle.com/javase/8/docs/api/javax/swing/filechooser/FileNameExtensionFilter.html
    if extension is not None:
        extensionFilterString = "%s Files (*.%s)" % (extension.upper(), extension)
        extensionFilterList = [extension]
        fil = FileNameExtensionFilter(extensionFilterString, extensionFilterList)
        fileChooser.fileFilter = fil
        fileChooser.addChoosableFileFilter(fil)

    fileChooser.fileSelectionMode = JFileChooser.FILES_ONLY
    returnVal = fileChooser.showOpenDialog(parent)
    if returnVal != JFileChooser.APPROVE_OPTION:
        # export cancelled or there was an error
        return None, ""

    # store the used directory
    lastDir = fileChooser.getCurrentDirectory().toString()
    # get file path
    selectedFile = fileChooser.getSelectedFile()
    return selectedFile, lastDir

def writeFile(file, data):
    # type: (str, str) -> ()
    """Writes data to file."""
    # write to the file
    if file is None:
        return

    writeFile = open(file, "w")
    writeFile.write(data)
    writeFile.close()

def readFile(file):
    # type: (str) -> (str)
    """Reads strings from a file."""
    if file is None:
        return None
    
    readFile = open(file, "r")
    return readFile.read()

# def dictToIssue(d):
#     """Returns an Issue from a dictionary."""
#     from Issue import Issue
#     from RequestResponse import RequestResponse, HttpService
#     if d is None:
#         return None
#     try:
#         if d["objtype"] is "httpservice":
#             ht = HttpService()
#             # should we remove the objtype key before thig assignment?
#             ht.__dict__.update(d)
#             return ht
#         if d["objtype"] is "requestresponse":
#             rr = RequestResponse()
#             rr.__dict__.update(d)
#             return rr
#         if d["objtype"] is "issue":
#             iss = Issue()
#             print "d", d
#             iss.__dict__.update(d)
#             # iss.__dict__ = d # would overwrite existing attributes
#             return iss
#     except:
#         pass
    
#     return None

def templateToIssue(d):
    """Returns an Issue from a dictionary."""
    from Issue import Issue
    if d is None:
        return None
    iss = Issue()
    iss.__dict__.update(d)
    # iss.__dict__ = d # would overwrite existing attributes
    return iss

def bytesToString(callbacks, b):
    # type: (bytearray) -> (str)
    """Converts a byte[] to string."""
    if b is None:
        return ""
    return callbacks.getHelpers().bytesToString(b)

def getPath(callbacks, reqResp):
    # type: (IHttpRequestResponse) -> (str)
    """Analyzes a byte[] of a request and returns the path."""
    if reqResp is None or callbacks is None:
        return ""
    info = callbacks.getHelpers().analyzeRequest(reqResp)
    return info.getUrl().getFile()

def burpToolName(flag):
    # type: (int) -> (str)
    """Converts a tool flag int to string representing the tool name."""
    # https://portswigger.net/burp/extender/api/constant-values.html#burp
    tool = {
        1: "Suite",
        2: "Target",
        4: "Proxy",
        8: "Spider",
        16: "Scanner",
        32: "Intruder",
        64: "Repeater",
        128: "Sequencer",
        256: "Decoder",
        512: "Comparer",
        1024: "Extender"
    }
    return tool[flag]