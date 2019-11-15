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