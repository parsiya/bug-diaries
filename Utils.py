# Utilities module.
# Move any utils not tied to other places here.

def 

### how apache commons-io.FilenameUtils.getExtension does it

# public static String getExtension(final String fileName) throws IllegalArgumentException {
#     if (fileName == null) {
#         return null;
#     }
#     final int index = indexOfExtension(fileName);
#     if (index == NOT_FOUND) {
#         return EMPTY_STRING;
#     }
#     return fileName.substring(index + 1);