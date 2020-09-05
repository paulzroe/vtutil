# vtutil
**vtutil** is a python wrapper for Virustotal [V2](https://developers.virustotal.com/reference) and [V3](https://developers.virustotal.com/v3.0/reference) API.

# Initializing vtutil

`import vtutil`

`vt3 = vtutil.VTUtilsV3("Your_VT_API_KEY")` \# to instantiate V3 API

`vt2 = vtutil.VTUtilsV2("Your_VT_API_KEY")` \# to instantiate V2 API


## Getting File Report 

`vt3.getfileReportv3("hash_of_file")`

## Getting File Behavior

`vt3.getfileBehaviorv3("hash_of_file")`

## Download a File

`vt3.get_file("hash", "output_directory")`
