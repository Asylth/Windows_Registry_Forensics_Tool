# Windows Registry Digital Forensics Tool

## What is it?
### Warning: Made for a school project. Use at your own risk!
   This is a small and quickly developed digital forensics tool for easily accessing and viewing large amounts of regestry information. When ran it will read the associated config file and fetch all the values associated with the keys specified. It's mainly designed to export these values to a file but it can also display them in cli if specified. 

## Compiling and Editing Source Code
   Go to the GitHub repository and click “code” and then “download ZIP” to download the source code as well as the pre-compiled .exe or go to releases and   download just the compiled version.
  For compiling after editing the source code make sure you have [python 3.10](https://www.python.org/downloads/), [pip](https://pip.pypa.io/en/stable/installation/) and [pyinstaller](https://pyinstaller.org/en/stable/) installed.
  Open cmd and navigate to the project folder (>cd <path>). Compile the python file using >pyinstaller --onefile your_pythonfile.py
  Once done the compiled application should now be in the dist folder.
  
### Required libraries for edit and .py script:
  Most should come with python 3.10

configparser, argparse, winreg, os, csv, codecs, datetime 
## Use
  Only works when running as admin!!!
### EXE
  Simply navigate to the file in cmd and execute the main.exe required aruments ```main.exe <arg> <arg>```

### Python Script
  Install all required libraries then navigate to the file in cmd and excecute it with ```python main.py <arg> <arg>```

### Arguments
  Defaults are bolded
  
  Subject: Determines which sections of the config file is loaded.
  
    system_info, autorun, applications, devices, all
  
  Action: Determines the action of the program. Should it export, display or both.
  
    view, export, both
  
  Filetype (optional): Filetype of exported info.
  
    csv, txt
  
  
  Path (optional): Determines export path.
  
    "path"
  
  Formatting ```main.exe <Subject> <Action> <Filetype> <"Path">```
  
  Example containing all the default argument types: ```main.exe all export txt "C:\"```
  
  Defaults in order: all, export, csv, "current app directory"
  
## Limitations
  -Config formating is strict. Doing it wrong will break it.
  -Lacks exception handling.
  -Requires admin access.
  -Depth is limited to 2 layers.
  -Depth does not fetch any entries other than the ones on the lowest layer.
  -Does not decrypt most windows encrypted entries like productId. It tried to decrypt all binary but if it fails or has a invalid output it will fall back to printing the raw binary value.
  
## Free Use
 Use, edit, copy, publish as you please. Would be nice with credit or a link back though.
 If you find a bug, fix or have ideas for improvement or similar feel free to share. I do not mind continuing to work on and improve this script.

