# ntreader
Simple utility for parsing UserAssist registry key entries in NTUSER.DAT files outside of home MS Windows system. 
It is cross-platform and easy to use but doesn't always work properly. Also it doesn't work with NTUSER.DAT files from 
legacy MS Windows operating systems (Windows Vista and earlier). But this will be fixed.

## How to use

Just build this program with `go build ntr.go` and execute in command line. By default it will look for *NTUSER.DAT* file in the 
home directory of a program, write log to terminal and create *report.txt* file with results in the program directory. You can 
use command line arguments to change this behavior (use `-h` argument to see more).

## Files overview

* **ntr.go** - main file with program code.

* **guids** - text file containing list of GUIDs and their corresponding system paths. This file must be updated with new entries 
  to get more readable program output.
  
 * **NTUSER/** - this directory contains examples of *NTUSER.DAT* files from different versions of MS Windows operating system. 
  You can use them as a program input.
  
  ## To-do list
  
  * improve recognition of registry entries in *NTUSER.DAT*
  * add legacy operating systems support
  * update *guids* file with new GUID/path pairs
  
  ## Contributing
  
  I will appreciate any help with this projects. You can write code, send me more examples of *NTUSER.DAT*, or just try this program 
  and send me output report file so I can manually compare result with input file and improve the program. I'm just a beginner in 
  programming and Go so any remarks and suggestions are welcomed. Thanks in advance!
