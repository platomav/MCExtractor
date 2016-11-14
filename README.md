# MCExtractor
Intel, AMD &amp; VIA Microcode Extraction Tool

[Official MC Extractor forum thread](http://www.win-raid.com/t2199f16-MC-Extractor-Intel-AMD-amp-VIA-Microcode-Extraction-Tool.html#msg30320)

##**A. About MC Extractor**

MC Extractor is a tool that can extract Intel, AMD and VIA processor microcode binaries. It can be used to identify what microcodes your BIOS/SPI holds, verify their integrity, show details about them, check if they exist at the microcode repository etc.

####**A1. MC Extractor Features**

- Supports all current & legacy Microcodes (from 1995 and onward)
- Converts Intel Microcode containers (dat,inc,txt,h) to binary images
- Shows microcode header structure and details on demand
- Scans for Intel, AMD and VIA microcodes in one run
- Verifies all microcode integrity via checksum
- Supports certain special/modded microcodes
- Lordkag's UEFI Strip optional integration support
- Extracts AMD microcodes with or without padding
- Ignores most false positives based on sanity checks
- Ability to print new database entries for manual entry
- Extracted duplicates are ignored based on name and contents
- Ability to use loose patterns for debugging or future proofing
- Multiple file drag & drop, mass file within folder scanning
- Reports unknown microcodes not found at the Microcode Repository Database
- Shows colored text to signify the importance of notes, warnings, errors etc
- Open Source project licensed under GNU GPL v3

####**A2. Microcode Repository Database**

MC Extractor's main goal is to allow users to quickly extract, determine & report new microcode versions without the use of special tools (MMTool) or Hex Editors. To do that effectively, a database had to be built. It's existence is very important for MC Extractor as it allows me to find new types of microcode, compare releases for similarities, check for updated binaries etc. Bundled with MC Extractor there's a file called MCE.dat which is required for the program to run. It includes all the Microcodes that are available at the Repository thread. This accommodates two actions: a) Check whether the imported microcode is up to date and b) Help find new Microcode releases sooner by reporting them.

####**A3. Sources and Inspiration**

MC Extractor is based on a fraction of [Lordkag's](http://www.win-raid.com/u369_lordkag.html) UEFIStrip so, first and foremost, I thank him a lot for all the work he does which inspired this project. Among others, great places to learn about microcodes are Intel's own download site and official documentation, Coreboot ([a](https://chromium.googlesource.com/chromiumos/third_party/coreboot/),[b](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu?id=HEAD),[c](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu/via/nano/update_ucode.h?id=HEAD)), [Microparse](https://github.com/ddcc/microparse) by Dominic Chen, Ben Hawkes's [Notes and Research](http://inertiawar.com/microcode/), Richard A Burton's [Microdecode](http://www.onlinecompiler.net/sourcecode&id=18684), [AIDA64 CPUID dumps](http://instlatx64.atw.hu/), [Sandpile CPUID](http://sandpile.org/x86/cpuid.htm), [Free Electrons](http://lxr.free-electrons.com/source/arch/x86/include/asm/microcode_amd.h) and many more which I may have forgotten but would have been here otherwise.

##**B. How to use MC Extractor**

There are two ways to use MC Extractor, MCE.exe & Command Prompt. The MCE executable allows you to drag & drop one or more firmware and view them one by one. To manually call MC Extractor, a Command Prompt can be used with -skip as parameter.

####**B1. MC Extractor Executable**

To use MC Extractor, select one or multiple files and Drag & Drop them to it's executable. You can also input certain optional parameters either by running MCE directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter as explained below.

####**B2. MC Extractor Parameters**

There are various parameters which enhance or modify the default behavior of MC Extractor.

* -? : Displays MCE's help & usage screen
* -skip : Skips MCE's options intro screen
* -info : Displays microcode header(s)
* -padd : Keeps padding of AMD microcodes
* -extr : Lordkag's UEFI Strip mode
* -false : Uses loose patterns (false positives)
* -file : Appends filename to New or Bad microcodes
* -cont : Converts Intel container (dat,inc,h,txt) to binary
* -mass : Scans all files of a given directory
* -pdb : Writes DB entries to file 

####**B3. MC Extractor Error Control**

During operation, MC Extractor may encounter some issues related to rare circumstances that can trigger Notes, Warnings or Errors. Notes (yellow color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected is encountered like unknown microcode sizes, failure to convert containers or find/open/read files etc.

##**C. Download MC Extractor**

MC Extractor is developed under Windows using Python 3.x. Since the Engine Firmware Repository Database is updated more frequently compared to the main program, a separate DB release is provided when needed.

####**C1. Compatibility**

MC Extractor has been tested to be compatible with Windows XP up to Windows 10 operating systems. It is built and executed using Python 3.4. Any latter v3.x releases might work depending on whether MCE's prerequisites are also compatible. The script is frozen using Py2Exe.

####**C2. Code Prerequisites**

To run MC Extractor, you need to have the following python modules installed:

* [Colorama](https://pypi.python.org/pypi/colorama)
* [PyWin32](https://sourceforge.net/projects/pywin32/files/pywin32/)

To freeze MC Extractor, you can use whatever you like. The following are verified to work:

* [Py2Exe](https://pypi.python.org/pypi/py2exe)
* [PyInstaller](https://pypi.python.org/pypi/PyInstaller/)
