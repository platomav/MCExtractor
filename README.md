# MCExtractor
Intel, AMD &amp; VIA Microcode Extraction Tool

[Official MC Extractor forum thread](http://www.win-raid.com/t2199f16-MC-Extractor-Intel-AMD-amp-VIA-Microcode-Extraction-Tool.html#msg30320)

##**A. About MC Extractor**

MC Extractor is a tool which can extract Intel, AMD and VIA processor microcode binaries. It can be used to identify what microcodes your BIOS/SPI holds, verify their integrity, show details about them, check if they exist at the microcode repository etc.

####**A1. MC Extractor Features**

- Supports all current & legacy Microcodes from 1995 and onward
- Scans for all Intel, AMD and VIA microcodes in one run
- Verifies all extracted microcode integrity via checksum
- Converts Intel containers (dat,inc,txt,h) to binary images
- Shows microcode header structure and details on demand
- Ignores most false positives based on sanity checks
- Supports certain special, fixed or modded microcodes
- Ability to extract AMD microcodes with or without padding
- Ability to print new database entries for manual DB entry
- Ability to use loose patterns for debugging or future proofing
- Ability to analyze multiple files by drag & drop or by input path
- Ability to ignore extracted duplicates based on name and contents
- Reports all microcodes which are not found at the Microcode Repository Database
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows colored text to signify the importance of notes, warnings & errors
- Open Source project licensed under GNU GPL v3, comment assisted code

####**A2. Microcode Repository Database**

MC Extractor's main goal is to allow users to quickly extract, determine & report new microcode versions without the use of special tools or Hex Editors. To do that effectively, a database had to be built. Its existence is very important for MC Extractor as it allows us to find new types of microcode, compare releases for similarities, check for updated binaries etc. Bundled with MC Extractor there's a file called MCE.dat which is required for the program to run. It includes all the Microcodes that have been found so far. This accommodates two actions: a) Check whether the imported microcode is up to date and b) Help find new Microcode releases sooner by reporting them.

####**A3. Sources and Inspiration**

MC Extractor is based on a fraction of [Lordkag's](http://www.win-raid.com/u369_lordkag.html) UEFIStrip so, first and foremost, I thank him a lot for all the work he does which inspired this project. Among others, great places to learn about microcodes are Intel's own download site and official documentation, Coreboot ([a](https://chromium.googlesource.com/chromiumos/third_party/coreboot/),[b](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu?id=HEAD),[c](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu/via/nano/update_ucode.h?id=HEAD)), [Microparse](https://github.com/ddcc/microparse) by Dominic Chen, Ben Hawkes's [Notes and Research](http://inertiawar.com/microcode/), Richard A Burton's [Microdecode](http://www.onlinecompiler.net/sourcecode&id=18684), [AIDA64 CPUID dumps](http://instlatx64.atw.hu/), [Sandpile CPUID](http://sandpile.org/x86/cpuid.htm), [Free Electrons](http://lxr.free-electrons.com/source/arch/x86/include/asm/microcode_amd.h) and many more which I may have forgotten but would have been here otherwise.

##**B. How to use MC Extractor**

There are two ways to use MC Extractor, MCE executable & Command Prompt. The MCE executable allows you to drag & drop one or more firmware and view them one by one. To manually call MC Extractor, a Command Prompt can be used with -skip as parameter.

####**B1. MC Extractor Executable**

To use MC Extractor, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MCE directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter as explained below.

####**B2. MC Extractor Parameters**

There are various parameters which enhance or modify the default behavior of MC Extractor.

* -? : Displays help & usage screen
* -skip : Skips options intro screen
* -mass : Scans all files of a given directory
* -info : Displays microcode header(s)
* -false : Uses loose patterns (false positives)
* -padd : Keeps padding of AMD microcodes
* -file : Appends filename to New or Bad microcodes
* -cont : Extracts Intel containers (dat,inc,h,txt)
* -pdb : Writes input DB entries to file

The following is Windows specific:

* -extr : Lordkag's UEFI Strip mode

####**B3. MC Extractor Error Control**

During operation, MC Extractor may encounter some issues that can trigger Notes, Warnings or Errors. Notes (yellow color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

##**C. Download MC Extractor**

MC Extractor is developed using Python 3.x and can work under Windows, Linux and macOS operating systems. Pre-built binaries are provided for Windows only with build/freeze instructions for all three OS found below.

####**C1. Compatibility**

MC Extractor has been tested to be compatible with Windows XP-10, Ubuntu 16.04 and macOS Sierra operating systems. It is expected to work at all Linux or macOS operating systems which have Python 3.x support but feel free to test it. It is executed using Python 3.4 under Windows and the built-in Python 3.5 under Linux and macOS. Any latter v3.x releases might work depending on whether MCE's prerequisites are also compatible.

####**C2. Code Prerequisites**

To run MC Extractor, you need to have the following 3rd party Python module installed:

* [Colorama](https://pypi.python.org/pypi/colorama)

To freeze MC Extractor, you can use whatever you like. The following are verified to work:

* [Py2exe](https://pypi.python.org/pypi/py2exe) (Windows)
* [Py2app](https://pypi.python.org/pypi/py2app) (macOS)
* [PyInstaller](https://pypi.python.org/pypi/PyInstaller/) (Windows/Linux/macOS)

####**C3. Freeze with PyInstaller**

PyInstaller can freeze MC Extractor at all three platforms, it is simple to run and gets updated often.

1. Make sure you have Python 3.5 installed
2. Use pip to install colorama module
3. Use pip to install pyinstaller module
4. Open a command prompt and execute:

> pyinstaller --clean --noconfirm --noupx --onefile --log-level=WARN --name MCE MCE.py

At dist folder you should find the final MCE executable