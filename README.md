# MCExtractor
Intel, AMD, VIA &amp; Freescale Microcode Extraction Tool

[MC Extractor News Feed](https://twitter.com/platomaniac)

[MC Extractor Discussion Topic](https://www.win-raid.com/t2199f47-MC-Extractor-Intel-AMD-VIA-amp-Freescale-Microcode-Extraction-Tool-Discussion.html)

[Intel, AMD &amp; VIA CPU Microcode Repositories](https://github.com/platomav/CPUMicrocodes)

[![MC Extractor Donation](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL)

![](https://i.imgur.com/1jZL0p2.png)

## **A. About MC Extractor**

MC Extractor is a tool which parses Intel, AMD, VIA and Freescale processor microcode binaries. It can be used by end-users who are looking for all relevant microcode information such as CPUID, Platform, Version, Date, Release, Size, Checksum etc. It is capable of converting Intel microcode containers (dat, inc, h, txt) to binary images for BIOS integration, detecting new/unknown microcodes, checking microcode health, Updated/Outdated status and more. MC Extractor can be also used as a research analysis tool with multiple structures which allow, among others, full parsing & information display of all documented or not microcode Headers. Moreover, with the help of its extensive database, MC Extractor is capable of uniquely categorizing all supported microcodes as well as check for any microcodes which have not been stored at the Microcode Repositories yet.

#### **A1. MC Extractor Features**

- Supports all current & legacy Microcodes from 1995 and onward
- Scans for all Intel, AMD, VIA & Freescale microcodes in one run
- Verifies all extracted microcode integrity via Checksums
- Checks if all Intel, AMD & VIA microcodes are Latest or Outdated
- Converts Intel containers (dat,inc,txt,h) to binary images
- Searches on demand for all microcodes based on CPUID
- Shows microcode Header structures and details on demand
- Ignores most false positives based on sanity checks
- Supports known special, fixed or modded microcodes
- Ability to quickly add new microcode entries to the database
- Ability to detect Intel Production/Pre-Production Release tag
- Ability to analyze multiple files by drag & drop or by input path
- Ability to ignore extracted duplicates based on name and contents
- Reports all microcodes which are not found at the Microcode Repositories
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows results in nice tables with colored text to signify emphasis
- Open Source project licensed under GNU GPL v3, comment assisted code

#### **A2. Microcode Repository Database**

MC Extractor allows end-users and/or researchers to quickly extract, view, convert & report new microcode versions without the use of special tools or Hex Editors. To do that effectively, a database had to be built. The [Intel, AMD &amp; VIA CPU Microcode Repositories](https://github.com/platomav/CPUMicrocodes) is a collection of every Intel, AMD &amp; VIA CPU Microcodes we have found. Its existence is very important for MC Extractor as it allows us to continue doing research, find new types of microcode, compare releases for similarities, check for updated binaries etc. Bundled with MC Extractor is a file called MCE.db which is required for the program to run. It includes entries for all Microcode binaries that are available to us. This accommodates primarily two actions: a) Check whether the imported microcode is up to date and b) Help find new Microcode releases sooner by reporting them at the [Intel, AMD & VIA CPU Microcode Repositories Discussion](https://www.win-raid.com/t3355f47-Intel-AMD-amp-VIA-CPU-Microcode-Repositories-Discussion.html) thread.

#### **A3. Sources and Inspiration**

MC Extractor was initially based on a fraction of [Lordkag's](http://www.win-raid.com/u369_lordkag.html) UEFIStrip tool so, first and foremost, I thank him for all his work which inspired this project. Among others, great places to learn about microcodes are Intel's own download site and official documentation, [Intel Microcode Patch Authentication](https://patents.google.com/patent/US20030196096A1/en), Coreboot ([a](https://chromium.googlesource.com/chromiumos/third_party/coreboot/),[b](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu?id=HEAD),[c](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu/via/nano/update_ucode.h?id=HEAD)), [Microparse](https://github.com/ddcc/microparse) by Dominic Chen, Ben Hawkes's [Notes and Research](http://inertiawar.com/microcode/), Richard A Burton's [Microdecode](http://www.onlinecompiler.net/sourcecode&id=18684), [AIDA64 CPUID dumps](http://instlatx64.atw.hu/), [Sandpile CPUID](http://sandpile.org/x86/cpuid.htm), Free Electrons ([a](http://lxr.free-electrons.com/source/arch/x86/include/asm/microcode_amd.h), [b](http://elixir.free-electrons.com/linux/latest/source/Documentation/powerpc/qe_firmware.txt)), [Freescale](http://opensource.freescale.com/firmware/) and many more which I may have forgotten but would have been here otherwise.

## **B. How to use MC Extractor**

There are two ways to use MC Extractor, MCE executable & Command Prompt. The MCE executable allows you to drag & drop one or more firmware and view them one by one or recursively scan entire directories. To manually call MC Extractor, a Command Prompt can be used with -skip as parameter.

#### **B1. MC Extractor Executable**

To use MC Extractor, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MCE directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter to recursively scan entire directories as explained below.

#### **B2. MC Extractor Parameters**

There are various parameters which enhance or modify the default behavior of MC Extractor:

* -?      : Displays help & usage screen
* -skip   : Skips welcome & options screen
* -exit   : Skips Press enter to exit prompt
* -redir  : Enables console redirection support
* -mass   : Scans all files of a given directory
* -info   : Displays microcode header(s)
* -add    : Adds new input microcode to DB
* -dbname : Renames input file based on DB name
* -cont   : Extracts Intel containers (dat,inc,h,txt)
* -search : Searches for microcodes based on CPUID
* -repo   : Builds microcode repositories from input

#### **B3. MC Extractor Error Control**

During operation, MC Extractor may encounter issues that can trigger Notes, Warnings and/or Errors. Notes (yellow/green color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Execute/Download MC Extractor**

MC Extractor is developed using Python 3.6 and can work under Windows, Linux and macOS operating systems. It consists of two files, the executable (MCE.exe or MCE) and the database (MCE.db). Regarding the executable, already built/frozen/compiled binaries are provided by me for Windows only (icon designed by [Alfredo Hernandez](https://www.alfredocreates.com/)). Thus, **you don't need to manually build/freeze/compile MC Extractor under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/MCExtractor/releases) tab, title should be "MC Extractor v1.X.X". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bundled with the latest executable release, title should be "DB rXX". For Linux and macOS or courageous Windows users, the build/freeze/compile instructions for all three OS can be found below.

**Note:** To extract the already built/frozen/compiled MC Extractor archives, you need to use programs which support RAR5 compression!

#### **C1. Compatibility**

MC Extractor should work at all Windows, Linux or macOS operating systems which have Python 3.6 support. Any latter v3.x releases might work depending on whether MCE's prerequisites are also compatible. Windows users who plan to use the already built/frozen/compiled binaries must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries. Windows users who plan to use console redirection must first "set PYTHONIOENCODING=UTF-8".

#### **C2. Code Prerequisites**

To run MC Extractor's python script, you need to have the following 3rd party Python modules installed:

* [Colorama](https://pypi.python.org/pypi/colorama/)
* [PTable](https://github.com/platomav/PTable/tree/boxchar)

To build/freeze/compile MC Extractor's python script, you can use whatever you like. The following are verified to work:

* [Py2exe](https://pypi.python.org/pypi/py2exe/) (Windows)
* [Py2app](https://pypi.python.org/pypi/py2app/) (macOS)
* [PyInstaller](https://github.com/pyinstaller/pyinstaller/tree/master/) (Windows/Linux/macOS)

#### **C3. Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile MC Extractor at all three supported platforms, it is simple to run and gets updated often.

1. Make sure you have Python 3.6 installed
2. Use pip to install colorama (PyPi)
3. Use pip to install PTable (Github, boxchar branch)
4. Use pip to install PyInstaller (Github, master branch)
5. Open a command prompt and execute:

> pyinstaller --noupx --onefile MCE.py

At dist folder you should find the final MCE executable

## **D. Pictures**

**Note:** Some pictures are outdated and depict older MC Extractor versions.

![](https://i.imgur.com/1jZL0p2.png)

![](https://i.imgur.com/LcFVxwI.png)

![](https://i.imgur.com/g6e8deP.png)

![](https://i.imgur.com/MpDwImf.png)

![](https://i.imgur.com/iIC6CfR.png)

![](https://i.imgur.com/S3qvvIp.png)

![](https://i.imgur.com/5sRuTXi.png)

![](https://i.imgur.com/tin1cl1.png)

![](https://i.imgur.com/r8Iaq7y.png)

![](https://i.imgur.com/AELEJeP.png)

![](https://i.imgur.com/3LFAqEz.png)

![](https://i.imgur.com/WZgJuHv.png)

![](https://i.imgur.com/6g4X1qD.png)

![](https://i.imgur.com/ASV52pd.png)

![](https://i.imgur.com/e7HU95o.png)

![](https://i.imgur.com/T1mLYm7.png)

![](https://i.imgur.com/zXdm2Xo.png)