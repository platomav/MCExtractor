# MCExtractor
**Intel, AMD, VIA &amp; Freescale Microcode Extraction Tool**

[MC Extractor News Feed](https://twitter.com/platomaniac)

[MC Extractor Discussion Topic](https://www.win-raid.com/t2199f47-MC-Extractor-Intel-AMD-VIA-amp-Freescale-Microcode-Extraction-Tool-Discussion.html)

[Intel, AMD, VIA &amp; Freescale CPU Microcode Repositories](https://github.com/platomav/CPUMicrocodes)

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL"><img border="0" title="MC Extractor Donation via Paypal or Debit/Credit Card" alt="MC Extractor Donation via Paypal or Debit/Credit Card" src="https://user-images.githubusercontent.com/11527726/109392268-e0f68280-7923-11eb-83d8-0a63f0d20783.png"></a>

![](https://i.imgur.com/25peZby.png)

## **A. About MC Extractor**

MC Extractor is a tool which parses Intel, AMD, VIA and Freescale processor microcode binaries. It can be used by end-users who are looking for all relevant microcode information such as CPUID, Platform, Version, Date, Release, Size, Checksum etc. It is capable of converting Intel microcode containers (dat, inc, h, txt) to binary images for BIOS integration, detecting new/unknown microcodes, checking microcode health, Updated/Outdated status and more. MC Extractor can be also used as a research analysis tool with multiple structures which allow, among others, full parsing & information display of all documented or not microcode Headers. Moreover, with the help of its extensive database, MC Extractor is capable of uniquely categorizing all supported microcodes as well as check for any microcodes which have not been stored at the Microcode Repositories yet.

#### **A1. MC Extractor Features**

- Supports all current & legacy Microcodes from 1995 and onward
- Scans for all Intel, AMD, VIA & Freescale microcodes in one run
- Verifies all extracted microcode integrity via Checksums
- Checks if all Intel, AMD & VIA microcodes are Latest or Outdated
- Searches on demand for all microcodes based on CPUID
- Shows microcode Header structures and details on demand
- Ignores most false positives based on sanity checks
- Supports known special, fixed or modded microcodes
- Ability to automatically extract Intel Extended microcodes
- Ability to automatically extract Intel Containers (dat,inc,txt,h)
- Ability to quickly add new microcode entries to the database
- Ability to detect Intel Production/Pre-Production Release tag
- Ability to check for MC Extractor and/or DB updates on demand
- Ability to analyze multiple files by drag & drop or by input path
- Ability to ignore extracted duplicates based on name and contents
- Ability to automatically scan for newer MC Extractor & Database releases
- Reports all microcodes which are not found at the Microcode Repositories
- Features command line parameters to enhance functionality & assist research
- Features user friendly messages & proper handling of unexpected code errors
- Shows results in nice tables with colored text to signify emphasis
- Open Source project under permissive license, comment assisted code

#### **A2. Microcode Repository Database**

MC Extractor allows end-users and/or researchers to quickly extract, view, convert & report new microcode versions without the use of special tools or Hex Editors. To do that effectively, a database had to be built. The [Intel, AMD, VIA &amp; Freescale CPU Microcode Repositories](https://github.com/platomav/CPUMicrocodes) is a collection of every Latest Production Intel, AMD &amp; VIA CPU Microcodes we have found. Its existence is very important for MC Extractor as it allows us to continue doing research, find new types of microcode, compare releases for similarities, check for updated binaries etc. Bundled with MC Extractor is a file called MCE.db which is required for the program to run. It includes entries for all Microcode binaries that are available to us. This accommodates primarily two actions: a) Check whether the imported microcode is up to date and b) Help find new Microcode releases sooner by reporting them at the [Intel, AMD, VIA &amp; Freescale CPU Microcode Repositories Discussion](https://www.win-raid.com/t3355f47-Intel-AMD-VIA-amp-Freescale-CPU-Microcode-Repositories-Discussion.html) thread.

#### **A3. Sources and Inspiration**

MC Extractor was initially based on a fraction of [Lordkag's](http://www.win-raid.com/u369_lordkag.html) UEFIStrip tool so, first and foremost, I thank him for all his work which inspired this project. Among others, great places to learn about microcodes are Intel's own download site and official documentation, [Intel Microcode Patch Authentication](https://patents.google.com/patent/US20030196096A1/en), Coreboot ([a](https://chromium.googlesource.com/chromiumos/third_party/coreboot/),[b](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu?id=HEAD),[c](https://review.coreboot.org/cgit/coreboot.git/tree/src/cpu/via/nano/update_ucode.h?id=HEAD)), [Microparse](https://github.com/ddcc/microparse) by Dominic Chen, Ben Hawkes's [Notes and Research](http://inertiawar.com/microcode/), Richard A Burton's [Microdecode](http://www.onlinecompiler.net/sourcecode&id=18684), [AIDA64 CPUID dumps](http://instlatx64.atw.hu/), [Sandpile CPUID](http://sandpile.org/x86/cpuid.htm), Free Electrons ([a](http://lxr.free-electrons.com/source/arch/x86/include/asm/microcode_amd.h), [b](http://elixir.free-electrons.com/linux/latest/source/Documentation/powerpc/qe_firmware.txt)), Freescale ([a](https://github.com/NXP/qoriq-fm-ucode/), [b](https://github.com/NXP/qoriq-qe-ucode/), [c](http://opensource.freescale.com/firmware/)) and many more which I may have forgotten but would have been here otherwise.

## **B. How to use MC Extractor**

There are two ways to use MC Extractor, MCE executable & Command Prompt. The MCE executable allows you to drag & drop one or more firmware and view them one by one or recursively scan entire directories. To manually call MC Extractor, a Command Prompt can be used with -skip as parameter.

#### **B1. MC Extractor Executable**

To use MC Extractor, select one or multiple files and Drag & Drop them to its executable. You can also input certain optional parameters either by running MCE directly or by first dropping one or more files to it. Keep in mind that, due to operating system limitations, there is a limit on how many files can be dropped at once. If the latter is a problem, you can always use the -mass parameter to recursively scan entire directories as explained below.

#### **B2. MC Extractor Parameters**

There are various parameters which enhance or modify the default behavior of MC Extractor:

* -?      : Displays help & usage screen
* -skip   : Skips welcome & options screen
* -exit   : Skips Press enter to exit prompt
* -mass   : Scans all files of a given directory
* -info   : Displays microcode header(s)
* -add    : Adds new input microcode to DB
* -dbname : Renames input file based on DB name
* -search : Searches for microcodes based on CPUID
* -last   : Shows "Last" status based on user input
* -repo   : Builds microcode repositories from input
* -blob   : Builds a Microcode Blob (MCB) from input

#### **B3. MC Extractor Microcode Blob (MCB)**

MC Extractor can build its own Microcode Blob (MCB) format, which combines multiple Intel or AMD microcode binaries into one file. This mainly allows quick & automatic extraction of the latest compatible microcode binary based on the equivalent user microcode binary input. The MCB consists of an identifiable Header and an Entry Look Up Table (LUT) followed by the actual Microcode binary data. The Header includes info such as Microcode Vendor (Intel or AMD), Number of Microcodes, MCE DB Revision and a Checksum which covers the entire blob. The LUT entries include details for each microcode binary such as CPUID, Platform, Revision, Date, Size, Checksum and blob Offset.

![](https://i.imgur.com/B0YOrpw.png)

To build a MCE Microcode Blob (MCB.bin), input the desired Intel or AMD microcode binaries and use -blob parameter. You can use your own microcodes or find the Latest Production Intel and AMD ones at the [Intel, AMD, VIA &amp; Freescale CPU Microcodes](https://github.com/platomav/CPUMicrocodes/) repository. To extract the latest microcode from a MCB, input a single microcode binary and use -blob -search parameters. MC Extractor will validate the detected MCB, check if the microcode is already up-to-date before extracting the latest and notify accordingly.

#### **B4. MC Extractor Error Control**

During operation, MC Extractor may encounter issues that can trigger Notes, Warnings and/or Errors. Notes (yellow/green color) provide useful information about a characteristic of this particular firmware. Warnings (purple color) notify the user of possible problems that can cause system instability. Errors (red color) are shown when something unexpected or problematic is encountered.

## **C. Download MC Extractor**

MC Extractor consists of two files, the executable (MCE.exe or MCE) and the database (MCE.db). An already built/frozen/compiled binary is provided by me for Windows only (icon designed by [Alfredo Hernandez](https://www.alfredocreates.com/) under Flaticon license). Thus, **you don't need to manually build/freeze/compile MC Extractor under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/MCExtractor/releases) tab, title should start with "MC Extractor v1.X.X". You may need to scroll down a bit if there are DB releases at the top. The latter can be used to update the outdated DB which was bundled with the latest executable release, title should start with "DB rXX". To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression.

#### **C1. Compatibility**

MC Extractor should work at all Windows, Linux, macOS or BSD operating systems which have Python >= 3.7 support. Windows users who plan to use the already built/frozen/compiled binaries must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **C2. Code Prerequisites**

To run MC Extractor's python script, you need to have the following 3rd party Python modules installed:

* [Colorama](https://pypi.org/project/colorama/)

> pip3 install colorama

* [PLTable](https://github.com/platomav/PLTable/)

> pip3 install pltable

#### **C3. Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile MC Extractor at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install colorama:

> pip3 install colorama

4. Use pip to install PLTable:

> pip3 install pltable

5. Build/Freeze/Compile MC Extractor:

> pyinstaller --noupx --onefile MCE.py

At dist folder you should find the final MCE executable

#### **C4. Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled MCE executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the MCE executable to the exclusions, build/freeze/compile MCE yourself or use the Python script directly.

## **D. Pictures**

**Note:** Some pictures may be outdated and depict older MC Extractor versions.

![](https://i.imgur.com/25peZby.png)

![](https://i.imgur.com/xd5jtZd.png)

![](https://i.imgur.com/IE9fKfj.png)

![](https://i.imgur.com/5M3w5Fs.png)

![](https://i.imgur.com/DfpkcYV.png)

![](https://i.imgur.com/AidY4WK.png)

![](https://i.imgur.com/5pb7C8q.png)

![](https://i.imgur.com/AMO6G38.png)

![](https://i.imgur.com/qssM45a.png)

![](https://i.imgur.com/97reP91.png)

![](https://i.imgur.com/IcqtKju.png)

![](https://i.imgur.com/lBmtfiW.png)

![](https://i.imgur.com/mUDPeZw.png)

![](https://i.imgur.com/YqCwKIN.png)

![](https://i.imgur.com/34Q0cZx.png)

![](https://i.imgur.com/FKF2l5O.png)

![](https://i.imgur.com/0kKFIVt.png)

![](https://i.imgur.com/FlmmYjV.png)

![](https://i.imgur.com/sprxSn3.png)

###### _Donate Button Card Image: [Credit and Loan Pack](https://flaticon.com/free-icon/credit-card_3898076) by **Freepik** under Flaticon license_
###### _Donate Button Paypal Image: [Credit Cards Pack](https://flaticon.com/free-icon/paypal_349278) by **Freepik** under Flaticon license_