'''
MC Extractor v1.1.0.0
Copyright (C) 2016 Plato Mavropoulos
Based on UEFIStrip v7.8.2 by Lordkag
'''

title = 'MC Extractor v1.1.0'

import sys
import re
import os
import zlib
import ctypes
import inspect
import colorama
import tempfile
import binascii
import datetime
import traceback
import win32console

colorama.init()
col_red = colorama.Fore.RED + colorama.Style.BRIGHT
col_green = colorama.Fore.GREEN + colorama.Style.BRIGHT
col_yellow = colorama.Fore.YELLOW + colorama.Style.BRIGHT
col_magenta = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
col_end = colorama.Fore.RESET + colorama.Style.RESET_ALL

char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class MCE_Param :
    
	def __init__(self,source) :
	
		self.all = ['-?','-skip','-info','-pdb','-padd','-file','-false','-extr','-exc','-cont','-mass']
		
		self.help_scr = False
		self.build_db = False
		self.skip_intro = False
		self.print_hdr = False
		self.pad_check = False
		self.exp_check = False
		self.print_file = False
		self.mce_extr = False
		self.exc_pause = False
		self.conv_cont = False
		self.mass_scan = False
		
		for i in source :
			if i == '-?' : self.help_scr = True
			if i == '-skip' : self.skip_intro = True
			if i == '-extr' : self.mce_extr = True
			if i == '-pdb' : self.build_db = True
			if i == '-info' : self.print_hdr = True
			if i == '-padd' : self.pad_check = True
			if i == '-false' : self.exp_check = True
			if i == '-file' : self.print_file = True
			if i == '-exc' : self.exc_pause = True
			if i == '-cont' : self.conv_cont = True
			if i == '-mass' : self.mass_scan = True
			
		if self.mce_extr or self.mass_scan : self.skip_intro = True

class Intel_MC_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("HeaderVersion",             uint32_t),  # 00 00000001 (Pattern)
		("UpdateRevision",            uint32_t),  # 04
		("Year",                      uint16_t),  # 08
		("Day",                       uint8_t),   # 0A
		("Month",                     uint8_t),   # 0B
		("ProcessorSignature",        uint32_t),  # 0C
		("Checksum",                  uint32_t),  # 10
		("LoaderRevision",            uint32_t),  # 14 00000001 (Pattern)
		("ProcessorFlags",            uint32_t),  # 18 xx000000 (Pattern)
		("DataSize",                  uint32_t),  # 1C
		("TotalSize",                 uint32_t),  # 20
		("Reserved1",                 uint32_t),  # 24 Splitting this field for better processing
		("Reserved2",                 uint32_t),  # 28
		("Reserved3",                 uint32_t),  # 2C
		# 30
    ]
    
	def mc_print(self) :
		
		full_date  = "%0.2X/%0.2X/%0.4X" % (self.Day, self.Month, self.Year)
		
		if self.Reserved1 == self.Reserved2 == self.Reserved3 == 0 :
			reserv_str = "00 * 12"
		else :
			reserv_str = "%0.8X %0.8X %0.8X" % (self.Reserved1, self.Reserved2, self.Reserved3)
		
		print("-----------------Intel Main Header-----------------\n")
		print("Header Version:                    %0.8X"   % self.HeaderVersion)
		print("Update Revision:                   %0.8X"   % self.UpdateRevision)
		print("Date (d/m/y):                      %s"      % full_date)
		print("Processor Signature:               %0.8X"   % self.ProcessorSignature)
		print("Checksum:                          %0.8X"   % self.Checksum)
		print("Loader Revision:                   %0.8X"   % self.LoaderRevision)
		print("Processor Flags:                   %0.8X"   % self.ProcessorFlags)
		print("Data Size:                         0x%0.2X" % self.DataSize)
		print("Total Size:                        0x%0.2X" % self.TotalSize)
		print("Reserved:                          %s"      % reserv_str)
		
class Intel_MC_Header_Extra(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Unknown1",                  uint32_t),    # 00 00000000 (Pattern)
		("MagicNumber",               uint32_t),    # 04 000000A1 (Pattern)
		("Unknown2",                  uint32_t),    # 08 00020001 (Pattern)
		("UpdateRevision",            uint32_t),    # 0C
		("Unknown3",                  uint32_t),    # 10
		("Unknown4",                  uint32_t),    # 14
		("Day",                       uint8_t),     # 18
		("Month",                     uint8_t),     # 19
		("Year",                      uint16_t),    # 1A
		("UpdateSize",                uint32_t),    # 1C dwords from Extra Header + encrypted padding
		("LoaderRevision",            uint32_t),    # 20 00000001 (Pattern), maybe Header Version
		("ProcessorSignature",        uint32_t),    # 24
		("Unknown5",                  uint32_t*7),  # 28 00000000 * 7 (Pattern)
		("Unknown6",                  uint32_t),    # 44
		("Unknown7",                  uint32_t),    # 48
		("Unknown8",                  uint32_t*5),  # 4C 00000000 * 5 (Pattern)
		("Unknown9",                  uint32_t*8),  # 60
		("RSAPublicKey",              uint32_t*64), # 80
		("RSAExponent",               uint32_t),    # 180
		# 184
    ]
    
	def mc_print_extra(self) :
		
		full_date  = "%0.2X/%0.2X/%0.4X" % (self.Day, self.Month, self.Year)
		
		Unknown5 = " ".join("%0.8X" % val for val in self.Unknown5)
		if re.match('(0{8} ){6}0{8}', Unknown5) : Unknown5 = '00 * 28'
		
		Unknown8 = " ".join("%0.8X" % val for val in self.Unknown8)
		if re.match('(0{8} ){4}0{8}', Unknown8) : Unknown8 = '00 * 20'
		
		Unknown9 = " ".join("%0.8X" % val for val in self.Unknown9)
		RSAPublicKey = " ".join("%0.8X" % val for val in self.RSAPublicKey)
		
		UpdateSize = (self.UpdateSize)*4
		
		print("")
		print("-----------------Intel Extra Header-----------------\n")
		print("Unknown 1:                         %0.8X"     % self.Unknown1)
		print("Magic Number:                      %0.8X"     % self.MagicNumber)
		print("Unknown 2:                         %0.8X"     % self.Unknown2)
		print("Update Revision:                   %0.8X"     % self.UpdateRevision)
		print("Unknown 3:                         %0.8X"     % self.Unknown3)
		print("Unknown 4:                         %0.8X"     % self.Unknown4)
		print("Date (d/m/y):                      %s"        % full_date)
		print("Update Size:                       0x%0.2X"   % UpdateSize)
		print("Loader Revision:                   %0.8X"     % self.LoaderRevision)
		print("Processor Signature:               %0.8X"     % self.ProcessorSignature)
		print("Unknown 5:                         %s"        % Unknown5)
		print("Unknown 6:                         %0.8X"     % self.Unknown6)
		print("Unknown 7:                         %0.8X"     % self.Unknown7)
		print("Unknown 8:                         %s"        % Unknown8)
		print("Unknown 9:                         %s [...]"  % Unknown9[:8])
		print("RSA Public Key:                    %s [...]"  % RSAPublicKey[:8])
		print("RSA Exponent:                      %0.8X"     % self.RSAExponent)

class Intel_MC_Header_Extended(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("ExtendedSignatureCount",    uint32_t),  # 00
		("ExtendedChecksum",          uint32_t),  # 04
		("Reserved1",                 uint32_t),  # 08 Splitting this field for better processing
		("Reserved2",                 uint32_t),  # 0C
		("Reserved3",                 uint32_t),  # 10
		# 14
    ]
    
	def mc_print_extended(self) :
		
		if self.Reserved1 == self.Reserved2 == self.Reserved3 == 0 :
			reserv_str = "00 * 12"
		else :
			reserv_str = "%0.8X %0.8X %0.8X" % (self.Reserved1, self.Reserved2, self.Reserved3)
		
		print("")
		print("-----------------Intel Extended Header-----------------\n")
		print("Extended Signature Count:           %0.2X" % self.ExtendedSignatureCount)
		print("Extended Checksum:                  %0.8X" % self.ExtendedChecksum)
		print("Reserved:                           %s"    % reserv_str)

class Intel_MC_Header_Extended_Field(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("ProcessorSignature",        uint32_t),  # 00
		("ProcessorFlags",            uint32_t),  # 04
		("Checksum",                  uint16_t),  # 08
		# 0C
    ]
    
	def mc_print_extended_field(self) :
		
		print("")
		print("-----------------Intel Extended Field------------------\n")
		print("Processor Signature:                %0.6X" % self.ProcessorSignature)
		print("Processor Flags:                    %0.2X" % self.ProcessorFlags)
		print("Checksum:                           %0.8X" % self.Checksum)

class AMD_MC_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Date",                      uint32_t),      # 00
		("PatchId",                   uint32_t),      # 04
		("DataId",                    uint16_t),      # 08
		("DataLen",                   uint8_t),       # 0A
		("InitFlag",                  uint8_t),       # 0B
		("DataChecksum",              uint32_t),      # 0C
		("NbDevId",                   uint32_t),      # 10
		("SbDevId",                   uint32_t),      # 14
		("ProcessorRevId",            uint16_t),      # 18
		("NbRevId",                   uint8_t),       # 1A
		("SbRevId",                   uint8_t),       # 1B
		("BiosApiRev",                uint8_t),       # 1C
		("Reserved",                  uint8_t * 3),   # 1D 000000 or AAAAAA (Pattern)
		("MatchReg",                  uint32_t * 8),  # 20 Not always present
		# 40
    ]
    
	def mc_print(self) :
		
		full_date = "%0.2X/%0.2X/%0.4X" % (self.Date >> 16 & 0xFF, self.Date >> 24, self.Date & 0xFFFF)
		proc_rev_str = "%0.2X0F%0.2X" % (self.ProcessorRevId >> 8, self.ProcessorRevId & 0xFF)
		
		if self.Reserved == [0, 0, 0] : reserv_str = "000000"
		else : reserv_str = "".join("%0.2X" % val for val in self.Reserved)
		
		matchreg_str = " ".join("%0.8X" % val for val in self.MatchReg)
		
		print("-----------------AMD Header-----------------\n")
		print("Date (d/m/y):                      %s"         % full_date)
		print("Patch Revision:                    %0.8X"      % self.PatchId)
		print("Data Revision:                     %0.4X"      % self.DataId)
		print("Data Length:                       %0.2X"      % self.DataLen)
		print("Init Flag:                         %0.2X"      % self.InitFlag)
		print("Checksum:                          %0.8X"      % self.DataChecksum)
		print("NB Dev ID:                         %0.8X"      % self.NbDevId)
		print("SB Dev ID:                         %0.8X"      % self.SbDevId)
		print("Processor Rev ID:                  %0.4X (%s)" % (self.ProcessorRevId, proc_rev_str))
		print("NB Rev ID:                         %0.2X"      % self.NbRevId)
		print("SB Rev ID:                         %0.2X"      % self.SbRevId)
		print("BIOS API Rev:                      %0.2X"      % self.BiosApiRev)
		print("Reserved:                          %s"         % reserv_str)
		print("Match Reg:                         %s"         % matchreg_str)
		
class VIA_MC_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Signature",                 char*4),    # 00 RRAS (Pattern)
		("UpdateRevision",            uint32_t),  # 04 00000000 (Pattern)
		("Year",                      uint16_t),  # 08
		("Day",                       uint8_t),   # 0A
		("Month",                     uint8_t),   # 0B
		("ProcessorSignature",        uint32_t),  # 0C
		("Checksum",                  uint32_t),  # 10
		("LoaderRevision",            uint32_t),  # 14 00000001 (Pattern)
		("Reserved",                  uint32_t),  # 18 FFFFFFFF (Pattern)
		("DataSize",                  uint32_t),  # 1C
		("TotalSize",                 uint32_t),  # 20
		("Name",                      char*8),    # 24
		("Unknown",                   uint32_t),  # 2C
		# 30
    ]
    
	def mc_print(self) :
		
		full_date  = "%0.2d/%0.2d/%0.4d" % (self.Day, self.Month, self.Year)
		
		print("-----------------VIA Header-----------------\n")
		print("Signature:                         %s"      % (self.Signature).decode('utf-8'))
		print("Update Revision:                   %0.8X"   % self.UpdateRevision)
		print("Date (d/m/y):                      %s"      % full_date)
		print("Processor Signature:               %0.8X"   % self.ProcessorSignature)
		print("Checksum:                          %0.8X"   % self.Checksum)
		print("Loader Revision:                   %0.8X"   % self.LoaderRevision)
		print("Reserved:                          %0.8X"   % self.Reserved)
		print("Data Size:                         0x%0.2X" % self.DataSize)
		print("Total Size:                        0x%0.2X" % self.TotalSize)
		print("Name:                              %s"      % (self.Name).decode('utf-8'))
		print("Unknown:                           %0.8X"   % self.Unknown)

def mce_help() :
	print("\nUsage: MCE.exe [FilePath] <Options>\n\n\
<Options>\n\n\
	-? : Displays MCE's help & usage screen\n\
	-skip : Skips MCE's options intro screen\n\
	-mass : Scans all files of a given directory\n\
	-info : Displays microcode header(s)\n\
	-false : Uses loose patterns (false positives)\n\
	-padd : Keeps padding of AMD microcodes\n\
	-extr : Lordkag's UEFI Strip mode\n\
	-file : Appends filename to New or Bad microcodes\n\
	-cont : Extracts Intel containers (dat,inc,h,txt)\n\
	-exc : Pauses after unexpected python exceptions (debugging)\n\
	-pdb : Writes input DB entries to file\
	")
	mce_exit(0)
		
def mce_exit(code) :
	if not param.mce_extr : wait_user = input("\nPress enter to exit")
	colorama.deinit() # Stop Colorama
	sys.exit(code)

def db_open() :
	fw_db = open(db_path, "r")
	return fw_db

def db_search(db_entry)	:
	fw_db = db_open()
	for line in fw_db :
		if len(line) < 2 or line[:3] == "***" : continue # Skip empty lines or comments
		elif db_entry in line : return 'Yes' # Known MC
	fw_db.close()
	return 'No' # MC not found
	
def get_script_dir(follow_symlinks=True) :
	if getattr(sys, 'frozen', False) :
		path = os.path.abspath(sys.executable)
	else :
		path = inspect.getabsfile(get_script_dir)
	if follow_symlinks :
		path = os.path.realpath(path)
    
	return os.path.dirname(path)

# https://stackoverflow.com/a/781074
def show_exception_and_exit(exc_type, exc_value, tb) :
	traceback.print_exception(exc_type, exc_value, tb)
	input("\nPress enter key to exit")
	sys.exit(-1)
	
def adler32(data) :
    return zlib.adler32(data) & 0xFFFFFFFF
	
def checksum32(data) :
	
	if not data :
		print("Empty data\n")
		return 0
	
	chk32 = 0
	
	for idx in range(0, len(data), 4) : # Move 4 bytes at a time
		chkbt = int.from_bytes(data[idx:idx + 4], 'little') # Convert to int, MSB at the end (LE)
		chk32 = chk32 + chkbt
	
	return -chk32 & 0xFFFFFFFF # Return 0

def mc_repair(semi_sum) :
	for i in range(4294967295) : # FFFFFFFF (max possible value of last 0x4)
		chk32 = semi_sum # Int sum of all but the last 0x4
		chk32 += i # Add last 0x4 sum from range
		if -chk32 & 0xFFFFFFFF == 0 : print(i)
	mce_exit(0)
	
def auto_name(t_folder, name_root, name_tail, name_ext) :
	
	name_ext = name_ext.lstrip(".")
	
	new_name = "%s.%s" % (name_root, name_ext)
	new_file = "%s%s" % (t_folder, new_name)
	
	xn = 1
	while os.path.exists(new_file) :
		xn += 1
		new_name = "%s%s%s.%s" % (name_root, name_tail, xn, name_ext)
		new_file = "%s%s" % (t_folder, new_name)
	
	return new_name.rstrip("."), new_file.rstrip(".")
	
def has_duplicate(file_path, file_data) :
	
	if not os.path.exists(file_path) : return False
	
	name_tail = "_nr"
	t_folder = os.path.dirname(file_path) + "\\"
	baseName = os.path.basename(file_path)
	name_root, name_ext = os.path.splitext(baseName)
	name_ext = name_ext.lstrip(".")
	new_crc32_int = binascii.crc32(file_data) & 0xFFFFFFFF
	
	xn = 1
	new_file = file_path
	
	while os.path.exists(new_file) :
		
		with open(new_file, 'rb') as old_file :
			old_data = old_file.read()
			old_crc32_int = binascii.crc32(old_data) & 0xFFFFFFFF
		
		if new_crc32_int == old_crc32_int : return True
		
		xn += 1
		new_name = "%s%s%s.%s" % (name_root, name_tail, xn, name_ext)
		new_file = "%s%s" % (t_folder, new_name)
	
	return False

def get_struct(str_, off, struct):
	my_struct = struct()
	struct_len = ctypes.sizeof(my_struct)
	str_data = str_[off:off + struct_len]
	fit_len = min(len(str_data), struct_len)
	
	if fit_len < struct_len:
		raise Exception(col_red + "\nError, cannot read struct: %d bytes available but %d required!\n" % (fit_len, struct_len) + col_end)
	
	ctypes.memmove(ctypes.addressof(my_struct), str_data, fit_len)
	
	return my_struct

def amd_padd(padd_bgn, max_padd, amd_size, ibv_size, com_size) :
	for padd_off in range(padd_bgn, padd_bgn + max_padd) :
		if reading[padd_off:padd_off + 1] != b'\x00' :
			if padd_off < (padd_bgn + amd_size) : mc_len = amd_size # Official size
			else : mc_len = ibv_size # Also a size found in BIOS			
			break # triggers "else"
	else : mc_len = com_size # Usual size found in BIOS
	
	return mc_len
	
# MCE Version Header
def mce_hdr() :
	db_rev = "None"
	try :
		fw_db = db_open()
		for line in fw_db :
			if 'Revision' in line :
				db_line = line.split()
				db_rev = db_line[2]
		fw_db.close()
	except :
		pass
		
	print("\n-------[ %s ]-------" % title)
	print("            Database  %s" % db_rev)

def init_file(in_file,orig_file,temp) :
	mc_file_name = ''
	
	if not os.path.isfile(in_file) :
		if any(p in in_file for p in param.all) : return ('continue','continue')
		
		print(col_red + "\nError" + col_end + ", file %s was not found!\n" % ascii(in_file))
		
		if not param.mass_scan : mce_exit(1)
		else : return ('continue','continue')

	with open(in_file, 'rb') as work_file : reading = work_file.read()
	
	if not temp :
		if not param.mce_extr : print("\nFile: %s\n" % ascii(os.path.basename(in_file)))
		if param.print_file : mc_file_name = '__%s' % os.path.basename(in_file)
	else :
		if param.print_file : mc_file_name = '__%s' % os.path.basename(orig_file)
	
	return (reading,mc_file_name)

# Force string to be printed as ASCII, ignore errors
def ascii(string) :
	# Input string is bare and only for printing (no open(), no Colorama etc)
	ascii_str = (str((string).encode('ascii', 'ignore'))).strip("b'")
	return ascii_str
	
def mass_scan(f_path) :
	mass_files = []
	for root, dirs, files in os.walk(f_path, topdown=False):
		for name in files :
			mass_files.append(os.path.join(root, name))
			
	input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
	return mass_files
	
# Get script location
mce_dir = get_script_dir()

# Set DB location
db_path = mce_dir + "\\" + "MCE.dat"

# Get MCE Parameters from input
param = MCE_Param(sys.argv)

# Enumerate parameter input
arg_num = len(sys.argv)

# Actions for MCE but not UEFIStrip
if param.mce_extr : pass
else : win32console.SetConsoleTitle(title) # Set console window title

if not param.skip_intro :
	mce_hdr()

	print("\nWelcome to Intel, AMD & VIA Microcode Extractor\n")

	arg_num = len(sys.argv)

	if arg_num == 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFile:       " + col_green + "%s" % ascii(os.path.basename(sys.argv[1])) + col_end)
	elif arg_num > 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFiles:       " + col_yellow + "Multiple" + col_end)
	else :
		print('Input a filename or "filepath" or press Enter to list options\n')
		print("\nFile:       " + col_magenta + "None" + col_end)

	input_var = input('\nOption(s):  ')

	# Anything quoted ("") is taken as one (file paths etc)
	input_var = re.split(''' (?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', input_var.strip())
	
	# Get MCE Parameters based on given Options
	param = MCE_Param(input_var)
	
	# Non valid parameters are treated as files
	if input_var[0] != "" :
		for i in input_var:
			if i not in param.all :
				(sys.argv).append(i.strip('"'))
	
	# Re-enumerate parameter input
	arg_num = len(sys.argv)
	
	os.system('cls')

	mce_hdr()

if (arg_num < 2 and not param.help_scr and not param.mass_scan) or param.help_scr :
	mce_help()
	mce_exit(0)

# Pause after any unexpected python exception
if param.exc_pause : sys.excepthook = show_exception_and_exit

if param.mass_scan :
	in_path = input('\nType the full folder path : ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable

# Check if DB exists
if not os.path.isfile(db_path) :
	print(col_red + "\nError, MCE.dat file is missing!\n" + col_end)
	mce_exit(1)
	
for in_file in source :

	# MC Variables
	mc_nr = 0
	type_conv = ''
	unk_size = False
	temp_file = None
	mc_bgn_list_a = []
	match_list_i = []
	match_list_a = []
	match_list_v = []
	mc_conv_data = bytearray()
	
	reading,mc_file_name = init_file(in_file,in_file,False)
	if reading == 'continue' : continue # Input is parameter, next file
	
	# Convert Intel containers (.dat , .inc , .h , .txt) to .bin
	if param.conv_cont :
		mc_f_ex = open(in_file, "r")
		
		temp_file = tempfile.NamedTemporaryFile(mode='ab', delete=False) # No auto delete for use at init_file
		
		try :
			for line in mc_f_ex :
				if type_conv == '' :
					if '/+++' in line[0:5] or '0x' in line[0:3] : type_conv = '.dat'
					elif line[0:4] == 'dd 0' : type_conv = '.inc'
				
				if type_conv == '.dat' :
					if line[0] == '/' : continue
					elif line[0] == ' ' : line = line[1:]
					
					if len(line) == 48 : # "0xjjjjjjjj,	0xjjjjjjjj,	0xjjjjjjjj,	0xjjjjjjjj,"
						wlp = line.strip().split(',')
						for i in range(0,4) :
							wlp[i] = wlp[i].replace('\t','').replace('0x','').replace(' ','')
							code = int.from_bytes(binascii.unhexlify(wlp[i]), 'little') # Int from BE bytes
							mc_conv_data += bytes.fromhex('%0.8X' % code)
					elif len(line) == 12 : # "0xjjjjjjjj,"
						wlp = str.encode(line[2:10]) # Hex string to bytes
						wlp = int.from_bytes(binascii.unhexlify(wlp), 'little')
						mc_conv_data += bytes.fromhex('%0.8X' % wlp)
						
				elif type_conv == '.inc' :
					if len(line) >= 14 : # "bb 0jjjjjjjjh"
						wlp = str.encode(line[4:12])
						wlp = int.from_bytes(binascii.unhexlify(wlp), 'little')
						mc_conv_data += bytes.fromhex('%0.8X' % wlp)
			
			if type_conv == '' : raise
		
			temp_file.write(mc_conv_data)
			
			reading,mc_file_name = init_file(temp_file.name,in_file,True)
			if reading == 'continue' : continue
		
		except :
			print(col_red + 'Error converting Intel container!\n' + col_end)
	
	# Intel Microcodes
	
	# CPUID 0306F2 = 03 + 06 + F2 = (1 + 4) + (2 + 5) + (3 + 6) = 06 (Family) + 3F (Model) + 02 (Stepping) = MU 063F02
	# MU 063F02 = 06 + 3F + 02 = (1 + 3 + 5) + (2 + 4 + 6) = 030 + 6F2 = CPUID 0306F2
	
	if not param.exp_check :
		# Intel 64 and IA-32 Architectures Software Developer's Manual [325462, 06/2016] (Vol 3A, Ch 9.11.1, Page 2954)
		# HeaderRev 01, LoaderRev 01, ProcesFlags xx00*3
		pat_icpu = re.compile(br'\x01\x00{3}.{4}[\x00-\x99](([\x19-\x20][\x01-\x31][\x01-\x12])|(\x18\x07\x00)).{8}\x01\x00{3}.\x00{3}', re.DOTALL)
	else :
		# HeaderRev 01-02, LoaderRev 01-02, ProcesFlags xxxx00*2, Reserved xx*12
		pat_icpu = re.compile(br'(\x01|\x02)\x00{3}.{4}[\x00-\x99](([\x19-\x20][\x01-\x31][\x01-\x12])|(\x18\x07\x00)).{8}(\x01|\x02)\x00{3}.{2}\x00{2}', re.DOTALL)
	
	match_list_i += pat_icpu.finditer(reading)
	
	for match_ucode in match_list_i :
		
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_hdr = get_struct(reading, mc_bgn, Intel_MC_Header)
		
		patch = '%0.8X' % mc_hdr.UpdateRevision
		
		year = '%0.4X' % mc_hdr.Year
		
		day = '%0.2X' % mc_hdr.Day
		
		month = '%0.2X' % mc_hdr.Month
		
		cpu_id = '%0.8X' % mc_hdr.ProcessorSignature
		
		plat_db = '%0.8X' % mc_hdr.ProcessorFlags
		plat_cut = '%0.2X' % mc_hdr.ProcessorFlags
		
		mc_len = mc_hdr.TotalSize
		if mc_len == 0 : mc_len = 2048
		mc_len_db = '%0.8X' % mc_len
		
		mc_chk = '%0.8X' % mc_hdr.Checksum
		
		res_field = mc_hdr.Reserved1 + mc_hdr.Reserved2 + mc_hdr.Reserved3
		
		full_date = "%s-%s-%s" % (day, month, year)
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%d-%m-%Y')
			if date_chk.year > 2016 or date_chk.year < 1993 : raise DateErr('WrongDate') # 1st MC from 1995 (P6), 1993 for safety
		except :
			if full_date == '07-00-1896' and patch == '000000D1' : pass # Drunk employee #1, Happy 0th month from 19th century Intel!
			else :
				print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, invalid Date of %s!\n" % (mc_bgn, full_date) + col_end)
				continue
		
		# Remove false results, based on Reserved field
		if res_field != 0 :
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, Reserved field not empty!\n" % (mc_bgn) + col_end)
			continue
			
		# Remove false results, based on data
		if reading[mc_bgn + 0x90:mc_bgn + 0x94] == b'\x00' * 4 : # 0x90 is either encrypted data (old MC) or RSA PKEY (Extra Header)
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, null data at 0x90!\n" % (mc_bgn) + col_end)
			continue
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()

			if reading[mc_bgn + 0x30:mc_bgn + 0x38] == b'\x00' * 4 + b'\xA1' + b'\x00' * 3 :
				mc_hdr_extra = get_struct(reading, mc_bgn + 0x30, Intel_MC_Header_Extra)
				mc_hdr_extra.mc_print_extra()
			
			if mc_hdr.TotalSize > mc_hdr.DataSize + 0x30 :
				mc_extended_off = mc_bgn + 0x30 + mc_hdr.DataSize
				mc_hdr_extended = get_struct(reading, mc_extended_off, Intel_MC_Header_Extended)
				mc_hdr_extended.mc_print_extended()
				
				mc_extended_field_off = mc_ext_off + 0x14
				
				for idx in range(mc_hdr_ext.ExtendedSignatureCount) :
					
					mc_hdr_extended_field = get_struct(reading, mc_extended_field_off, Intel_MC_Header_Extended_Field)
					mc_hdr_extended_field.mc_print_extended_field()
					mc_extended_field_off += 0x0C
					
			continue # Next MC of input file
		
		db_entry = '%s%s%s%s%s%s%s%s' % (cpu_id, plat_db, patch, month, day, year, mc_len_db, mc_chk) # mCodeInfo compatible format
		
		if param.build_db :
			with open(mce_dir + "\\" + 'MCE_DB_INTEL.txt', 'a') as db_file : db_file.write(db_entry + '\n')
			continue # Next MC of input file
		
		mc_name = "cpu%s_plat%s_ver%s_date%s" % (cpu_id, plat_cut, patch, full_date)
		mc_nr += 1
		
		print("%0.2d. %s , Size 0x%X , Offset 0x%0.2X" % (mc_nr, mc_name, mc_len, mc_bgn))
		
		mc_end = mc_bgn + mc_len
		mc_data = reading[mc_bgn:mc_end]
		valid_chk = checksum32(mc_data)
		
		# Create extraction folder
		if '-extr' in sys.argv : mc_extract = mce_dir + "\\" + '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + "\\" + 'MC_Extract\\Intel\\'
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if valid_chk != 0 :
			if patch == '000000FF' and cpu_id == '000506E3' and full_date == '05-01-2016' : # Someone "fixed" the modded MC checksum wrongfully
				mc_path = mc_extract + "%s.bin" % mc_name
			else :
				print(col_magenta + '\nWarning: This microcode is packed or badly extracted, please report it!\n' + col_end)
				mc_path = mc_extract + "!Bad_%s%s.bin" % (mc_name,mc_file_name)	
		elif db_search(db_entry) == 'No' :
			print(col_yellow + "\nNote: This microcode was not found at the database, please report it!\n" + col_end)
			mc_path = mc_extract + "!New_%s%s.bin" % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + "%s.bin" % mc_name
		
		if not has_duplicate(mc_path, mc_data) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)
	
	# AMD Microcodes
	
	# CPUID 610F21 = 61 + 0F + 21  = (1 + 4) + (2 + 5) + (3 + 6) = 6+F + 12 + 01 = 15 + 12 + 01 = MU 151201
	# MU 151201 = 15 + 12 + 01 = 6+F + 12 + 01 = (1 + 3 + 5) + (2 + 4 + 6) = 610 + F21 = CPUID 610F21
	
	# UEFI patterns
	pat_acpu_1 = re.compile(br'\x24\x55\x43\x4F\x44\x45((\x56\x53)|(\x32\x4B)|(\x34\x4B))') # $UCODEVS, $UCODE2K, $UCODE4K
	match_list_a += pat_acpu_1.finditer(reading)
	
	# 1st MC from 1999 (K7), 2000 due to K7 Erratum and performance
	if not param.exp_check :
		# BIOS pattern
		pat_acpu_2 = re.compile(br'[\x00-\x18]\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x03]\x80.{18}[\x00-\x01](\xAA|\x00){3}', re.DOTALL)
		match_list_a += pat_acpu_2.finditer(reading)
	else :
		# Data Rev 00-09, Reserved AA or 00, API 00-09
		pat_acpu_3 = re.compile(br'[\x00-\x18]\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x09]\x80.{18}[\x00-\x09](\xAA|\x00){3}', re.DOTALL)
		match_list_a += pat_acpu_3.finditer(reading)
	
	for match_ucode in match_list_a :
		
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		if reading[mc_bgn:mc_bgn + 6] == b'$UCODE' : mc_bgn += 8
		
		if mc_bgn in mc_bgn_list_a : continue # Already covered by one of the previous patterns
		else : mc_bgn_list_a.append(mc_bgn) # To not check again by a different pattern
		
		mc_hdr = get_struct(reading, mc_bgn, AMD_MC_Header)
		
		patch = '%0.8X' % mc_hdr.PatchId
		
		data_len = '%0.2X' % mc_hdr.DataLen
		
		year = '%0.4X' % (mc_hdr.Date & 0xFFFF)
		
		day = '%0.2X' % (mc_hdr.Date >> 16 & 0xFF)
		
		month = '%0.2X' % (mc_hdr.Date >> 24)
		
		cpu_id = '%0.4X' % mc_hdr.ProcessorRevId
		cpu_id = '00' + cpu_id[:2] + "0F" + cpu_id[2:] # Thank you AMD for a useless header
		
		mc_chk = mc_hdr.DataChecksum
		mc_chk_hex = '%0.8X' % mc_chk
		
		nb_id = '%0.8X' % mc_hdr.NbDevId
		
		sb_id = '%0.8X' % mc_hdr.SbDevId
		
		nbsb_rev_id = '%0.2X' % mc_hdr.NbRevId + '%0.2X' % mc_hdr.SbRevId
		
		full_date = "%s-%s-%s" % (day, month, year)

		# Remove false results, based on Date
		if full_date == '09-13-2011' and patch == '03000027' : pass # Drunk employee #2, Happy 13th month from AMD!
		elif month == '13' or year > '2016' :
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, invalid Date of %s!\n" % (mc_bgn, full_date) + col_end)
			continue
		
		# Remove false results, based on VEN_IDs
		if (nb_id != '0'*8 and '1002' not in nb_id[4:8] and '1022' not in nb_id[4:8]) \
		or (sb_id != '0'*8 and '1002' not in sb_id[4:8] and '1022' not in sb_id[4:8]) :
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, invalid VEN_IDs of %s,%s!\n" % (mc_bgn, nb_id[4:8], sb_id[4:8]) + col_end)
			continue
		
		# Remove false results, based on Data Length
		if data_len not in ['10','20','00'] :
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, Data Length not standard!\n" % (mc_bgn) + col_end)
			continue
		
		# Remove false results, based on data
		if reading[mc_bgn + 0x40:mc_bgn + 0x44] == b'\x00' * 4 : # 0x40 has non-null data
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, null data at 0x40!\n" % (mc_bgn) + col_end)
			continue
		
		# Print the Header
		if param.print_hdr :
			mc_hdr.mc_print()
			continue
		
		if data_len == '20' : # 00, 01, 02, 10, 12, 30
			mc_len_amd = 0x3C0
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x440, 0x3C0, 0x400, 0x800)
			else : mc_len = mc_len_amd
			
		elif data_len == '10' : # 04, 06, 0C, 20
			mc_len_amd = 0x200
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x600, 0x200, 0x400, 0x800)
			else : mc_len = mc_len_amd
			
		elif cpu_id[2:4] in ['50'] :
			mc_len_amd = 0x620
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x1E0, 0x620, 0x620, 0x800)
			else : mc_len = mc_len_amd
			
		elif cpu_id[2:4] in ['58'] :
			mc_len_amd = 0x567
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x299, 0x567, 0x567, 0x800)
			else : mc_len = mc_len_amd
			
		elif cpu_id[2:4] in ['60', '61', '63', '66', '67'] :
			mc_len_amd = 0xA20
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x5E0, 0xA20, 0xA20, 0x1000) # Assumed common size
			else : mc_len = mc_len_amd
			
		elif cpu_id[2:4] in ['68'] :
			mc_len_amd = 0x980
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x680, 0x980, 0x980, 0x1000) # Assumed common size
			else : mc_len = mc_len_amd
			
		elif cpu_id[2:4] in ['70', '73'] :
			mc_len_amd = 0xD60
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x20, 0xD60, 0xD60, 0xD80)
			else : mc_len = mc_len_amd
			
		else :
			unk_size = True
		
		mc_name = "cpu%s_nb%s_sb%s_rev%s_ver%s_date%s" % (cpu_id, nb_id, sb_id, nbsb_rev_id, patch, full_date)
		mc_nr += 1
		
		if unk_size :
			mc_len_db = '00000000'
			print(col_red + "\n%0.2d. Error: %s not extracted at 0x%0.2X, unknown Size!\n" % (mc_nr, mc_name, mc_bgn) + col_end)
			continue
		else :
			mc_len_db = '%0.8X' % mc_len_amd
		
		mc_extr = reading[mc_bgn:mc_bgn + mc_len]
		mc_data = reading[mc_bgn:mc_bgn + mc_len_amd]
		mc_file_chk = '%0.8X' % adler32(mc_data) # Custom Data-only Checksum
		valid_chk = checksum32(mc_extr[0x40:]) # AMD File Checksum (Data+Padding)
		
		db_entry = '%s%s%s0000%s%s%s%s%s%s%s%s' % (cpu_id, nb_id, sb_id, nbsb_rev_id, patch, month, day, year, mc_len_db, mc_chk_hex, mc_file_chk)
		
		if param.build_db :
			with open(mce_dir + "\\" + 'MCE_DB_AMD.txt', 'a') as db_file : db_file.write(db_entry + '\n')
			continue # Next MC of input file
		
		print("%0.2d. %s , Size 0x%X , Offset 0x%0.2X" % (mc_nr, mc_name, mc_len, mc_bgn))
		
		# Create extraction folder
		if '-extr' in sys.argv : mc_extract = mce_dir + "\\" + '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + "\\" + 'MC_Extract\\AMD\\'
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if int(cpu_id[2:4], 16) < 0x50 and (valid_chk + mc_chk) & 0xFFFFFFFF != 0 :
			print(col_magenta + '\nWarning: This microcode is packed or badly extracted, please report it!\n' + col_end)
			mc_path = mc_extract + "!Bad_%s%s.bin" % (mc_name,mc_file_name)
		elif db_search(db_entry) == 'No' :
			print(col_yellow + "\nNote: This microcode was not found at the database, please report it!\n" + col_end)
			mc_path = mc_extract + "!New_%s%s.bin" % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + "%s.bin" % mc_name
		
		if not has_duplicate(mc_path, mc_extr) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_extr)
			
	# VIA Microcodes
	
	# 000006F1 = VIA ???
	# 000006F2 = VIA Nano 1000/2000
	# 000006F3 = VIA Nano 1000/2000
	# 000006F8 = VIA Nano 3000 rev B0
	# 000006FA = VIA Nano 3000 rev B2
	# 000006FC = VIA Nano X2/QuadCore
	# 000006FD = VIA ???
	# 000006FE = VIA Eden X4
	# 00010690 = VIA C4610 ??? (EPIA-M920,EPIA-P910,EPIA-E900,AMOS-3005,VIPRO VP7910,ARTiGO A1250)
	
	if not param.exp_check :
		# Signature RRAS, Loader Revision 01, Reserved FF
		pat_vcpu = re.compile(br'\x52\x52\x41\x53.{16}\x01\x00{3}\xFF{4}', re.DOTALL)
	else :
		# Signature RRAS, Reserved FF
		pat_vcpu = re.compile(br'\x52\x52\x41\x53.{20}\xFF{4}', re.DOTALL)
	
	match_list_v += pat_vcpu.finditer(reading)
	
	for match_ucode in match_list_v :
		
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_hdr = get_struct(reading, mc_bgn, VIA_MC_Header)
		
		patch = '%0.2X' % mc_hdr.UpdateRevision
		patch_db = '%0.8X' % mc_hdr.UpdateRevision
		
		year = '%0.4d' % mc_hdr.Year
		
		day = '%0.2d' % mc_hdr.Day
		
		month = '%0.2d' % mc_hdr.Month
		
		cpu_id = '%0.8X' % mc_hdr.ProcessorSignature
		
		mc_len = mc_hdr.TotalSize
		mc_len_db = '%0.8X' % mc_len
		
		mc_chk = '%0.8X' % mc_hdr.Checksum
		
		name = '%s' % str(mc_hdr.Name).strip("b'")
		
		full_date = "%s-%s-%s" % (day, month, year)
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%d-%m-%Y')
			if date_chk.year > 2016 or date_chk.year < 2006 : raise DateErr('WrongDate') # 1st MC from 2008 (Nano), 2006 for safety
		except :
			# VIA is sober? No drunk employee #3 ???
			print(col_magenta + "\nWarning: Skipped microcode at 0x%0.2X, invalid Date of %s!\n" % (mc_bgn, full_date) + col_end)
			continue
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			continue
		
		db_entry = '%s%s%s%s%s%s%s%s' % (cpu_id, name, patch_db, month, day, year, mc_len_db, mc_chk)
		
		if param.build_db :
			with open(mce_dir + "\\" + 'MCE_DB_VIA.txt', 'a') as db_file : db_file.write(db_entry + '\n')
			continue
		
		mc_name = "cpu%s_sig%s_ver%s_size%s_date%s" % (cpu_id, name, patch, mc_len_db, full_date)
		mc_nr += 1
		
		print("%0.2d. %s , Size 0x%X , Offset 0x%0.2X" % (mc_nr, mc_name, mc_len, mc_bgn))
		
		mc_end = mc_bgn + mc_len
		mc_data = reading[mc_bgn:mc_end]
		valid_chk = checksum32(mc_data)
		
		# Create extraction folder
		if '-extr' in sys.argv : mc_extract = mce_dir + "\\" + '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + "\\" + 'MC_Extract\\VIA\\'
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if valid_chk != 0 :
			print(col_magenta + '\nWarning: This microcode is packed or badly extracted, please report it!\n' + col_end)
			mc_path = mc_extract + '!Bad_%s%s.bin' % (mc_name,mc_file_name)
		elif db_search(db_entry) == 'No' :
			print(col_yellow + '\nNote: This microcode was not found at the database, please report it!\n' + col_end)
			mc_path = mc_extract + '!New_%s%s.bin' % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + '%s.bin' % mc_name
		
		if not has_duplicate(mc_path, mc_data) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)

	if temp_file is not None :
		temp_file.close()
		os.remove(temp_file.name)

mce_exit(0)