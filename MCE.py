#!/usr/bin/env python3

"""
MC Extractor
Intel, AMD, VIA & Freescale Microcode Extractor
Copyright (C) 2016-2018 Plato Mavropoulos
"""

title = 'MC Extractor v1.24.2'

import os
import re
import sys
import zlib
import time
import struct
import shutil
import ctypes
import inspect
import sqlite3
import colorama
import binascii
import datetime
import traceback
import prettytable

colorama.init()
col_r = colorama.Fore.RED + colorama.Style.BRIGHT
col_g = colorama.Fore.GREEN + colorama.Style.BRIGHT
col_b = colorama.Fore.BLUE + colorama.Style.BRIGHT
col_y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
col_m = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
col_c = colorama.Fore.CYAN + colorama.Style.BRIGHT
col_e = colorama.Fore.RESET + colorama.Style.RESET_ALL

# Detect OS platform
mce_os = sys.platform
if mce_os == 'win32' :
	cl_wipe = 'cls'
elif mce_os.startswith('linux') or mce_os == 'darwin' or mce_os.find('bsd') != -1  :
	cl_wipe = 'clear'
else :
	print(col_r + '\nError: ' + col_e + 'Unsupported platform "%s"!\n' % mce_os)
	if ' -exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)

# Detect Python version
mce_py = sys.version_info
try :
	assert mce_py >= (3,6)
except :
	print(col_r + '\nError: ' + col_e + 'Python >= 3.6 required, not %d.%d!\n' % (mce_py[0],mce_py[1]))
	if ' -exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)

cur_count = 0
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

def mce_help() :
	
	text = "\nUsage: MCE [FilePath] {Options}\n\n{Options}\n\n"
	text += "-?      : Displays help & usage screen\n"
	text += "-skip   : Skips welcome & options screen\n"
	text += "-exit   : Skips Press enter to exit prompt\n"
	text += "-redir  : Enables console redirection support\n"
	text += "-mass   : Scans all files of a given directory\n"
	text += "-info   : Displays microcode header(s)\n"
	text += "-add    : Adds new input microcode to DB\n"
	text += "-dbname : Renames input file based on DB name\n"
	text += "-cont   : Extracts Intel containers (dat,inc,h,txt)\n"
	text += "-search : Searches for microcodes based on CPUID\n"
	text += "-last   : Shows Latest status based on user input\n"
	text += "-repo   : Builds microcode repositories from input"
	
	print(text)
	mce_exit()

class MCE_Param :

	def __init__(self,source) :
	
		self.all = ['-?','-skip','-info','-add','-extr','-cont','-mass','-search','-dbname','-repo','-exit','-ubutest','-redir','-blob','-last']
		self.win = ['-extr'] # Windows only
		
		if mce_os == 'win32' : self.val = self.all
		else : self.val = [item for item in self.all if item not in self.win]
		
		self.help_scr = False
		self.build_db = False
		self.skip_intro = False
		self.print_hdr = False
		self.mce_extr = False
		self.conv_cont = False
		self.mass_scan = False
		self.search = False
		self.give_db_name = False
		self.build_repo = False
		self.ubu_test = False
		self.skip_pause = False
		self.cli_redirect = False
		self.build_blob = False
		self.print_last = False
		
		for i in source :
			if i == '-?' : self.help_scr = True
			if i == '-skip' : self.skip_intro = True
			if i == '-add' : self.build_db = True
			if i == '-info' : self.print_hdr = True
			if i == '-cont' : self.conv_cont = True
			if i == '-mass' : self.mass_scan = True
			if i == '-search' : self.search = True
			if i == '-dbname' : self.give_db_name = True
			if i == '-repo' : self.build_repo = True
			if i == '-ubutest' : self.ubu_test = True # Hidden (TBD)
			if i == '-exit' : self.skip_pause = True
			if i == '-redir' : self.cli_redirect = True
			if i == '-blob' : self.build_blob = True # Hidden (TBD)
			if i == '-last' : self.print_last = True
			
			# Windows only options
			if mce_os == 'win32' :
				if i == '-extr': self.mce_extr = True # Hidden
			
		if self.mce_extr or self.mass_scan or self.search or self.build_repo or self.conv_cont or self.build_blob or self.print_last : self.skip_intro = True
		if self.conv_cont : self.give_db_name = False
		if self.mce_extr : self.cli_redirect = True
		if self.cli_redirect or self.print_last : self.skip_pause = True

# noinspection PyTypeChecker
class Intel_MC_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("HeaderVersion",             uint32_t),  # 00 00000001 (Pattern)
		("UpdateRevision",            uint32_t),  # 04 Signed to signify PRD/PRE
		("Year",                      uint16_t),  # 08
		("Day",                       uint8_t),   # 0A
		("Month",                     uint8_t),   # 0B
		("ProcessorSignature",        uint32_t),  # 0C
		("Checksum",                  uint32_t),  # 10 OEM validation only
		("LoaderRevision",            uint32_t),  # 14 00000001 (Pattern)
		("ProcessorFlags",            uint8_t),   # 18 Supported Platforms
		("Reserved0",                 uint8_t*3), # 19 000000 (Pattern)
		("DataSize",                  uint32_t),  # 1C Extra + Patch
		("TotalSize",                 uint32_t),  # 20 Header + Extra + Patch + Extended
		("Reserved1",                 uint32_t),  # 24 00000000 (Pattern)
		("Reserved2",                 uint32_t),  # 28 00000000 (Pattern)
		("Reserved3",                 uint32_t),  # 2C 00000000 (Pattern)
		# 30
	]

	def mc_print(self) :
		Reserved0 = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		
		if self.Reserved1 == self.Reserved2 == self.Reserved3 == 0 : reserv_str = '0x0'
		else : reserv_str = '%0.8X %0.8X %0.8X' % (self.Reserved1, self.Reserved2, self.Reserved3)
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Main' + col_e
		pt.add_row(['Header Version', '%d' % self.HeaderVersion])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
		pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		pt.add_row(['Loader Version', '%d' % self.LoaderRevision])
		pt.add_row(['Platform', '%0.2X (%s)' % (self.ProcessorFlags, ','.join(map(str, intel_plat(mc_hdr.ProcessorFlags))))])
		pt.add_row(['Reserved', '0x0' if Reserved0 == '000000' else Reserved0])
		pt.add_row(['Data Size', '0x%X' % self.DataSize])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['Reserved', reserv_str])
		
		print(pt)

# noinspection PyTypeChecker
class Intel_MC_Header_Extra(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("ModuleType",                uint16_t),    # 00 0000 (always)
		("ModuleSubType",             uint16_t),    # 02 0000 (always)
		("ModuleSize",			      uint32_t),    # 04 dwords
		("Flags",                     uint16_t),    # 08 0 RSA Signed, 1-31 Reserved
		("Unknown1",                  uint16_t),    # 0A 0002 (always)
		("UpdateRevision",            uint32_t),    # 0C Signed to signify PRD/PRE
		("VCN",                  	  uint32_t),    # 10 Version Control Number
		("MultiPurpose1",     	      uint32_t),    # 14 dwords from Extra, UpdateSize, Empty etc
		("Day",                       uint8_t),     # 18
		("Month",                     uint8_t),     # 19
		("Year",                      uint16_t),    # 1A
		("UpdateSize",                uint32_t),    # 1C dwords from Extra without encrypted padding
		("ProcessorSignatureCount",   uint32_t),    # 20 max is 8 (8 * 0x4 = 0x20)
		("ProcessorSignature0",       uint32_t),    # 24
		("ProcessorSignature1",		  uint32_t),    # 28
		("ProcessorSignature2",		  uint32_t),    # 2C
		("ProcessorSignature3",		  uint32_t),    # 30
		("ProcessorSignature4",		  uint32_t),    # 34
		("ProcessorSignature5",		  uint32_t),    # 38
		("ProcessorSignature6",		  uint32_t),    # 3C
		("ProcessorSignature7",		  uint32_t),    # 40
		("MultiPurpose2",      	      uint32_t),    # 44 dwords from Extra + encrypted padding, UpdateSize, Platform, Empty
		("SVN",     				  uint32_t),    # 48 Security Version Number
		("Reserved",                  uint32_t*5),  # 4C Reserved (00000000)
		("Unknown2",                  uint32_t*8),  # 60 256-bit hash probably
		("RSAPublicKey",              uint32_t*64), # 80
		("RSAExponent",               uint32_t),    # 180 0x11 = 17 (always)
		("RSASignature",              uint32_t*64), # 184
		# 284
	]

	def mc_print_extra(self) :
		print()
		
		f1,f2 = self.get_flags()
		
		Reserved = int.from_bytes(self.Reserved, 'little')
		Unknown2 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown2))
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extra' + col_e
		pt.add_row(['Module Type', '%d' % self.ModuleType])
		pt.add_row(['Module Sub Type', '%d' % self.ModuleSubType])
		pt.add_row(['Module Size', '0x%X' % (self.ModuleSize * 4)])
		pt.add_row(['RSA Signed', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '0x%X' % f2])
		pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Version Control Number', '%d' % self.VCN])
		if self.MultiPurpose1 == mc_hdr.ProcessorFlags : pt.add_row(['Platform (MP1)', '%0.2X (%s)' % (self.MultiPurpose1, ','.join(map(str, intel_plat(mc_hdr.ProcessorFlags))))])
		elif self.MultiPurpose1 * 4 == self.UpdateSize * 4 : pt.add_row(['Update Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
		elif self.MultiPurpose1 * 4 == file_end - 0x30 : pt.add_row(['Padded Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
		else : pt.add_row(['Multi Purpose 1', '0x%X' % self.MultiPurpose1])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
		pt.add_row(['Update Size', '0x%X' % (self.UpdateSize * 4)])
		pt.add_row(['CPU Signatures', '%d' % self.ProcessorSignatureCount])
		if self.ProcessorSignature0 != 0 : pt.add_row(['CPUID 0', '%0.5X' % self.ProcessorSignature0])
		if self.ProcessorSignature1 != 0 : pt.add_row(['CPUID 1', '%0.5X' % self.ProcessorSignature1])
		if self.ProcessorSignature2 != 0 : pt.add_row(['CPUID 2', '%0.5X' % self.ProcessorSignature2])
		if self.ProcessorSignature3 != 0 : pt.add_row(['CPUID 3', '%0.5X' % self.ProcessorSignature3])
		if self.ProcessorSignature4 != 0 : pt.add_row(['CPUID 4', '%0.5X' % self.ProcessorSignature4])
		if self.ProcessorSignature5 != 0 : pt.add_row(['CPUID 5', '%0.5X' % self.ProcessorSignature5])
		if self.ProcessorSignature6 != 0 : pt.add_row(['CPUID 6', '%0.5X' % self.ProcessorSignature6])
		if self.ProcessorSignature7 != 0 : pt.add_row(['CPUID 7', '%0.5X' % self.ProcessorSignature7])
		if self.MultiPurpose2 == mc_hdr.ProcessorFlags : pt.add_row(['Platform (MP2)', '%0.2X (%s)' % (self.MultiPurpose2, ','.join(map(str, intel_plat(mc_hdr.ProcessorFlags))))])
		elif self.MultiPurpose2 * 4 == self.UpdateSize * 4 : pt.add_row(['Update Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
		elif self.MultiPurpose2 * 4 == file_end - 0x30 : pt.add_row(['Padded Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
		else : pt.add_row(['Multi Purpose 2', '0x%X' % self.MultiPurpose2])
		pt.add_row(['Security Version Number', '%d' % self.SVN])
		pt.add_row(['Reserved', '0x%X' % Reserved])
		pt.add_row(['Unknown 2', '%s [...]' % Unknown2[:8]])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		print(pt)
	
	def get_flags(self) :
		flags = Intel_MC_Header_Extra_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.RSASigned, flags.b.Reserved
		
class Intel_MC_Header_Extra_Flags(ctypes.LittleEndianStructure):
	_fields_ = [
		('RSASigned', uint16_t, 1), # RSA Signature usage
		('Reserved', uint16_t, 7)
	]
	
class Intel_MC_Header_Extra_GetFlags(ctypes.Union):
	_fields_ = [
		('b', Intel_MC_Header_Extra_Flags),
		('asbytes', uint16_t)
	]

class Intel_MC_Header_Extended(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("ExtendedSignatureCount",    uint32_t),  # 00
		("ExtendedChecksum",          uint32_t),  # 04
		("Reserved1",                 uint32_t),  # 08
		("Reserved2",                 uint32_t),  # 0C
		("Reserved3",                 uint32_t),  # 10
		# 14
	]

	def mc_print_extended(self) :
		print()
		
		if self.Reserved1 == self.Reserved2 == self.Reserved3 == 0 : reserv_str = '0x0'
		else : reserv_str = '%0.8X %0.8X %0.8X' % (self.Reserved1, self.Reserved2, self.Reserved3)

		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extended' + col_e
		pt.add_row(['Extended Signatures', '%d' % self.ExtendedSignatureCount])
		pt.add_row(['Extended Checksum', '%0.8X' % self.ExtendedChecksum])
		pt.add_row(['Reserved', reserv_str])
		
		print(pt)

class Intel_MC_Header_Extended_Field(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("ProcessorSignature",        uint32_t),  # 00
		("ProcessorFlags",            uint32_t),  # 04
		("Checksum",                  uint32_t),  # 08 replace CPUID, Platform, Checksum at Main Header w/o Extended
		# 0C
	]

	def mc_print_extended_field(self) :
		print()
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extended Field' + col_e
		pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
		pt.add_row(['Platform', '%0.2X %s' % (self.ProcessorFlags, intel_plat(self.ProcessorFlags))])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		
		print(pt)

# noinspection PyTypeChecker
class AMD_MC_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Date",                      uint32_t),      # 0x00
		("UpdateRevision",            uint32_t),      # 0x04
		("LoaderID",                  uint16_t),      # 0x08 00 - 04 80 (Pattern)
		("DataSize",                  uint8_t),       # 0x0A 00, 10 or 20 (Pattern)
		("InitializationFlag",        uint8_t),       # 0x0B 00 or 01 (Pattern)
		("DataChecksum",              uint32_t),      # 0x0C OEM validation only
		("NorthBridgeVEN_ID",         uint16_t),      # 0x10 0000 or 1022 (Pattern)
		("NorthBridgeDEV_ID",         uint16_t),      # 0x12
		("SouthBridgeVEN_ID",         uint16_t),      # 0x14 0000 or 1022 (Pattern)
		("SouthBridgeDEV_ID",         uint16_t),      # 0x16
		("ProcessorSignature",        uint16_t),      # 0x18
		("NorthBridgeREV_ID",         uint8_t),       # 0x1A
		("SouthBridgeREV_ID",         uint8_t),       # 0x1B
		("BiosApiREV_ID",             uint8_t),       # 0x1C 00 or 01 (Pattern)
		("Reserved",                  uint8_t * 3),   # 0x1D 000000 or AAAAAA (Pattern)
		# 0x20
	]

	def mc_print(self) :	
		reserv_str = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_r + 'AMD Header' + col_e
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Date & 0xFFFF, self.Date >> 24, self.Date >> 16 & 0xFF)])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Loader ID', '0x%X' % self.LoaderID])
		pt.add_row(['Data Size', '0x%X' % self.DataSize])
		pt.add_row(['Initialization Flag', '0x%X' % self.InitializationFlag])
		pt.add_row(['Data Checksum', '%0.8X' % self.DataChecksum])
		pt.add_row(['NorthBridge Vendor ID', '0x%X' % self.NorthBridgeVEN_ID])
		pt.add_row(['NorthBridge Device ID', '0x%X' % self.NorthBridgeDEV_ID])
		pt.add_row(['SouthBridge Vendor ID', '0x%X' % self.SouthBridgeVEN_ID])
		pt.add_row(['SouthBridge Device ID', '0x%X' % self.SouthBridgeDEV_ID])
		pt.add_row(['CPUID', '%0.2X0F%0.2X' % (self.ProcessorSignature >> 8, self.ProcessorSignature & 0xFF)])
		pt.add_row(['NorthBridge Revision', '0x%X' % self.NorthBridgeREV_ID])
		pt.add_row(['SouthBridge Revision', '0x%X' % self.SouthBridgeREV_ID])
		pt.add_row(['BIOS API Revision', '0x%X' % self.BiosApiREV_ID])
		pt.add_row(['Reserved', reserv_str])
		
		print(pt)

# noinspection PyTypeChecker
class VIA_MC_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Signature",                 char*4),    # 00 RRAS (Pattern)
		("UpdateRevision",            uint32_t),  # 04
		("Year",                      uint16_t),  # 08
		("Day",                       uint8_t),   # 0A
		("Month",                     uint8_t),   # 0B
		("ProcessorSignature",        uint32_t),  # 0C
		("Checksum",                  uint32_t),  # 10 OEM validation only
		("LoaderRevision",            uint32_t),  # 14 00000001 (Pattern)
		("CNRRevision",               uint8_t),   # 18 0 CNR001 A0, 1 CNR001 A1
		("Reserved",                  uint8_t*3), # 19 FFFFFF (Pattern)
		("DataSize",                  uint32_t),  # 1C
		("TotalSize",                 uint32_t),  # 20
		("Name",                      char*12),   # 24
		# 30
	]

	def mc_print(self) :		
		reserv_str = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_c + 'VIA Header' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Date', '%0.4d-%0.2d-%0.2d' % (self.Year, self.Month, self.Day)])
		pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		pt.add_row(['Loader Version', '%d' % self.LoaderRevision])
		if self.CNRRevision != 0xFF :
			pt.add_row(['CNR Revision', '001 A%d' % self.CNRRevision])
			pt.add_row(['Reserved', reserv_str])
		else :
			pt.add_row(['Reserved', 'FFFFFFFF'])
		pt.add_row(['Data Size', '0x%X' % self.DataSize])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['Name', self.Name.replace(b'\x7f', b'\x2e').decode('utf-8')])
		
		print(pt)

# noinspection PyTypeChecker		
class FSL_MC_Header(ctypes.BigEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("TotalSize",                 uint32_t),    # 00 Entire file
		("Signature",                 char*3),      # 04 QEF (Pattern)
		("HeaderVersion",             uint8_t),     # 07 01 (Pattern)
		("Name",                      char*62),     # 08 Null-terminated ID String
		("IRAM",                      uint8_t),     # 46 I-RAM (0 shared, 1 split)
		("CountMC",                   uint8_t),     # 47 Number of MC structures
		("Model",                     uint16_t),    # 48 SoC Model
		("Major",                     uint8_t),     # 4A SoC Revision Major
		("Minor",                     uint8_t),     # 4B SoC Revision Minor
		("Reserved0",                 uint32_t),    # 4C Alignment
		("ExtendedModes",             uint64_t),    # 50 Extended Modes
		("VTraps",                    uint32_t*8),  # 58 Virtual Trap Addresses
		("Reserved1",                 uint32_t),    # 78 Alignment
		# 7C
	]

	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		vtraps_str = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.VTraps))
		if vtraps_str == '00000000' * 8 : vtraps_str = '0x0'
		
		pt.title = col_y + 'Freescale Header Main' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Header Version', '%d' % self.HeaderVersion])
		pt.add_row(['I-RAM', ['Shared','Split'][self.IRAM]])
		pt.add_row(['Microcode Count', '%d' % self.CountMC])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['SoC Model', '%0.4d' % self.Model])
		pt.add_row(['SoC Major', '%d' % self.Major])
		pt.add_row(['SoC Minor', '%d' % self.Minor])
		pt.add_row(['Reserved', '0x%X' % self.Reserved0])
		pt.add_row(['Extended Modes', '0x%X' % self.ExtendedModes])
		pt.add_row(['Virtual Traps', vtraps_str])
		pt.add_row(['Reserved', '0x%X' % self.Reserved1])
		
		print(pt)
		
# noinspection PyTypeChecker		
class FSL_MC_Entry(ctypes.BigEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Name",                      char*32),     # 00 Null-terminated ID String
		("Traps",                     uint32_t*16), # 20 Trap Addresses (0 ignore)
		("ECCR",                      uint32_t),    # 60 ECCR Register value
		("IRAMOffset",                uint32_t),    # 64 Code Offset into I-RAM
		("CodeLength",                uint32_t),    # 68 dwords (*4, 1st Entry only)
		("CodeOffset",                uint32_t),    # 6C MC Offset (from 0x0, 1st Entry only)
		("Major",                     uint8_t),     # 70 Major
		("Minor",                     uint8_t),     # 71 Minor
		("Revision",                  uint8_t),     # 72 Revision
		("Reserved0",                 uint8_t),     # 73 Alignment
		("Reserved1",                 uint32_t),    # 74 Future Expansion
		# 78
	]

	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		traps_str = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Traps))
		if traps_str == '00000000' * 16 : traps_str = '0x0'
		
		pt.title = col_y + 'Freescale Header Entry' + col_e
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Traps', traps_str])
		pt.add_row(['ECCR', '0x%X' % self.ECCR])
		pt.add_row(['I-RAM Offset', '0x%X' % self.IRAMOffset])
		pt.add_row(['Code Length', '0x%X' % self.CodeLength])
		pt.add_row(['Code Offset', '0x%X' % self.CodeOffset])
		pt.add_row(['Major', '%d' % self.Major])
		pt.add_row(['Minor', '%d' % self.Minor])
		pt.add_row(['Revision', '0x%X' % self.Revision])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		print(pt)
		
# noinspection PyTypeChecker		
class MCB_Header(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		('Tag',                       char*4),      # 00 Microcode Blob Tag ($MCB)
		('MCCount',                   uint16_t),    # 04 Microcode Entry Count
		('MCEDBRev',                  uint8_t),     # 06 MCE DB Revision
		('MCEDBDev',                  uint8_t),     # 07 MCE DB Developer (0 No, 1 Yes)
		('HeaderRev',                 uint8_t),     # 08 MCB Header Revision (1)
		('MCVendor',                  uint8_t),     # 09 Microcode Vendor (0 Intel)
		('Reserved',                  uint16_t),    # 0A Reserved (0)
		('Checksum',                  uint32_t),    # 0C CRC-32 of Entries + Data
		# 0x10
	]
	
	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Microcode Blob Header' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Microcode Count', self.MCCount])
		pt.add_row(['MCE DB Revision', 'r%d' % self.MCEDBRev])
		pt.add_row(['MCE DB Developer', ['No','Yes'][self.MCEDBDev]])
		pt.add_row(['Header Revision', self.HeaderRev])
		pt.add_row(['Microcode Vendor', ['Intel'][self.MCVendor]])
		pt.add_row(['Reserved', self.Reserved])
		pt.add_row(['Checksum', '0x%0.8X' % self.Checksum])
		
		print(pt)

# noinspection PyTypeChecker		
class MCB_Entry(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		('CPUID',                     uint32_t),    # 00 CPUID
		('Platform',                  uint32_t),    # 04 Platform (Intel)
		('Revision',                  uint32_t),    # 08 Revision
		('Year',                      uint16_t),    # 0C Year
		('Month',                     uint8_t),     # 0E Month
		('Day',                       uint8_t),     # 0F Day
		('Offset',                    uint32_t),    # 10 Offset
		('Size',                      uint32_t),    # 14 Size
		('Checksum',                  uint32_t),    # 18 Checksum (Vendor/MCE)
		('Reserved',                  uint32_t),    # 1C Reserved (0)
		# 0x20
	]
	
	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Microcode Blob Entry' + col_e
		pt.add_row(['CPUID', '%0.8X' % self.CPUID])
		pt.add_row(['Platform', intel_plat(self.Platform)])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
		pt.add_row(['Offset', '0x%X' % self.Offset])
		pt.add_row(['Size', '0x%X' % self.Size])
		pt.add_row(['Checksum', '0x%0.8X' % self.Checksum])
		pt.add_row(['Reserved', self.Reserved])
		
		print(pt)

# Setup DB Tables
def create_tables():
	c.execute('CREATE TABLE IF NOT EXISTS MCE(revision INTEGER, developer INTEGER, date INTEGER)')
	c.execute('CREATE TABLE IF NOT EXISTS Intel(cpuid BLOB, platform BLOB, version BLOB, yyyymmdd TEXT, size BLOB, checksum BLOB)')
	c.execute('CREATE TABLE IF NOT EXISTS VIA(cpuid BLOB, signature TEXT, version BLOB, yyyymmdd TEXT, size BLOB, checksum BLOB)')
	c.execute('CREATE TABLE IF NOT EXISTS FSL(name TEXT, model BLOB, major BLOB, minor BLOB, size BLOB, checksum BLOB, note TEXT)')
	c.execute('CREATE TABLE IF NOT EXISTS AMD(cpuid BLOB, nbdevid BLOB, sbdevid BLOB, nbsbrev BLOB, version BLOB,\
				yyyymmdd TEXT, size BLOB, chkbody BLOB, chkmc BLOB)')
	
	conn.commit()
	
	return
		
def mce_exit(code=0) :
	if not param.mce_extr and not param.skip_pause : input("\nPress enter to exit")
	try :
		c.close()
		conn.close() # Close DB connection
	except :
		pass
	colorama.deinit() # Stop Colorama
	sys.exit(code)
	
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
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print(col_r + '\nError: MCE just crashed, please report the following:\n')
		traceback.print_exception(exc_type, exc_value, tb)
		if not param.skip_pause : input(col_e + '\nPress enter to exit')
	colorama.deinit() # Stop Colorama
	sys.exit(-1)
	
def adler32(data) :
	return zlib.adler32(data) & 0xFFFFFFFF
	
def crc32(data) :
	return zlib.crc32(data) & 0xFFFFFFFF
	
def checksum32(data) :	
	chk32 = 0
	
	for idx in range(0, len(data), 4) : # Move 4 bytes at a time
		chkbt = int.from_bytes(data[idx:idx + 4], 'little') # Convert to int
		chk32 += chkbt
	
	return -chk32 & 0xFFFFFFFF # Return 0

# Process ctypes Structure Classes
def get_struct(input_stream, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = input_stream[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset > file_end) or (fit_len < struct_len) :
		print(col_r + "Error: Offset 0x%X out of bounds, possibly incomplete image!" % start_offset + col_e)
		
		mce_exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure

def intel_plat(cpuflags) :
	platforms = []
	
	if cpuflags == 0 : # 1995-1998
		platforms.append(0)
	else:
		for bit in range(8) : # 0-7
			cpu_flag = cpuflags >> bit & 1
			if cpu_flag == 1 : platforms.append(bit)
			
	return platforms

def mc_db_name(work_file, in_file, mc_name) :
	new_dir_name = os.path.join(os.path.dirname(in_file), mc_name + '.bin')
	work_file.close()
	if not os.path.exists(new_dir_name) : os.rename(in_file, new_dir_name)
	elif os.path.basename(in_file) == mc_name + '.bin' : pass
	else : print(col_r + 'Error: ' + col_e + 'A file with the same name already exists!')

def db_new_MCE() :
	db_is_dev = (c.execute('SELECT developer FROM MCE')).fetchone()[0]
	db_rev_now = (c.execute('SELECT revision FROM MCE')).fetchone()[0]
	
	c.execute('UPDATE MCE SET date=?', (int(time.time()),))
	
	if db_is_dev == 0 :
		c.execute('UPDATE MCE SET revision=?', (db_rev_now + 1,))
		c.execute('UPDATE MCE SET developer=1')
	
def copy_file_with_warn(work_file) :
	work_file.close()
		
	file_name = os.path.basename(in_file)
	warn_dir = os.path.join(mce_dir, '__Warnings__', '')
	warn_name = os.path.join(warn_dir, file_name)
		
	if not os.path.isdir(warn_dir) : os.mkdir(warn_dir)
	
	if os.path.isfile(warn_name) : warn_name += '_%d' % cur_count
		
	shutil.copyfile(in_file, warn_name)
	
def save_mc_file(mc_path, mc_data, mc_hash) :
	if not param.ubu_test :
		if os.path.isfile(mc_path) :
			with open(mc_path, 'rb') as mc_file : found_data = mc_file.read()
			
			if mc_data == found_data : os.remove(mc_path)
			else : mc_path = '%s_%0.8X.bin' % (mc_path[:-4], mc_hash)
			
		with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)

def mc_upd_chk_intel(mc_upd_chk_rsl, in_pl_bit, in_rel) :
	is_latest = True
	mc_latest = None
	
	for entry in mc_upd_chk_rsl :
		db_day = entry[0][6:8]
		db_month = entry[0][4:6]
		db_year = entry[0][:4]
		db_pl_val = int(entry[1], 16)
		db_pl_bit = intel_plat(int(entry[1], 16))
		db_ver = int(entry[2], 16)
		db_rel = 'PRE' if ctypes.c_int(db_ver).value < 0 else 'PRD'
		
		# Same Release, Same or more Platform IDs, Newer Date, Same Date but more Platform IDs (not for -last)
		if in_rel == db_rel and set(in_pl_bit).issubset(db_pl_bit) and \
		((year < db_year or (year == db_year and (month < db_month or (month == db_month and day < db_day)))) or
		((year,month,day) == (db_year,db_month,db_day) and len(in_pl_bit) < len(db_pl_bit)) and not param.print_last) :
			is_latest = False
			mc_latest = [cpu_id, db_pl_val, db_ver, db_year, db_month, db_day, db_rel]
	
	return is_latest, mc_latest
	
def mc_upd_chk(mc_upd_chk_rsl) :
	is_latest = True
	mc_latest = None
	
	for entry in mc_upd_chk_rsl :
		db_day = entry[0][6:8]
		db_month = entry[0][4:6]
		db_year = entry[0][:4]
		db_ver = int(entry[1], 16)
		
		# Newer Date
		if year < db_year or (year == db_year and (month < db_month or (month == db_month and day < db_day))) :
			is_latest = False
			mc_latest = [cpu_id, db_ver, db_year, db_month, db_day]
	
	return is_latest, mc_latest
	
def build_mc_repo(vendor, is_latest, rel_file) :
	if is_latest and ((vendor == 'INTEL' and rel_file == 'PRD') or (vendor in ['AMD','VIA'])) :
		repo_name = os.path.basename(in_file)
		repo_dir = os.path.join(mce_dir, '__REPO_%s__' % vendor, '')
		if not os.path.isdir(repo_dir) : os.mkdir(repo_dir)
		shutil.copyfile(in_file, repo_dir + repo_name)

def mc_table(row_col_names,header,padd) :
	pt = prettytable.PrettyTable(row_col_names)
	if not param.cli_redirect : pt.set_style(prettytable.BOX_CHARS)
	pt.header = header # Boolean
	pt.left_padding_width = padd if not param.ubu_test else 0
	pt.right_padding_width = padd if not param.ubu_test else 0
	pt.hrules = prettytable.ALL
	pt.vrules = prettytable.ALL
	pt_empty = str(pt)
	
	return pt,pt_empty

def display_sql(cursor,title,header,padd):
	rows = cursor.fetchall()
	if not rows : return
	
	if param.ubu_test : padd = 0
	
	sqlr = prettytable.PrettyTable()
	sqlr.set_style(prettytable.BOX_CHARS)
	sqlr.header = header # Boolean
	sqlr.left_padding_width = padd
	sqlr.right_padding_width = padd
	sqlr.hrules = prettytable.ALL
	sqlr.vrules = prettytable.ALL
	sqlr.title = title
	
	row_id = -1
	for name in [cn[0].upper() for cn in cursor.description]:
		row_id += 1
		sqlr.add_column(name, [row[row_id] for row in rows])
	
	print('\n%s' % sqlr)
	
# MCE Version Header
def mce_hdr() :
	db_rev = col_r + 'Unknown' + col_e
	db_dev = col_r + ' Unknown' + col_e
	
	if os.path.isfile(db_path) :
		try :
			hdr_conn = sqlite3.connect(db_path)
			hdr_c = hdr_conn.cursor()
			
			hdr_c.execute('PRAGMA quick_check')
			
			hdr_res = (hdr_c.execute('SELECT revision, developer FROM MCE')).fetchone()
			db_rev = col_y + 'r' + str(hdr_res[0]) + col_e
			db_dev = hdr_res[1]
		
			if db_dev == 1 : db_dev = col_y + ' Dev' + col_e
			else : db_dev = ''
		
			hdr_c.close()
			hdr_conn.close()
		except :
			pass
	
	hdr_pt,hdr_pt_empty = mc_table([], False, 1)
	hdr_pt.add_row([col_y + '        %s' % title + col_e + ' %s%s        ' % (db_rev, db_dev)])
	print(hdr_pt)
	
def mass_scan(f_path) :
	mass_files = []
	for root, dirs, files in os.walk(f_path):
		for name in files :
			mass_files.append(os.path.join(root, name))
			
	input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
	
	return mass_files
	
# Get script location
mce_dir = get_script_dir()

# Set DB location
db_path = os.path.join(mce_dir, 'MCE.db')

# Set MCB location
mcb_path = os.path.join(mce_dir, 'MCB.bin')

# Get MCE Parameters from input
param = MCE_Param(sys.argv)

# Enumerate parameter input
arg_num = len(sys.argv)

# Actions for MCE but not UBU or UEFIStrip
if param.mce_extr or param.ubu_test :
	pass
else :
	sys.excepthook = show_exception_and_exit # Pause after any unexpected python exception
	# Set console window title
	if mce_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title)
	if mce_os.startswith('linux') or mce_os == 'darwin' or mce_os.find('bsd') != -1 :
		sys.stdout.write("\x1b]2;" + title + "\x07")

if not param.skip_intro :
	mce_hdr()

	print("\nWelcome to Intel, AMD, VIA & Freescale Microcode Extractor\n")

	arg_num = len(sys.argv)
	
	if arg_num == 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFile:       " + col_g + "%s" % os.path.basename(sys.argv[1]) + col_e)
	elif arg_num > 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFiles:       " + col_y + "Multiple" + col_e)
	else :
		print('Input a file name/path or press Enter to list options\n')
		print("\nFile:       " + col_m + "None" + col_e)

	input_var = input('\nOption(s):  ')

	# Anything quoted ("") is taken as one (file paths etc)
	input_var = re.split(''' (?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', input_var.strip())
	
	# Get MCE Parameters based on given Options
	param = MCE_Param(input_var)
	
	# Non valid parameters are treated as files
	if input_var[0] != "" :
		for i in input_var:
			if i not in param.val :
				sys.argv.append(i.strip('"'))
	
	# Re-enumerate parameter input
	arg_num = len(sys.argv)
	
	os.system(cl_wipe)

	mce_hdr()

elif not param.mce_extr and not param.print_last :
	mce_hdr()

if (arg_num < 2 and not param.help_scr and not param.mass_scan and not param.search and not param.print_last) or param.help_scr :
	mce_help()
	mce_exit()

if param.mass_scan :
	in_path = input('\nEnter the full folder path: ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable
	
# Connect to DB, if it exists
if os.path.isfile(db_path) :
	conn = sqlite3.connect(db_path)
	c = conn.cursor()
	
	try :
		c.execute('PRAGMA quick_check')
	except :
		print(col_r + "\nError: MCE.db file is corrupted!" + col_e)
		mce_exit(1)
	
	create_tables()
else :
	c = None
	conn = None
	print(col_r + "\nError: MCE.db file is missing!" + col_e)
	mce_exit(1)

# Search DB by CPUID (Intel/AMD/VIA) or Model (Freescale)
if param.search and not param.build_blob :
	if len(source) >= 2 :
		cpu_id = source[1]
	else :
		cpu_id = input('\nEnter Intel/AMD/VIA CPUID or Freescale Model: ')
	
	try :
		cpu_id = '%0.8X' % int(cpu_id, 16)
	except :
		print(col_r + '\nError: Invalid CPUID (Intel, AMD, VIA) or Model (FSL)!' + col_e)
		mce_exit(1)
	
	res_i = c.execute('SELECT cpuid,platform,version,yyyymmdd,size FROM Intel WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
	display_sql(res_i, col_b + 'Intel' + col_e, True, 1)
	
	res_a = c.execute('SELECT cpuid,version,yyyymmdd,size FROM AMD WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
	display_sql(res_a, col_r + 'AMD' + col_e, True, 1)
	
	res_v = c.execute('SELECT cpuid,signature,version,yyyymmdd,size FROM VIA WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
	display_sql(res_v, col_c + 'VIA' + col_e, True, 1)
	
	res_f = c.execute('SELECT name,model,major,minor,size,note FROM FSL WHERE model=? ORDER BY name DESC', (cpu_id,))
	display_sql(res_f, col_y + 'Freescale' + col_e, True, 1)
	
	mce_exit()
	
# Detect latest Intel or AMD microcode via user input
# Can be used with currently loaded microcode info from OS
if param.print_last :
	platform = 0
	
	if len(source) == 4 : # Intel
		vendor = 'Intel'
		cpu_id = source[1]
		version = source[2]
		platform = source[3]
	elif len(source) == 3 : # AMD
		vendor = 'AMD'
		cpu_id = source[1]
		version = source[2]
	else :
		vendor = input('\nEnter Microcode Vendor (Intel, AMD): ')
		cpu_id = input('\nEnter CPUID (i.e. 406F1): ')
		version = input('\nEnter Version (i.e. B000021): ')
		if vendor == 'Intel' : platform = input('\nEnter Platform (i.e. EF): ')
	
	try :
		assert vendor in ('Intel','AMD')
		cpu_id = int(cpu_id, 16)
		version = int(version, 16)
		platform = int(platform, 16) # Microcode IDs or System ID (i.e. 0x12 = 1,4 or 0x02 = 1 or 0x10 = 4)
	except :
		print(col_r + '\nError: Invalid Vendor, CPUID, Version or Platform!' + col_e)
		mce_exit(1)
	
	# The input microcode date is required for Latest check, get it from DB
	# The Latest AMD check is inaccurate for 2002-2003 microcodes due to lack of NB ID & Rev
	if vendor == 'Intel' :
		date = (c.execute('SELECT yyyymmdd FROM Intel WHERE cpuid=? AND version=?', ('%0.8X' % cpu_id, '%0.8X' % version,))).fetchall()
	else :
		date = (c.execute('SELECT yyyymmdd FROM AMD WHERE cpuid=? AND version=?', ('%0.8X' % cpu_id, '%0.8X' % version,))).fetchall()
	
	if not date :
		print(col_r + '\nError: %s CPUID %0.8X Version %0.8X not found in DB!' % (vendor, cpu_id, version) + col_e)
		mce_exit(2)
	
	day = date[0][0][6:8]
	month = date[0][0][4:6]
	year = date[0][0][:4]
	
	if vendor == 'Intel' :
		mc_upd_chk_rsl = (c.execute('SELECT yyyymmdd,platform,version FROM Intel WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		is_latest, mc_latest = mc_upd_chk_intel(mc_upd_chk_rsl, intel_plat(platform), 'PRE' if ctypes.c_int(version).value < 0 else 'PRD')
	else :
		mc_upd_chk_rsl = (c.execute('SELECT yyyymmdd,version FROM AMD WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		is_latest, mc_latest = mc_upd_chk(mc_upd_chk_rsl)
	
	print('\n%s' % is_latest)
	if vendor == 'Intel' and mc_latest :
		print('cpu%0.8X_plat%0.8X_ver%0.8X_%s-%s-%s_%s' % (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4],mc_latest[5],mc_latest[6]))
	elif vendor == 'AMD' and mc_latest :
		print('cpu%0.8X_ver%0.8X_%s-%s-%s' % (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4]))
	
	mce_exit()

in_count = len(source)
for arg in source :
	if arg in param.val : in_count -= 1

# Blob Variables
blob_lut_init = []
blob_lut_done = b''
blob_data = b''
blob_count = 0
mc_latest = None
	
# Intel - HeaderRev 01, LoaderRev 01, ProcesFlags xx00*3 (Intel 64 and IA-32 Architectures Software Developer's Manual Vol 3A, Ch 9.11.1)
pat_icpu = re.compile(br'\x01\x00{3}.{4}[\x00-\x99](([\x19\x20][\x01-\x31][\x01-\x12])|(\x18\x07\x00)).{8}[\x00\x01]\x00{3}.\x00{3}', re.DOTALL)

# AMD - Year 20xx, Month 1-13, LoaderID 00-04, DataSize 00|10|20, InitFlag 00-01, NorthBridgeVEN_ID 0000|1022, SouthBridgeVEN_ID 0000|1022, BiosApiREV_ID 00-01, Reserved 00|AA
pat_acpu = re.compile(br'\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x04]\x80[\x00\x20\x10][\x00\x01].{4}((\x00{2})|(\x22\x10)).{2}((\x00{2})|(\x22\x10)).{6}[\x00\x01](\x00{3}|\xAA{3})', re.DOTALL)

# VIA - Signature RRAS, Loader Revision 01
pat_vcpu = re.compile(br'\x52\x52\x41\x53.{16}\x01\x00{3}', re.DOTALL)

# Freescale - Signature QEF, Header Revision 01
pat_fcpu = re.compile(br'\x51\x45\x46\x01.{62}[\x00-\x01]', re.DOTALL)

for in_file in source :

	# MC Variables
	mc_nr = 0
	total = 0
	type_conv = ''
	temp_file = None
	mc_hdr_extra = None
	mc_hdr_extended = None
	msg_i = []
	msg_a = []
	msg_v = []
	msg_f = []
	match_list_i = []
	match_list_a = []
	match_list_v = []
	match_list_f = []
	mc_conv_data = b''
	no_yes = [col_r + 'No' + col_e,col_g + 'Yes' + col_e]
	cur_count += 1
	
	if not os.path.isfile(in_file) :
		if any(p in in_file for p in param.val) : continue
		
		print(col_r + "\nError" + col_e + ": file %s was not found!\n" % in_file)
		
		if not param.mass_scan : mce_exit(1)
		else : continue
	
	if not param.mce_extr and not param.ubu_test : print(col_c + '\n%s (%d/%d)\n' % (os.path.basename(in_file), cur_count, in_count) + col_e)
	
	# Convert Intel containers (.dat , .inc , .h , .txt) to .bin
	if param.conv_cont :
		mc_f_ex = open(in_file, 'r', encoding = 'utf-8')
		
		try :
			for line in mc_f_ex :
				if type_conv == '' :
					if '/+++' in line[:5] or '0x' in line[:3] : type_conv = '.dat'
					elif line[:4] == 'dd 0' : type_conv = '.inc'
				
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
			
			if type_conv == '' : raise Exception('')
			
			temp_file = os.path.join(mce_dir, '__temp-mc__.temp')
			with open(temp_file, 'wb') as temp : temp.write(mc_conv_data)
		
		except :
			print(col_r + 'Error: Cannot convert Intel container!\n' + col_e)
	
	with open(temp_file if temp_file else in_file, 'rb') as work_file :
		reading = work_file.read()
		file_end = work_file.seek(0,2)
		work_file.seek(0,0)
		
	if temp_file and os.path.isfile(temp_file) : os.remove(temp_file)
	
	# Intel Microcodes
	
	match_list_i += pat_icpu.finditer(reading)
	
	total += len(match_list_i)
	
	col_names = ['#','CPUID','Platform ID','Revision','Date','Type','Size','Offset','Last']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_i :
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_hdr = get_struct(reading, mc_bgn, Intel_MC_Header)
		
		patch_u = mc_hdr.UpdateRevision # Unsigned, general usage
		patch_s = ctypes.c_int(patch_u).value # Signed, release usage
		
		year = '%0.4X' % mc_hdr.Year
		
		day = '%0.2X' % mc_hdr.Day
		
		month = '%0.2X' % mc_hdr.Month
		
		cpu_id = mc_hdr.ProcessorSignature
		
		plat = mc_hdr.ProcessorFlags
		plat_bit = intel_plat(mc_hdr.ProcessorFlags)
		
		mc_len = mc_hdr.TotalSize
		if mc_len == 0 : mc_len = 2048
		
		mc_chk = mc_hdr.Checksum # For OEM validation, not checked by CPU
		
		res_field = mc_hdr.Reserved1 + mc_hdr.Reserved2 + mc_hdr.Reserved3
		
		full_date = "%s-%s-%s" % (year, month, day)
		
		# Detect Release based on Patch signature
		if patch_s >= 0 : rel_file = 'PRD'
		else : rel_file = 'PRE'
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
			if date_chk.year > 2020 or date_chk.year < 1993 : raise Exception('WrongDate') # 1st MC from 1995 (P6), 1993 for safety
		except :
			if full_date == '1896-00-07' and patch_u == 0xD1 : pass # Drunk Intel employee 1, Happy 0th month from 19th century Intel!
			else :
				msg_i.append(col_m + "\nWarning: Skipped Intel microcode at 0x%X, invalid Date of %s!" % (mc_bgn, full_date) + col_e)
				if not param.mce_extr : copy_file_with_warn(work_file)
				continue
		
		# Remove false results, based on Reserved field
		if res_field != 0 :
			msg_i.append(col_m + "\nWarning: Skipped Intel microcode at 0x%X, Reserved field not empty!" % mc_bgn + col_e)
			if not param.mce_extr : copy_file_with_warn(work_file)
			continue
		
		# Detect Extra Header
		if reading[mc_bgn + 0x30:mc_bgn + 0x38] == b'\x00\x00\x00\x00\xA1\x00\x00\x00' :
			mc_extra_found = True
			mc_hdr_extra = get_struct(reading, mc_bgn + 0x30, Intel_MC_Header_Extra)
			
			# RSA Signature cannot be verified (Hash probably from Header + Decrypted Patch)
			
		else :
			mc_extra_found = False
		
		# Analyze and validate optional Extended Header
		if mc_hdr.TotalSize > mc_hdr.DataSize + 0x30 :
			mc_extended_found = True
			mc_extended_off = mc_bgn + 0x30 + mc_hdr.DataSize
			mc_hdr_extended = get_struct(reading, mc_extended_off, Intel_MC_Header_Extended)
			ext_header_checksum = mc_hdr_extended.ExtendedChecksum
			ext_fields_count = mc_hdr_extended.ExtendedSignatureCount
			ext_header_size = 0x14 + ext_fields_count * 0xC # 20 intro bytes, 12 for each field
			ext_header_data = reading[mc_bgn + 0x30 + mc_hdr.DataSize:mc_bgn + 0x30 + mc_hdr.DataSize + ext_header_size]
			valid_ext_chk = checksum32(ext_header_data)
		else :
			mc_extended_found = False
			mc_extended_off = -1
			ext_fields_count = -1
			valid_ext_chk = 0
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			
			if mc_extra_found :
				mc_hdr_extra.mc_print_extra()
			
			if mc_extended_found :
				mc_hdr_extended.mc_print_extended()
				
				mc_extended_field_off = mc_extended_off + 0x14
				
				for idx in range(ext_fields_count) :
					mc_hdr_extended_field = get_struct(reading, mc_extended_field_off, Intel_MC_Header_Extended_Field)
					mc_hdr_extended_field.mc_print_extended_field()
					mc_extended_field_off += 0xC
					
			continue # Next MC of input file
		
		mc_name = 'cpu%0.5X_plat%0.2X_ver%0.8X_%s_%s_%0.8X' % (cpu_id, plat, patch_u, full_date, rel_file, mc_chk)
		mc_nr += 1
		
		mc_at_db = (c.execute('SELECT * FROM Intel WHERE cpuid=? AND platform=? AND version=? AND yyyymmdd=? AND size=? \
					AND checksum=?', ('%0.8X' % cpu_id, '%0.8X' % plat, '%0.8X' % patch_u, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				c.execute('INSERT INTO Intel (cpuid, platform, version, yyyymmdd, size, checksum) VALUES (?,?,?,?,?,?)',
						('%0.8X' % cpu_id, '%0.8X' % plat, '%0.8X' % patch_u, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk))
				
				conn.commit()
			
				print(col_g + "\nAdded Intel: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			continue
		
		mc_upd_chk_rsl = (c.execute('SELECT yyyymmdd,platform,version FROM Intel WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		
		# Determine if MC is Last or Outdated
		is_latest, mc_latest = mc_upd_chk_intel(mc_upd_chk_rsl, plat_bit, rel_file)
		
		# Build Microcode Repository (PRD & Last)
		if param.build_repo :
			build_mc_repo('INTEL', is_latest, rel_file)
			
			continue
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		valid_mc_chk = checksum32(mc_data)
		
		# Prepare Microcode Blob
		if param.build_blob :
			blob_count += 1
			
			# CPUID [0x4] + Platform [0x4] + Version [0x4] + Date [0x4] + Offset [0x4] + Size [0x4] + Checksum [0x4] + Reserved [0x4]
			blob_lut_init.append([cpu_id, plat, patch_u, mc_hdr.Year, mc_hdr.Month, mc_hdr.Day, 0, mc_len, mc_chk, 0])
			
			blob_data += mc_data
				
			continue
			
		row = [mc_nr, '%X' % cpu_id, '%0.2X (%s)' % (plat, ','.join(map(str, plat_bit))), '%X' % patch_u, full_date, rel_file, '0x%X' % mc_len, '0x%X' % mc_bgn, no_yes[is_latest]]
		pt.add_row(row)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'Intel', '')
		if not param.ubu_test and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if valid_mc_chk != 0 or valid_ext_chk != 0 :
			if patch_u == 0xFF and cpu_id == 0x506E3 and full_date == '2016-01-05' : # Someone "fixed" the modded MC checksum wrongfully
				mc_path = '%s%s.bin' % (mc_extract, mc_name)
			else :
				msg_i.append(col_m + '\nWarning: Microcode #%d is corrupted, please report it!' % mc_nr + col_e)
				mc_path = '%s!Bad_%s.bin' % (mc_extract, mc_name)
		elif mc_at_db is None :
			msg_i.append(col_g + "\nNote: Microcode #%d was not found at the database, please report it!" % mc_nr + col_e)
			mc_path = '%s!New_%s.bin' % (mc_extract, mc_name)
		else :
			mc_path = '%s%s.bin' % (mc_extract, mc_name)
		
		save_mc_file(mc_path, mc_data, adler32(mc_data))
	
	if str(pt) != pt_empty :
		pt.title = col_b + 'Intel' + col_e
		print(pt)
	for msg in msg_i: print(msg)
	if msg_i : print()
	
	# AMD Microcodes
	
	match_list_a += pat_acpu.finditer(reading)
	
	total += len(match_list_a)
	
	col_names = ['#', 'CPUID', 'Revision', 'Date', 'Size', 'Offset', 'Last']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_a :
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_bgn -= 1 # Pattern starts from 2nd byte for performance (Year 20xx in BE)
		
		mc_hdr = get_struct(reading, mc_bgn, AMD_MC_Header)
		
		patch = mc_hdr.UpdateRevision
		
		data_len = '%0.2X' % mc_hdr.DataSize
		
		year = '%0.4X' % (mc_hdr.Date & 0xFFFF)
		
		day = '%0.2X' % (mc_hdr.Date >> 16 & 0xFF)
		
		month = '%0.2X' % (mc_hdr.Date >> 24)
		
		cpu_id = '%0.4X' % mc_hdr.ProcessorSignature
		cpu_id = '00' + cpu_id[:2] + '0F' + cpu_id[2:] # Thank you AMD for a useless header
		
		mc_chk = mc_hdr.DataChecksum
		
		nb_id = '%0.4X%0.4X' % (mc_hdr.NorthBridgeDEV_ID, mc_hdr.NorthBridgeVEN_ID)
		
		sb_id = '%0.4X%0.4X' % (mc_hdr.SouthBridgeDEV_ID, mc_hdr.SouthBridgeVEN_ID)
		
		nbsb_rev_id = '%0.2X' % mc_hdr.NorthBridgeREV_ID + '%0.2X' % mc_hdr.SouthBridgeREV_ID
		
		if (cpu_id,patch,year) == ('00800F11',0x8001105,'2016') : year = '2017' # Drunk AMD employee 2, Zen in January 2016!
		if (cpu_id,patch,month,day) == ('00730F01',0x7030106,'09','02') : month,day = '02','09' # Drunk AMD employee 3, 2018-09 in 2018-02!
		
		full_date = "%s-%s-%s" % (year, month, day)
		
		# Remove false results, based on Date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
			
			if date_chk.year > 2020 : raise Exception('WrongDate') # 1st MC from 1999 (K7), 2000 for K7 Erratum and performance
		except :
			if (full_date,patch) == ('2011-13-09',0x3000027) : pass # Drunk AMD employee 1, Happy 13th month from AMD!
			else :
				msg_a.append(col_m + "\nWarning: Skipped AMD microcode at 0x%X, invalid Date of %s!" % (mc_bgn, full_date) + col_e)
				if not param.mce_extr : copy_file_with_warn(work_file)
				continue
		
		# Remove false results, based on data
		if reading[mc_bgn + 0x40:mc_bgn + 0x44] == b'\x00' * 4 : # 0x40 has non-null data
			msg_a.append(col_m + "\nWarning: Skipped AMD microcode at 0x%X, null data at 0x40!" % mc_bgn + col_e)
			if not param.mce_extr : copy_file_with_warn(work_file)
			continue
		
		# Print the Header
		if param.print_hdr :
			mc_hdr.mc_print()
			continue
		
		# Determine size based on generation
		if data_len == '20' : mc_len = 0x3C0
		elif data_len == '10' : mc_len = 0x200
		elif cpu_id[2:4] in ['50'] : mc_len = 0x620
		elif cpu_id[2:4] in ['58'] : mc_len = 0x567
		elif cpu_id[2:4] in ['60','61','63','66','67'] : mc_len = 0xA20
		elif cpu_id[2:4] in ['68'] : mc_len = 0x980
		elif cpu_id[2:4] in ['70','73'] : mc_len = 0xD60
		elif cpu_id[2:4] in ['80','81','82'] : mc_len = 0xC80
		else : mc_len = 0
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		mc_file_chk = adler32(mc_data) # Custom Data-only Checksum
		valid_chk = checksum32(mc_data[0x40:]) # AMD File Checksum (Data+Padding)
		
		mc_name = 'cpu%s_ver%0.8X_%s_%0.8X' % (cpu_id, patch, full_date, mc_file_chk)
		mc_nr += 1
		
		if mc_len == 0 :
			msg_a.append(col_r + "\nError: Microcode #%d %s not extracted at 0x%X, unknown Size!" % (mc_nr, mc_name, mc_bgn) + col_e)
			continue
		else :
			mc_len_db = '%0.8X' % mc_len
		
		mc_at_db = (c.execute('SELECT * FROM AMD WHERE cpuid=? AND nbdevid=? AND sbdevid=? AND nbsbrev=? AND version=? \
								AND yyyymmdd=? AND size=? AND chkbody=? AND chkmc=?', (cpu_id, nb_id, sb_id, nbsb_rev_id,
								'%0.8X' % patch, year + month + day, mc_len_db, '%0.8X' % mc_chk, '%0.8X' % mc_file_chk, ))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				c.execute('INSERT INTO AMD (cpuid, nbdevid, sbdevid, nbsbrev, version, yyyymmdd, size, chkbody, chkmc) \
							VALUES (?,?,?,?,?,?,?,?,?)', (cpu_id, nb_id, sb_id, nbsb_rev_id, '%0.8X' % patch, year + month + day,
							mc_len_db, '%0.8X' % mc_chk, '%0.8X' % mc_file_chk))
				
				conn.commit()
				
				print(col_g + "\nAdded AMD: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			continue
		
		mc_upd_chk_rsl = (c.execute('SELECT yyyymmdd,version FROM AMD WHERE cpuid=? AND nbdevid=? AND sbdevid=? AND nbsbrev=?',
						(cpu_id, nb_id, sb_id, nbsb_rev_id,))).fetchall()
		
		# Determine if MC is Last or Outdated
		is_latest, mc_latest = mc_upd_chk(mc_upd_chk_rsl)
		
		# Build Microcode Repository (Last)
		if param.build_repo :
			build_mc_repo('AMD', is_latest, '')
			continue
		
		row = [mc_nr, cpu_id, '%0.8X' % patch, full_date, '0x%X' % mc_len, '0x%X' % mc_bgn, no_yes[is_latest]]
		pt.add_row(row)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'AMD', '')
		if not param.ubu_test and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if int(cpu_id[2:4], 16) < 0x50 and (valid_chk + mc_chk) & 0xFFFFFFFF != 0 :
			msg_a.append(col_m + '\nWarning: Microcode #%d is corrupted, please report it!' % mc_nr + col_e)
			mc_path = '%s!Bad_%s.bin' % (mc_extract, mc_name)
		elif mc_at_db is None :
			msg_a.append(col_g + "\nNote: Microcode #%d was not found at the database, please report it!" % mc_nr + col_e)
			mc_path = '%s!New_%s.bin' % (mc_extract, mc_name)
		else :
			mc_path = '%s%s.bin' % (mc_extract, mc_name)
			
		save_mc_file(mc_path, mc_data, mc_file_chk)
		
	if str(pt) != pt_empty :
		pt.title = col_r + 'AMD' + col_e
		print(pt)
	for msg in msg_a: print(msg)
	if msg_i or msg_a : print()
	
	# VIA Microcodes
	
	match_list_v += pat_vcpu.finditer(reading)
	
	total += len(match_list_v)
	
	col_names = ['#', 'CPUID', 'Name', 'Revision', 'Date', 'Size', 'Offset', 'Last']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_v :
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_hdr = get_struct(reading, mc_bgn, VIA_MC_Header)
		
		patch = mc_hdr.UpdateRevision
		
		year = '%0.4d' % mc_hdr.Year
		
		day = '%0.2d' % mc_hdr.Day
		
		month = '%0.2d' % mc_hdr.Month
		
		cpu_id = mc_hdr.ProcessorSignature
		
		mc_len = mc_hdr.TotalSize
		
		mc_chk = mc_hdr.Checksum
		
		name = '%s' % mc_hdr.Name.replace(b'\x7f', b'\x2e').decode('utf-8') # Replace 0x7f "control" character with 0x2e "fullstop" instead
		
		full_date = "%s-%s-%s" % (year, month, day)
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
			if date_chk.year > 2020 or date_chk.year < 2006 : raise Exception('WrongDate') # 1st MC from 2008 (Nano), 2006 for safety
		except :
			msg_v.append(col_m + "\nWarning: Skipped VIA microcode at 0x%X, invalid Date of %s!\n" % (mc_bgn, full_date) + col_e)
			if not param.mce_extr : copy_file_with_warn(work_file)
			continue
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			continue
		
		mc_name = 'cpu%0.5X_ver%0.8X_sig[%s]_%s_%0.8X' % (cpu_id, patch, name, full_date, mc_chk)
		mc_nr += 1
		
		mc_at_db = (c.execute('SELECT * FROM VIA WHERE cpuid=? AND signature=? AND version=? AND yyyymmdd=? AND size=? AND checksum=?',
				  ('%0.8X' % cpu_id, name, '%0.8X' % patch, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				c.execute('INSERT INTO VIA (cpuid, signature, version, yyyymmdd, size, checksum) VALUES (?,?,?,?,?,?)',
						('%0.8X' % cpu_id, name, '%0.8X' % patch, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk))
				
				conn.commit()
			
				print(col_g + "\nAdded VIA: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			continue
		
		mc_upd_chk_rsl = (c.execute('SELECT yyyymmdd,version FROM VIA WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		
		# Determine if MC is Last or Outdated
		is_latest, mc_latest = mc_upd_chk(mc_upd_chk_rsl)
		
		# Build Microcode Repository (Last)
		if param.build_repo :
			build_mc_repo('VIA', is_latest, '')
			continue
		
		row = [mc_nr, '%X' % cpu_id, name, '%X' % patch, full_date, '0x%X' % mc_len, '0x%X' % mc_bgn, no_yes[is_latest]]
		pt.add_row(row)
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		valid_chk = checksum32(mc_data)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'VIA', '')
		if not param.ubu_test and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if valid_chk != 0 :
			if full_date == '2011-08-09' and name == '06FA03BB0' and mc_chk == 0x9B86F886 : # Drunk VIA employee 1, Signature is 06FA03BB0 instead of 06FA003BB
				mc_path = '%s%s.bin' % (mc_extract, mc_name)
			elif full_date == '2011-08-09' and name == '06FE105A' and mc_chk == 0x8F396F73 : # Drunk VIA employee 2, Checksum for Reserved FF*4 instead of 00FF*3
				mc_path = '%s%s.bin' % (mc_extract, mc_name)
			else :
				msg_v.append(col_m + '\nWarning: Microcode #%d is corrupted, please report it!\n' % mc_nr + col_e)
				mc_path = '%s!Bad_%s.bin' % (mc_extract, mc_name)
		elif mc_at_db is None :
			msg_v.append(col_g + '\nNote: Microcode #%d was not found at the database, please report it!\n' % mc_nr + col_e)
			mc_path = '%s!New_%s.bin' % (mc_extract, mc_name)
		else :
			mc_path = '%s%s.bin' % (mc_extract, mc_name)
		
		save_mc_file(mc_path, mc_data, adler32(mc_data))

	if str(pt) != pt_empty :
		pt.title = col_c + 'VIA' + col_e
		print(pt)
	for msg in msg_v: print(msg)
	if msg_i or msg_a or msg_v : print()
	
	# Freescale Microcodes
	
	match_list_f += pat_fcpu.finditer(reading)
	
	total += len(match_list_f)
	
	col_names = ['#', 'Name', 'SoC Model', 'SoC Major', 'SoC Minor', 'Size', 'Offset']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_f :
		
		if param.build_repo : continue
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_bgn -= 4 # Pattern starts from 5th byte for performance (Signature QEF)
		
		mc_hdr = get_struct(reading, mc_bgn, FSL_MC_Header)
		
		name = mc_hdr.Name.decode('utf-8')
		
		model = '%0.4d' % mc_hdr.Model
		
		major = '%d' % mc_hdr.Major
		
		minor = '%d' % mc_hdr.Minor
		
		mc_len = mc_hdr.TotalSize
		
		mc_chk = int.from_bytes(reading[mc_bgn + mc_len - 4:mc_bgn + mc_len], 'big')
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			
			qe_off = 0x7C # Header size
			for qe_mc in range(mc_hdr.CountMC) :
				qe_hdr = get_struct(reading, qe_off, FSL_MC_Entry)
				qe_hdr.mc_print()
				qe_off += 0x78 # Entry size
			
			continue
		
		mc_name = 'soc%s_rev%s.%s_sig[%s]_%0.8X' % (model, major, minor, name, mc_chk)
		
		mc_nr += 1
		
		mc_at_db = (c.execute('SELECT * FROM FSL WHERE name=? AND model=? AND major=? AND minor=? AND size=? AND checksum=?',
				  (name, model, major, minor, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				c.execute('INSERT INTO FSL (name, model, major, minor, size, checksum) VALUES (?,?,?,?,?,?)',
						(name, model, major, minor, '%0.8X' % mc_len, '%0.8X' % mc_chk))
				
				conn.commit()
			
				print(col_g + "\nAdded Freescale: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			
			continue
		
		row = [mc_nr, name, model, major, minor, '0x%X' % mc_len, '0x%X' % mc_bgn]
		pt.add_row(row)
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		
		calc_crc = (binascii.crc32(mc_data[:-4], -1) ^ -1) & 0xFFFFFFFF
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'Freescale', '')
		if not param.ubu_test and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if calc_crc != mc_chk :
			msg_f.append(col_m + '\nWarning: Microcode #%d is corrupted, please report it!\n' % mc_nr + col_e)
			mc_path = '%s!Bad_%s.bin' % (mc_extract, mc_name)
		elif mc_at_db is None :
			msg_f.append(col_g + '\nNote: Microcode #%d was not found at the database, please report it!\n' % mc_nr + col_e)
			mc_path = '%s!New_%s.bin' % (mc_extract, mc_name)
		else :
			mc_path = '%s%s.bin' % (mc_extract, mc_name)
		
		save_mc_file(mc_path, mc_data, adler32(mc_data))
	
	if str(pt) != pt_empty :
		pt.title = col_y + 'Freescale' + col_e
		print(pt)
	for msg in msg_f: print(msg)
		
	if total == 0 : print('File does not contain CPU microcodes')

# Search Microcode Blob for Latest (-blob -search)
if param.build_blob and param.search :
	if mc_latest is None :
		print(col_y + '\nNote: Microcode is the latest!' + col_e) # Based on DB
		mce_exit(1)
	
	if os.path.isfile(mcb_path) :
		last_path = os.path.join(mce_dir, 'last.bin') # Previous Latest MCB Microcode location
		
		# Delete previous Latest MCB Microcode
		if os.path.isfile(last_path) : os.remove(last_path)
	
		with open(mcb_path, 'rb') as mcb :
			mcb_data = mcb.read()
			file_end = mcb.seek(0,2)
			mcb.seek(0,0)
			
			mcb_hdr = get_struct(mcb_data, 0, MCB_Header)
			
			if mcb_hdr.Tag == b'$MCB' : # Sanity checks
				mcb_count = mcb_hdr.MCCount
				mcb_dbrev = mcb_hdr.MCEDBRev
				mcb_dbdev = mcb_hdr.MCEDBDev
				mcb_rev = mcb_hdr.HeaderRev
				mcb_ven = mcb_hdr.MCVendor
				mcb_crc = mcb_hdr.Checksum
				
				for e in range(0, mcb_count) :
					mcb_lut = get_struct(mcb_data, 0x10 + e * 0x20, MCB_Entry)
					
					mcb_cpuid = mcb_lut.CPUID
					mcb_plat = mcb_lut.Platform
					mcb_ver = mcb_lut.Revision
					mcb_year = '%0.4X' % mcb_lut.Year
					mcb_month = '%0.2X' % mcb_lut.Month
					mcb_day = '%0.2X' % mcb_lut.Day
					mcb_rel = 'PRE' if ctypes.c_int(mcb_lut.Revision).value < 0 else 'PRD'
					
					if (mcb_ven,mcb_cpuid,mcb_plat,mcb_ver,mcb_year,mcb_month,mcb_day,mcb_rel) == (0,mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4],mc_latest[5],mc_latest[6]) :
						with open(last_path, 'wb') as mc : mc.write(mcb_data[mcb_lut.Offset:mcb_lut.Offset + mcb_lut.Size])
						break
				else :
					print(col_r + '\nError: Latest microcode not within MCB.bin!' + col_e)
					mce_exit(3)
						
	else :
		print(col_r + '\nError: MCB.bin is missing!' + col_e)
		mce_exit(2)
	
	print(col_g + '\nLatest Microcode extracted!' + col_e)
	mce_exit(0)
	
# Build Microcode Blob (-blob)
elif param.build_blob :
	db_rev_now = (c.execute('SELECT revision FROM MCE')).fetchone()[0] # Get DB Revision
	db_is_dev = (c.execute('SELECT developer FROM MCE')).fetchone()[0] # Get DB Developer
	
	# Determine Microcode Blob offsets
	blob_offset = 0x10 + blob_count * 0x20 # Header Length = 0x10, Entry Length = 0x20
	for i in range(len(blob_lut_init)) :
		blob_lut_init[i][6] += blob_offset # 6 = Microcode Offset
		blob_offset += blob_lut_init[i][7] # 7 = Microcode Size
		blob_lut_done += struct.pack('<IIIHBBIIII', blob_lut_init[i][0], blob_lut_init[i][1], blob_lut_init[i][2], blob_lut_init[i][3],
						 blob_lut_init[i][4], blob_lut_init[i][5], blob_lut_init[i][6], blob_lut_init[i][7], blob_lut_init[i][8], blob_lut_init[i][9])
	
	# Tag [0x4] + Entry Count [0x2] + DB Revision [0x1] + DB Developer [0x1] + Header Revision [0x1] + Vendor [0x1] + Reserved [0x2] + CRC32 [0x4]
	blob_hdr = struct.pack('<4sHBBBBHI', b'$MCB', blob_count, db_rev_now, db_is_dev, 1, 0, 0, crc32(blob_lut_done + blob_data))
	
	# Delete previous Microcode Blob
	if os.path.isfile(mcb_path) : os.remove(mcb_path)
	
	# Generate final Microcode Blob
	with open(mcb_path, 'ab') as mc_blob :
		mc_blob.write(blob_hdr)
		mc_blob.write(blob_lut_done)
		mc_blob.write(blob_data)

mce_exit()
