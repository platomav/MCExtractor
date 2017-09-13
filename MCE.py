#!/usr/bin/env python3

"""
MC Extractor
Intel, AMD, VIA & Freescale Microcode Extractor
Copyright (C) 2016-2017 Plato Mavropoulos
"""

title = 'MC Extractor v1.7.1'

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
import tempfile
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

# Detect OS Platform
mce_os = sys.platform
if mce_os == 'win32' :
	cl_wipe = 'cls'
	os_dir = '\\'
elif mce_os.startswith('linux') or mce_os == 'darwin' :
	cl_wipe = 'clear'
	os_dir = '//'
else :
	print(col_r + '\nError: ' + col_e + 'Unsupported platform: %s\n' % mce_os)
	input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)

cur_count = 0
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class MCE_Param :

	def __init__(self,source) :
	
		self.all = ['-?','-skip','-info','-add','-padd','-file','-check','-extr','-cont','-mass','-verbose','-search','-olddb','-dbname']
		
		self.win = ['-extr'] # Windows only
		
		if mce_os == 'win32' :
			self.val = self.all
		else :
			self.val = [item for item in self.all if item not in self.win]
		
		self.help_scr = False
		self.build_db = False
		self.skip_intro = False
		self.print_hdr = False
		self.pad_check = False
		self.exp_check = False
		self.print_file = False
		self.mce_extr = False
		self.conv_cont = False
		self.mass_scan = False
		self.verbose = False
		self.old_db = False
		self.search = False
		self.give_db_name = False
		
		for i in source :
			if i == '-?' : self.help_scr = True
			if i == '-skip' : self.skip_intro = True
			if i == '-add' : self.build_db = True
			if i == '-info' : self.print_hdr = True
			if i == '-padd' : self.pad_check = True
			if i == '-check' : self.exp_check = True
			if i == '-file' : self.print_file = True
			if i == '-cont' : self.conv_cont = True
			if i == '-mass' : self.mass_scan = True
			if i == '-verbose' : self.verbose = True
			if i == '-olddb' : self.old_db = True
			if i == '-search' : self.search = True
			if i == '-dbname' : self.give_db_name = True
			
			if mce_os == 'win32' : # Windows only options
				if i == '-extr': self.mce_extr = True
			
		if self.mce_extr or self.mass_scan or self.search : self.skip_intro = True
		if self.mce_extr : self.verbose = True

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
		full_date  = "%0.4X-%0.2X-%0.2X" % (self.Year, self.Month, self.Day)
		
		platforms = intel_plat(self.ProcessorFlags)
		
		if self.Reserved1 == self.Reserved2 == self.Reserved3 == 0 : reserv_str = "00 * 12"
		else : reserv_str = "%0.8X %0.8X %0.8X" % (self.Reserved1, self.Reserved2, self.Reserved3)
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_b + 'Intel Main Header' + col_e
		pt.add_row(['Header', '%0.8X' % self.HeaderVersion])
		pt.add_row(['Update', '%0.8X' % self.UpdateRevision])
		pt.add_row(['Date', '%s' % full_date])
		pt.add_row(['CPUID', '%0.8X' % self.ProcessorSignature])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		pt.add_row(['Loader', '%0.8X' % self.LoaderRevision])
		pt.add_row(['Platform', '%0.2X %s' % (self.ProcessorFlags, platforms)])
		pt.add_row(['Data Size', '0x%0.2X' % self.DataSize])
		pt.add_row(['Total Size', '0x%0.2X' % self.TotalSize])
		pt.add_row(['Reserved', '%s' % reserv_str])
		
		print(pt)

# noinspection PyTypeChecker
class Intel_MC_Header_Extra(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Unknown1",                  uint32_t),    # 00 00000000 (always, Header Type probably)
		("ExtraHeaderSize",			  uint32_t),    # 04 dwords (0x284)
		("Unknown2",                  uint16_t),    # 08 0001 or 0000 (RSA usage probably)
		("Unknown3",                  uint16_t),    # 08 0002 (always)
		("UpdateRevision",            uint32_t),    # 0C
		("VCN",                  	  uint32_t),    # 10 Version Control Number
		("Unknown4",     			  uint32_t),    # 14 dwords from Extra or UpdateSize or Empty etc...
		("Day",                       uint8_t),     # 18
		("Month",                     uint8_t),     # 19
		("Year",                      uint16_t),    # 1A
		("UpdateSize",                uint32_t),    # 1C dwords from Extra without encrypted padding
		("ProcessorSignatureCount",   uint32_t),    # 20 max is probably 8 (8 * 4 = 0x20)
		("ProcessorSignature0",       uint32_t),    # 24
		("ProcessorSignature1",		  uint32_t),    # 28
		("ProcessorSignature2",		  uint32_t),    # 2C
		("ProcessorSignature3",		  uint32_t),    # 30
		("ProcessorSignature4",		  uint32_t),    # 34
		("ProcessorSignature5",		  uint32_t),    # 38
		("ProcessorSignature6",		  uint32_t),    # 3C
		("ProcessorSignature7",		  uint32_t),    # 40
		("Unknown5",      			  uint32_t),    # 44 dwords from Extra with encrypted padding or UpdateSize or Platform or Empty
		("SVN",     				  uint32_t),    # 48 Security Version Number
		("Unknown6",                  uint32_t),    # 4C 00000000 (always, reserved probably)
		("Unknown7",                  uint32_t),    # 50 00000000 (always, reserved probably)
		("Unknown8",                  uint32_t),    # 54 00000000 (always, reserved probably)
		("Unknown9",                  uint32_t),    # 58 00000000 (always, reserved probably)
		("Unknown10",                 uint32_t),    # 5C 00000000 (always, reserved probably)
		("Unknown11",                 uint32_t*8),  # 60 probably a 256-bit hash
		("RSAPublicKey",              uint32_t*64), # 80
		("RSAExponent",               uint32_t),    # 180
		("RSASignature",              uint32_t*64), # 184
		# 284
	]

	def mc_print_extra(self) :
		print()
		
		full_date  = "%0.4X-%0.2X-%0.2X" % (self.Year, self.Month, self.Day)
		
		platforms = intel_plat(mc_hdr.ProcessorFlags)
		
		Unknown11 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown11))
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_b + 'Intel Extra Header' + col_e
		pt.add_row(['Unknown 1', '%0.8X' % self.Unknown1])
		pt.add_row(['Header Size', '0x%0.2X' % (self.ExtraHeaderSize * 4)])
		if self.Unknown2 == 1 : pt.add_row(['RSA Block', 'Yes'])
		elif self.Unknown2 == 0 : pt.add_row(['RSA Block', 'No'])
		else : pt.add_row(['Unknown 2', '%0.4X' % self.Unknown2])
		pt.add_row(['Unknown 3', '%0.4X' % self.Unknown3])
		pt.add_row(['Update', '%0.8X' % self.UpdateRevision])
		pt.add_row(['Version Control', '%X' % self.VCN])
		pt.add_row(['Multi Purpose 1', '%0.8X' % self.Unknown4])
		pt.add_row(['Date', '%s' % full_date])
		pt.add_row(['Update Size', '0x%0.2X' % (self.UpdateSize * 4)])
		pt.add_row(['CPU Signatures', '%X' % self.ProcessorSignatureCount])
		if self.ProcessorSignature0 != 0 : pt.add_row(['CPUID 0', '%0.8X' % self.ProcessorSignature0])
		if self.ProcessorSignature1 != 0 : pt.add_row(['CPUID 1', '%0.8X' % self.ProcessorSignature1])
		if self.ProcessorSignature2 != 0 : pt.add_row(['CPUID 2', '%0.8X' % self.ProcessorSignature2])
		if self.ProcessorSignature3 != 0 : pt.add_row(['CPUID 3', '%0.8X' % self.ProcessorSignature3])
		if self.ProcessorSignature4 != 0 : pt.add_row(['CPUID 4', '%0.8X' % self.ProcessorSignature4])
		if self.ProcessorSignature5 != 0 : pt.add_row(['CPUID 5', '%0.8X' % self.ProcessorSignature5])
		if self.ProcessorSignature6 != 0 : pt.add_row(['CPUID 6', '%0.8X' % self.ProcessorSignature6])
		if self.ProcessorSignature7 != 0 : pt.add_row(['CPUID 7', '%0.8X' % self.ProcessorSignature7])
		if self.Unknown5 == mc_hdr.ProcessorFlags : pt.add_row(['Platform', '%0.2X %s' % (self.Unknown5, platforms)])
		elif self.Unknown5 * 4 == self.UpdateSize * 4 : pass # Covered by UpdateSize
		elif self.Unknown5 * 4 == file_end - 0x30 : pt.add_row(['Padded Size', '0x%0.2X' % (self.Unknown5 * 4)])
		else : pt.add_row(['Multi Purpose 2', '%0.8X' % self.Unknown5])
		pt.add_row(['Security Version', '%X' % self.SVN])
		if self.Unknown6 != 0 : pt.add_row(['Unknown 6', '%0.8X' % self.Unknown6])
		if self.Unknown7 != 0 : pt.add_row(['Unknown 7', '%0.8X' % self.Unknown7])
		if self.Unknown8 != 0 : pt.add_row(['Unknown 8', '%0.8X' % self.Unknown8])
		if self.Unknown9 != 0 : pt.add_row(['Unknown 9', '%0.8X' % self.Unknown9])
		if self.Unknown10 != 0 : pt.add_row(['Unknown 10', '%0.8X' % self.Unknown10])
		pt.add_row(['Unknown 11', '%s [...]' % Unknown11[:8]])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%0.2X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		print(pt)

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
		
		if self.Reserved1 == self.Reserved2 == self.Reserved3 == 0 : reserv_str = "00 * 12"
		else : reserv_str = "%0.8X %0.8X %0.8X" % (self.Reserved1, self.Reserved2, self.Reserved3)

		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_b + 'Intel Extended Header' + col_e
		pt.add_row(['Extended Signatures', '%X' % self.ExtendedSignatureCount])
		pt.add_row(['Extended Checksum', '%0.8X' % self.ExtendedChecksum])
		pt.add_row(['Reserved', '%s' % reserv_str])
		
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
		
		platforms = intel_plat(self.ProcessorFlags)
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_b + 'Intel Extended Field' + col_e
		pt.add_row(['CPUID', '%0.6X' % self.ProcessorSignature])
		pt.add_row(['Platform', '%0.2X %s' % (self.ProcessorFlags, platforms)])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		
		print(pt)

# noinspection PyTypeChecker
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
		full_date = "%0.4X-%0.2X-%0.2X" % (self.Date & 0xFFFF, self.Date >> 24, self.Date >> 16 & 0xFF)
		
		proc_rev_str = "%0.2X0F%0.2X" % (self.ProcessorRevId >> 8, self.ProcessorRevId & 0xFF)
		
		if self.Reserved == [0, 0, 0] : reserv_str = "000000"
		else : reserv_str = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved))
		
		#matchreg_str = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.MatchReg))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_r + 'AMD Header' + col_e
		pt.add_row(['Date',full_date])
		pt.add_row(['Update','%0.8X' % self.PatchId])
		pt.add_row(['Data Revision','%0.4X' % self.DataId])
		pt.add_row(['Data Length','%0.2X' % self.DataLen])
		pt.add_row(['Init Flag','%0.2X' % self.InitFlag])
		pt.add_row(['Checksum','%0.8X' % self.DataChecksum])
		pt.add_row(['NB Dev ID','%0.8X' % self.NbDevId])
		pt.add_row(['SB Dev ID','%0.8X' % self.SbDevId])
		pt.add_row(['CPU Rev ID','%s' % proc_rev_str])
		pt.add_row(['NB Rev ID','%0.2X' % self.NbRevId])
		pt.add_row(['SB Rev ID','%0.2X' % self.SbRevId])
		pt.add_row(['BIOS API Rev','%0.2X' % self.BiosApiRev])
		pt.add_row(['Reserved','%s' % reserv_str])
		
		print(pt)

# noinspection PyTypeChecker
class AMD_MC_Header_Extra(ctypes.LittleEndianStructure) :
	_pack_   = 1
	_fields_ = [
		("Unknown1",				uint32_t * 0x40),	# 100 (20+)
		("Unknown2",				uint32_t * 0x80),	# 300
		("Flags",					uint32_t),			# 304
		("PatchId",					uint32_t),			# 308
		# 308
	]

	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_r + 'AMD Extra Header' + col_e
		pt.add_row(['Flags', '%0.8X' % self.Flags])
		pt.add_row(['Patch Revision', '%0.8X' % self.PatchId])
		
		print(pt)

# noinspection PyTypeChecker
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
		full_date  = "%0.4d-%0.2d-%0.2d" % (self.Year, self.Month, self.Day)
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		pt.title = col_c + 'VIA Header' + col_e
		pt.add_row(['Signature', '%s' % self.Signature.decode('utf-8')])
		pt.add_row(['Update', '%0.8X' % self.UpdateRevision])
		pt.add_row(['Date', '%s' % full_date])
		pt.add_row(['CPUID', '%0.8X' % self.ProcessorSignature])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		pt.add_row(['Loader', '%0.8X' % self.LoaderRevision])
		pt.add_row(['Reserved', '%0.8X' % self.Reserved])
		pt.add_row(['Data Size', '0x%0.2X' % self.DataSize])
		pt.add_row(['Total Size', '0x%0.2X' % self.TotalSize])
		pt.add_row(['Name', '%s' % self.Name.decode('utf-8')])
		pt.add_row(['Unknown', '%0.8X' % self.Unknown])
		
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
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		vtraps_str = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.VTraps))
		if vtraps_str == '0000' * 8 : vtraps_str = '0000 * 8'
		
		pt.title = col_y + 'Freescale QEF Header' + col_e
		pt.add_row(['Signature', '%s' % self.Signature.decode('utf-8')])
		pt.add_row(['Name', '%s' % self.Name.decode('utf-8')])
		pt.add_row(['Header', '%X' % self.HeaderVersion])
		pt.add_row(['I-RAM', '%s' % ['Shared','Split'][self.IRAM]])
		pt.add_row(['MC Count', '%X' % self.CountMC])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['SoC Model', '%0.4d' % self.Model])
		pt.add_row(['SoC Major', '%X' % self.Major])
		pt.add_row(['SoC Minor', '%X' % self.Minor])
		pt.add_row(['Reserved', '%X' % self.Reserved0])
		pt.add_row(['Extended Modes', '%0.8X' % self.ExtendedModes])
		pt.add_row(['Virtual Traps', '%s' % vtraps_str])
		pt.add_row(['Reserved', '%X' % self.Reserved1])
		
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
		pt, pt_empty = mc_table(['Field', 'Value'], False, 0)
		
		traps_str = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Traps))
		if traps_str == '0000' * 16 : traps_str = '0000 * 16'
		
		pt.title = col_y + 'Freescale QEF Entry' + col_e
		pt.add_row(['Name', '%s' % self.Name.decode('utf-8')])
		pt.add_row(['Traps', '%s' % traps_str])
		pt.add_row(['ECCR', '%0.8X' % self.ECCR])
		pt.add_row(['I-RAM Offset', '0x%X' % self.IRAMOffset])
		pt.add_row(['Code Length', '0x%X' % self.CodeLength])
		pt.add_row(['Code Offset', '0x%X' % self.CodeOffset])
		pt.add_row(['Major', '%X' % self.Major])
		pt.add_row(['Minor', '%X' % self.Minor])
		pt.add_row(['Revision', '%X' % self.Revision])
		pt.add_row(['Reserved 0', '%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '%X' % self.Reserved1])
		
		print(pt)

def mce_help() :
	
	text = "\nUsage: MCE [FilePath] {Options}\n\n{Options}\n\n"
	text += "-?       : Displays help & usage screen\n"
	text += "-skip    : Skips options intro screen\n"
	text += "-mass    : Scans all files of a given directory\n"
	text += "-info    : Displays microcode header(s)\n"
	text += "-check   : Copies skipped microcodes to check\n"
	text += "-padd    : Keeps padding of AMD microcodes\n"
	text += "-file    : Appends filename to New or Bad microcodes\n"
	text += "-add     : Adds new input microcode to DB\n"
	text += "-dbname  : Renames input file based on DB name\n"
	text += "-cont    : Extracts Intel containers (dat,inc,h,txt)\n"
	text += "-search  : Searches for microcodes based on CPUID\n"
	text += "-verbose : Shows all microcode details"
	
	if mce_os == 'win32' :
		text += "\n-extr    : Lordkag's UEFIStrip mode"
	
	print(text)
	mce_exit()

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
	if not param.mce_extr : input("\nPress enter to exit")
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
	print(col_r + '\nError: MCE just crashed, please report the following:\n')
	traceback.print_exception(exc_type, exc_value, tb)
	input(col_e + '\nPress enter to exit')
	colorama.deinit() # Stop Colorama
	sys.exit(-1)
	
def adler32(data) :
	return zlib.adler32(data) & 0xFFFFFFFF
	
def checksum32(data) :
	if not data :
		print(col_r + '\nError: Empty data\n' + col_e)
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
	mce_exit()
	
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
	t_folder = os.path.dirname(file_path) + os_dir
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

# Inspired from Igor Skochinsky's me_unpack
def get_struct(str_, off, struct) :
	my_struct = struct()
	struct_len = ctypes.sizeof(my_struct)
	str_data = str_[off:off + struct_len]
	fit_len = min(len(str_data), struct_len)
	
	if (off > file_end) or (fit_len < struct_len) :
		print(col_r + "Error: Offset 0x%0.2X out of bounds, incomplete image!" % off + col_e)
		
		mce_exit(1)
	
	ctypes.memmove(ctypes.addressof(my_struct), str_data, fit_len)
	
	return my_struct

def intel_plat(cpuflags) :
	platforms = []
	
	if cpuflags == 0:  # 1995-1998
		platforms.append(0)
	else:
		for bit in range(8):  # 0-7
			cpu_flag = cpuflags >> bit & 1
			if cpu_flag == 1: platforms.append(bit)
			
	return platforms

def amd_padd(padd_bgn, max_padd, amd_size, ibv_size, com_size) :
	for padd_off in range(padd_bgn, padd_bgn + max_padd) :
		if reading[padd_off:padd_off + 1] != b'\x00' :
			if padd_off < (padd_bgn + amd_size) : mc_len = amd_size # Official size
			else : mc_len = ibv_size # Also a size found in BIOS			
			break # triggers "else"
	else : mc_len = com_size # Usual size found in BIOS
	
	return mc_len

def mc_db_name(work_file, in_file, mc_name) :
	new_dir_name = os.path.join(os.path.dirname(in_file), mc_name + '.bin')
	work_file.close()
	if not os.path.exists(new_dir_name) : os.rename(in_file, new_dir_name)
	elif os.path.basename(in_file) == mc_name + '.bin' : pass
	else : print(col_r + 'Error: ' + col_e + 'A file with the same name already exists!')

def mc_verbose(work_file) :
	work_file.close()
	suffix = 0
		
	file_name = os.path.basename(in_file)
	check_dir = mce_dir + os_dir + '__CHECK__' + os_dir
		
	if not os.path.isdir(check_dir) : os.mkdir(check_dir)
		
	while os.path.exists(check_dir + file_name) :
		suffix += 1
		file_name += '_%s' % suffix
		
	shutil.copyfile(in_file, check_dir + file_name)
	
def mc_upd_chk(mc_dates) :
	mc_latest = True
	
	if mc_dates is not None :
		for date in mc_dates :
			dd = date[0][6:8]
			mm = date[0][4:6]
			yyyy = date[0][:4]
			
			if year < yyyy or (year == yyyy and (month < mm or (month == mm and day < dd))) :
				mc_latest = False
				break # No need for more loops
	
	if mc_latest : mc_upd = col_g + 'Latest' + col_e
	else : mc_upd = col_r + 'Outdated' + col_e
	
	return mc_upd
	
def mc_table(row_col_names,header,padd) :
	pt = prettytable.PrettyTable(row_col_names)
	pt.header = header # Boolean
	pt.padding_width = padd
	pt.hrules = prettytable.ALL
	pt.vrules = prettytable.ALL
	pt_empty = str(pt)
	
	return pt,pt_empty

def display_sql(cursor,title,header,padd):
	col_names = [cn[0].upper() for cn in cursor.description]
	rows = cursor.fetchall()
	
	sqlr = prettytable.PrettyTable()
	sqlr.header = header
	sqlr.padding_width = padd
	sqlr.hrules = prettytable.ALL
	sqlr.vrules = prettytable.ALL
	sqlr.title = title
	row_id = -1
	
	for name in col_names:
		row_id += 1
		sqlr.add_column(name, [row[row_id] for row in rows])
	
	return sqlr
	
# MCE Version Header
def mce_hdr() :
	db_rev = col_r + 'Unknown' + col_e
	db_dev = ''
	
	if os.path.isfile(db_path) :
		try :
			hdr_conn = sqlite3.connect(db_path)
			hdr_c = hdr_conn.cursor()
			
			hdr_c.execute('PRAGMA quick_check')
			
			hdr_res = (hdr_c.execute('SELECT revision, developer FROM MCE')).fetchone()
			db_rev = 'r' + str(hdr_res[0])
			db_dev = hdr_res[1]
		
			if db_dev == 1 : db_dev = ' Dev'
			else : db_dev = ''
		
			hdr_c.close()
			hdr_conn.close()
		except :
			pass
		
	print("\n-------[ %s ]-------" % title)
	print("            Database  %s%s" % (db_rev,db_dev))

def init_file(in_file,orig_file,temp,in_count,cur_count) :
	mc_file_name = ''
	
	if not os.path.isfile(in_file) :
		if any(p in in_file for p in param.val) : return 'continue', 'continue', 'continue', 'continue'
		
		print(col_r + "\nError" + col_e + ": file %s was not found!\n" % force_ascii(in_file))
		
		if not param.mass_scan : mce_exit(1)
		else : return 'continue', 'continue', 'continue', 'continue'

	with open(in_file, 'rb') as work_file :
		reading = work_file.read()
		file_end = work_file.seek(0,2)
		work_file.seek(0,0)
	
	if not temp :
		if not param.mce_extr : print("\nFile (%d/%d): %s\n" % (cur_count, in_count, force_ascii(os.path.basename(in_file))))
		if param.print_file : mc_file_name = '__%s' % os.path.basename(in_file)
	else :
		if param.print_file : mc_file_name = '__%s' % os.path.basename(orig_file)
	
	return work_file, reading, file_end, mc_file_name

# Force string to be printed as ASCII, ignore errors
def force_ascii(string) :
	# Input string is bare and only for printing (no open(), no Colorama etc)
	ascii_str = str((string.encode('ascii', 'ignore')).decode('utf-8', 'ignore'))
	
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
db_path = mce_dir + os_dir + "MCE.db"

# Get MCE Parameters from input
param = MCE_Param(sys.argv)

# Enumerate parameter input
arg_num = len(sys.argv)

# Actions for MCE but not UEFIStrip
if param.mce_extr :
	pass
else :
	sys.excepthook = show_exception_and_exit # Pause after any unexpected python exception
	if mce_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title) # Set console window title

if not param.skip_intro :
	mce_hdr()

	print("\nWelcome to Intel, AMD, VIA & Freescale Microcode Extractor\n")

	arg_num = len(sys.argv)
	
	if arg_num == 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFile:       " + col_g + "%s" % force_ascii(os.path.basename(sys.argv[1])) + col_e)
	elif arg_num > 2 :
		print("Press Enter to skip or input -? to list options\n")
		print("\nFiles:       " + col_y + "Multiple" + col_e)
	else :
		print('Input a filename or "filepath" or press Enter to list options\n')
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

if (arg_num < 2 and not param.help_scr and not param.mass_scan and not param.search and not param.old_db) or param.help_scr :
	mce_help()
	mce_exit()

if param.mass_scan :
	in_path = input('\nType the full folder path : ')
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
	print(col_r + "\nError: MCE.db file is missing!" + col_e)
	mce_exit(1)

# Search DB by CPUID (Intel/AMD/VIA) or Model (Freescale)
if param.search :
	# noinspection PyUnboundLocalVariable
	if len(source) == 2 : i_cpuid = source[1] # -search CPUID expected
	else : i_cpuid = input('\nEnter CPUID to search: ')
	
	# noinspection PyUnboundLocalVariable
	res_i = c.execute('SELECT * FROM Intel WHERE cpuid=? ORDER BY date(yyyymmdd) DESC', (i_cpuid,))
	print('\n%s' % display_sql(res_i, col_b + 'Intel' + col_e, True, 1))
	
	res_a = c.execute('SELECT * FROM AMD WHERE cpuid=? ORDER BY date(yyyymmdd) DESC', (i_cpuid,))
	print('\n%s' % display_sql(res_a, col_r + 'AMD' + col_e, True, 1))
	
	res_v = c.execute('SELECT * FROM VIA WHERE cpuid=? ORDER BY date(yyyymmdd) DESC', (i_cpuid,))
	print('\n%s' % display_sql(res_v, col_c + 'VIA' + col_e, True, 1))
	
	res_f = c.execute('SELECT * FROM FSL WHERE model=? ORDER BY name DESC', (i_cpuid,))
	print('\n%s' % display_sql(res_f, col_y + 'Freescale' + col_e, True, 1))
	
	mce_exit()

# Build old DB format for UEFI BIOS Updater (UBU)
if param.old_db :
	# noinspection PyUnboundLocalVariable
	res_i = (c.execute('SELECT * FROM Intel')).fetchall() # Intel only
	
	res_m = (c.execute('SELECT * FROM MCE')).fetchall()
	db_rev = 'r' + str(res_m[0][0])
	db_date = datetime.datetime.utcfromtimestamp(res_m[0][2]).strftime('%Y-%m-%d, %H:%M')
	
	if res_m[0][1] == 1 : db_dev = ' Dev'
	else : db_dev = ''
	
	old_hdr = "MC Extractor Intel Microcode Repository Database\nRevision %s%s (%s)\n\n" % (db_rev,db_dev,db_date)
	
	mct = ''
	for mc in res_i :
		for field in mc :
			mct += str(field)
		mct += '\n'

	with open(mce_dir + os_dir + 'MCE.dat', 'w') as db_old : db_old.write(old_hdr + mct)
	
	print(col_y + '\nBuilt old MCE.dat database format (%s%s %s)' % (db_rev,db_dev,db_date) + col_e)
	
	mce_exit()

in_count = len(source)

# Intel - HeaderRev 01, LoaderRev 01, ProcesFlags xx00*3 (Intel 64 and IA-32 Architectures Software Developer's Manual Vol 3A, Ch 9.11.1)
pat_icpu = re.compile(br'\x01\x00{3}.{4}[\x00-\x99](([\x19-\x20][\x01-\x31][\x01-\x12])|(\x18\x07\x00)).{8}\x01\x00{3}.\x00{3}', re.DOTALL)

# AMD - Year 2000+, Month 1-13, DataId, BiosApiRev 00-01, Reserved 00|AA
pat_acpu = re.compile(br'[\x00-\x18]\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x04]\x80.{18}[\x00-\x01](\x00{3}|\xAA{3})', re.DOTALL)

# VIA - Signature RRAS, Loader Revision 01, Reserved FF
pat_vcpu = re.compile(br'\x52\x52\x41\x53.{16}\x01\x00{3}\xFF{4}', re.DOTALL)

# Freescale - Signature QEF, Header Revision 01
pat_fcpu = re.compile(br'\x51\x45\x46\x01.{62}[\x00-\x01]', re.DOTALL)

for in_file in source :

	# MC Variables
	skip = 0
	mc_nr = 0
	total = 0
	type_conv = ''
	temp_file = None
	msg_i = []
	msg_a = []
	msg_v = []
	msg_f = []
	match_list_i = []
	match_list_a = []
	match_list_v = []
	match_list_f = []
	mc_bgn_list_a = []
	mc_conv_data = bytearray()
	cur_count += 1
	
	# noinspection PyRedeclaration
	work_file,reading,file_end,mc_file_name = init_file(in_file,in_file,False,in_count,cur_count)
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
			
			if type_conv == '' : raise Exception('')
		
			temp_file.write(mc_conv_data)
			
			work_file,reading,file_end,mc_file_name = init_file(temp_file.name,in_file,True,in_count,cur_count)
			if reading == 'continue' : continue
		
		except :
			print(col_r + 'Error: Cannot convert Intel container!\n' + col_e)
	
	# Intel Microcodes
	
	# CPUID 0306F2 = 03 + 06 + F2 = (1 + 4) + (2 + 5) + (3 + 6) = 06 (Family) + 3F (Model) + 02 (Stepping) = MU 063F02
	# MU 063F02 = 06 + 3F + 02 = (1 + 3 + 5) + (2 + 4 + 6) = 030 + 6F2 = CPUID 0306F2
	
	match_list_i += pat_icpu.finditer(reading)
	
	total += len(match_list_i)
	
	if param.verbose : col_names = ['#','CPUID','PLATFORM','VERSION','YYYY-MM-DD','SIZE','CHECKSUM','OFFSET','STATUS']
	else : col_names = ['#','CPUID','PLATFORM','VERSION','YYYY-MM-DD','STATUS']
	
	pt,pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_i :
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_hdr = get_struct(reading, mc_bgn, Intel_MC_Header)
		
		patch = '%0.8X' % mc_hdr.UpdateRevision
		
		year = '%0.4X' % mc_hdr.Year
		
		day = '%0.2X' % mc_hdr.Day
		
		month = '%0.2X' % mc_hdr.Month
		
		cpu_id = '%0.8X' % mc_hdr.ProcessorSignature
		
		plat_db = '%0.8X' % mc_hdr.ProcessorFlags
		plat_cut = '%0.2X' % mc_hdr.ProcessorFlags
		plat_bit = intel_plat(mc_hdr.ProcessorFlags)
		
		mc_len = mc_hdr.TotalSize
		if mc_len == 0 : mc_len = 2048
		mc_len_db = '%0.8X' % mc_len
		
		mc_chk = '%0.8X' % mc_hdr.Checksum
		
		res_field = mc_hdr.Reserved1 + mc_hdr.Reserved2 + mc_hdr.Reserved3
		
		full_date = "%s-%s-%s" % (year, month, day)
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
			if date_chk.year > 2017 or date_chk.year < 1993 : raise Exception('WrongDate') # 1st MC from 1995 (P6), 1993 for safety
		except :
			if full_date == '1896-00-07' and patch == '000000D1' : pass # Drunk Intel employee #1, Happy 0th month from 19th century Intel!
			else :
				if param.verbose : msg_i.append(col_m + "\nWarning: Skipped Intel microcode at 0x%0.2X, invalid Date of %s!" % (mc_bgn, full_date) + col_e)
				if param.exp_check : mc_verbose(work_file)
				skip += 1
				continue
		
		# Remove false results, based on Reserved field
		if res_field != 0 :
			if param.verbose : msg_i.append(col_m + "\nWarning: Skipped Intel microcode at 0x%0.2X, Reserved field not empty!" % mc_bgn + col_e)
			if param.exp_check : mc_verbose(work_file)
			skip += 1
			continue
		
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
			valid_ext_chk = 0
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()

			if reading[mc_bgn + 0x34:mc_bgn + 0x38] == b'\xA1' + b'\x00' * 3 :
				mc_hdr_extra = get_struct(reading, mc_bgn + 0x30, Intel_MC_Header_Extra)
				mc_hdr_extra.mc_print_extra()
			
			if mc_extended_found :
				# noinspection PyUnboundLocalVariable
				mc_hdr_extended.mc_print_extended()
				
				# noinspection PyUnboundLocalVariable
				mc_extended_field_off = mc_extended_off + 0x14
				
				# noinspection PyUnboundLocalVariable
				for idx in range(ext_fields_count) :
					mc_hdr_extended_field = get_struct(reading, mc_extended_field_off, Intel_MC_Header_Extended_Field)
					mc_hdr_extended_field.mc_print_extended_field()
					mc_extended_field_off += 0xC
					
			continue # Next MC of input file
		
		mc_name = "cpu%s_plat%s_ver%s_date%s" % (cpu_id, plat_cut, patch, full_date)
		mc_nr += 1
		
		mc_at_db = (c.execute('SELECT * FROM Intel WHERE cpuid=? AND platform=? AND version=? AND yyyymmdd=? AND size=? \
					AND checksum=?', (cpu_id, plat_db, patch, year + month + day, mc_len_db, mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				c.execute('INSERT INTO Intel (cpuid, platform, version, yyyymmdd, size, checksum) VALUES (?,?,?,?,?,?)',
						(cpu_id, plat_db, patch, year + month + day, mc_len_db, mc_chk))
			
				c.execute('UPDATE MCE SET date=?', (int(time.time()),))
			
				conn.commit()
			
				print(col_g + "\nAdded Intel: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			
			continue
		
		mc_dates = (c.execute('SELECT yyyymmdd FROM Intel WHERE cpuid=? AND platform=?', (cpu_id, plat_db,))).fetchall()
		
		# Determine if MC is Latest or Outdated
		mc_upd = mc_upd_chk(mc_dates)
		
		if param.verbose : row = [mc_nr, cpu_id, '%s %s' % (plat_cut, plat_bit), patch, full_date, '0x%0.2X' % mc_len, mc_chk, '0x%0.2X' % mc_bgn, mc_upd]
		else : row = [mc_nr, cpu_id, plat_cut, patch, full_date, mc_upd]
		pt.add_row(row)
		
		mc_end = mc_bgn + mc_len
		mc_data = reading[mc_bgn:mc_end]
		valid_mc_chk = checksum32(mc_data)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = mce_dir + os_dir +  '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + os_dir + 'Extracted' + os_dir + 'Intel' + os_dir
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if valid_mc_chk != 0 or valid_ext_chk != 0 :
			if patch == '000000FF' and cpu_id == '000506E3' and full_date == '2016-01-05' : # Someone "fixed" the modded MC checksum wrongfully
				mc_path = mc_extract + "%s.bin" % mc_name
			else :
				msg_i.append(col_m + '\nWarning: Microcode #%s is packed or badly extracted, please report it!' % mc_nr + col_e)
				mc_path = mc_extract + "!Bad_%s%s.bin" % (mc_name,mc_file_name)
		elif mc_at_db is None :
			msg_i.append(col_g + "\nNote: Microcode #%s was not found at the database, please report it!" % mc_nr + col_e)
			mc_path = mc_extract + "!New_%s%s.bin" % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + "%s.bin" % mc_name
		
		if not has_duplicate(mc_path, mc_data) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)
	
	if str(pt) != pt_empty :
		pt.title = col_b + 'Intel' + col_e
		print(pt)
	for i in range(len(msg_i)): print(msg_i[i])
	if msg_i : print()
	
	# AMD Microcodes
	
	# CPUID 610F21 = 61 + 0F + 21  = (1 + 4) + (2 + 5) + (3 + 6) = 6+F + 12 + 01 = 15 + 12 + 01 = MU 151201
	# MU 151201 = 15 + 12 + 01 = 6+F + 12 + 01 = (1 + 3 + 5) + (2 + 4 + 6) = 610 + F21 = CPUID 610F21
	
	match_list_a += pat_acpu.finditer(reading)
	
	total += len(match_list_a)
	
	if param.verbose : col_names = ['#', 'CPUID', 'VERSION', 'YYYY-MM-DD', 'SIZE', 'CHKAMD', 'CHKMCE', 'OFFSET', 'STATUS']
	else : col_names = ['#', 'CPUID', 'VERSION', 'YYYY-MM-DD', 'STATUS']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_a :
		
		unk_size = False
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
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
		
		if cpu_id == '00800F11' and patch == '08001105' and year == '2016' : year = '2017' # Drunk AMD employee #2, Zen in January 2016!
		
		full_date = "%s-%s-%s" % (year, month, day)
		
		# Remove false results, based on Date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
			
			if date_chk.year > 2017 or date_chk.year < 2000 : raise Exception('WrongDate') # 1st MC from 1999 (K7), 2000 for K7 Erratum and performance
		except :
			if full_date == '2011-13-09' and patch == '03000027' : pass # Drunk AMD employee #1, Happy 13th month from AMD!
			else :
				if param.verbose : msg_a.append(col_m + "\nWarning: Skipped AMD microcode at 0x%0.2X, invalid Date of %s!" % (mc_bgn, full_date) + col_e)
				if param.exp_check : mc_verbose(work_file)
				skip += 1
				continue
		
		# Remove false results, based on VEN_IDs
		if (nb_id != '0'*8 and '1002' not in nb_id[4:8] and '1022' not in nb_id[4:8]) \
		or (sb_id != '0'*8 and '1002' not in sb_id[4:8] and '1022' not in sb_id[4:8]) :
			if param.verbose : msg_a.append(col_m + "\nWarning: Skipped AMD microcode at 0x%0.2X, invalid VEN_IDs of %s,%s!" % (mc_bgn, nb_id[4:8], sb_id[4:8]) + col_e)
			if param.exp_check : mc_verbose(work_file)
			skip += 1
			continue
		
		# Remove false results, based on Data Length
		if data_len not in ['10','20','00'] :
			if param.verbose : msg_a.append(col_m + "\nWarning: Skipped AMD microcode at 0x%0.2X, Data Length not standard!" % mc_bgn + col_e)
			if param.exp_check : mc_verbose(work_file)
			skip += 1
			continue
		
		# Remove false results, based on data
		if reading[mc_bgn + 0x40:mc_bgn + 0x44] == b'\x00' * 4 : # 0x40 has non-null data
			if param.verbose : msg_a.append(col_m + "\nWarning: Skipped AMD microcode at 0x%0.2X, null data at 0x40!" % mc_bgn + col_e)
			if param.exp_check : mc_verbose(work_file)
			skip += 1
			continue
		
		# Print the Header
		if param.print_hdr :
			mc_hdr.mc_print()
			
			if cpu_id[2:4] in ['80'] :
				mc_hdr_extra = get_struct(reading, mc_bgn + 0x20, AMD_MC_Header_Extra)
				mc_hdr_extra.mc_print()
			continue
		
		mc_name = "cpu%s_ver%s_date%s" % (cpu_id, patch, full_date)
		mc_nr += 1
		
		# Determine size based on generation
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
			
		elif cpu_id[2:4] in ['80'] :
			mc_len_amd = 0xD00
			if param.pad_check : mc_len = amd_padd(mc_bgn + mc_len_amd, 0x80, 0xD00, 0xD00, 0xD80)
			else : mc_len = mc_len_amd
			
		else :
			unk_size = True
		
		if unk_size :
			mc_len_db = '00000000'
			msg_a.append(col_r + "\n%0.2d. Error: %s not extracted at 0x%0.2X, unknown Size!" % (mc_nr, mc_name, mc_bgn) + col_e)
			continue
		else :
			mc_len_db = '%0.8X' % mc_len_amd
		
		mc_extr = reading[mc_bgn:mc_bgn + mc_len]
		mc_data = reading[mc_bgn:mc_bgn + mc_len_amd]
		mc_file_chk = '%0.8X' % adler32(mc_data) # Custom Data-only Checksum
		valid_chk = checksum32(mc_extr[0x40:]) # AMD File Checksum (Data+Padding)
		
		mc_at_db = (c.execute('SELECT * FROM AMD WHERE cpuid=? AND nbdevid=? AND sbdevid=? AND nbsbrev=? AND version=? \
								AND yyyymmdd=? AND size=? AND chkbody=? AND chkmc=?', (cpu_id, nb_id, sb_id, nbsb_rev_id,
								patch, year + month + day, mc_len_db, mc_chk_hex, mc_file_chk, ))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				c.execute('INSERT INTO AMD (cpuid, nbdevid, sbdevid, nbsbrev, version, yyyymmdd, size, chkbody, chkmc) \
							VALUES (?,?,?,?,?,?,?,?,?)', (cpu_id, nb_id, sb_id, nbsb_rev_id, patch, year + month + day,
							mc_len_db, mc_chk_hex, mc_file_chk))
			
				c.execute('UPDATE MCE SET date=?', (int(time.time()),))
				
				conn.commit()
				
				print(col_g + "\nAdded AMD: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			
			continue
		
		mc_dates = (c.execute('SELECT yyyymmdd FROM AMD WHERE cpuid=? AND nbdevid=? AND sbdevid=? AND nbsbrev=?',
							 (cpu_id, nb_id, sb_id, nbsb_rev_id,))).fetchall()
		
		# Determine if MC is Latest or Outdated
		mc_upd = mc_upd_chk(mc_dates)
		
		if param.verbose : row = [mc_nr, cpu_id, patch, full_date, '0x%0.2X' % mc_len_amd, mc_chk_hex, mc_file_chk, '0x%0.2X' % mc_bgn, mc_upd]
		else : row = [mc_nr, cpu_id, patch, full_date, mc_upd]
		pt.add_row(row)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = mce_dir + os_dir +  '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + os_dir + 'Extracted' + os_dir + 'AMD' + os_dir
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if int(cpu_id[2:4], 16) < 0x50 and (valid_chk + mc_chk) & 0xFFFFFFFF != 0 :
			msg_a.append(col_m + '\nWarning: Microcode #%s is packed or badly extracted, please report it!' % mc_nr + col_e)
			mc_path = mc_extract + "!Bad_%s%s.bin" % (mc_name,mc_file_name)
		elif cpu_id[2:4] in ['80'] and reading[mc_bgn + mc_len - 0x80:mc_bgn + mc_len] != b'\xFF' * 0x80 :
			msg_a.append(col_m + '\nWarning: Ryzen microcode #%s size might be wrong, please report it!' % mc_nr + col_e)
			mc_path = mc_extract + "!Zen_%s%s.bin" % (mc_name,mc_file_name)
		elif mc_at_db is None :
			msg_a.append(col_g + "\nNote: Microcode #%s was not found at the database, please report it!" % mc_nr + col_e)
			mc_path = mc_extract + "!New_%s%s.bin" % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + "%s.bin" % mc_name
		
		if not has_duplicate(mc_path, mc_extr) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_extr)
		
	if str(pt) != pt_empty :
		pt.title = col_r + 'AMD' + col_e
		print(pt)
	for i in range(len(msg_a)) : print(msg_a[i])
	if msg_i or msg_a : print()
	
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
	
	match_list_v += pat_vcpu.finditer(reading)
	
	total += len(match_list_v)
	
	if param.verbose : col_names = ['#', 'CPUID', 'NAME', 'VERSION', 'YYYY-MM-DD', 'SIZE', 'CHECKSUM', 'OFFSET', 'STATUS']
	else : col_names = ['#', 'CPUID', 'NAME', 'VERSION', 'YYYY-MM-DD', 'STATUS']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_v :
		
		# noinspection PyRedeclaration
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
		
		full_date = "%s-%s-%s" % (year, month, day)
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
			if date_chk.year > 2017 or date_chk.year < 2006 : raise Exception('WrongDate') # 1st MC from 2008 (Nano), 2006 for safety
		except :
			# VIA is sober? No drunk VIA employee ???
			if param.verbose : msg_v.append(col_m + "\nWarning: Skipped VIA microcode at 0x%0.2X, invalid Date of %s!\n" % (mc_bgn, full_date) + col_e)
			if param.exp_check : mc_verbose(work_file)
			skip += 1
			continue
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			continue
		
		mc_name = "cpu%s_sig%s_size%s_date%s" % (cpu_id, name, mc_len_db, full_date)
		mc_nr += 1
		
		mc_at_db = (c.execute('SELECT * FROM VIA WHERE cpuid=? AND signature=? AND version=? AND yyyymmdd=? AND size=? AND checksum=?',
				  (cpu_id, name, patch_db, year + month + day, mc_len_db, mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				c.execute('INSERT INTO VIA (cpuid, signature, version, yyyymmdd, size, checksum) VALUES (?,?,?,?,?,?)',
						(cpu_id, name, patch_db, year + month + day, mc_len_db, mc_chk))
			
				c.execute('UPDATE MCE SET date=?', (int(time.time()),))
			
				conn.commit()
			
				print(col_g + "\nAdded VIA: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			
			continue
		
		mc_dates = (c.execute('SELECT yyyymmdd FROM VIA WHERE cpuid=?', (cpu_id,))).fetchall()
		
		# Determine if MC is Latest or Outdated
		mc_upd = mc_upd_chk(mc_dates)
		
		if param.verbose : row = [mc_nr, cpu_id, name, patch, full_date, '0x%0.2X' % mc_len, mc_chk, '0x%0.2X' % mc_bgn, mc_upd]
		else : row = [mc_nr, cpu_id, name, patch, full_date, mc_upd]
		pt.add_row(row)
		
		mc_end = mc_bgn + mc_len
		mc_data = reading[mc_bgn:mc_end]
		valid_chk = checksum32(mc_data)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = mce_dir + os_dir +  '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + os_dir + 'Extracted' + os_dir + 'VIA' + os_dir
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if valid_chk != 0 :
			msg_v.append(col_m + '\nWarning: Microcode #%s is packed or badly extracted, please report it!\n' % mc_nr + col_e)
			mc_path = mc_extract + '!Bad_%s%s.bin' % (mc_name,mc_file_name)
		elif mc_at_db is None :
			msg_v.append(col_g + '\nNote: Microcode #%s was not found at the database, please report it!\n' % mc_nr + col_e)
			mc_path = mc_extract + '!New_%s%s.bin' % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + '%s.bin' % mc_name
		
		if not has_duplicate(mc_path, mc_data) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)

	if str(pt) != pt_empty :
		pt.title = col_c + 'VIA' + col_e
		print(pt)
	for i in range(len(msg_v)) : print(msg_v[i])
	if msg_i or msg_a or msg_v : print()
	
	# Freescale Microcodes
	
	match_list_f += pat_fcpu.finditer(reading)
	
	total += len(match_list_f)
	
	if param.verbose : col_names = ['#', 'NAME', 'SOC-MODEL', 'SOC-MAJOR', 'SOC-MINOR', 'SIZE', 'CHECKSUM', 'OFFSET']
	else : col_names = ['#', 'NAME', 'SOC-MODEL', 'SOC-MAJOR', 'SOC-MINOR']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_f :
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_bgn -= 4 # Pattern starts at Signature for performance
		
		mc_hdr = get_struct(reading, mc_bgn, FSL_MC_Header)
		
		name = '%s' % mc_hdr.Name.decode('utf-8')
		
		model = '%0.4d' % mc_hdr.Model
		
		major = '%d' % mc_hdr.Major
		
		minor = '%d' % mc_hdr.Minor
		
		mc_len = mc_hdr.TotalSize
		mc_len_db = '%0.8X' % mc_len
		
		mc_chk = '%0.8X' % int.from_bytes(reading[mc_bgn + mc_len - 4:mc_bgn + mc_len], 'big')
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			
			qe_off = 0x7C # Header size
			for qe_mc in range(mc_hdr.CountMC) :
				qe_hdr = get_struct(reading, qe_off, FSL_MC_Entry)
				qe_hdr.mc_print()
				qe_off += 0x78 # Entry size
			
			continue
		
		mc_name = "soc%s_rev%s.%s_chk%s_[%s]" % (model, major, minor, mc_chk, name)
		
		mc_nr += 1
		
		mc_at_db = (c.execute('SELECT * FROM FSL WHERE name=? AND model=? AND major=? AND minor=? AND size=? AND checksum=?',
				  (name, model, major, minor, mc_len_db, mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				c.execute('INSERT INTO FSL (name, model, major, minor, size, checksum) VALUES (?,?,?,?,?,?)',
						(name, model, major, minor, mc_len_db, mc_chk))
			
				c.execute('UPDATE MCE SET date=?', (int(time.time()),))
			
				conn.commit()
			
				print(col_g + "\nAdded Freescale: %s\n" % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(work_file, in_file, mc_name)
			
			continue
		
		if param.verbose : row = [mc_nr, name, model, major, minor, '0x%0.2X' % mc_len, mc_chk, '0x%0.2X' % mc_bgn]
		else : row = [mc_nr, name, model, major, minor]
		pt.add_row(row)
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		
		calc_crc = (binascii.crc32(mc_data[0:-4], -1) ^ -1) & 0xFFFFFFFF
		
		# Create extraction folder
		if '-extr' in source : mc_extract = mce_dir + os_dir +  '..\Z_Extract\\CPU\\'
		else : mc_extract = mce_dir + os_dir + 'Extracted' + os_dir + 'Freescale' + os_dir
		if not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if calc_crc != int(mc_chk, 16) :
			msg_f.append(col_m + '\nWarning: Microcode #%s is packed or badly extracted, please report it!\n' % mc_nr + col_e)
			mc_path = mc_extract + '!Bad_%s%s.bin' % (mc_name,mc_file_name)
		elif mc_at_db is None :
			msg_f.append(col_g + '\nNote: Microcode #%s was not found at the database, please report it!\n' % mc_nr + col_e)
			mc_path = mc_extract + '!New_%s%s.bin' % (mc_name,mc_file_name)
		else :
			mc_path = mc_extract + '%s.bin' % mc_name
		
		if not has_duplicate(mc_path, mc_data) :
			baseName = os.path.basename(mc_path)
			name_root, name_ext = os.path.splitext(baseName)
			mc_path = auto_name (mc_extract, name_root, "_nr", "bin")[1]
			
			with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)
	
	if str(pt) != pt_empty :
		pt.title = col_y + 'Freescale' + col_e
		print(pt)
	for i in range(len(msg_f)) : print(msg_f[i])
	
	if temp_file is not None :
		temp_file.close()
		os.remove(temp_file.name)
		
	if total == 0 or skip == total :
		print('File does not contain CPU microcodes')
		
	if skip > 0 and not param.verbose : print(col_y + '\nNote: %s skipped microcode(s), use -verbose for details' % skip + col_e)

mce_exit()