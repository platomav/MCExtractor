#!/usr/bin/env python3

"""
MC Extractor
Intel, AMD, VIA & Freescale Microcode Extractor
Copyright (C) 2016-2020 Plato Mavropoulos
"""

title = 'MC Extractor v1.43.1'

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
import urllib.request

# Initialize and setup Colorama
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
elif mce_os.startswith('linux') or mce_os == 'darwin' or mce_os.find('bsd') != -1 :
	cl_wipe = 'clear'
else :
	print(col_r + '\nError: Unsupported platform "%s"!\n' % mce_os + col_e)
	if '-exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)

# Detect Python version
mce_py = sys.version_info
try :
	assert mce_py >= (3,7)
except :
	print(col_r + '\nError: Python >= 3.7 required, not %d.%d!\n' % (mce_py[0],mce_py[1]) + col_e)
	if '-exit' not in sys.argv : input('Press enter to exit')
	colorama.deinit()
	sys.exit(-1)

# Fix Windows Unicode console redirection
if mce_os == 'win32' : sys.stdout.reconfigure(encoding='utf-8')

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

def mce_help() :
	print(
		  '\nUsage: MCE [FilePath] {Options}\n\n{Options}\n\n'
		  '-?      : Displays help & usage screen\n'
		  '-skip   : Skips welcome & options screen\n'
		  '-exit   : Skips Press enter to exit prompt\n'
		  '-mass   : Scans all files of a given directory\n'
		  '-info   : Displays microcode header(s)\n'
		  '-add    : Adds new input microcode to DB\n'
		  '-dbname : Renames input file based on DB name\n'
		  '-search : Searches for microcodes based on CPUID\n'
		  '-updchk : Checks for MC Extractor & DB updates\n'
		  '-last   : Shows \"Last\" status based on user input\n'
		  '-repo   : Builds microcode repositories from input\n'
		  '-blob   : Builds a Microcode Blob (MCB) from input'
		  )
	
	mce_exit(0)

class MCE_Param :

	def __init__(self, mce_os, source) :
	
		self.all = ['-?','-skip','-info','-add','-extr','-ubu','-mass','-search','-dbname','-repo','-exit','-blob','-last','-updchk']
		self.win = ['-extr','-ubu'] # Windows only
		
		if mce_os == 'win32' : self.val = self.all
		else : self.val = [item for item in self.all if item not in self.win]
		
		self.help_scr = False
		self.build_db = False
		self.skip_intro = False
		self.print_hdr = False
		self.mce_extr = False
		self.mass_scan = False
		self.search = False
		self.give_db_name = False
		self.build_repo = False
		self.mce_ubu = False
		self.skip_pause = False
		self.build_blob = False
		self.get_last = False
		self.upd_check = False
		
		for i in source :
			if i == '-?' : self.help_scr = True
			if i == '-skip' : self.skip_intro = True
			if i == '-add' : self.build_db = True
			if i == '-info' : self.print_hdr = True
			if i == '-mass' : self.mass_scan = True
			if i == '-search' : self.search = True
			if i == '-dbname' : self.give_db_name = True
			if i == '-repo' : self.build_repo = True
			if i == '-exit' : self.skip_pause = True
			if i == '-blob' : self.build_blob = True
			if i == '-last' : self.get_last = True
			if i == '-updchk' : self.upd_check = True
			
			# Windows only options
			if mce_os == 'win32' :
				if i == '-ubu' : self.mce_ubu = True # Hidden
				if i == '-extr': self.mce_extr = True # Hidden
			
		if self.mce_extr or self.mass_scan or self.search or self.build_repo or self.build_blob \
		or self.get_last or self.upd_check : self.skip_intro = True

class Intel_MC_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("HeaderVersion",             uint32_t),  # 0x00 00000001 (Pattern)
		("UpdateRevision",            uint32_t),  # 0x04 Signed to signify PRD/PRE
		("Year",                      uint16_t),  # 0x08
		("Day",                       uint8_t),   # 0x0A
		("Month",                     uint8_t),   # 0x0B
		("ProcessorSignature",        uint32_t),  # 0x0C
		("Checksum",                  uint32_t),  # 0x10 OEM validation only
		("LoaderRevision",            uint32_t),  # 0x14 00000001 (Pattern)
		("PlatformIDs",               uint8_t),   # 0x18 Supported Platforms
		("Reserved0",                 uint8_t*3), # 0x19 00 * 3 (Pattern)
		("DataSize",                  uint32_t),  # 0x1C Extra + Patch
		("TotalSize",                 uint32_t),  # 0x20 Header + Extra + Patch + Extended
		("Reserved1",                 uint32_t*3),# 0x24 00 * 12 (Pattern)
		# 0x30
	]

	# Intel 64 and IA-32 Architectures Software Developer's Manual Vol 3A, Ch 9.11.1
	
	def mc_print(self) :
		Reserved0 = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved0))
		Reserved1 = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Reserved1))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Main' + col_e
		pt.add_row(['Header Version', self.HeaderVersion])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
		pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		pt.add_row(['Loader Version', self.LoaderRevision])
		pt.add_row(['Platform', '%0.2X (%s)' % (self.PlatformIDs, ','.join(map(str, intel_plat(mc_hdr.PlatformIDs))))])
		pt.add_row(['Reserved 0', '0x0' if Reserved0 == '00' * 3 else Reserved0])
		pt.add_row(['Data Size', '0x%X' % self.DataSize])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['Reserved 1', '0x0' if Reserved1 == '00' * 12 else Reserved1])
		
		print(pt)

class Intel_MC_Header_Extra_R1(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("ModuleType",                uint16_t),    # 0x00 0000 (always)
		("ModuleSubType",             uint16_t),    # 0x02 0000 (always)
		("ModuleSize",			      uint32_t),    # 0x04 dwords
		("Flags",                     uint16_t),    # 0x08 0 RSA Signed, 1-31 Reserved
		("RSAKeySize",                uint16_t),    # 0x0A 1K multiple (2 * 1024 = 2048)
		("UpdateRevision",            uint32_t),    # 0x0C Signed to signify PRD/PRE
		("VCN",                  	  uint32_t),    # 0x10 Version Control Number
		("MultiPurpose1",     	      uint32_t),    # 0x14 dwords from Extra, UpdateSize, Empty etc
		("Day",                       uint8_t),     # 0x18
		("Month",                     uint8_t),     # 0x19
		("Year",                      uint16_t),    # 0x1A
		("UpdateSize",                uint32_t),    # 0x1C dwords from Extra without encrypted padding
		("ProcessorSignatureCount",   uint32_t),    # 0x20 max is 8 (8 * 0x4 = 0x20)
		("ProcessorSignature0",       uint32_t),    # 0x24
		("ProcessorSignature1",		  uint32_t),    # 0x28
		("ProcessorSignature2",		  uint32_t),    # 0x2C
		("ProcessorSignature3",		  uint32_t),    # 0x30
		("ProcessorSignature4",		  uint32_t),    # 0x34
		("ProcessorSignature5",		  uint32_t),    # 0x38
		("ProcessorSignature6",		  uint32_t),    # 0x3C
		("ProcessorSignature7",		  uint32_t),    # 0x40
		("MultiPurpose2",      	      uint32_t),    # 0x44 dwords from Extra + encrypted padding, UpdateSize, Platform, Empty
		("SVN",     				  uint32_t),    # 0x48 Security Version Number
		("Reserved",                  uint32_t*5),  # 0x4C Reserved (00000000)
		("Unknown",                   uint32_t*8),  # 0x60
		("RSAPublicKey",              uint32_t*64), # 0x80
		("RSAExponent",               uint32_t),    # 0x180 0x11 (17)
		("RSASignature",              uint32_t*64), # 0x184 0x14 --> SHA-1 or 0x20 --> SHA-256
		# 0x284
	]

	def mc_print(self) :
		print()
		
		f1,f2 = self.get_flags()
		cpuids = self.get_cpuids()
		
		Reserved = int.from_bytes(self.Reserved, 'little')
		Unknown = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown))
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extra' + col_e
		pt.add_row(['Module Type', self.ModuleType])
		pt.add_row(['Module Sub Type', self.ModuleSubType])
		pt.add_row(['Module Size', '0x%X' % (self.ModuleSize * 4)])
		pt.add_row(['RSA Signed', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '{0:07b}b'.format(f2)])
		pt.add_row(['RSA Key Size', self.RSAKeySize * 1024])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Version Control Number', self.VCN])
		if self.MultiPurpose1 == mc_hdr.PlatformIDs : pt.add_row(['Platform (MP1)', '%0.2X (%s)' % (self.MultiPurpose1, ','.join(map(str, intel_plat(mc_hdr.PlatformIDs))))])
		elif self.MultiPurpose1 * 4 == self.UpdateSize * 4 : pt.add_row(['Update Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
		elif self.MultiPurpose1 * 4 == mc_len - 0x30 : pt.add_row(['Padded Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
		else : pt.add_row(['Multi Purpose 1', '0x%X' % self.MultiPurpose1])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
		pt.add_row(['Update Size', '0x%X' % (self.UpdateSize * 4)])
		pt.add_row(['CPU Signatures', self.ProcessorSignatureCount])
		[pt.add_row(['CPUID %d' % i, '%0.5X' % cpuids[i]]) for i in range(len(cpuids)) if cpuids[i] != 0]
		if self.MultiPurpose2 == mc_hdr.PlatformIDs : pt.add_row(['Platform (MP2)', '%0.2X (%s)' % (self.MultiPurpose2, ','.join(map(str, intel_plat(mc_hdr.PlatformIDs))))])
		elif self.MultiPurpose2 * 4 == self.UpdateSize * 4 : pt.add_row(['Update Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
		elif self.MultiPurpose2 * 4 == mc_len - 0x30 : pt.add_row(['Padded Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
		else : pt.add_row(['Multi Purpose 2', '0x%X' % self.MultiPurpose2])
		pt.add_row(['Security Version Number', self.SVN])
		pt.add_row(['Reserved', '0x%X' % Reserved])
		pt.add_row(['Unknown', '%s [...]' % Unknown[:8]])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Exponent', '0x%X' % self.RSAExponent])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		print(pt)
	
	def get_flags(self) :
		flags = Intel_MC_Header_Extra_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.RSASigned, flags.b.Reserved
		
	def get_cpuids(self) :
		return (self.ProcessorSignature0,self.ProcessorSignature1,self.ProcessorSignature2,self.ProcessorSignature3,
				self.ProcessorSignature4,self.ProcessorSignature5,self.ProcessorSignature6,self.ProcessorSignature7)
		
class Intel_MC_Header_Extra_R2(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('ModuleType',                uint16_t),    # 0x00 0000 (always)
		('ModuleSubType',             uint16_t),    # 0x02 0000 (always)
		('ModuleSize',			      uint32_t),    # 0x04 dwords
		('Flags',                     uint16_t),    # 0x08 0 RSA Signed, 1-31 Reserved
		('RSAKeySize',                uint16_t),    # 0x0A 1K multiple (3 * 1024 = 3072)
		('UpdateRevision',            uint32_t),    # 0x0C Signed to signify PRD/PRE
		('VCN',                  	  uint32_t),    # 0x10 Version Control Number
		('MultiPurpose1',     	      uint32_t),    # 0x14 dwords from Extra, UpdateSize, Empty etc
		('Day',                       uint8_t),     # 0x18
		('Month',                     uint8_t),     # 0x19
		('Year',                      uint16_t),    # 0x1A
		('UpdateSize',                uint32_t),    # 0x1C dwords from Extra without encrypted padding
		('ProcessorSignatureCount',   uint32_t),    # 0x20 max is 8 (8 * 0x4 = 0x20)
		('ProcessorSignature0',       uint32_t),    # 0x24
		('ProcessorSignature1',		  uint32_t),    # 0x28
		('ProcessorSignature2',		  uint32_t),    # 0x2C
		('ProcessorSignature3',		  uint32_t),    # 0x30
		('ProcessorSignature4',		  uint32_t),    # 0x34
		('ProcessorSignature5',		  uint32_t),    # 0x38
		('ProcessorSignature6',		  uint32_t),    # 0x3C
		('ProcessorSignature7',		  uint32_t),    # 0x40
		('MultiPurpose2',      	      uint32_t),    # 0x44 dwords from Extra + encrypted padding, UpdateSize, Platform, Empty
		('SVN',     				  uint32_t),    # 0x48 Security Version Number
		('Reserved',                  uint32_t*5),  # 0x4C Reserved (00000000)
		('Unknown',                   uint32_t*8),  # 0x60
		('RSAPublicKey',              uint32_t*96), # 0x80 Exponent is 0x10001 (65537)
		('RSASignature',              uint32_t*96), # 0x200 0x33 --> 0x13 = Unknown + 0x20 = SHA-256
		# 0x380
	]

	def mc_print(self) :
		print()
		
		f1,f2 = self.get_flags()
		cpuids = self.get_cpuids()
		
		Reserved = int.from_bytes(self.Reserved, 'little')
		Unknown = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown))
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSAPublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.RSASignature))
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extra' + col_e
		pt.add_row(['Module Type', self.ModuleType])
		pt.add_row(['Module Sub Type', self.ModuleSubType])
		pt.add_row(['Module Size', '0x%X' % (self.ModuleSize * 4)])
		pt.add_row(['RSA Signed', ['No','Yes'][f1]])
		pt.add_row(['Flags Reserved', '{0:07b}b'.format(f2)])
		pt.add_row(['RSA Key Size', self.RSAKeySize * 1024])
		pt.add_row(['Update Version', '%X' % self.UpdateRevision])
		pt.add_row(['Version Control Number', self.VCN])
		if self.MultiPurpose1 == mc_hdr.PlatformIDs : pt.add_row(['Platform (MP1)', '%0.2X (%s)' % (self.MultiPurpose1, ','.join(map(str, intel_plat(mc_hdr.PlatformIDs))))])
		elif self.MultiPurpose1 * 4 == self.UpdateSize * 4 : pt.add_row(['Update Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
		elif self.MultiPurpose1 * 4 == mc_len - 0x30 : pt.add_row(['Padded Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
		else : pt.add_row(['Multi Purpose 1', '0x%X' % self.MultiPurpose1])
		pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
		pt.add_row(['Update Size', '0x%X' % (self.UpdateSize * 4)])
		pt.add_row(['CPU Signatures', self.ProcessorSignatureCount])
		[pt.add_row(['CPUID %d' % i, '%0.5X' % cpuids[i]]) for i in range(len(cpuids)) if cpuids[i] != 0]
		if self.MultiPurpose2 == mc_hdr.PlatformIDs : pt.add_row(['Platform (MP2)', '%0.2X (%s)' % (self.MultiPurpose2, ','.join(map(str, intel_plat(mc_hdr.PlatformIDs))))])
		elif self.MultiPurpose2 * 4 == self.UpdateSize * 4 : pt.add_row(['Update Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
		elif self.MultiPurpose2 * 4 == mc_len - 0x30 : pt.add_row(['Padded Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
		else : pt.add_row(['Multi Purpose 2', '0x%X' % self.MultiPurpose2])
		pt.add_row(['Security Version Number', self.SVN])
		pt.add_row(['Reserved', '0x%X' % Reserved])
		pt.add_row(['Unknown', '%s [...]' % Unknown[:8]])
		pt.add_row(['RSA Public Key', '%s [...]' % RSAPublicKey[:8]])
		pt.add_row(['RSA Signature', '%s [...]' % RSASignature[:8]])
		
		print(pt)
	
	def get_flags(self) :
		flags = Intel_MC_Header_Extra_GetFlags()
		flags.asbytes = self.Flags
		
		return flags.b.RSASigned, flags.b.Reserved
		
	def get_cpuids(self) :
		return (self.ProcessorSignature0,self.ProcessorSignature1,self.ProcessorSignature2,self.ProcessorSignature3,
				self.ProcessorSignature4,self.ProcessorSignature5,self.ProcessorSignature6,self.ProcessorSignature7)
		
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
	_pack_ = 1
	_fields_ = [
		('ExtendedSignatureCount',    uint32_t),    # 0x00
		('ExtendedChecksum',          uint32_t),    # 0x04
		('Reserved',                  uint32_t*3),  # 0x08
		# 0x14
	]

	def mc_print(self) :
		print()
		
		Reserved = int.from_bytes(self.Reserved, 'little')

		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extended' + col_e
		pt.add_row(['Extended Signatures', self.ExtendedSignatureCount])
		pt.add_row(['Extended Checksum', '%0.8X' % self.ExtendedChecksum])
		pt.add_row(['Reserved', '0x%X' % Reserved])
		
		print(pt)

class Intel_MC_Header_Extended_Field(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('ProcessorSignature',        uint32_t),  # 0x00
		('PlatformIDs',               uint32_t),  # 0x04
		('Checksum',                  uint32_t),  # 0x08 replace CPUID, Platform, Checksum at Main Header w/o Extended
		# 0x0C
	]

	def mc_print(self) :
		print()
		
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_b + 'Intel Header Extended Field' + col_e
		pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
		pt.add_row(['Platform', '%0.2X %s' % (self.PlatformIDs, intel_plat(self.PlatformIDs))])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		
		print(pt)

class AMD_MC_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
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
		pt.add_row(['Checksum', '%0.8X' % self.DataChecksum])
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

class VIA_MC_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("Signature",                 char*4),    # 0x00 RRAS (Pattern)
		("UpdateRevision",            uint32_t),  # 0x04
		("Year",                      uint16_t),  # 0x08
		("Day",                       uint8_t),   # 0x0A
		("Month",                     uint8_t),   # 0x0B
		("ProcessorSignature",        uint32_t),  # 0x0C
		("Checksum",                  uint32_t),  # 0x10 OEM validation only
		("LoaderRevision",            uint32_t),  # 0x14 00000001 (Pattern)
		("CNRRevision",               uint8_t),   # 0x18 0 CNR001 A0, 1 CNR001 A1
		("Reserved",                  uint8_t*3), # 0x19 FFFFFF (Pattern)
		("DataSize",                  uint32_t),  # 0x1C
		("TotalSize",                 uint32_t),  # 0x20
		("Name",                      char*12),   # 0x24
		# 0x30
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
		pt.add_row(['Loader Version', self.LoaderRevision])
		if self.CNRRevision != 0xFF :
			pt.add_row(['CNR Revision', '001 A%d' % self.CNRRevision])
			pt.add_row(['Reserved', reserv_str])
		else :
			pt.add_row(['Reserved', '0xFFFFFFFF'])
		pt.add_row(['Data Size', '0x%X' % self.DataSize])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['Name', self.Name.replace(b'\x7F',b'\x2E').decode('utf-8').strip()])
		
		print(pt)
		
class FSL_MC_Header(ctypes.BigEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("TotalSize",                 uint32_t),    # 0x00 Entire file
		("Signature",                 char*3),      # 0x04 QEF (Pattern)
		("HeaderVersion",             uint8_t),     # 0x07 01 (Pattern)
		("Name",                      char*62),     # 0x08 Null-terminated ID String
		("IRAM",                      uint8_t),     # 0x46 I-RAM (0 shared, 1 split)
		("CountMC",                   uint8_t),     # 0x47 Number of MC structures
		("Model",                     uint16_t),    # 0x48 SoC Model
		("Major",                     uint8_t),     # 0x4A SoC Revision Major
		("Minor",                     uint8_t),     # 0x4B SoC Revision Minor
		("Reserved0",                 uint32_t),    # 0x4C Alignment
		("ExtendedModes",             uint64_t),    # 0x50 Extended Modes
		("VTraps",                    uint32_t*8),  # 0x58 Virtual Trap Addresses
		("Reserved1",                 uint32_t),    # 0x78 Alignment
		# 0x7C
	]

	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		vtraps_str = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.VTraps))
		if vtraps_str == '00000000' * 8 : vtraps_str = '0x0'
		
		pt.title = col_y + 'Freescale Header Main' + col_e
		pt.add_row(['Signature', self.Signature.decode('utf-8')])
		pt.add_row(['Name', self.Name.decode('utf-8')])
		pt.add_row(['Header Version', self.HeaderVersion])
		pt.add_row(['I-RAM', ['Shared','Split'][self.IRAM]])
		pt.add_row(['Microcode Count', self.CountMC])
		pt.add_row(['Total Size', '0x%X' % self.TotalSize])
		pt.add_row(['SoC Model', '%0.4d' % self.Model])
		pt.add_row(['SoC Major', self.Major])
		pt.add_row(['SoC Minor', self.Minor])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Extended Modes', '0x%X' % self.ExtendedModes])
		pt.add_row(['Virtual Traps', vtraps_str])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		print(pt)
				
class FSL_MC_Entry(ctypes.BigEndianStructure) :
	_pack_ = 1
	_fields_ = [
		("Name",                      char*32),     # 0x00 Null-terminated ID String
		("Traps",                     uint32_t*16), # 0x20 Trap Addresses (0 ignore)
		("ECCR",                      uint32_t),    # 0x60 ECCR Register value
		("IRAMOffset",                uint32_t),    # 0x64 Code Offset into I-RAM
		("CodeLength",                uint32_t),    # 0x68 dwords (*4, 1st Entry only)
		("CodeOffset",                uint32_t),    # 0x6C MC Offset (from 0x0, 1st Entry only)
		("Major",                     uint8_t),     # 0x70 Major
		("Minor",                     uint8_t),     # 0x71 Minor
		("Revision",                  uint8_t),     # 0x72 Revision
		("Reserved0",                 uint8_t),     # 0x73 Alignment
		("Reserved1",                 uint32_t),    # 0x74 Future Expansion
		# 0x78
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
		pt.add_row(['Major', self.Major])
		pt.add_row(['Minor', self.Minor])
		pt.add_row(['Revision', '0x%X' % self.Revision])
		pt.add_row(['Reserved 0', '0x%X' % self.Reserved0])
		pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
		
		print(pt)
				
class MCB_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Tag',                       char*4),      # 0x00 Microcode Blob Tag ($MCB)
		('MCCount',                   uint16_t),    # 0x04 Microcode Entry Count
		('MCEDBRev',                  uint16_t),    # 0x06 MCE DB Revision
		('HeaderRev',                 uint8_t),     # 0x08 MCB Header Revision (2)
		('MCVendor',                  uint8_t),     # 0x09 Microcode Vendor (0 Intel, 1 AMD)
		('Reserved',                  char*2),      # 0x0A Reserved ($$)
		('Checksum',                  uint32_t),    # 0x0C CRC-32 of Header + Entries + Data
		# 0x10
	]
	
	def mc_print(self) :
		pt, pt_empty = mc_table(['Field', 'Value'], False, 1)
		
		pt.title = col_y + 'Microcode Blob Header' + col_e
		pt.add_row(['Tag', self.Tag.decode('utf-8')])
		pt.add_row(['Microcode Count', self.MCCount])
		pt.add_row(['MCE DB Revision', self.MCEDBRev])
		pt.add_row(['Header Revision', self.HeaderRev])
		pt.add_row(['Microcode Vendor', ['Intel','AMD'][self.MCVendor]])
		pt.add_row(['Reserved', self.Reserved.decode('utf-8')])
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		
		print(pt)
		
class MCB_Entry(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('CPUID',                     uint32_t),    # 0x00 CPUID
		('Platform',                  uint32_t),    # 0x04 Platform (Intel only)
		('Revision',                  uint32_t),    # 0x08 Revision
		('Year',                      uint16_t),    # 0x0C Year
		('Month',                     uint8_t),     # 0x0E Month
		('Day',                       uint8_t),     # 0x0F Day
		('Offset',                    uint32_t),    # 0x10 Offset
		('Size',                      uint32_t),    # 0x14 Size
		('Checksum',                  uint32_t),    # 0x18 Checksum (Vendor/MCE)
		('Reserved',                  uint32_t),    # 0x1C Reserved (0)
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
		pt.add_row(['Checksum', '%0.8X' % self.Checksum])
		pt.add_row(['Reserved', self.Reserved])
		
		print(pt)
		
def mce_exit(code=0) :
	if not param.mce_extr and not param.skip_pause : input('\nPress enter to exit')
	
	try :
		cursor.close() # Close DB Cursor
		connection.close() # Close DB Connection
	except :
		pass
	colorama.deinit() # Stop Colorama
	sys.exit(code)
	
# https://stackoverflow.com/a/22881871 by jfs
def get_script_dir(follow_symlinks=True) :
	if getattr(sys, 'frozen', False) :
		path = os.path.abspath(sys.executable)
	else :
		path = inspect.getabsfile(get_script_dir)
	if follow_symlinks :
		path = os.path.realpath(path)

	return os.path.dirname(path)

# https://stackoverflow.com/a/781074 by Torsten Marek
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print(col_r + '\nError: MC Extractor crashed, please report the following:\n')
		traceback.print_exception(exc_type, exc_value, tb)
		print(col_e)
	if not param.skip_pause : input('Press enter to exit')
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
	
# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(input_stream, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = input_stream[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= file_end) or (fit_len < struct_len) :
		print(col_r + 'Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name.__name__) + col_e)
		
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

def mc_db_name(in_file, mc_name) :
	new_dir_name = os.path.join(os.path.dirname(in_file), mc_name + '.bin')
	
	if not os.path.exists(new_dir_name) : os.rename(in_file, new_dir_name)
	elif os.path.basename(in_file) == mc_name + '.bin' : pass
	else : print(col_r + 'Error: A file with the same name already exists!' + col_e)

def update_check() :
	try :
		latest_mce = urllib.request.urlopen('https://raw.githubusercontent.com/platomav/MCExtractor/master/MCE.py').read().decode('utf-8')
		latest_mce_idx = latest_mce.find('title = \'MC Extractor v')
		if latest_mce_idx != -1 :
			latest_mce_ver = latest_mce[latest_mce_idx:][23:].split('\'')[0].split('_')[0]
			script_mce_ver = title[14:].split('_')[0]
			mce_is_upd = mce_is_latest(script_mce_ver.split('.')[:3], latest_mce_ver.split('.')[:3])
		else :
			raise()
		
		latest_db = urllib.request.urlopen('https://raw.githubusercontent.com/platomav/MCExtractor/master/MCE.db').read()
		with open('__MCE_DB__.temp', 'wb') as temp_db : temp_db.write(latest_db)
		connection_temp = sqlite3.connect('__MCE_DB__.temp')
		cursor_temp = connection_temp.cursor()
		cursor_temp.execute('PRAGMA quick_check')
		latest_db_rev = (cursor_temp.execute('SELECT revision FROM MCE')).fetchone()[0]
		cursor_temp.close()
		connection_temp.close()
		if os.path.isfile('__MCE_DB__.temp') : os.remove('__MCE_DB__.temp')
		
		script_db_rev = (cursor.execute('SELECT revision FROM MCE')).fetchone()[0]
		db_is_upd = True if script_db_rev >= latest_db_rev else False
		
		pt, pt_empty = mc_table(['#','Current','Latest','Updated'], True, 1)
		pt.title = col_y + 'MC Extractor & DB Update Check' + col_e
		pt.add_row(['MCE', script_mce_ver, latest_mce_ver, col_g + 'Yes' + col_e if mce_is_upd else col_r + 'No' + col_e])
		pt.add_row(['DB', script_db_rev, latest_db_rev, col_g + 'Yes' + col_e if db_is_upd else col_r + 'No' + col_e])
		print('\n%s' % pt)
		
		mce_github = 'Download the latest from https://github.com/platomav/MCExtractor/'
		if mce_is_upd and db_is_upd : print(col_g + '\nMC Extractor & Database are up to date!' + col_e)
		elif not mce_is_upd and not db_is_upd : print(col_m + '\nMC Extractor & Database are outdated!\n\n%s' % mce_github + col_e)
		elif not mce_is_upd : print(col_m + '\nMC Extractor is outdated!\n\n%s' % mce_github + col_e)
		elif not db_is_upd : print(col_m + '\nMC Extractor Database is outdated!\n\n%s' % mce_github + col_e)
	
	except :
		print(col_r + '\nError: Failed to check for MC Extractor & Database updates!' + col_e)
	
	mce_exit(0)
	
def mce_is_latest(ver_before, ver_after) :
	# ver_before/ver_after = [X.X.X]
	
	if int(ver_before[0]) > int(ver_after[0]) or (int(ver_before[0]) == int(ver_after[0]) and (int(ver_before[1]) > int(ver_after[1])
	or (int(ver_before[1]) == int(ver_after[1]) and int(ver_before[2]) >= int(ver_after[2])))) :
		return True
	else :
		return False
	
def db_new_MCE() :
	db_is_dev = (cursor.execute('SELECT developer FROM MCE')).fetchone()[0]
	db_rev_now = (cursor.execute('SELECT revision FROM MCE')).fetchone()[0]
	
	cursor.execute('UPDATE MCE SET date=?', (int(time.time()),))
	
	if db_is_dev == 0 :
		cursor.execute('UPDATE MCE SET revision=?', (db_rev_now + 1,))
		cursor.execute('UPDATE MCE SET developer=1')
	
def copy_file_with_warn() :
	file_name = os.path.basename(in_file)
	warn_dir = os.path.join(mce_dir, 'Warnings', '')
	warn_name = os.path.join(warn_dir, file_name)
		
	if not os.path.isdir(warn_dir) : os.mkdir(warn_dir)
	
	# Check if same file already exists
	if os.path.isfile(warn_name) :
		with open(warn_name, 'br') as file :
			if adler32(file.read()) == adler32(reading) : return
		
		warn_name += '_%d' % cur_count
		
	shutil.copyfile(in_file, warn_name)
	
def save_mc_file(mc_path, mc_data, mc_hash) :
	if not param.mce_ubu :
		if os.path.isfile(mc_path) :
			with open(mc_path, 'rb') as mc_file : found_data = mc_file.read()
			
			if mc_data == found_data : os.remove(mc_path)
			else : mc_path = '%s_%0.8X.bin' % (mc_path[:-4], mc_hash)
			
		with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)

def mc_upd_chk_intel(mc_upd_chk_rsl, in_pl_bit, in_rel, in_ver) :
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
		
		# Same Release, Same or more Platform IDs, Newer Date, Same Date but more Platform IDs or Newer Version (not for -last)
		if in_rel == db_rel and set(in_pl_bit).issubset(db_pl_bit) and \
		((year < db_year or (year == db_year and (month < db_month or (month == db_month and day < db_day)))) or
		((year,month,day) == (db_year,db_month,db_day) and (len(in_pl_bit) < len(db_pl_bit) or in_ver < db_ver) and not param.get_last)) :
			is_latest = False
			mc_latest = [cpu_id, db_pl_val, db_ver, db_year, db_month, db_day, db_rel]
	
	return is_latest, mc_latest
	
def mc_upd_chk_amd(mc_upd_chk_rsl, in_ver) :
	is_latest = True
	mc_latest = None
	
	for entry in mc_upd_chk_rsl :
		db_day = entry[0][6:8]
		db_month = entry[0][4:6]
		db_year = entry[0][:4]
		db_ver = int(entry[1], 16)
		
		# Newer Date, Same Date but Newer Version (not for -last)
		if (year < db_year or (year == db_year and (month < db_month or (month == db_month and day < db_day)))) \
		or ((year,month,day) == (db_year,db_month,db_day) and in_ver < db_ver and not param.get_last) :
			is_latest = False
			mc_latest = [cpu_id, db_ver, db_year, db_month, db_day]
	
	return is_latest, mc_latest
	
def build_mc_repo(vendor, mc_name) :
	repo_dir = os.path.join(mce_dir, 'Repo_%s' % vendor, '')
	if not os.path.isdir(repo_dir) : os.mkdir(repo_dir)
	shutil.copyfile(in_file, repo_dir + mc_name + '.bin')

def mc_table(row_col_names,header,padd) :
	pt = prettytable.PrettyTable(row_col_names)
	pt.set_style(prettytable.UNICODE_LINES)
	pt.xhtml = True
	pt.header = header # Boolean
	pt.left_padding_width = padd if not param.mce_ubu else 0
	pt.right_padding_width = padd if not param.mce_ubu else 0
	pt.hrules = prettytable.ALL
	pt.vrules = prettytable.ALL
	pt_empty = str(pt)
	
	return pt,pt_empty

def display_sql(cursor,title,header,padd):
	rows = cursor.fetchall()
	if not rows : return
	
	if param.mce_ubu : padd = 0
	
	sqlr = prettytable.PrettyTable()
	sqlr.set_style(prettytable.UNICODE_LINES)
	sqlr.xhtml = True
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
	
def mce_hdr(hdr_title) :
	hdr_pt,hdr_pt_empty = mc_table([], False, 1)
	hdr_pt.add_row([col_y + '        %s        ' % hdr_title + col_e])
	
	print(hdr_pt)
	
def mass_scan(f_path) :
	mass_files = []
	for root, dirs, files in os.walk(f_path):
		for name in files :
			mass_files.append(os.path.join(root, name))
			
	input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
	
	return mass_files

# Get MCE Parameters from input
param = MCE_Param(mce_os, sys.argv)

# Pause after any unexpected python exception
if not param.mce_extr and not param.mce_ubu :
	sys.excepthook = show_exception_and_exit
	
# Get script location
mce_dir = get_script_dir()

# Set DB location
db_path = os.path.join(mce_dir, 'MCE.db')

# Set MCB location
mcb_path = os.path.join(mce_dir, 'MCB.bin')

# Enumerate parameter input
arg_num = len(sys.argv)

# Connect to MCE Database
if os.path.isfile(db_path) :
	connection = sqlite3.connect(db_path)
	cursor = connection.cursor()
	
	# Validate DB health
	try :
		cursor.execute('PRAGMA quick_check')
	except :
		mce_hdr(title)
		print(col_r + '\nError: MCE.db file is corrupted!' + col_e)
		mce_exit(1)
	
	# Initialize DB, if found empty
	cursor.execute('CREATE TABLE IF NOT EXISTS MCE(revision INTEGER DEFAULT 0, developer INTEGER DEFAULT 1, date INTEGER DEFAULT 0,\
					minimum BLOB DEFAULT "0.0.0")')
	cursor.execute('CREATE TABLE IF NOT EXISTS Intel(cpuid BLOB, platform BLOB, version BLOB, yyyymmdd TEXT, size BLOB, checksum BLOB)')
	cursor.execute('CREATE TABLE IF NOT EXISTS VIA(cpuid BLOB, signature TEXT, version BLOB, yyyymmdd TEXT, size BLOB, checksum BLOB)')
	cursor.execute('CREATE TABLE IF NOT EXISTS FSL(name TEXT, model BLOB, major BLOB, minor BLOB, size BLOB, checksum BLOB, note TEXT)')
	cursor.execute('CREATE TABLE IF NOT EXISTS AMD(cpuid BLOB, nbdevid BLOB, sbdevid BLOB, nbsbrev BLOB, version BLOB,\
					yyyymmdd TEXT, size BLOB, chkbody BLOB, chkmc BLOB)')
	if not cursor.execute('SELECT EXISTS(SELECT 1 FROM MCE)').fetchone()[0] : cursor.execute('INSERT INTO MCE DEFAULT VALUES')
	connection.commit()
	
	# Check for MCE & DB incompatibility
	db_rev = (cursor.execute('SELECT revision FROM MCE')).fetchone()[0]
	db_min = (cursor.execute('SELECT minimum FROM MCE')).fetchone()[0]
	if not mce_is_latest(title[14:].split('_')[0].split('.')[:3], db_min.split('_')[0].split('.')[:3]) :
		mce_hdr(title)
		print(col_r + '\nError: DB r%d requires MCE >= v%s!' % (db_rev,db_min) + col_e)
		mce_exit(1)
	
else :
	cursor = None
	connection = None
	mce_hdr(title)
	print(col_r + '\nError: MCE.db file is missing!' + col_e)
	mce_exit(1)

rev_dev = (cursor.execute('SELECT revision, developer FROM MCE')).fetchone()
mce_title = '%s r%d%s' % (title, rev_dev[0], ' Dev' if rev_dev[1] else '')

# Set console/shell window title
if not param.mce_extr and not param.mce_ubu :
	if mce_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(mce_title)
	elif mce_os.startswith('linux') or mce_os == 'darwin' or mce_os.find('bsd') != -1 : sys.stdout.write('\x1b]2;' + mce_title + '\x07')

if not param.skip_intro :
	mce_hdr(mce_title)

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
	param = MCE_Param(mce_os, input_var)
	
	# Non valid parameters are treated as files
	if input_var[0] != "" :
		for i in input_var:
			if i not in param.val :
				sys.argv.append(i.strip('"'))
	
	# Re-enumerate parameter input
	arg_num = len(sys.argv)
	
	os.system(cl_wipe)
	
	mce_hdr(mce_title)

elif not param.mce_extr and not param.get_last :
	mce_hdr(mce_title)

if (arg_num < 2 and not param.upd_check and not param.help_scr and not param.mass_scan
and not param.search and not param.get_last) or param.help_scr :
	mce_help()

if param.mass_scan :
	in_path = input('\nEnter the full folder path: ')
	source = mass_scan(in_path)
else :
	source = sys.argv[1:] # Skip script/executable
	
if param.upd_check : update_check()

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
	
	res_i = cursor.execute('SELECT cpuid,platform,version,yyyymmdd,size FROM Intel WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
	display_sql(res_i, col_b + 'Intel' + col_e, True, 1)
	
	res_a = cursor.execute('SELECT cpuid,version,yyyymmdd,size FROM AMD WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
	display_sql(res_a, col_r + 'AMD' + col_e, True, 1)
	
	res_v = cursor.execute('SELECT cpuid,signature,version,yyyymmdd,size FROM VIA WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
	display_sql(res_v, col_c + 'VIA' + col_e, True, 1)
	
	res_f = cursor.execute('SELECT name,model,major,minor,size,note FROM FSL WHERE model=? ORDER BY name DESC', (cpu_id,))
	display_sql(res_f, col_y + 'Freescale' + col_e, True, 1)
	
	mce_exit()
	
# Detect latest Intel or AMD microcode via user input
# Can be used with currently loaded microcode info from OS
if param.get_last :
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
		date = (cursor.execute('SELECT yyyymmdd FROM Intel WHERE cpuid=? AND version=?', ('%0.8X' % cpu_id, '%0.8X' % version,))).fetchall()
	else :
		date = (cursor.execute('SELECT yyyymmdd FROM AMD WHERE cpuid=? AND version=?', ('%0.8X' % cpu_id, '%0.8X' % version,))).fetchall()
	
	if not date :
		print(col_r + '\nError: %s CPUID %0.8X Version %0.8X not found in DB!' % (vendor, cpu_id, version) + col_e)
		mce_exit(2)
	
	day = date[0][0][6:8]
	month = date[0][0][4:6]
	year = date[0][0][:4]
	
	if vendor == 'Intel' :
		mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,platform,version FROM Intel WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		is_latest, mc_latest = mc_upd_chk_intel(mc_upd_chk_rsl, intel_plat(platform), 'PRE' if ctypes.c_int(version).value < 0 else 'PRD', version)
	else :
		mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,version FROM AMD WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		is_latest, mc_latest = mc_upd_chk_amd(mc_upd_chk_rsl, version)
	
	print('\n%s' % is_latest)
	if vendor == 'Intel' and mc_latest :
		print('cpu%0.8X_plat%0.8X_ver%0.8X_%s-%s-%s_%s' % (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4],mc_latest[5],mc_latest[6]))
	elif vendor == 'AMD' and mc_latest :
		print('cpu%0.8X_ver%0.8X_%s-%s-%s' % (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4]))
	
	mce_exit(0)
	
# Intel - HeaderRev 01, Year 1993-2022, Day 01-31, Month 01-12, CPUID xxxxxx00, LoaderRev 00-01, PlatformIDs 000000xx, DataSize xxxxxx00, TotalSize xxxxxx00, Reserved1
pat_icpu = re.compile(br'\x01\x00{3}.{4}(([\x00-\x22]\x20)|([\x93-\x99]\x19))[\x01-\x31][\x01-\x12].{3}\x00.{4}[\x01\x00]\x00{3}.\x00{3}.{3}\x00.{3}\x00{13}', re.DOTALL)

# AMD - Year 20xx, Month 01-13, LoaderID 00-04, DataSize 00|10|20, InitFlag 00-01, NorthBridgeVEN_ID 0000|1022, SouthBridgeVEN_ID 0000|1022, BiosApiREV_ID 00-01, Reserved 00|AA
pat_acpu = re.compile(br'\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x04]\x80[\x00\x20\x10][\x00\x01].{4}((\x00{2})|(\x22\x10)).{2}((\x00{2})|(\x22\x10)).{6}[\x00\x01](\x00{3}|\xAA{3})', re.DOTALL)

# VIA - Signature RRAS, Year 2006-2022 (0x07D6-0x07E5), Day 01-31, Month 01-12, LoaderRev 01, Reserved, DataSize xxxxxx00, TotalSize xxxxxx00
pat_vcpu = re.compile(br'\x52\x52\x41\x53.{4}[\xD6-\xE6]\x07[\x01-\x1F][\x01-\x0C].{3}\x00.{4}\x01\x00{3}.{7}\x00.{3}\x00', re.DOTALL)

# Freescale - Signature QEF, HeaderRev 01, IRAM 00-01, Reserved0, Reserved1
pat_fcpu = re.compile(br'\x51\x45\x46\x01.{62}[\x00\x01].{5}\x00{4}.{40}\x00{4}', re.DOTALL)

# Global Variable Initialization
mc_latest = None
match_list_i = None
repo_included = []
temp_mc_paths = []
blob_lut_init = []
blob_lut_done = b''
blob_data = b''
blob_count = 0
cur_count = 0
in_count = len(source)
for arg in source :
	if arg in param.val : in_count -= 1
	
for in_file in source :
	
	# File Variable Initialization
	mc_nr = 0
	total = 0
	type_conv = ''
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
		
		print(col_r + '\nError: file %s was not found!' % in_file + col_e)
		
		if not param.mass_scan : mce_exit(1)
		else : continue
	
	if not param.mce_extr and not param.mce_ubu :
		if in_file in temp_mc_paths : print(col_c + '\n%s\n' % os.path.basename(in_file) + col_e)
		else : print(col_c + '\n%s (%d/%d)\n' % (os.path.basename(in_file), cur_count, in_count) + col_e)
	
	with open(in_file, 'rb') as work_file :
		reading = work_file.read()
		file_end = len(reading)
	
	# Detect & Convert Intel Containers (.dat|.inc|.h|.txt) to binary images
	if in_file not in temp_mc_paths :
		try :
			with open(in_file, 'r', encoding = 'utf-8', errors = 'ignore') as in_cont :
				sample = in_cont.readlines(3072)
				
				for line in sample :
					if (line[:4],line[12:13]) == ('dd 0','h') :
						type_conv = '.inc'
						break
					elif '0x00000001,' in line[:13] :
						type_conv = '.dat'
						break
				
			if not type_conv : raise()
			
			with open(in_file, 'r', encoding = 'utf-8') as in_cont :
				
				for line in in_cont :
					line = line.strip('\n ')
					
					if type_conv == '.dat' :
						if line[0] == '/' : # Comment
							continue
						elif len(line) >= 47 and (line[:2],line[10:11]) == ('0x',',') : # "0xjjjjjjjj, 0xjjjjjjjj, 0xjjjjjjjj, 0xjjjjjjjj,"
							wlp = line.split(',')
							for i in range(0,4) :
								wlp[i] = wlp[i].replace('\t','').replace('0x','').replace(' ','')
								code = int.from_bytes(binascii.unhexlify(wlp[i]), 'little') # Int from BE bytes
								mc_conv_data += bytes.fromhex('%0.8X' % code)
						elif len(line) >= 11 and (line[:2],line[10:11]) == ('0x',',') : # "0xjjjjjjjj,"
							wlp = str.encode(line[2:10]) # Hex string to bytes
							wlp = int.from_bytes(binascii.unhexlify(wlp), 'little')
							mc_conv_data += bytes.fromhex('%0.8X' % wlp)
							
					elif type_conv == '.inc' :
						if len(line) >= 13 and (line[:4],line[12:13]) == ('dd 0','h') : # "dd 0jjjjjjjjh"
							wlp = str.encode(line[4:12])
							wlp = int.from_bytes(binascii.unhexlify(wlp), 'little')
							mc_conv_data += bytes.fromhex('%0.8X' % wlp)
		except :
			pass
		
		if mc_conv_data :
			cont_path = os.path.join(mce_dir, 'Container_%s_%0.8X.temp' % (os.path.basename(in_file), adler32(mc_conv_data)))
			temp_mc_paths.append(cont_path) # Store Intel Container microcode binary path to parse once and delete at the end
			source.append(cont_path) # Add Intel Container microcode binary path to the input files
			with open(cont_path, 'wb') as temp : temp.write(mc_conv_data)
	
	# Intel Microcodes
	
	match_list_i += pat_icpu.finditer(reading)
	
	total += len(match_list_i)
	
	col_names = ['#','CPUID','Platform ID','Revision','Date','Type','Size','Offset','Last']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_i :
		
		# Microcode Variable Initialization
		valid_ext_chk = 0
		mc_reserved_all = 0
		mc_cpuid_chk = True
		mc_patch_chk = True
		mc_latest = None
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_hdr = get_struct(reading, mc_bgn, Intel_MC_Header)
		
		patch_u = mc_hdr.UpdateRevision # Unsigned, general usage
		patch_s = ctypes.c_int(patch_u).value # Signed, release usage
		
		year = '%0.4X' % mc_hdr.Year
		
		day = '%0.2X' % mc_hdr.Day
		
		month = '%0.2X' % mc_hdr.Month
		
		cpu_id = mc_hdr.ProcessorSignature
		
		plat = mc_hdr.PlatformIDs
		plat_bit = intel_plat(mc_hdr.PlatformIDs)
		
		mc_len = 0x800 if mc_hdr.TotalSize == 0 else mc_hdr.TotalSize
		
		mc_chk = mc_hdr.Checksum # For OEM validation, not checked by CPU
		
		full_date = '%s-%s-%s' % (year, month, day)
		
		if param.print_hdr : mc_hdr.mc_print()
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		valid_mc_chk = checksum32(mc_data)
		
		# Detect Release based on Patch signature
		rel_file = 'PRD' if patch_s >= 0 else 'PRE'
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
		except :
			msg_i.append(col_m + '\nWarning: Skipped Intel microcode at 0x%X, invalid Date of %s!' % (mc_bgn, full_date) + col_e)
			if not param.mce_extr : copy_file_with_warn()
			continue
		
		# Analyze Extra Header
		if reading[mc_bgn + 0x30:mc_bgn + 0x38] == b'\x00\x00\x00\x00\xA1\x00\x00\x00' : mc_hdr_extra = get_struct(reading, mc_bgn + 0x30, Intel_MC_Header_Extra_R1)
		elif reading[mc_bgn + 0x30:mc_bgn + 0x38] == b'\x00\x00\x00\x00\xE0\x00\x00\x00' : mc_hdr_extra = get_struct(reading, mc_bgn + 0x30, Intel_MC_Header_Extra_R2)
		else : mc_hdr_extra = None
			
		if mc_hdr_extra :
			mc_reserved_all += (int.from_bytes(mc_hdr_extra.Reserved, 'little') + mc_hdr_extra.get_flags()[1])
			
			if cpu_id != 0 and cpu_id not in mc_hdr_extra.get_cpuids() : mc_cpuid_chk = False
			if patch_u != mc_hdr_extra.UpdateRevision and (cpu_id,patch_u,full_date) not in [(0x306C3,0x99,'2013-01-21'),(0x506E3,0xFF,'2016-01-05')] : mc_patch_chk = False
			
			# RSA Signature cannot be validated, Hash is probably derived from Header + Decrypted Patch (Commented out for performance)
			"""
			rsa_pexp = mc_hdr_extra.RSAExponent if ctypes.sizeof(mc_hdr_extra) == 0x284 else 65537 # 17 for RSA 2048-bit or 65537 for RSA 3072-bit
			rsa_pkey = int.from_bytes(mc_hdr_extra.RSAPublicKey, 'little')
			rsa_sign = int.from_bytes(mc_hdr_extra.RSASignature, 'little')
			if rsa_pexp and rsa_pkey and rsa_sign : mc_sign = '%X' % pow(rsa_sign, rsa_pexp, rsa_pkey) # SHA-1 or SHA-256 or Unknown + SHA-256
			"""
			
			if param.print_hdr : mc_hdr_extra.mc_print()
		
		# Analyze, Validate & Extract optional Extended Header, each field only once
		if mc_hdr.TotalSize > mc_hdr.DataSize + 0x30 and in_file not in temp_mc_paths :
			ext_hdr_size = ctypes.sizeof(Intel_MC_Header_Extended)
			ext_fld_size = ctypes.sizeof(Intel_MC_Header_Extended_Field)
			
			mc_ext_off = mc_bgn + 0x30 + mc_hdr.DataSize
			mc_hdr_ext = get_struct(reading, mc_ext_off, Intel_MC_Header_Extended)
			mc_reserved_all += int.from_bytes(mc_hdr_ext.Reserved, 'little')
			if param.print_hdr : mc_hdr_ext.mc_print()
			
			ext_header_checksum = mc_hdr_ext.ExtendedChecksum
			ext_fields_count = mc_hdr_ext.ExtendedSignatureCount
			ext_header_size = ext_hdr_size + ext_fields_count * ext_fld_size # 20 intro bytes, 12 for each field
			ext_header_data = reading[mc_bgn + 0x30 + mc_hdr.DataSize:mc_bgn + 0x30 + mc_hdr.DataSize + ext_header_size]
			valid_ext_chk = checksum32(ext_header_data) # Extended Header + Fields Checksum
			
			mc_ext_field_off = mc_ext_off + ext_hdr_size
			for ext_idx in range(ext_fields_count) :
				mc_hdr_ext_field = get_struct(reading, mc_ext_field_off, Intel_MC_Header_Extended_Field)
				if param.print_hdr : mc_hdr_ext_field.mc_print()
				
				if mc_hdr_extra and mc_hdr_ext_field.ProcessorSignature not in mc_hdr_extra.get_cpuids() : mc_cpuid_chk = False
				
				ext_mc_data = bytearray(mc_data) # Duplicate main Microcode container data for Extended replacements
				ext_mc_data[0xC:0x10] = struct.pack('<I', mc_hdr_ext_field.ProcessorSignature) # Extended CPUID
				ext_mc_data[0x10:0x14] = struct.pack('<I', mc_hdr_ext_field.Checksum) # Extended Checksum
				ext_mc_data[0x18:0x1C] = struct.pack('<I', mc_hdr_ext_field.PlatformIDs) # Extended Platform IDs
				
				ext_mc_path = os.path.join(mce_dir, 'Extended_%s_%d_%0.8X.temp' % (os.path.basename(in_file), ext_idx + 1, mc_hdr_ext_field.Checksum))
				temp_mc_paths.append(ext_mc_path) # Store Extended microcode binary path to parse once and delete at the end
				source.append(ext_mc_path) # Add Extended microcode binary path to the input files
				with open(ext_mc_path, 'wb') as ext_mc : ext_mc.write(ext_mc_data)
				
				mc_ext_field_off += ext_fld_size
				
		if param.print_hdr : continue # No more info to print, next MC of input file
		
		mc_name = 'cpu%0.5X_plat%0.2X_ver%0.8X_%s_%s_%0.8X' % (cpu_id, plat, patch_u, full_date, rel_file, mc_chk)
		mc_nr += 1
		
		# Check if any Reserved fields are not empty/0
		if mc_reserved_all != 0 :
			msg_i.append(col_m + '\nWarning: Microcode #%d has non-empty Reserved fields, please report it!' % mc_nr + col_e)
			if not param.mce_extr : copy_file_with_warn()
			
		# Check if Main and/or Extended Header CPUID is contained in the Extra Header CPUIDs 0-7 (ignore microcode containers with CPUID 0)
		if not mc_cpuid_chk :
			msg_i.append(col_m + '\nWarning: Microcode #%d has Header CPUID discrepancy, please report it!' % mc_nr + col_e)
			if not param.mce_extr : copy_file_with_warn()
		
		# Check if Main and Extra Header UpdateRevision values are the same (ignore certain special OEM modified Main Headers)
		if not mc_patch_chk :
			msg_i.append(col_m + '\nWarning: Microcode #%d has Header Update Revision discrepancy, please report it!' % mc_nr + col_e)
			if not param.mce_extr : copy_file_with_warn()
		
		mc_at_db = (cursor.execute('SELECT * FROM Intel WHERE cpuid=? AND platform=? AND version=? AND yyyymmdd=? AND size=? \
					AND checksum=?', ('%0.8X' % cpu_id, '%0.8X' % plat, '%0.8X' % patch_u, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None and in_file not in temp_mc_paths :
				db_new_MCE()
				
				cursor.execute('INSERT INTO Intel (cpuid, platform, version, yyyymmdd, size, checksum) VALUES (?,?,?,?,?,?)',
						('%0.8X' % cpu_id, '%0.8X' % plat, '%0.8X' % patch_u, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk))
				
				connection.commit()
			
				print(col_g + '\nAdded Intel: %s\n' % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			if in_file not in temp_mc_paths : mc_db_name(in_file, mc_name)
			continue
		
		mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,platform,version FROM Intel WHERE cpuid=?', ('%0.8X' % cpu_id,))).fetchall()
		
		# Determine if MC is Last or Outdated
		is_latest, mc_latest = mc_upd_chk_intel(mc_upd_chk_rsl, plat_bit, rel_file, patch_u)
		
		# Build Microcode Repository (PRD & Last)
		if param.build_repo :
			mc_repo_id = 'Intel_%0.5X_%0.2X' % (cpu_id, plat) # Unique Intel Repo Entry: CPUID + Platform
			if in_file not in temp_mc_paths and rel_file == 'PRD' and cpu_id != 0 and is_latest and mc_repo_id not in repo_included  :
				build_mc_repo('INTEL', mc_name)
				repo_included.append(mc_repo_id)
			continue
		
		# Prepare Microcode Blob
		if param.build_blob :
			if in_file not in temp_mc_paths :
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
		if not param.mce_ubu and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
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
		if match_list_a or match_list_v or match_list_f : print()
		print(pt)
	for msg in msg_i: print(msg)
	
	# AMD Microcodes
	
	match_list_a += pat_acpu.finditer(reading)
	
	total += len(match_list_a)
	
	col_names = ['#', 'CPUID', 'Revision', 'Date', 'Size', 'Offset', 'Last']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_a :
		
		# Microcode Variable Initialization
		mc_latest = None
		
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
			
			if date_chk.year > 2022 : raise Exception('WrongDate') # 1st MC from 1999 (K7), 2000 for K7 Erratum and performance
		except :
			if (full_date,patch) == ('2011-13-09',0x3000027) : pass # Drunk AMD employee 1, Happy 13th month from AMD!
			else :
				msg_a.append(col_m + '\nWarning: Skipped AMD microcode at 0x%X, invalid Date of %s!' % (mc_bgn, full_date) + col_e)
				if not param.mce_extr : copy_file_with_warn()
				continue
		
		# Remove false results, based on data
		if reading[mc_bgn + 0x40:mc_bgn + 0x44] == b'\x00' * 4 : # 0x40 has non-null data
			msg_a.append(col_m + '\nWarning: Skipped AMD microcode at 0x%X, null data at 0x40!' % mc_bgn + col_e)
			if not param.mce_extr : copy_file_with_warn()
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
		elif cpu_id[2:4] in ['80','81','82','83','86','87'] : mc_len = 0xC80
		else : mc_len = 0
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		mc_file_chk = adler32(mc_data) # Custom Data-only Checksum
		valid_chk = checksum32(mc_data[0x40:]) # AMD File Checksum (Data+Padding)
		
		mc_name = 'cpu%s_ver%0.8X_%s_%0.8X' % (cpu_id, patch, full_date, mc_file_chk)
		mc_nr += 1
		
		if mc_len == 0 :
			msg_a.append(col_r + '\nError: Microcode #%d %s not extracted at 0x%X, unknown Size!' % (mc_nr, mc_name, mc_bgn) + col_e)
			if not param.mce_extr : copy_file_with_warn()
			continue
		else :
			mc_len_db = '%0.8X' % mc_len
		
		mc_at_db = (cursor.execute('SELECT * FROM AMD WHERE cpuid=? AND nbdevid=? AND sbdevid=? AND nbsbrev=? AND version=? \
								AND yyyymmdd=? AND size=? AND chkbody=? AND chkmc=?', (cpu_id, nb_id, sb_id, nbsb_rev_id,
								'%0.8X' % patch, year + month + day, mc_len_db, '%0.8X' % mc_chk, '%0.8X' % mc_file_chk, ))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				cursor.execute('INSERT INTO AMD (cpuid, nbdevid, sbdevid, nbsbrev, version, yyyymmdd, size, chkbody, chkmc) \
							VALUES (?,?,?,?,?,?,?,?,?)', (cpu_id, nb_id, sb_id, nbsb_rev_id, '%0.8X' % patch, year + month + day,
							mc_len_db, '%0.8X' % mc_chk, '%0.8X' % mc_file_chk))
				
				connection.commit()
				
				print(col_g + '\nAdded AMD: %s\n' % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(in_file, mc_name)
			continue
		
		mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,version FROM AMD WHERE cpuid=?', (cpu_id,))).fetchall()
		
		# Determine if MC is Last or Outdated
		is_latest, mc_latest = mc_upd_chk_amd(mc_upd_chk_rsl, patch)
		
		# Build Microcode Repository (Last)
		if param.build_repo :
			mc_repo_id = 'AMD_%s' % cpu_id # Unique AMD Repo Entry: CPUID
			if in_file not in temp_mc_paths and is_latest and mc_repo_id not in repo_included :
				build_mc_repo('AMD', mc_name)
				repo_included.append(mc_repo_id)
			continue
		
		# Prepare Microcode Blob
		if param.build_blob :
			if in_file not in temp_mc_paths :
				blob_count += 1
				
				# CPUID [0x4] + Reserved [0x4] + Version [0x4] + Date [0x4] + Offset [0x4] + Size [0x4] + Checksum [0x4] + Reserved [0x4]
				blob_lut_init.append([int(cpu_id, 16), 0, patch, int(year, 16), int(month, 16), int(day, 16), 0, mc_len, mc_file_chk, 0])
				
				blob_data += mc_data
			continue
		
		row = [mc_nr, cpu_id, '%0.8X' % patch, full_date, '0x%X' % mc_len, '0x%X' % mc_bgn, no_yes[is_latest]]
		pt.add_row(row)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'AMD', '')
		if not param.mce_ubu and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
		if int(cpu_id[2:4], 16) < 0x50 and (valid_chk + mc_chk) & 0xFFFFFFFF != 0 :
			msg_a.append(col_m + '\nWarning: Microcode #%d is corrupted, please report it!' % mc_nr + col_e)
			mc_path = '%s!Bad_%s.bin' % (mc_extract, mc_name)
		elif mc_at_db is None :
			msg_a.append(col_g + '\nNote: Microcode #%d was not found at the database, please report it!' % mc_nr + col_e)
			mc_path = '%s!New_%s.bin' % (mc_extract, mc_name)
		else :
			mc_path = '%s%s.bin' % (mc_extract, mc_name)
			
		save_mc_file(mc_path, mc_data, mc_file_chk)
		
	if str(pt) != pt_empty :
		pt.title = col_r + 'AMD' + col_e
		if match_list_i or match_list_v or match_list_f : print()
		print(pt)
	for msg in msg_a: print(msg)
	
	# VIA Microcodes
	
	match_list_v += pat_vcpu.finditer(reading)
	
	total += len(match_list_v)
	
	col_names = ['#', 'CPUID', 'Name', 'Revision', 'Date', 'Size', 'Offset']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_v :
		
		# Microcode Variable Initialization
		mc_latest = None
		
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
		
		name = mc_hdr.Name.replace(b'\x7F',b'\x2E').decode('utf-8').strip() # Replace 0x7F "control" character with 0x2E "fullstop" instead
		
		full_date = '%s-%s-%s' % (year, month, day)
		
		# Remove false results, based on date
		try :
			date_chk = datetime.datetime.strptime(full_date, '%Y-%m-%d')
		except :
			msg_v.append(col_m + '\nWarning: Skipped VIA microcode at 0x%X, invalid Date of %s!\n' % (mc_bgn, full_date) + col_e)
			if not param.mce_extr : copy_file_with_warn()
			continue
		
		# Print the Header(s)
		if param.print_hdr :
			mc_hdr.mc_print()
			continue
		
		mc_name = 'cpu%0.5X_ver%0.8X_sig[%s]_%s_%0.8X' % (cpu_id, patch, name, full_date, mc_chk)
		mc_nr += 1
		
		mc_at_db = (cursor.execute('SELECT * FROM VIA WHERE cpuid=? AND signature=? AND version=? AND yyyymmdd=? AND size=? AND checksum=?',
				  ('%0.8X' % cpu_id, name, '%0.8X' % patch, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				cursor.execute('INSERT INTO VIA (cpuid, signature, version, yyyymmdd, size, checksum) VALUES (?,?,?,?,?,?)',
						('%0.8X' % cpu_id, name, '%0.8X' % patch, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk))
				
				connection.commit()
			
				print(col_g + '\nAdded VIA: %s\n' % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(in_file, mc_name)
			continue
			
		# Build Microcode Repository (All)
		if param.build_repo :
			build_mc_repo('VIA', mc_name)
			continue
		
		row = [mc_nr, '%X' % cpu_id, name, '%X' % patch, full_date, '0x%X' % mc_len, '0x%X' % mc_bgn]
		pt.add_row(row)
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		valid_chk = checksum32(mc_data)
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'VIA', '')
		if not param.mce_ubu and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
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
		if match_list_i or match_list_a or match_list_f : print()
		print(pt)
	for msg in msg_v: print(msg)
	
	# Freescale Microcodes
	
	match_list_f += pat_fcpu.finditer(reading)
	
	total += len(match_list_f)
	
	col_names = ['#', 'Name', 'SoC Model', 'SoC Major', 'SoC Minor', 'Size', 'Offset']
	
	pt, pt_empty = mc_table(col_names, True, 1)
	
	for match_ucode in match_list_f :
		
		# Microcode Variable Initialization
		mc_reserved_all = 0
		mc_latest = None
		
		# noinspection PyRedeclaration
		(mc_bgn, end_mc_match) = match_ucode.span()
		
		mc_bgn -= 4 # Pattern starts from 5th byte for performance (Signature QEF)
		
		mc_hdr = get_struct(reading, mc_bgn, FSL_MC_Header)
		
		name = mc_hdr.Name.decode('utf-8')
		
		model = '%0.4d' % mc_hdr.Model
		
		major = mc_hdr.Major
		
		minor = mc_hdr.Minor
		
		mc_len = mc_hdr.TotalSize
		
		mc_chk = int.from_bytes(reading[mc_bgn + mc_len - 4:mc_bgn + mc_len], 'big')
		
		mc_reserved_all += (mc_hdr.Reserved0 + mc_hdr.Reserved1)
		
		if param.print_hdr : mc_hdr.mc_print()
			
		qe_off = ctypes.sizeof(FSL_MC_Header) # Header size
		for qe_mc in range(mc_hdr.CountMC) :
			qe_hdr = get_struct(reading, qe_off, FSL_MC_Entry)
			mc_reserved_all += (qe_hdr.Reserved0 + qe_hdr.Reserved1)
			if param.print_hdr : qe_hdr.mc_print()
			qe_off += ctypes.sizeof(FSL_MC_Entry) # Entry size
			
		if param.print_hdr : continue # No more info to print, next MC of input file
		
		mc_name = 'soc%s_rev%s.%s_sig[%s]_%0.8X' % (model, major, minor, name, mc_chk)
		mc_nr += 1
		
		# Check if any Reserved fields are not empty/0
		if mc_reserved_all != 0 :
			msg_i.append(col_m + '\nWarning: Microcode #%d has non-empty Reserved fields, please report it!' % mc_nr + col_e)
			if not param.mce_extr : copy_file_with_warn()
		
		mc_at_db = (cursor.execute('SELECT * FROM FSL WHERE name=? AND model=? AND major=? AND minor=? AND size=? AND checksum=?',
				  (name, model, major, minor, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
		
		if param.build_db :
			if mc_at_db is None :
				db_new_MCE()
				
				cursor.execute('INSERT INTO FSL (name, model, major, minor, size, checksum) VALUES (?,?,?,?,?,?)',
						(name, model, major, minor, '%0.8X' % mc_len, '%0.8X' % mc_chk))
				
				connection.commit()
			
				print(col_g + '\nAdded Freescale: %s\n' % mc_name + col_e)
			
			continue
			
		# Rename input file based on the DB structured name
		if param.give_db_name :
			mc_db_name(in_file, mc_name)
			continue
		
		# Build Microcode Repository (All)
		if param.build_repo :
			build_mc_repo('FSL', mc_name)
			continue
		
		row = [mc_nr, name, model, major, minor, '0x%X' % mc_len, '0x%X' % mc_bgn]
		pt.add_row(row)
		
		mc_data = reading[mc_bgn:mc_bgn + mc_len]
		
		calc_crc = (binascii.crc32(mc_data[:-4], -1) ^ -1) & 0xFFFFFFFF
		
		# Create extraction folder
		if '-extr' in source : mc_extract = os.path.join(mce_dir, '..', 'Z_Extract', 'CPU', '')
		else : mc_extract = os.path.join(mce_dir, 'Extracted', 'Freescale', '')
		if not param.mce_ubu and not os.path.exists(mc_extract) : os.makedirs(mc_extract)
		
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
		if match_list_i or match_list_a or match_list_v : print()
		print(pt)
	for msg in msg_f: print(msg)
		
	if mc_conv_data :
		print(col_y + 'Note: Detected Intel Microcode Container...' + col_e)
	elif total == 0 and in_file in temp_mc_paths :
		print(col_r + 'Error: File should contain CPU microcodes, please report it!' + col_e)
		if not param.mce_extr : copy_file_with_warn()
	elif total == 0 :
		print('File does not contain CPU microcodes')
	
# Remove any temporary Intel Container or Extended files
for temp_mc in temp_mc_paths :
	if os.path.isfile(temp_mc) : os.remove(temp_mc)

# Extract Latest from Microcode Blob (-blob -search)
if param.build_blob and param.search :
	if mc_latest is None :
		print(col_y + 'Microcode is the latest!' + col_e) # Based on DB
		mce_exit(1)
	
	if os.path.isfile(mcb_path) :
		last_path = os.path.join(mce_dir, 'last.bin') # Previous Latest MCB Microcode location
		
		# Delete previous Latest MCB Microcode
		if os.path.isfile(last_path) : os.remove(last_path)
		
		with open(mcb_path, 'rb') as mcb :
			mcb_data = mcb.read()
			file_end = len(mcb_data)
		
		mcb_hdr = get_struct(mcb_data, 0, MCB_Header)
		mcb_tag = mcb_hdr.Tag
		mcb_rev = mcb_hdr.HeaderRev
		mcb_res = mcb_hdr.Reserved
		
		if (mcb_tag,mcb_rev,mcb_res) == (b'$MCB',2,b'$$') : # Sanity checks
			mcb_count = mcb_hdr.MCCount
			mcb_dbrev = mcb_hdr.MCEDBRev
			mcb_ven = mcb_hdr.MCVendor
			mcb_crc = mcb_hdr.Checksum
			
			if crc32(mcb_data[:0xC] + mcb_data[0x10:]) != mcb_crc :
				print(col_r + 'Error: MCB.bin is corrupted!' + col_e)
				mce_exit(4)
			
			for e in range(0, mcb_count) :
				mcb_lut = get_struct(mcb_data, 0x10 + e * 0x20, MCB_Entry)
				
				mcb_cpuid = mcb_lut.CPUID
				mcb_plat = mcb_lut.Platform
				mcb_ver = mcb_lut.Revision
				mcb_year = '%0.4X' % mcb_lut.Year
				mcb_month = '%0.2X' % mcb_lut.Month
				mcb_day = '%0.2X' % mcb_lut.Day
				mcb_rel = 'PRE' if ctypes.c_int(mcb_lut.Revision).value < 0 else 'PRD'
				
				if mcb_ven == 0 and (mcb_cpuid,mcb_plat,mcb_ver,mcb_year,mcb_month,mcb_day,mcb_rel) == (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4],mc_latest[5],mc_latest[6]) \
				or mcb_ven == 1 and (mcb_cpuid,mcb_ver,mcb_year,mcb_month,mcb_day) == (int(mc_latest[0], 16),mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4]) :
					with open(last_path, 'wb') as mc : mc.write(mcb_data[mcb_lut.Offset:mcb_lut.Offset + mcb_lut.Size])
					break
			
			else :
				print(col_r + 'Error: Latest microcode not within MCB.bin!' + col_e)
				mce_exit(5)
					
		else :
			print(col_r + 'Error: MCB.bin is invalid!' + col_e)
			mce_exit(3)
						
	else :
		print(col_r + 'Error: MCB.bin is missing!' + col_e)
		mce_exit(2)
	
	print(col_g + 'Latest Microcode extracted!' + col_e)
	mce_exit(0)
	
# Build Microcode Blob (-blob)
elif param.build_blob :
	db_rev_now = (cursor.execute('SELECT revision FROM MCE')).fetchone()[0] # Get DB Revision
	
	# Determine Microcode Blob offsets
	blob_offset = 0x10 + blob_count * 0x20 # Header Length = 0x10, Entry Length = 0x20
	for i in range(len(blob_lut_init)) :
		blob_lut_init[i][6] += blob_offset # 6 = Microcode Offset
		blob_offset += blob_lut_init[i][7] # 7 = Microcode Size
		blob_lut_done += struct.pack('<IIIHBBIIII', blob_lut_init[i][0], blob_lut_init[i][1], blob_lut_init[i][2], blob_lut_init[i][3],
						 blob_lut_init[i][4], blob_lut_init[i][5], blob_lut_init[i][6], blob_lut_init[i][7], blob_lut_init[i][8], blob_lut_init[i][9])
	
	# Tag [0x4] + Entry Count [0x2] + DB Revision [0x2] + Header Revision [0x1] + Vendor [0x1] + Reserved [0x2] + CRC-32 [0x4]
	blob_hdr = struct.pack('<4sHHBB2s', b'$MCB', blob_count, db_rev_now, 2, 0 if match_list_i else 1, b'$$')
	blob_hdr += struct.pack('<I', crc32(blob_hdr[:0xC] + blob_lut_done + blob_data))
	
	# Delete previous Microcode Blob
	if os.path.isfile(mcb_path) : os.remove(mcb_path)
	
	# Generate final Microcode Blob
	with open(mcb_path, 'ab') as mc_blob :
		mc_blob.write(blob_hdr)
		mc_blob.write(blob_lut_done)
		mc_blob.write(blob_data)
		
	print(col_g + 'Created MCE Microcode Blob (MCB)!' + col_e)
		
mce_exit(0)