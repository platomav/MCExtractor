#!/usr/bin/env python3
#coding=utf-8

"""
MC Extractor
Intel, AMD, VIA & Freescale Microcode Extractor
Copyright (C) 2016-2024 Plato Mavropoulos
"""

title = 'MC Extractor v1.101.0'

import sys

# Detect Python version
sys_py = sys.version_info
if sys_py < (3,7) :
    sys.stdout.write('%s\n\nError: Python >= 3.7 required, not %d.%d!\n' % (title, sys_py[0], sys_py[1]))
    if '-exit' not in sys.argv : (raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
    sys.exit(-1)

# Detect OS platform
sys_os = sys.platform
if sys_os == 'win32' :
    cl_wipe = 'cls'
    sys.stdout.reconfigure(encoding='utf-8') # Fix Windows Unicode console redirection
elif sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1 :
    cl_wipe = 'clear'
else :
    print('%s\n\nError: Unsupported platform "%s"!\n' % (title, sys_os))
    if '-exit' not in sys.argv : input('Press enter to exit')
    sys.exit(-1)

import os
import re
import zlib
import struct
import shutil
import ctypes
import hashlib
import inspect
import sqlite3
import threading
import traceback
import urllib.request
import importlib.util

# Check code dependency installation
for depend in ['colorama','pltable'] :
    if not importlib.util.find_spec(depend) :
        print('%s\n\nError: Dependency "%s" is missing!\n       Install via "pip3 install %s"\n' % (title, depend, depend))
        if '-exit' not in sys.argv : input('Press enter to exit')
        sys.exit(1)
        
import pltable
import colorama

# Initialize and setup Colorama
colorama.init()
col_r = colorama.Fore.RED + colorama.Style.BRIGHT
col_c = colorama.Fore.CYAN + colorama.Style.BRIGHT
col_b = colorama.Fore.BLUE + colorama.Style.BRIGHT
col_g = colorama.Fore.GREEN + colorama.Style.BRIGHT
col_y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
col_m = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
col_e = colorama.Fore.RESET + colorama.Style.RESET_ALL

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
          '-info   : Displays microcode structure info\n'
          '-add    : Adds input microcode to DB, if new\n'
          '-dbn    : Renames input file based on unique DB name\n'
          '-duc    : Disables automatic check for MCE & DB updates\n'
          '-search : Searches for microcodes based on CPUID/Model\n'
          '-last   : Shows \"Last\" status based on user input\n'
          '-repo   : Builds microcode repositories from input\n'
          '-blob   : Builds a Microcode Blob (MCB) from input'
          )
    
    print(col_g + '\nCopyright (C) 2016-2024 Plato Mavropoulos' + col_e)
    
    if getattr(sys, 'frozen', False) : print(col_c + '\nRunning in frozen state!' + col_e)
    
    mce_exit(0)

class MCE_Param :

    def __init__(self, source) :
    
        self.val = ['-?','-skip','-info','-add','-mass','-search','-dbn','-repo','-exit','-blob','-last','-duc']
        
        self.help_scr = False
        self.build_db = False
        self.skip_intro = False
        self.print_hdr = False
        self.mass_scan = False
        self.search = False
        self.give_db_name = False
        self.build_repo = False
        self.skip_pause = False
        self.build_blob = False
        self.get_last = False
        self.upd_dis = False
        
        if '-?' in source : self.help_scr = True
        if '-skip' in source : self.skip_intro = True
        if '-add' in source : self.build_db = True
        if '-info' in source : self.print_hdr = True
        if '-mass' in source : self.mass_scan = True
        if '-search' in source : self.search = True
        if '-dbn' in source : self.give_db_name = True
        if '-repo' in source : self.build_repo = True
        if '-exit' in source : self.skip_pause = True
        if '-blob' in source : self.build_blob = True
        if '-last' in source : self.get_last = True
        if '-duc' in source : self.upd_dis = True
            
        if self.mass_scan or self.search or self.build_repo or self.build_blob or self.get_last : self.skip_intro = True

# https://stackoverflow.com/a/65447493 by Shail-Shouryya
class Thread_With_Result(threading.Thread) :
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None) :
        self.result = None
        if kwargs is None : kwargs = {}

        def function() :
            self.result = target(*args, **kwargs)

        super().__init__(group=group, target=function, name=name, daemon=daemon)

class Intel_MC_Header(ctypes.LittleEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('HeaderType',              uint32_t),      # 0x00 1 Microcode, 2 In-Field Scan (IFS)
        ('UpdateRevision',          uint32_t),      # 0x04 Signed to signify PRD/PRE
        ('Year',                    uint16_t),      # 0x08
        ('Day',                     uint8_t),       # 0x0A
        ('Month',                   uint8_t),       # 0x0B
        ('ProcessorSignature',      uint32_t),      # 0x0C CPUID
        ('Checksum',                uint32_t),      # 0x10 OEM validation only
        ('LoaderRevision',          uint32_t),      # 0x14 1
        ('PlatformIDs',             uint32_t),      # 0x18 Supported Platforms
        ('DataSize',                uint32_t),      # 0x1C Extra + Patch
        ('TotalSize',               uint32_t),      # 0x20 Header + Extra + Patch + Extended
        ('MetadataSize',            uint32_t),      # 0x24 In-Field Scan (IFS) Metadata Structures
        ('UpdateRevisionMin',       uint32_t),      # 0x28 Minimum Required Version (OS Kernel Late Loading)
        ('Reserved',                uint32_t),      # 0x2C 0
        # 0x30
    ]

    def mc_print(self) :
        pt, _ = mc_table(['Field', 'Value'], False, 1)

        pt.title = col_b + 'Intel Header Main' + col_e
        pt.add_row(['Header Type', intel_header_types[self.HeaderType]])
        pt.add_row(['Update Version', '%X' % self.UpdateRevision])
        pt.add_row(['Release Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
        pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
        pt.add_row(['Checksum', '%0.8X' % self.Checksum])
        pt.add_row(['Loader Version', self.LoaderRevision])
        pt.add_row(['Platforms', '%0.2X (%s)' % (self.PlatformIDs, ','.join(map(str, intel_plat(mc_hdr.PlatformIDs))))])
        pt.add_row(['Data Size', '0x%X' % self.DataSize])
        pt.add_row(['Total Size', '0x%X' % self.TotalSize])
        pt.add_row(['Metadata Size', '0x%X' % self.MetadataSize])
        pt.add_row(['Minimum Version', '%X' % self.UpdateRevisionMin])
        pt.add_row(['Reserved', '0x%0.8X' % self.Reserved])

        print(pt)

class IntelMicrocodeHeaderExtraBase(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('ModuleType',              uint16_t),      # 0x00 0
        ('ModuleSubType',           uint16_t),      # 0x02 0
        ('ModuleSize',              uint32_t),      # 0x04 dwords
        ('Flags',                   uint16_t),      # 0x08 0 RSA Signed, 1-31 Reserved
        ('RSAKeySize',              uint16_t),      # 0x0A 1K multiple (e.g. 3 * 1024 = 3072)
        ('UpdateRevision',          uint32_t),      # 0x0C Signed to signify PRD/PRE
        ('VCN',                     uint32_t),      # 0x10 Version Control Number
        ('MultiPurpose1',           uint32_t),      # 0x14 dwords from Extra, UpdateSize, Empty etc
        ('Day',                     uint8_t),       # 0x18
        ('Month',                   uint8_t),       # 0x19
        ('Year',                    uint16_t),      # 0x1A
        ('UpdateSize',              uint32_t),      # 0x1C dwords from Extra without encrypted padding
        ('ProcessorSignatureCount', uint32_t),      # 0x20 max is 8 (8 * 0x4 = 0x20)
        ('ProcessorSignature0',     uint32_t),      # 0x24
        ('ProcessorSignature1',     uint32_t),      # 0x28
        ('ProcessorSignature2',     uint32_t),      # 0x2C
        ('ProcessorSignature3',     uint32_t),      # 0x30
        ('ProcessorSignature4',     uint32_t),      # 0x34
        ('ProcessorSignature5',     uint32_t),      # 0x38
        ('ProcessorSignature6',     uint32_t),      # 0x3C
        ('ProcessorSignature7',     uint32_t),      # 0x40
        ('MultiPurpose2',           uint32_t),      # 0x44 dwords from Extra + encrypted padding, UpdateSize, Platform, Empty
        ('ProcessorSignature0Unk',  uint8_t),       # 0x48
        ('ProcessorSignature1Unk',  uint8_t),       # 0x49
        ('ProcessorSignature2Unk',  uint8_t),       # 0x4A
        ('ProcessorSignature3Unk',  uint8_t),       # 0x4B
        ('ProcessorSignature4Unk',  uint8_t),       # 0x4C
        ('ProcessorSignature5Unk',  uint8_t),       # 0x4D
        ('ProcessorSignature6Unk',  uint8_t),       # 0x4E
        ('ProcessorSignature7Unk',  uint8_t),       # 0x4F
        ('Unknown0',                uint32_t),      # 0x50 Could be flags or struct length (e.g. 0x80, 0x00)
        ('Unknown1',                uint32_t),      # 0x54
        ('Unknown2',                uint32_t),      # 0x58
        ('Unknown3',                uint32_t),      # 0x5C
        ('Nonce',                   uint32_t*8),    # 0x60 RC4 Nonce
        # 0x80 (parent class, base)
    ]
    
    def _get_rsa(self, rsa_mod, rsa_sig, rsa_exp, rsa_len):
        self.rsa_exp = rsa_exp
        self.rsa_mod = '%0.*X' % (rsa_len * 2, int.from_bytes(rsa_mod, 'little'))
        self.rsa_sig = '%0.*X' % (rsa_len * 2, int.from_bytes(rsa_sig, 'little'))
    
    def get_flags(self):
        flags = IntelMicrocodeHeaderExtraGetFlags()
        flags.asbytes = self.Flags
        
        return flags.b.RSASigned, flags.b.Reserved

    def get_cpuids(self):
        return (self.ProcessorSignature0,self.ProcessorSignature1,self.ProcessorSignature2,self.ProcessorSignature3,
                self.ProcessorSignature4,self.ProcessorSignature5,self.ProcessorSignature6,self.ProcessorSignature7)

    def get_cpuids_unk(self):
        return (self.ProcessorSignature0Unk,self.ProcessorSignature1Unk,self.ProcessorSignature2Unk,self.ProcessorSignature3Unk,
                self.ProcessorSignature4Unk,self.ProcessorSignature5Unk,self.ProcessorSignature6Unk,self.ProcessorSignature7Unk)
    
    def mc_print(self):
        self.f1,self.f2 = self.get_flags()
        self.cpuids = self.get_cpuids()
        self.cpuids_unk = self.get_cpuids_unk()
        self.nonce = '%0.*X' % (0x20 * 2, int.from_bytes(self.Nonce, 'little'))
        
        pt,_ = mc_table(['Field', 'Value'], False, 1)
        
        pt.title = col_b + 'Intel Header Extra' + col_e
        pt.add_row(['Module Type', self.ModuleType])
        pt.add_row(['Module Sub Type', self.ModuleSubType])
        pt.add_row(['Module Size', '0x%X' % (self.ModuleSize * 4)])
        pt.add_row(['RSA Signed', ['No','Yes'][self.f1]])
        pt.add_row(['Flags Reserved', '{0:015b}b'.format(self.f2)])
        pt.add_row(['RSA Key Size', self.RSAKeySize * 1024])
        pt.add_row(['Update Version', '%X' % self.UpdateRevision])
        pt.add_row(['Version Control Number', self.VCN])
        if self.MultiPurpose1 == mc_hdr.PlatformIDs:
            pt.add_row(['Platforms (MP1)', '%0.2X (%s)' % (self.MultiPurpose1, ','.join(map(str, intel_plat(self.MultiPurpose1))))])
        elif self.MultiPurpose1 * 4 == self.UpdateSize * 4:
            pt.add_row(['Update Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
        elif self.MultiPurpose1 * 4 == mc_len - int_hdr_size:
            pt.add_row(['Padded Size (MP1)', '0x%X' % (self.MultiPurpose1 * 4)])
        else:
            pt.add_row(['Multi Purpose 1', '0x%X' % self.MultiPurpose1])
        pt.add_row(['Build Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
        pt.add_row(['Update Size', '0x%X' % (self.UpdateSize * 4)])
        pt.add_row(['CPU Signatures', self.ProcessorSignatureCount])
        any(pt.add_row(['CPUID %d' % i, '%0.5X' % self.cpuids[i]]) for i in range(len(self.cpuids)) if self.cpuids[i] != 0)
        if self.MultiPurpose2 == mc_hdr.PlatformIDs:
            pt.add_row(['Platforms (MP2)', '%0.2X (%s)' % (self.MultiPurpose2, ','.join(map(str, intel_plat(self.MultiPurpose2))))])
        elif self.MultiPurpose2 * 4 == self.UpdateSize * 4:
            pt.add_row(['Update Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
        elif self.MultiPurpose2 * 4 == mc_len - int_hdr_size:
            pt.add_row(['Padded Size (MP2)', '0x%X' % (self.MultiPurpose2 * 4)])
        else:
            pt.add_row(['Multi Purpose 2', '0x%X' % self.MultiPurpose2])
        any(pt.add_row(['CPUID %d Unknown' % i, '0x%X' % self.cpuids_unk[i]]) for i in range(len(self.cpuids_unk)) if self.cpuids_unk[i] != 0)
        pt.add_row(['Unknown 0', '0x%X' % self.Unknown0])
        pt.add_row(['Unknown 1', '0x%X' % self.Unknown1])
        pt.add_row(['Unknown 2', '0x%X' % self.Unknown2])
        pt.add_row(['Unknown 3', '0x%X' % self.Unknown3])
        pt.add_row(['RC4 Nonce', '%s [...]' % self.nonce[:14]])
        pt.add_row(['RSA Public Key', '%s [...]' % self.rsa_mod[:14]])
        pt.add_row(['RSA Exponent', '0x%X' % self.rsa_exp])
        pt.add_row(['RSA Signature', '%s [...]' % self.rsa_sig[:14]])
        
        print()
        print(pt)

class IntelMicrocodeHeaderExtraR1(IntelMicrocodeHeaderExtraBase):
    _pack_ = 1
    _fields_ = [
        ('RSAPublicKey',            uint32_t*64),   # 0x80
        ('RSAExponent',             uint32_t),      # 0x180 0x11 (17)
        ('RSASignature',            uint32_t*64),   # 0x184 0x14 --> SHA-1 or 0x20 --> SHA-256
        # 0x204 (child class, R1)
    ]
    
    def mc_print(self):
        self._get_rsa(self.RSAPublicKey, self.RSASignature, self.RSAExponent, 0x100)
        super().mc_print()
        
class IntelMicrocodeHeaderExtraR2(IntelMicrocodeHeaderExtraBase):
    _pack_ = 1
    _fields_ = [
        ('RSAPublicKey',            uint32_t*96),   # 0x80 Exponent is 0x10001 (65537)
        ('RSASignature',            uint32_t*96),   # 0x200 0x33 --> 0x13 = Unknown + 0x20 = SHA-256
        # 0x300 (child class, R2)
    ]
    
    def mc_print(self):
        self._get_rsa(self.RSAPublicKey, self.RSASignature, 0x10001, 0x180)
        super().mc_print()
        
class IntelMicrocodeHeaderExtraFlags(ctypes.LittleEndianStructure):
    _fields_ = [
        ('RSASigned', uint16_t, 1), # RSA Signature usage
        ('Reserved', uint16_t, 15)
    ]
    
class IntelMicrocodeHeaderExtraGetFlags(ctypes.Union):
    _fields_ = [
        ('b', IntelMicrocodeHeaderExtraFlags),
        ('asbytes', uint16_t)
    ]

class IntelMetadataHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('MetaType',                uint32_t),      # 0x00 0 END, 1 IFS 
        ('MetaSize',                uint32_t),      # 0x04 Entire struct including headers
        # 0x08
    ]

    def mc_print(self):
        pt, _ = mc_table(['Field', 'Value'], False, 1)

        pt.title = col_b + 'Intel Metadata Header' + col_e
        pt.add_row(['Metadata Type', intel_meta_types[self.MetaType]])
        pt.add_row(['Metadata Size', '0x%X' % self.MetaSize])

        print(pt)

class IntelMetadataEntry(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('TestType',                uint32_t),      # 0x00 IFS test type
        ('FusaInfo',                uint32_t),      # 0x04 FUSA info
        ('ImageCount',              uint32_t),      # 0x08 Total images count
        ('ImageCurrent',            uint32_t),      # 0x0C Current image number
        ('ChunkCount',              uint32_t),      # 0x10 Chunks count in image
        ('ChunkStart',              uint32_t),      # 0x14 Starting chunk in image
        ('ChunkSize',               uint32_t),      # 0x18 Size of each chunk
        ('StrideChunks',            uint32_t),      # 0x1C Chunks in a stride
        ('Reserved',                uint32_t*54),   # 0x20 Alignment padding
        # 0xF8
    ]

    def mc_print(self):
        pt, _ = mc_table(['Field', 'Value'], False, 1)

        pt.title = col_b + 'Intel Metadata Entry' + col_e
        pt.add_row(['Test Type', '0x%X' % self.TestType])
        pt.add_row(['FUSA Info', '0x%X' % self.FusaInfo])
        pt.add_row(['Total Images', self.ImageCount])
        pt.add_row(['Current Image', self.ImageCurrent])
        pt.add_row(['Total Chunks', self.ChunkCount])
        pt.add_row(['Starting Chunk', self.ChunkStart])
        pt.add_row(['Chunk Size', '0x%X' % self.ChunkSize])
        pt.add_row(['Stride Chunks', self.StrideChunks])
        pt.add_row(['Reserved', '0x%X' % self.Reserved])

        print(pt)

class Intel_MC_Header_Extended(ctypes.LittleEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('ExtendedSignatureCount',    uint32_t),        # 0x00
        ('ExtendedChecksum',        uint32_t),        # 0x04
        ('Reserved',                uint32_t*3),    # 0x08
        # 0x14
    ]

    def mc_print(self) :
        print()

        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
        pt.title = col_b + 'Intel Header Extended' + col_e
        pt.add_row(['Extended Signatures', self.ExtendedSignatureCount])
        pt.add_row(['Extended Checksum', '%0.8X' % self.ExtendedChecksum])
        pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
        
        print(pt)

class Intel_MC_Header_Extended_Field(ctypes.LittleEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('ProcessorSignature',        uint32_t),        # 0x00
        ('PlatformIDs',                uint32_t),        # 0x04
        ('Checksum',                uint32_t),        # 0x08 replace CPUID, Platform, Checksum at Main Header w/o Extended
        # 0x0C
    ]

    def mc_print(self) :
        print()
        
        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
        pt.title = col_b + 'Intel Header Extended Field' + col_e
        pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
        pt.add_row(['Platforms', '%0.2X (%s)' % (self.PlatformIDs, ','.join(map(str, intel_plat(self.PlatformIDs))))])
        pt.add_row(['Checksum', '%0.8X' % self.Checksum])
        
        print(pt)

class AMD_MC_Header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Year',                    uint16_t),      # 0x00
        ('Day',                     uint8_t),       # 0x02
        ('Month',                   uint8_t),       # 0x03
        ('UpdateRevision',          uint32_t),      # 0x04
        ('LoaderID',                uint16_t),      # 0x08 00-05|10|15 80
        ('DataSize',                uint8_t),       # 0x0A 00 or 10 or 20 or AM5+ DataSize [16:31]
        ('InitializationFlag',      uint8_t),       # 0x0B 00 or 01 or AM5+ DataSize [00:15]
        ('DataChecksum',            uint32_t),      # 0x0C OEM validation only
        ('NorthBridgeVEN_ID',       uint16_t),      # 0x10 0000 or 1022
        ('NorthBridgeDEV_ID',       uint16_t),      # 0x12
        ('SouthBridgeVEN_ID',       uint16_t),      # 0x14 0000 or 1022
        ('SouthBridgeDEV_ID',       uint16_t),      # 0x16
        ('ProcessorSignature',      uint16_t),      # 0x18
        ('NorthBridgeREV_ID',       uint8_t),       # 0x1A
        ('SouthBridgeREV_ID',       uint8_t),       # 0x1B
        ('BiosApiRevision',         uint8_t),       # 0x1C 00 or 01
        ('LoadControl',             uint8_t),       # 0x1D 00 or AA Reserved (AM4-), Bits 0-1 Flags (AM5+)
        ('Reserved_1E',             uint8_t),       # 0x1E 00 or AA
        ('Reserved_1F',             uint8_t),       # 0x1F 00 or AA
        # 0x20
    ]

    def _get_load_control(self):
        load_ctrl = AMDMicrocodeHeaderGetLoadControl()
        load_ctrl.asbytes = self.LoadControl

        return load_ctrl.b.SerializedLoad, load_ctrl.b.LoadOnBothThreads, load_ctrl.b.Reserved

    def get_data_size(self):
        if self.LoaderID >= 0x8005:
            return int(f'0x{self.InitializationFlag:X}{self.DataSize:X}', 16) * 0x10

        return self.DataSize

    def mc_print(self):
        pt, _ = mc_table(['Field', 'Value'], False, 1) 

        pt.title = col_r + 'AMD Header' + col_e
        pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
        pt.add_row(['Update Version', '%X' % self.UpdateRevision])
        pt.add_row(['Loader ID', '0x%X' % self.LoaderID])
        pt.add_row(['Data Size', f'0x{self.get_data_size():X}'])
        if self.LoaderID < 0x8005:
            pt.add_row(['Initialization Flag', f'0x{self.InitializationFlag:X}'])
        pt.add_row(['Checksum', f'0x{self.DataChecksum:08X}'])
        pt.add_row(['NorthBridge Vendor ID', f'0x{self.NorthBridgeVEN_ID:04X}'])
        pt.add_row(['NorthBridge Device ID', f'0x{self.NorthBridgeDEV_ID:04X}'])
        pt.add_row(['SouthBridge Vendor ID', f'0x{self.SouthBridgeVEN_ID:04X}'])
        pt.add_row(['SouthBridge Device ID', f'0x{self.SouthBridgeDEV_ID:04X}'])
        pt.add_row(['CPUID', f'{self.ProcessorSignature >> 8:02X}0F{self.ProcessorSignature & 0xFF:02X}'])
        pt.add_row(['NorthBridge Revision', f'0x{self.NorthBridgeREV_ID:02X}'])
        pt.add_row(['SouthBridge Revision', f'0x{self.SouthBridgeREV_ID:02X}'])
        pt.add_row(['BIOS API Revision', f'0x{self.BiosApiRevision:02X}'])
        if self.LoadControl in (0x00, 0xAA):
            pt.add_row(['Reserved 0x1D', f'0x{self.LoadControl:X}'])
        else:
            load_serial, load_threads, load_reserved = self._get_load_control()
            pt.add_row(['Load Control Serialized', ['No', 'Yes'][load_serial]])
            pt.add_row(['Load Control Both Threads', ['No', 'Yes'][load_threads]])
            pt.add_row(['Load Control Reserved', '{0:06b}b'.format(load_reserved)])
        pt.add_row(['Reserved 0x1E', f'0x{self.Reserved_1E:X}'])
        pt.add_row(['Reserved 0x1F', f'0x{self.Reserved_1F:X}'])

        print(pt)

class AMDMicrocodeHeaderLoadControl(ctypes.LittleEndianStructure):
    _fields_ = [
        ('SerializedLoad', uint8_t, 1), # Patch must be loaded serially across all cores
        ('LoadOnBothThreads', uint8_t, 1), # Patch must be loaded on both threads across all cores
        ('Reserved', uint8_t, 6)
    ]

class AMDMicrocodeHeaderGetLoadControl(ctypes.Union):
    _fields_ = [
        ('b', AMDMicrocodeHeaderLoadControl),
        ('asbytes', uint8_t)
    ]

class VIA_MC_Header(ctypes.LittleEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('Signature',                char*4),        # 0x00 RRAS
        ('UpdateRevision',            uint32_t),        # 0x04
        ('Year',                    uint16_t),        # 0x08
        ('Day',                        uint8_t),        # 0x0A
        ('Month',                    uint8_t),        # 0x0B
        ('ProcessorSignature',        uint32_t),        # 0x0C
        ('Checksum',                uint32_t),        # 0x10 OEM validation only
        ('LoaderRevision',            uint32_t),        # 0x14 00000001
        ('CNRRevision',                uint8_t),        # 0x18 0 CNR001 A0, 1 CNR001 A1
        ('Reserved',                uint8_t*3),        # 0x19 FF * 3
        ('DataSize',                uint32_t),        # 0x1C
        ('TotalSize',                uint32_t),        # 0x20
        ('Name',                    char*12),        # 0x24
        # 0x30
    ]

    def mc_print(self) :
        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
        pt.title = col_c + 'VIA Header' + col_e
        pt.add_row(['Signature', self.Signature.decode('utf-8')])
        pt.add_row(['Update Version', '%X' % self.UpdateRevision])
        pt.add_row(['Date', '%0.4d-%0.2d-%0.2d' % (self.Year, self.Month, self.Day)])
        pt.add_row(['CPUID', '%0.5X' % self.ProcessorSignature])
        pt.add_row(['Checksum', '%0.8X' % self.Checksum])
        pt.add_row(['Loader Version', self.LoaderRevision])
        if self.CNRRevision != 0xFF :
            pt.add_row(['CNR Revision', '001 A%d' % self.CNRRevision])
            pt.add_row(['Reserved', '0x%X' % int.from_bytes(self.Reserved, 'little')])
        else :
            pt.add_row(['Reserved', '0xFFFFFFFF'])
        pt.add_row(['Data Size', '0x%X' % self.DataSize])
        pt.add_row(['Total Size', '0x%X' % self.TotalSize])
        pt.add_row(['Name', self.Name.replace(b'\x7F',b'\x2E').decode('utf-8').strip()])
        
        print(pt)
        
class FSL_MC_Header(ctypes.BigEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('TotalSize',                uint32_t),        # 0x00 Entire file
        ('Signature',                char*3),        # 0x04 QEF
        ('HeaderVersion',            uint8_t),        # 0x07 01
        ('Name',                    char*62),        # 0x08 Null-terminated ID String
        ('IRAM',                    uint8_t),        # 0x46 I-RAM (0 shared, 1 split)
        ('CountMC',                    uint8_t),        # 0x47 Number of MC structures
        ('Model',                    uint16_t),        # 0x48 SoC Model
        ('Major',                    uint8_t),        # 0x4A SoC Revision Major
        ('Minor',                    uint8_t),        # 0x4B SoC Revision Minor
        ('Reserved0',                uint32_t),        # 0x4C Alignment
        ('ExtendedModes',            uint64_t),        # 0x50 Extended Modes
        ('VTraps',                    uint32_t*8),    # 0x58 Virtual Trap Addresses
        ('Reserved1',                uint32_t),        # 0x78 Alignment
        # 0x7C
    ]

    def mc_print(self) :
        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
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
        pt.add_row(['Virtual Traps', '0x%X' % int.from_bytes(self.VTraps, 'little')])
        pt.add_row(['Reserved 1', '0x%X' % self.Reserved1])
        
        print(pt)
                
class FSL_MC_Entry(ctypes.BigEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('Name',                    char*32),        # 0x00 Null-terminated ID String
        ('Traps',                    uint32_t*16),    # 0x20 Trap Addresses (0 ignore)
        ('ECCR',                    uint32_t),        # 0x60 ECCR Register value
        ('IRAMOffset',                uint32_t),        # 0x64 Code Offset into I-RAM
        ('CodeLength',                uint32_t),        # 0x68 dwords (*4, 1st Entry only)
        ('CodeOffset',                uint32_t),        # 0x6C MC Offset (from 0x0, 1st Entry only)
        ('Major',                    uint8_t),        # 0x70 Major
        ('Minor',                    uint8_t),        # 0x71 Minor
        ('Revision',                uint8_t),        # 0x72 Revision
        ('Reserved0',                uint8_t),        # 0x73 Alignment
        ('Reserved1',                uint32_t),        # 0x74 Future Expansion
        # 0x78
    ]

    def mc_print(self) :
        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
        pt.title = col_y + 'Freescale Header Entry' + col_e
        pt.add_row(['Name', self.Name.decode('utf-8')])
        pt.add_row(['Traps', '0x%X' % int.from_bytes(self.Traps, 'little')])
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

class MicrocodeCPUID(ctypes.LittleEndianStructure):
    _fields_ = [
        ('Stepping', ctypes.c_uint, 4),
        ('Model', ctypes.c_uint, 4),
        ('Family', ctypes.c_uint, 4),
        ('ProcessorType', ctypes.c_uint, 2),
        ('Reserved1415', ctypes.c_uint, 2),
        ('ModelExtended', ctypes.c_uint, 4),
        ('FamilyExtended', ctypes.c_uint, 8),
        ('Reserved2831', ctypes.c_uint, 4)
    ]

class MicrocodeGetCPUID(ctypes.Union):
    _fields_ = [
        ('b', MicrocodeCPUID),
        ('asbytes', ctypes.c_uint)
    ]           

class MCB_Header(ctypes.LittleEndianStructure) :
    _pack_ = 1
    _fields_ = [
        ('Tag',                        char*4),        # 0x00 Microcode Blob Tag ($MCB)
        ('MCCount',                    uint16_t),        # 0x04 Microcode Entry Count
        ('MCEDBRev',                uint16_t),        # 0x06 MCE DB Revision
        ('HeaderRev',                uint8_t),        # 0x08 MCB Header Revision (2)
        ('MCVendor',                uint8_t),        # 0x09 Microcode Vendor (0 Intel, 1 AMD)
        ('Reserved',                char*2),        # 0x0A Reserved ($$)
        ('Checksum',                uint32_t),        # 0x0C CRC-32 of Header + Entries + Data
        # 0x10
    ]
    
    def mc_print(self) :
        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
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
        ('CPUID',                    uint32_t),        # 0x00 CPUID
        ('Platform',                uint32_t),        # 0x04 Platform (Intel only)
        ('Revision',                uint32_t),        # 0x08 Revision
        ('Year',                    uint16_t),        # 0x0C Year
        ('Month',                    uint8_t),        # 0x0E Month
        ('Day',                        uint8_t),        # 0x0F Day
        ('Offset',                    uint32_t),        # 0x10 Offset
        ('Size',                    uint32_t),        # 0x14 Size
        ('Checksum',                uint32_t),        # 0x18 Checksum (Vendor/MCE)
        ('Reserved',                uint32_t),        # 0x1C Reserved (0)
        # 0x20
    ]
    
    def mc_print(self) :
        pt, _ = mc_table(['Field', 'Value'], False, 1)
        
        pt.title = col_y + 'Microcode Blob Entry' + col_e
        pt.add_row(['CPUID', '%0.8X' % self.CPUID])
        pt.add_row(['Platform', intel_plat(self.Platform)])
        pt.add_row(['Date', '%0.4X-%0.2X-%0.2X' % (self.Year, self.Month, self.Day)])
        pt.add_row(['Offset', '0x%X' % self.Offset])
        pt.add_row(['Size', '0x%X' % self.Size])
        pt.add_row(['Checksum', '%0.8X' % self.Checksum])
        pt.add_row(['Reserved', self.Reserved])
        
        print(pt)
        
def mce_exit(code) :
    try :
        # Before exiting, print output of MCE & DB update check Thread, if completed/dead
        if not thread_update.is_alive() and thread_update.result : print(thread_update.result)

        # Remove temporary microcode files
        for temp_mc_path in temp_mc_paths:
            if os.path.isfile(temp_mc_path):
                os.remove(temp_mc_path)

        # Remove empty temporary directory
        if not len(os.listdir(temp_path)):
            shutil.rmtree(temp_path)

        # Before exiting, close DB
        cursor.close() # Close DB Cursor
        connection.close() # Close DB Connection
    except :
        pass
    
    colorama.deinit() # Stop Colorama
    
    if not param.skip_pause : input('\nPress enter to exit')
    
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
        print(col_r + '\nError: %s crashed, please report the following:\n' % title)
        traceback.print_exception(exc_type, exc_value, tb)
        print(col_e)
    if not param.skip_pause : input('Press enter to exit')
    colorama.deinit() # Stop Colorama
    sys.exit(-1)

def report_msg(msg_len) :
    return f' You can help this project\n{" " * msg_len}by sharing it at https://win-raid.com forum. Thank you!'

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def adler32(data, iv=1) :
    return zlib.adler32(data, iv) & 0xFFFFFFFF
    
def crc32(data, iv=0) :
    return zlib.crc32(data, iv) & 0xFFFFFFFF
    
def checksum32(data) :    
    chk32 = 0
    
    for idx in range(0, len(data), 4) :
        chk32 += int.from_bytes(data[idx:idx + 4], 'little')
    
    return -chk32 & 0xFFFFFFFF
    
# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(input_stream, start_offset, class_name, param_list = None) :
    if param_list is None : param_list = []
    
    structure = class_name(*param_list) # Unpack parameter list
    struct_len = ctypes.sizeof(structure)
    struct_data = input_stream[start_offset:start_offset + struct_len]
    fit_len = min(len(struct_data), struct_len)
    
    if (start_offset >= file_end) or (fit_len < struct_len) :
        print(col_r + 'Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name.__name__) + col_e)
        
        mce_exit(-1)
    
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

def mc_db_name(in_file, mc_name, mc_nr) :
    new_file_name = os.path.join(os.path.dirname(in_file), mc_name + '.bin')
    
    if mc_nr == 2 : print(col_m + 'Warning: This file includes multiple microcodes!' + col_e)
    elif not os.path.isfile(new_file_name) : os.replace(in_file, new_file_name)
    elif os.path.basename(in_file) == mc_name + '.bin' : pass
    else : print(col_r + 'Error: A file with the same name already exists!' + col_e)

def date_check(year, month, day) :
    year,month,day = int(year), int(month), int(day)
    
    if not (year >= 0 and 1 <= month <= 12 and 1 <= day <= 31) : return False
    
    if year % 4 == 0 : # Check for Leap Years (February)
        if month == 2 and day > 29 : return False
    else :
        if month == 2 and day > 28 : return False
    
    return True
    
def mce_upd_check(db_path) :
    result = None
    
    try :
        with urllib.request.urlopen('https://raw.githubusercontent.com/platomav/MCExtractor/master/MCE.py') as gpy : git_py = gpy.read(0x100)
        git_py_utf = git_py.decode('utf-8','ignore')
        git_py_idx = git_py_utf.find('title = \'MC Extractor v')
        if git_py_idx == -1 : raise Exception('BAD_PY_FORMAT')
        git_py_ver = git_py_utf[git_py_idx:][23:].split('\'')[0].split('_')[0]
        cur_py_ver = title[14:].split('_')[0]
        py_print = '(v%s --> v%s)' % (cur_py_ver, git_py_ver)
        py_is_upd = mce_is_latest(cur_py_ver.split('.')[:3], git_py_ver.split('.')[:3])
        
        with urllib.request.urlopen('https://raw.githubusercontent.com/platomav/MCExtractor/master/MCE.db') as gdb : git_db = gdb.read()
        tmp_db = db_path + '.temp'
        with open(tmp_db, 'wb') as db : db.write(git_db)
        git_conn = sqlite3.connect(tmp_db)
        git_curs = git_conn.cursor()
        git_curs.execute('PRAGMA quick_check')
        git_db_ver = (git_curs.execute('SELECT revision FROM MCE')).fetchone()[0]
        git_curs.close()
        git_conn.close()
        if os.path.isfile(tmp_db) : os.remove(tmp_db)
        cur_conn = sqlite3.connect(db_path)
        cur_curs = cur_conn.cursor()
        cur_curs.execute('PRAGMA quick_check')
        cur_db_ver = (cur_curs.execute('SELECT revision FROM MCE')).fetchone()[0]
        cur_curs.close()
        cur_conn.close()
        db_print = '(r%s --> r%s)' % (cur_db_ver, git_db_ver)
        db_is_upd = cur_db_ver >= git_db_ver
        
        git_link = '\n         Download the latest from https://github.com/platomav/MCExtractor/'
        if not py_is_upd and not db_is_upd : result = col_m + '\nWarning: Outdated MC Extractor %s & Database %s!' % (py_print,db_print) + git_link + col_e
        elif not py_is_upd : result = col_m + '\nWarning: Outdated MC Extractor %s!' % py_print + git_link + col_e
        elif not db_is_upd : result = col_m + '\nWarning: Outdated Database %s!' % db_print + git_link + col_e
    except :
        result = None
    
    return result
    
def mce_is_latest(ver_before, ver_after) :
    # ver_before/ver_after = [X.X.X]
    
    if int(ver_before[0]) > int(ver_after[0]) or (int(ver_before[0]) == int(ver_after[0]) and (int(ver_before[1]) > int(ver_after[1])
    or (int(ver_before[1]) == int(ver_after[1]) and int(ver_before[2]) >= int(ver_after[2])))) :
        return True
    
    return False

def get_temp_path(temp_input):
    if not os.path.isdir(temp_path):
        os.makedirs(temp_path)

    return os.path.join(temp_path, os.path.basename(temp_input))

def chk_mc_mod(mc_nr, msg_vendor, mc_db_note) :
    mod_info = ' (%s)' % mc_db_note if mc_db_note != '' else ''
    msg_vendor.append(col_y + "\nNote: Microcode #%d has an OEM/User modified header%s!" % (mc_nr, mod_info) + col_e)
    
    return msg_vendor
    
def chk_mc_cross(cross_list, msg_vendor) :
    for mc_index, mc_cross in enumerate(cross_list, 1):
        if mc_index != len(cross_list):
            mc_curr_num, _, mc_curr_end = mc_cross
            _, mc_next_bgn, _ = cross_list[mc_index]

            if mc_next_bgn < mc_curr_end:
                msg_vendor.append(col_m + '\nWarning: Microcode #%d is crossing over to the next microcode(s)!' % mc_curr_num + col_e)
                copy_file_with_warn()

    return msg_vendor
    
def db_new_MCE() :
    db_is_dev = (cursor.execute('SELECT developer FROM MCE')).fetchone()[0]
    db_rev_now = (cursor.execute('SELECT revision FROM MCE')).fetchone()[0]
    
    if db_is_dev == 0 :
        cursor.execute('UPDATE MCE SET revision=? WHERE ROWID=1', (db_rev_now + 1,))
        cursor.execute('UPDATE MCE SET developer=1 WHERE ROWID=1')
        
        connection.commit()
    
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
    
def save_mc_file(mc_path, mc_data, mc_chk) :
    if os.path.isfile(mc_path) :
        with open(mc_path, 'rb') as mc_dup : dup_data = mc_dup.read()
        
        if mc_data == dup_data : return
        
        mc_path = '%s_%0.8X.bin' % (mc_path[:-4], mc_chk)
    
    with open(mc_path, 'wb') as mc_file : mc_file.write(mc_data)

def mc_upd_chk_intel(mc_upd_chk_rsl, in_pl_bit, in_rel, in_ver, in_mod) :
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
    
    if in_mod == 1 : is_latest = False # Modded input microcodes should not be shown as Latest
    
    return is_latest, mc_latest
    
def mc_upd_chk_amd(mc_upd_chk_rsl, in_ver, in_mod) :
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
            
    if in_mod == 1 : is_latest = False # Modded input microcodes should not be shown as Latest
    
    return is_latest, mc_latest
    
def build_mc_repo(vendor, mc_name) :
    repo_dir = os.path.join(mce_dir, 'Repo_%s' % vendor, '')
    if not os.path.isdir(repo_dir) : os.mkdir(repo_dir)
    shutil.copyfile(in_file, repo_dir + mc_name + '.bin')

def mc_table(row_col_names,header,padd) :
    pt = pltable.PrettyTable(row_col_names)
    pt.set_style(pltable.UNICODE_LINES)
    pt.xhtml = True
    pt.header = header # Boolean
    pt.left_padding_width = padd
    pt.right_padding_width = padd
    pt.hrules = pltable.ALL
    pt.vrules = pltable.ALL
    pt_empty = str(pt)
    
    return pt,pt_empty

def display_sql(cursor,title,header,padd):
    rows = cursor.fetchall()
    if not rows : return
    
    sqlr = pltable.PrettyTable()
    sqlr.set_style(pltable.UNICODE_LINES)
    sqlr.xhtml = True
    sqlr.header = header # Boolean
    sqlr.left_padding_width = padd
    sqlr.right_padding_width = padd
    sqlr.hrules = pltable.ALL
    sqlr.vrules = pltable.ALL
    sqlr.title = title
    
    row_id = -1
    for name in [cn[0].upper() for cn in cursor.description]:
        row_id += 1
        sqlr.add_column(name, [row[row_id] for row in rows])
    
    print('\n%s' % sqlr)
    
def mce_hdr(hdr_title) :
    hdr_pt, _ = mc_table([], False, 1)
    hdr_pt.add_row([col_y + '        %s        ' % hdr_title + col_e])
    
    print(hdr_pt)
    
def mass_scan(f_path) :
    mass_files = []
    for root, _, files in os.walk(f_path):
        for name in files :
            mass_files.append(os.path.join(root, name))
            
    input('\nFound %s file(s)\n\nPress enter to start' % len(mass_files))
    
    return mass_files

# Get MCE Parameters from input
param = MCE_Param(sys.argv)

# Pause after any unexpected python exception
sys.excepthook = show_exception_and_exit
    
# Get script location
mce_dir = get_script_dir()

# Set DB location
db_path = os.path.join(mce_dir, 'MCE.db')

# Set temp location
temp_path = os.path.join(mce_dir, 'Temporary')

# Initialize & Start background Thread for MCE & DB update check
thread_update = Thread_With_Result(target=mce_upd_check, args=(db_path,), daemon=True)
if not param.upd_dis : thread_update.start() # Start as soon as possible (mce_dir, db_path)

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
        mce_exit(-1)
    
    # Initialize DB, if found empty
    cursor.execute('CREATE TABLE IF NOT EXISTS MCE(revision INTEGER DEFAULT 0, developer INTEGER DEFAULT 1, minimum BLOB DEFAULT "0.0.0")')
    cursor.execute('CREATE TABLE IF NOT EXISTS Intel(type BLOB, cpuid BLOB, platform BLOB, version BLOB, yyyymmdd TEXT, size BLOB, \
                    checksum BLOB DEFAULT "00000000", adler32 BLOB DEFAULT "00000000", adler32e BLOB DEFAULT "00000000", \
                    modded INTEGER DEFAULT 0, notes TEXT DEFAULT "", sha256 BLOB)')
    cursor.execute('CREATE TABLE IF NOT EXISTS AMD(cpuid BLOB, nbdevid BLOB, sbdevid BLOB, nbsbrev BLOB, version BLOB, yyyymmdd TEXT, \
                    size BLOB, checksum BLOB DEFAULT "00000000", adler32 BLOB DEFAULT "00000000", modded INTEGER DEFAULT 0, \
                    notes TEXT DEFAULT "", sha256 BLOB)')
    cursor.execute('CREATE TABLE IF NOT EXISTS VIA(cpuid BLOB, signature TEXT, version BLOB, yyyymmdd TEXT, size BLOB, \
                    checksum BLOB DEFAULT "00000000", adler32 BLOB DEFAULT "00000000", modded INTEGER DEFAULT 0, \
                    notes TEXT DEFAULT "", sha256 BLOB)')
    cursor.execute('CREATE TABLE IF NOT EXISTS FSL(name TEXT, model BLOB, major BLOB, minor BLOB, size BLOB, checksum BLOB DEFAULT "00000000", \
                    adler32 BLOB DEFAULT "00000000", modded INTEGER DEFAULT 0, notes TEXT DEFAULT "", sha256 BLOB)')

    if not cursor.execute('SELECT EXISTS(SELECT 1 FROM MCE)').fetchone()[0] : cursor.execute('INSERT INTO MCE DEFAULT VALUES')
    
    connection.commit()
    
    # Check for MCE & DB incompatibility
    db_rev = (cursor.execute('SELECT revision FROM MCE')).fetchone()[0]
    db_dev = ['',' Dev'][(cursor.execute('SELECT developer FROM MCE')).fetchone()[0]]
    db_min = (cursor.execute('SELECT minimum FROM MCE')).fetchone()[0]
    if not mce_is_latest(title[14:].split('_')[0].split('.')[:3], db_min.split('_')[0].split('.')[:3]) :
        mce_hdr(title)
        print(col_r + '\nError: DB r%d%s requires MCE >= v%s!' % (db_rev, db_dev, db_min) + col_e)
        mce_exit(-1)
    
else :
    cursor = None
    connection = None
    mce_hdr(title)
    print(col_r + '\nError: MCE.db file is missing!' + col_e)
    mce_exit(-1)

rev_dev = (cursor.execute('SELECT revision, developer FROM MCE')).fetchone()
mce_title = '%s r%d%s' % (title, rev_dev[0], ' Dev' if rev_dev[1] else '')

# Set console/shell window title
if sys_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(mce_title)
elif sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1 : sys.stdout.write('\x1b]2;' + mce_title + '\x07')

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
    param = MCE_Param(input_var)
    
    # Non valid parameters are treated as files
    if input_var[0] != "" :
        for i in input_var:
            if i not in param.val :
                sys.argv.append(i.strip('"'))
    
    # Re-enumerate parameter input
    arg_num = len(sys.argv)
    
    os.system(cl_wipe)
    
    mce_hdr(mce_title)

elif not param.get_last :
    mce_hdr(mce_title)

if (arg_num < 2 and not param.help_scr and not param.mass_scan
and not param.search and not param.get_last) or param.help_scr :
    mce_help()

if param.mass_scan :
    in_path = input('\nEnter the full folder path: ')
    source = mass_scan(in_path)
else :
    source = sys.argv[1:] # Skip script/executable

# Search DB by CPUID (Intel/AMD/VIA) or Model (Freescale)
if param.search and not param.build_blob :
    if len(source) >= 2 :
        cpu_id = source[1]
    else :
        cpu_id = input('\nEnter Intel/AMD/VIA CPUID (i.e. 000A0671) or Freescale Model (i.e. 5040): ')
    
    try :
        cpu_id = '%0.8X' % int(cpu_id, 16)
    except :
        print(col_r + '\nError: Invalid CPUID (Intel, AMD, VIA) or Model (Freescale)!' + col_e)
        mce_exit(-1)
    
    res_i = cursor.execute('SELECT type,cpuid,platform,version,yyyymmdd,size,modded,notes FROM Intel WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
    display_sql(res_i, col_b + 'Intel' + col_e, True, 1)
    
    res_a = cursor.execute('SELECT cpuid,version,yyyymmdd,size,modded,notes FROM AMD WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
    display_sql(res_a, col_r + 'AMD' + col_e, True, 1)
    
    res_v = cursor.execute('SELECT cpuid,signature,version,yyyymmdd,size,modded,notes FROM VIA WHERE cpuid=? ORDER BY yyyymmdd DESC', (cpu_id,))
    display_sql(res_v, col_c + 'VIA' + col_e, True, 1)
    
    res_f = cursor.execute('SELECT name,model,major,minor,size,modded,notes FROM FSL WHERE model=? ORDER BY name DESC', (cpu_id[4:],))
    display_sql(res_f, col_y + 'Freescale' + col_e, True, 1)
    
    mce_exit(0)
    
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
        mce_exit(-1)
    
    # The input microcode date is required for Latest check, get it from DB
    # The Latest AMD check is inaccurate for 2002-2003 microcodes due to lack of NB ID & Rev
    if vendor == 'Intel' :
        date = (cursor.execute('SELECT yyyymmdd FROM Intel WHERE cpuid=? AND version=?', ('%0.8X' % cpu_id, '%0.8X' % version,))).fetchall()
    else :
        date = (cursor.execute('SELECT yyyymmdd FROM AMD WHERE cpuid=? AND version=?', ('%0.8X' % cpu_id, '%0.8X' % version,))).fetchall()
    
    if not date :
        print(col_r + '\nError: %s CPUID %0.8X Version %0.8X not found in DB!' % (vendor, cpu_id, version) + col_e)
        mce_exit(-1)
    
    day = date[0][0][6:8]
    month = date[0][0][4:6]
    year = date[0][0][:4]
    
    if vendor == 'Intel' :
        mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,platform,version FROM Intel WHERE cpuid=? AND modded=?', ('%0.8X' % cpu_id,0,))).fetchall()
        is_latest, mc_latest = mc_upd_chk_intel(mc_upd_chk_rsl, intel_plat(platform), 'PRE' if ctypes.c_int(version).value < 0 else 'PRD', version, 0)
    else :
        mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,version FROM AMD WHERE cpuid=? AND modded=?', ('%0.8X' % cpu_id,0,))).fetchall()
        is_latest, mc_latest = mc_upd_chk_amd(mc_upd_chk_rsl, version, 0)
    
    print('\n%s' % is_latest)
    if vendor == 'Intel' and mc_latest :
        print('cpu%0.8X_plat%0.8X_ver%0.8X_%s-%s-%s_%s' % (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4],mc_latest[5],mc_latest[6]))
    elif vendor == 'AMD' and mc_latest :
        print('cpu%0.8X_ver%0.8X_%s-%s-%s' % (mc_latest[0],mc_latest[1],mc_latest[2],mc_latest[3],mc_latest[4]))
    
    mce_exit(0)

# Intel - HeaderType 01-02, Year 1993-2026, Day 01-31, Month 01-12, CPUID xxxxxx00, LoaderRev 00-01, PlatformIDs 000000xx, DataSize xxxxxx00, TotalSize xxxxxx00, MetaSize xxxxxx00
pat_int = re.compile(br'[\x01\x02]\x00{3}.{4}(([\x00-\x09\x10-\x19\x20-\x26]\x20)|([\x93-\x99]\x19))[\x01-\x09\x10-\x19\x20-\x29\x30-\x31][\x01-\x09\x10-\x12].{3}\x00.{4}[\x01\x00]\x00{3}.\x00{3}.{3}\x00.{3}\x00.{3}\x00', re.DOTALL)

# AMD - Year 20xx, Day 01-31, Month 01-13, NorthBridgeVEN_ID 0000|1022, SouthBridgeVEN_ID 0000|1022, BiosApiRevision 00-01, LoadControl 00-0F|AA
pat_amd = re.compile(br'\x20[\x01-\x09\x10-\x19\x20-\x29\x30-\x31][\x01-\x09\x10-\x13].{5}\x80.{6}((\x00{2})|(\x22\x10)).{2}((\x00{2})|(\x22\x10)).{6}[\x00\x01]([\x00-\x0F]|\xAA)', re.DOTALL)

# VIA - Signature RRAS, Year 2006-2026 (0x07D6-0x07EA), Day 01-31 (0x01-0x1F), Month 01-12 (0x01-0x0C), LoaderRev 01, Reserved, DataSize xxxxxx00, TotalSize xxxxxx00
pat_via = re.compile(br'\x52\x52\x41\x53.{4}[\xD6-\xEA]\x07[\x01-\x1F][\x01-\x0C].{3}\x00.{4}\x01\x00{3}.{7}\x00.{3}\x00', re.DOTALL)

# Freescale - Signature QEF, HeaderRev 01, IRAM 00-01, Reserved0, Reserved1
pat_fsl = re.compile(br'\x51\x45\x46\x01.{62}[\x00\x01].{5}\x00{4}.{40}\x00{4}', re.DOTALL)

# Ctypes Structure Size Initialization
int_hdr_size = ctypes.sizeof(Intel_MC_Header)
int_meta_hdr_size = ctypes.sizeof(IntelMetadataHeader)
int_meta_mod_size = ctypes.sizeof(IntelMetadataEntry)
fsl_hdr_size = ctypes.sizeof(FSL_MC_Header)
fsl_mod_size = ctypes.sizeof(FSL_MC_Entry)
ext_hdr_size = ctypes.sizeof(Intel_MC_Header_Extended)
ext_mod_size = ctypes.sizeof(Intel_MC_Header_Extended_Field)

# Microcode Extraction Directories
extr_dir_int = os.path.join(mce_dir, 'Extracted', 'Intel', '')
extr_dir_amd = os.path.join(mce_dir, 'Extracted', 'AMD', '')
extr_dir_via = os.path.join(mce_dir, 'Extracted', 'VIA', '')
extr_dir_fsl = os.path.join(mce_dir, 'Extracted', 'Freescale', '')

# Known Bad Intel Microcodes
known_bad_intel = [
    (0x306C3,0x99,'2013-01-21'),
    (0x506E3,0xFF,'2016-01-05'),
    (0x606E4,0xC,'2019-01-24'),
    (0x90672,0xFF,'2021-11-11'),
    (0x90675,0xFF,'2021-11-11'),
    (0xFF0671,0x104,'2022-04-19')
    ]

# Intel Microcode/IFS Header Types
intel_header_types = {
    1: 'Microcode',
    2: 'In-Field Scan'
    }

# Intel Metadata Header Types
intel_meta_types = {
    0: 'Metadata End',
    1: 'In-Field Scan'
    }

# CPUID Processor Types
cpuid_processor_types = {
    0: 'OEM',
    1: 'Intel OverDrive',
    2: 'Intel Dual',
    3: 'Reserved'
    }

# Global Variable Initialization
in_file = ''
mc_latest = None
match_list_i = None
repo_included = []
temp_mc_paths = []
blob_lut_init = []
blob_lut_done = b''
blob_data = b''
blob_count = 0
cur_count = 0
mc_nr = 0
in_count = len(source)
for arg in source :
    if arg in param.val : in_count -= 1

for in_file in source :
    
    if not os.path.isfile(in_file) :
        if any(p in in_file for p in param.val) : continue # Parameter, skip
        
        print(col_r + '\nError: file %s was not found!' % in_file + col_e)
        
        if not param.mass_scan : mce_exit(-1)
        else : continue # Next file
    
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
    cross_list_i = []
    cross_list_a = []
    cross_list_v = []
    cross_list_f = []
    mc_conv_data = b''
    no_yes = [col_r + 'No' + col_e,col_g + 'Yes' + col_e]
    cur_count += 1
    
    if in_file in temp_mc_paths : print(col_c + '\n%s\n' % os.path.basename(in_file) + col_e)
    else : print(col_c + '\n%s (%d/%d)\n' % (os.path.basename(in_file), cur_count, in_count) + col_e)
    
    with open(in_file, 'rb') as work_file :
        reading = work_file.read()
        file_end = len(reading)
    
    # Skip AMI BIOS Guard (PFAT) protected images
    if reading[0x8:0x10] == b'_AMIPFAT' :
        print('Detected' + col_y + ' AMI BIOS Guard (PFAT) ' + col_e + 'protected image, prior extraction required!' + \
              '\n\nUse "AMI BIOS Guard Extractor" from https://github.com/platomav/BIOSUtilities')
        
        copy_file_with_warn()
        
        continue # Next file
    
    # Detect & Convert Intel Containers (.dat|.inc|.h|.txt) to binary images
    if in_file not in temp_mc_paths :
        try :
            with open(in_file, 'r', encoding = 'utf-8', errors = 'ignore') as in_cont : sample = in_cont.readlines(2048)
                
            for line in sample :
                if (line[:4],line[12:13]) == ('dd 0','h') :
                    type_conv = '.inc'
                    break
                if '0x00000001,' in line[:13] :
                    type_conv = '.dat'
                    break
                
            if not type_conv : raise Exception('UNKNOWN_CONTAINER_TYPE')
            
            with open(in_file, 'r', encoding = 'utf-8') as in_cont : lines = in_cont.readlines()
            
            for line in lines :
                line = line.strip('\n ')
                
                if type_conv == '.dat' :
                    if line[0] == '/' : continue # Comment, next line
                    
                    if len(line) >= 47 and (line[:2],line[10:11]) == ('0x',',') : # "0xjjjjjjjj, 0xjjjjjjjj, 0xjjjjjjjj, 0xjjjjjjjj,"
                        for value in line.split(',')[:4] :
                            dword = int(value.replace('\t','').replace('0x','').replace(' ',''), 16)
                            mc_conv_data += dword.to_bytes(4, 'little')
                    elif len(line) >= 11 and (line[:2],line[10:11]) == ('0x',',') : # "0xjjjjjjjj,"
                        dword = int(line[2:10], 16)
                        mc_conv_data += dword.to_bytes(4, 'little')
                    
                elif type_conv == '.inc' :
                    if len(line) >= 13 and (line[:4],line[12:13]) == ('dd 0','h') : # "dd 0jjjjjjjjh"
                        dword = int(line[4:12], 16)
                        mc_conv_data += dword.to_bytes(4, 'little')
        except :
            pass
        
        if mc_conv_data :
            cont_path = get_temp_path('Container_%s_%0.8X.temp' % (os.path.basename(in_file), adler32(mc_conv_data)))
            temp_mc_paths.append(cont_path) # Store Intel Container microcode binary path to parse once and delete at the end
            source.append(cont_path) # Add Intel Container microcode binary path to the input files
            with open(cont_path, 'wb') as temp : temp.write(mc_conv_data)
    
    # Intel Microcodes
    
    match_list_i += pat_int.finditer(reading)
    
    total += len(match_list_i)
    
    pt, pt_empty = mc_table(['#','Type','CPUID','Platforms','Revision','Date','State','Size','Offset','Last'], True, 1)
    
    for match_ucode_i in match_list_i :
        
        # Microcode Variable Initialization
        ext_chk_mce = 0
        valid_ext_chk = 0
        mc_reserved_all = 0
        mc_hdr_extra = None
        mc_cpuid_chk = True
        mc_patch_chk = True
        mc_latest = None
        
        mc_bgn = match_ucode_i.start()
        
        mc_hdr = get_struct(reading, mc_bgn, Intel_MC_Header)
        
        mc_type = mc_hdr.HeaderType
        
        patch_u = mc_hdr.UpdateRevision # Unsigned, general usage
        patch_s = ctypes.c_int(patch_u).value # Signed, release usage
        
        year = '%0.4X' % mc_hdr.Year
        
        day = '%0.2X' % mc_hdr.Day
        
        month = '%0.2X' % mc_hdr.Month
        
        cpu_id = mc_hdr.ProcessorSignature
        
        plat = mc_hdr.PlatformIDs
        plat_bit = intel_plat(mc_hdr.PlatformIDs)
        
        mc_len = 0x800 if mc_hdr.TotalSize == 0 else mc_hdr.TotalSize
        
        mc_len_data = 0x7D0 if mc_hdr.DataSize == 0 else mc_hdr.DataSize
        
        mc_len_meta = mc_hdr.MetadataSize
        
        mc_chk = mc_hdr.Checksum # For OEM validation, not checked by CPU
        
        full_date = '%s-%s-%s' % (year, month, day)
        
        # Remove false results, based on date or checksum
        if not date_check(year, month, day) or not mc_chk:
            total -= 1

            continue # Next microcode
        
        if param.print_hdr : mc_hdr.mc_print()
        
        mc_data = reading[mc_bgn:mc_bgn + mc_len]
        
        # Analyze Extra Header
        if mc_data[int_hdr_size:int_hdr_size + 0x8] == b'\x00\x00\x00\x00\xA1\x00\x00\x00':
            mc_hdr_extra = get_struct(mc_data, int_hdr_size, IntelMicrocodeHeaderExtraR1)
        elif mc_data[int_hdr_size:int_hdr_size + 0x8] == b'\x00\x00\x00\x00\xE0\x00\x00\x00':
            mc_hdr_extra = get_struct(mc_data, int_hdr_size, IntelMicrocodeHeaderExtraR2)
        
        if mc_hdr_extra :
            mc_reserved_all += mc_hdr_extra.get_flags()[1]

            if cpu_id != 0 and cpu_id not in mc_hdr_extra.get_cpuids() \
            and (cpu_id, patch_u, full_date) not in known_bad_intel: mc_cpuid_chk = False

            if patch_u != mc_hdr_extra.UpdateRevision and (cpu_id,patch_u,full_date) not in known_bad_intel : mc_patch_chk = False
            
            # RSA Signature cannot be validated, Hash is probably derived from Header + Decrypted Patch
            
            if param.print_hdr : mc_hdr_extra.mc_print()
        
        mc_at_db = (cursor.execute('SELECT * FROM Intel WHERE type=? AND cpuid=? AND platform=? AND version=? AND yyyymmdd=? AND size=? AND checksum=?',
                   ('%0.8X' % mc_type, '%0.8X' % cpu_id, '%0.8X' % plat, '%0.8X' % patch_u, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
        
        # Analyze, Validate & Extract optional Extended Header, each Entry only once
        if mc_len > mc_len_data + int_hdr_size and in_file not in temp_mc_paths :
            mc_ext_off = int_hdr_size + mc_len_data
            mc_hdr_ext = get_struct(mc_data, mc_ext_off, Intel_MC_Header_Extended)
            mc_reserved_all += int.from_bytes(mc_hdr_ext.Reserved, 'little')
            if param.print_hdr : mc_hdr_ext.mc_print()
            
            ext_fields_count = mc_hdr_ext.ExtendedSignatureCount
            ext_header_size = ext_hdr_size + ext_fields_count * ext_mod_size # 0x14 Header, 0xC for each Entry
            ext_header_data = mc_data[int_hdr_size + mc_len_data:int_hdr_size + mc_len_data + ext_header_size]
            ext_chk_mce = adler32(ext_header_data) # Custom Intel Microcode Extended Checksum
            
            # Check Extended Header + Fields Checksum (Adler32 > Checksum32)
            valid_ext_chk = 0 if mc_at_db and ext_chk_mce == int(mc_at_db[8], 16) else checksum32(ext_header_data)
            
            mc_ext_field_off = mc_ext_off + ext_hdr_size
            for ext_idx in range(ext_fields_count) :
                mc_hdr_ext_field = get_struct(mc_data, mc_ext_field_off, Intel_MC_Header_Extended_Field)
                if param.print_hdr : mc_hdr_ext_field.mc_print()

                if mc_hdr_extra and mc_hdr_ext_field.ProcessorSignature not in mc_hdr_extra.get_cpuids() \
                and (cpu_id, patch_u, full_date) not in known_bad_intel: mc_cpuid_chk = False

                ext_mc_data = bytearray(mc_data) # Duplicate main Microcode container data for Extended replacements
                ext_mc_data[0xC:0x10] = struct.pack('<I', mc_hdr_ext_field.ProcessorSignature) # Extended CPUID
                ext_mc_data[0x10:0x14] = struct.pack('<I', mc_hdr_ext_field.Checksum) # Extended Checksum
                ext_mc_data[0x18:0x1C] = struct.pack('<I', mc_hdr_ext_field.PlatformIDs) # Extended Platform IDs
                
                ext_mc_path = get_temp_path('Extended_%s_%d_%0.8X.temp' % (os.path.basename(in_file), ext_idx + 1, mc_hdr_ext_field.Checksum))
                temp_mc_paths.append(ext_mc_path) # Store Extended microcode binary path to parse once and delete at the end
                source.append(ext_mc_path) # Add Extended microcode binary path to the input files
                with open(ext_mc_path, 'wb') as ext_mc : ext_mc.write(ext_mc_data)
                
                mc_ext_field_off += ext_mod_size
                
        if param.print_hdr : continue # No more info to print, next microcode
        
        # Detect Release based on Patch signature
        rel_file = 'PRD' if patch_s >= 0 else 'PRE'
        
        mc_name = 'cpu%0.5X_plat%0.2X_ver%0.8X_%s_%s_%0.8X' % (cpu_id, plat, patch_u, full_date, rel_file, mc_chk)
        mc_nr += 1
        
        # Check if any Reserved fields are not empty/0
        if mc_reserved_all != 0 :
            msg_i.append(col_m + '\nWarning: Microcode #%d has non-empty Reserved fields!%s' % (mc_nr, report_msg(9)) + col_e)
            copy_file_with_warn()
        
        # Check if Main and/or Extended Header CPUID is contained in the Extra Header CPUIDs 0-7 (ignore microcode containers with CPUID 0)
        if not mc_cpuid_chk :
            msg_i.append(col_m + '\nWarning: Microcode #%d has Header CPUID discrepancy!%s' % (mc_nr, report_msg(9)) + col_e)
            copy_file_with_warn()
        
        # Check if Main and Extra Header UpdateRevision values are the same (ignore certain special OEM modified Main Headers)
        if not mc_patch_chk :
            msg_i.append(col_m + '\nWarning: Microcode #%d has Header Update Revision discrepancy!%s' % (mc_nr, report_msg(9)) + col_e)
            copy_file_with_warn()
        
        mc_is_mod = mc_at_db[9] if mc_at_db else 0 # Get microcode modded state
        
        mc_chk_mce = adler32(mc_data) # Custom Intel Microcode Checksum
        
        mc_hash_mce = sha256(mc_data) # Custom Intel Microcode Hash
        
        if param.build_db :
            if mc_at_db is None and in_file not in temp_mc_paths :
                db_new_MCE()
                
                cursor.execute('INSERT INTO Intel (type, cpuid, platform, version, yyyymmdd, size, checksum, adler32, adler32e, sha256) VALUES (?,?,?,?,?,?,?,?,?,?)',
                              ('%0.8X' % mc_type, '%0.8X' % cpu_id, '%0.8X' % plat, '%0.8X' % patch_u, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,
                              '%0.8X' % mc_chk_mce, '%0.8X' % ext_chk_mce, mc_hash_mce))
                
                connection.commit()
                
                print(col_g + '\nAdded Intel: %s\n' % mc_name + col_e)
            
            continue # Next microcode
            
        # Rename input file based on the DB structured name
        if param.give_db_name :
            if in_file not in temp_mc_paths : mc_db_name(in_file, mc_name, mc_nr)
            
            continue # Next microcode
        
        mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,platform,version FROM Intel WHERE cpuid=? AND modded=?', ('%0.8X' % cpu_id,0,))).fetchall()
        
        # Determine if MC is Last or Outdated
        is_latest, mc_latest = mc_upd_chk_intel(mc_upd_chk_rsl, plat_bit, rel_file, patch_u, mc_is_mod)
        
        # Build Microcode Repository (PRD & Last)
        if param.build_repo :
            mc_repo_id = 'Intel_%0.5X_%0.2X' % (cpu_id, plat) # Unique Intel Repo Entry: CPUID + Platform
            
            if in_file not in temp_mc_paths and rel_file == 'PRD' and cpu_id not in [0,0x506C0] and is_latest and mc_repo_id not in repo_included  :
                build_mc_repo('INTEL', mc_name)
                repo_included.append(mc_repo_id)
            
            continue # Next microcode
        
        # Prepare Microcode Blob
        if param.build_blob :
            if in_file not in temp_mc_paths :
                blob_count += 1
                
                # CPUID [0x4] + Platform [0x4] + Version [0x4] + Date [0x4] + Offset [0x4] + Size [0x4] + Checksum [0x4] + Reserved [0x4]
                blob_lut_init.append([cpu_id, plat, patch_u, mc_hdr.Year, mc_hdr.Month, mc_hdr.Day, 0, mc_len, mc_chk, 0])
                
                blob_data += mc_data
            
            continue # Next microcode

        # Check if Microcode is marked as OEM/User modified in DB
        if mc_at_db and mc_is_mod : msg_i = chk_mc_mod(mc_nr, msg_i, mc_at_db[10])
        
        row = [mc_nr, intel_header_types[mc_type], '%X' % cpu_id, '%0.2X (%s)' % (plat, ','.join(map(str, plat_bit))),
               '%X' % patch_u, full_date, rel_file, '0x%X' % mc_len, '0x%X' % mc_bgn, no_yes[is_latest]]

        pt.add_row(row)
        
        # Create extraction folder
        if not os.path.exists(extr_dir_int) : os.makedirs(extr_dir_int)
        
        # Check Microcode Checksum (Adler32 > Checksum32)
        mc_chk_ok = 0 if mc_at_db and mc_chk_mce == int(mc_at_db[7], 16) else checksum32(mc_data)
        
        if mc_chk_ok != 0 or valid_ext_chk != 0 :
            if (cpu_id,patch_u,full_date) in known_bad_intel : # Someone "fixed" the modded MC checksum wrongfully
                mc_path = '%s%s.bin' % (extr_dir_int, mc_name)
            else :
                msg_i.append(col_m + '\nWarning: Microcode #%d is corrupted!' % mc_nr + col_e)
                mc_path = '%s!Bad_%s.bin' % (extr_dir_int, mc_name)
        elif len(mc_data) < mc_len :
            msg_i.append(col_m + '\nWarning: Microcode #%d is truncated!' % mc_nr + col_e)
            mc_path = '%s!Bad_%s.bin' % (extr_dir_int, mc_name)
        elif mc_at_db is None :
            msg_i.append(col_g + '\nNote: Microcode #%d is not in the database!%s' % (mc_nr, report_msg(6)) + col_e)
            mc_path = '%s!New_%s.bin' % (extr_dir_int, mc_name)
        else :
            mc_path = '%s%s.bin' % (extr_dir_int, mc_name)
        
        save_mc_file(mc_path, mc_data, mc_chk_mce)
        
        cross_list_i.append((mc_nr, mc_bgn, mc_bgn + mc_len))

    msg_i = chk_mc_cross(cross_list_i, msg_i)
    
    if str(pt) != pt_empty :
        pt.title = col_b + 'Intel' + col_e
        if match_list_a or match_list_v or match_list_f : print()
        print(pt)
    for msg in msg_i: print(msg)
    
    # AMD Microcodes
    
    match_list_a += pat_amd.finditer(reading)
    
    total += len(match_list_a)
    
    pt, pt_empty = mc_table(['#', 'CPUID', 'Revision', 'Date', 'Size', 'Offset', 'Last'], True, 1)
    
    for match_ucode_a in match_list_a :
        
        # Microcode Variable Initialization
        mc_latest = None
        
        mc_bgn = match_ucode_a.start()
        
        mc_bgn -= 1 # Pattern starts from 2nd byte for performance (Year 20xx in BE)
        
        mc_hdr = get_struct(reading, mc_bgn, AMD_MC_Header)
        
        patch = mc_hdr.UpdateRevision
        
        mc_len_data = mc_hdr.get_data_size()
        
        year = '%0.4X' % mc_hdr.Year
        
        day = '%0.2X' % mc_hdr.Day
        
        month = '%0.2X' % mc_hdr.Month
        
        cpu_id = '%0.4X' % mc_hdr.ProcessorSignature
        cpu_id = '00' + cpu_id[:2] + '0F' + cpu_id[2:] # Thank you AMD for a useless header
        
        mc_chk = mc_hdr.DataChecksum
        
        nb_id = '%0.4X%0.4X' % (mc_hdr.NorthBridgeDEV_ID, mc_hdr.NorthBridgeVEN_ID)
        
        sb_id = '%0.4X%0.4X' % (mc_hdr.SouthBridgeDEV_ID, mc_hdr.SouthBridgeVEN_ID)
        
        nbsb_rev_id = '%0.2X' % mc_hdr.NorthBridgeREV_ID + '%0.2X' % mc_hdr.SouthBridgeREV_ID
        
        if (cpu_id,patch,month) == ('00300F10',0x3000027,'13') : month = '12' # Drunk AMD employee 1, happy 13th month!
        if (cpu_id,patch,year) == ('00800F11',0x8001105,'2016') : year = '2017' # Drunk AMD employee 2, Zen in January 2016!
        if (cpu_id,patch,month,day) == ('00730F01',0x7030106,'09','02') : month,day = '02','09' # Drunk AMD employee 3, 2018-09 in 2018-02!
        
        full_date = "%s-%s-%s" % (year, month, day)
        
        # Remove false results, based on Date (1st MC from 1999 but 2001+ for K7 Erratum, performance and pattern strength)
        if any(h in year[2:4] for h in ['A','B','C','D','E','F']) or not date_check(year, month, day) or not (2000 < int(year) < 2026):
            total -= 1

            continue # Next microcode
        
        # Remove false results, based on data
        if reading[mc_bgn + 0x40:mc_bgn + 0x44] == b'\x00' * 4 : # 0x40 has non-null data
            total -= 1

            continue # Next microcode

        # Remove false positive CPUID 00000F00 w/o mc_len_data
        if cpu_id == '00000F00' and mc_len_data not in [0x10, 0x20]:
            total -= 1

            continue # Next microcode

        # Print the Header
        if param.print_hdr :
            mc_hdr.mc_print()
            
            continue # No more info to print, next microcode
        
        mc_nr += 1
        
        # Determine size based on generation
        if mc_len_data == 0x20 : mc_len = 0x3C0
        elif mc_len_data == 0x10 : mc_len = 0x200
        elif mc_len_data : mc_len = mc_len_data
        elif cpu_id[2:4] in ['50'] : mc_len = 0x620
        elif cpu_id[2:4] in ['58'] : mc_len = 0x567
        elif cpu_id[2:4] in ['60','61','63','66','67'] : mc_len = 0xA20
        elif cpu_id[2:4] in ['68','69'] : mc_len = 0x980
        elif cpu_id[2:4] in ['70','73'] : mc_len = 0xD60
        elif cpu_id[2:4] in ['80','81','82','83','85','86','87','88','89','8A'] : mc_len = 0xC80
        elif cpu_id[2:4] in ['A0','A1','A2','A3','A4','A5','A6','A7','AA'] : mc_len = 0x15C0
        elif cpu_id[2:4] in ['B4'] : mc_len = 0x3820
        else :
            msg_a.append(col_r + '\nError: Skipped potential AMD Microcode #%d at 0x%X, unknown %s size!%s' % (mc_nr, mc_bgn, cpu_id, report_msg(7)) + col_e)
            copy_file_with_warn()
            
            continue # Next microcode
        
        mc_data = reading[mc_bgn:mc_bgn + mc_len]
        
        mc_chk_mce = adler32(mc_data) # Custom AMD Microcode Checksum
        
        mc_hash_mce = sha256(mc_data) # Custom AMD Microcode Hash
        
        mc_name = 'cpu%s_ver%0.8X_%s_%0.8X' % (cpu_id, patch, full_date, mc_chk_mce)
        
        mc_at_db = (cursor.execute('SELECT * FROM AMD WHERE cpuid=? AND nbdevid=? AND sbdevid=? AND nbsbrev=? AND version=? \
                    AND yyyymmdd=? AND size=? AND checksum=? AND adler32=?', (cpu_id, nb_id, sb_id, nbsb_rev_id, '%0.8X' % patch,
                    year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk, '%0.8X' % mc_chk_mce, ))).fetchone()
        
        mc_is_mod = mc_at_db[9] if mc_at_db else 0 # Get microcode modded state
        
        if param.build_db :
            if mc_at_db is None :
                db_new_MCE()
                
                cursor.execute('INSERT INTO AMD (cpuid, nbdevid, sbdevid, nbsbrev, version, yyyymmdd, size, checksum, adler32, sha256) \
                                VALUES (?,?,?,?,?,?,?,?,?,?)', (cpu_id, nb_id, sb_id, nbsb_rev_id, '%0.8X' % patch, year + month + day,
                                '%0.8X' % mc_len, '%0.8X' % mc_chk, '%0.8X' % mc_chk_mce, mc_hash_mce))
                
                connection.commit()
                
                print(col_g + '\nAdded AMD: %s\n' % mc_name + col_e)
            
            continue # Next microcode
            
        # Rename input file based on the DB structured name
        if param.give_db_name :
            if in_file not in temp_mc_paths : mc_db_name(in_file, mc_name, mc_nr)
            
            continue # Next microcode
        
        mc_upd_chk_rsl = (cursor.execute('SELECT yyyymmdd,version FROM AMD WHERE cpuid=?', (cpu_id,))).fetchall()
        
        # Determine if MC is Last or Outdated
        is_latest, mc_latest = mc_upd_chk_amd(mc_upd_chk_rsl, patch, mc_is_mod)
        
        # Build Microcode Repository (Last)
        if param.build_repo :
            mc_repo_id = 'AMD_%s' % cpu_id # Unique AMD Repo Entry: CPUID
            if in_file not in temp_mc_paths and is_latest and mc_repo_id not in repo_included :
                build_mc_repo('AMD', mc_name)
                repo_included.append(mc_repo_id)
            
            continue # Next microcode
        
        # Prepare Microcode Blob
        if param.build_blob :
            if in_file not in temp_mc_paths :
                blob_count += 1
                
                # CPUID [0x4] + Reserved [0x4] + Version [0x4] + Date [0x4] + Offset [0x4] + Size [0x4] + Checksum [0x4] + Reserved [0x4]
                blob_lut_init.append([int(cpu_id, 16), 0, patch, int(year, 16), int(month, 16), int(day, 16), 0, mc_len, mc_chk_mce, 0])
                
                blob_data += mc_data
            
            continue # Next microcode
        
        # Check if Microcode is marked as OEM/User modified in DB
        if mc_at_db and mc_is_mod : msg_a = chk_mc_mod(mc_nr, msg_a, mc_at_db[10])
        
        row = [mc_nr, cpu_id, '%0.8X' % patch, full_date, '0x%X' % mc_len, '0x%X' % mc_bgn, no_yes[is_latest]]
        pt.add_row(row)
        
        # Create extraction folder
        if not os.path.exists(extr_dir_amd) : os.makedirs(extr_dir_amd)
        
        # Check Microcode Checksum (Adler32 > Checksum32 > None)
        if mc_at_db and mc_chk_mce == int(mc_at_db[8], 16) : mc_chk_ok = 0
        elif mc_chk : mc_chk_ok = (checksum32(mc_data[0x40:]) + mc_chk) & 0xFFFFFFFF
        else : mc_chk_ok = 0
        
        if mc_chk_ok != 0 :
            msg_a.append(col_m + '\nWarning: Microcode #%d is corrupted!' % mc_nr + col_e)
            mc_path = '%s!Bad_%s.bin' % (extr_dir_amd, mc_name)
        elif len(mc_data) < mc_len :
            msg_a.append(col_m + '\nWarning: Microcode #%d is truncated!' % mc_nr + col_e)
            mc_path = '%s!Bad_%s.bin' % (extr_dir_amd, mc_name)
        elif mc_at_db is None :
            msg_a.append(col_g + '\nNote: Microcode #%d is not in the database!%s' % (mc_nr, report_msg(6)) + col_e)
            mc_path = '%s!New_%s.bin' % (extr_dir_amd, mc_name)
        else :
            mc_path = '%s%s.bin' % (extr_dir_amd, mc_name)
            
        save_mc_file(mc_path, mc_data, mc_chk_mce)

        cross_list_a.append((mc_nr, mc_bgn, mc_bgn + mc_len))

    msg_a = chk_mc_cross(cross_list_a, msg_a)

    if str(pt) != pt_empty :
        pt.title = col_r + 'AMD' + col_e
        if match_list_i or match_list_v or match_list_f : print()
        print(pt)
    for msg in msg_a: print(msg)
    
    # VIA Microcodes
    
    match_list_v += pat_via.finditer(reading)
    
    total += len(match_list_v)
    
    pt, pt_empty = mc_table(['#', 'CPUID', 'Name', 'Revision', 'Date', 'Size', 'Offset'], True, 1)
    
    for match_ucode_v in match_list_v :
        
        # Microcode Variable Initialization
        mc_latest = None
        
        mc_bgn = match_ucode_v.start()
        
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
        
        # Remove false results, based on date or checksum
        if not date_check(year, month, day) or not mc_chk:
            total -= 1

            continue # Next microcode
        
        # Print the Header(s)
        if param.print_hdr :
            mc_hdr.mc_print()
            
            continue # No more info to print, next microcode
        
        mc_data = reading[mc_bgn:mc_bgn + mc_len]
        mc_chk_mce = adler32(mc_data) # Custom VIA Microcode Checksum
        
        mc_hash_mce = sha256(mc_data) # Custom VIA Microcode Hash
        
        mc_name = 'cpu%0.5X_ver%0.8X_sig[%s]_%s_%0.8X' % (cpu_id, patch, name, full_date, mc_chk)
        mc_nr += 1
        
        mc_at_db = (cursor.execute('SELECT * FROM VIA WHERE cpuid=? AND signature=? AND version=? AND yyyymmdd=? AND size=? AND checksum=?',
                   ('%0.8X' % cpu_id, name, '%0.8X' % patch, year + month + day, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
        
        mc_is_mod = mc_at_db[7] if mc_at_db else 0 # Get microcode modded state
        
        if param.build_db :
            if mc_at_db is None :
                db_new_MCE()
                
                cursor.execute('INSERT INTO VIA (cpuid, signature, version, yyyymmdd, size, checksum, adler32, sha256) \
                                VALUES (?,?,?,?,?,?,?,?)', ('%0.8X' % cpu_id, name, '%0.8X' % patch, year + month + day,
                                '%0.8X' % mc_len, '%0.8X' % mc_chk, '%0.8X' % mc_chk_mce, mc_hash_mce))
                
                connection.commit()
            
                print(col_g + '\nAdded VIA: %s\n' % mc_name + col_e)
            
            continue # Next microcode
            
        # Rename input file based on the DB structured name
        if param.give_db_name :
            if in_file not in temp_mc_paths : mc_db_name(in_file, mc_name, mc_nr)
            
            continue # Next microcode
            
        # Build Microcode Repository (All)
        if param.build_repo :
            build_mc_repo('VIA', mc_name)
            
            continue # Next microcode
        
        # Check if Microcode is marked as OEM/User modified in DB
        if mc_at_db and mc_is_mod : msg_v = chk_mc_mod(mc_nr, msg_v, mc_at_db[8])
        
        row = [mc_nr, '%X' % cpu_id, name, '%X' % patch, full_date, '0x%X' % mc_len, '0x%X' % mc_bgn]
        pt.add_row(row)
        
        # Create extraction folder
        if not os.path.exists(extr_dir_via) : os.makedirs(extr_dir_via)
        
        # Check Microcode Checksum (Adler32 > Checksum32)
        mc_chk_ok = 0 if mc_at_db and mc_chk_mce == int(mc_at_db[6], 16) else checksum32(mc_data)
        
        if mc_chk_ok != 0 :
            if (full_date,name,mc_chk) == ('2011-08-09','06FA03BB0',0x9B86F886) : # Drunk VIA employee 1, Signature is 06FA03BB0 instead of 06FA003BB
                mc_path = '%s%s.bin' % (extr_dir_via, mc_name)
            elif (full_date,name,mc_chk) == ('2011-08-09','06FE105A',0x8F396F73) : # Drunk VIA employee 2, Checksum for Reserved FF*4 instead of 00FF*3
                mc_path = '%s%s.bin' % (extr_dir_via, mc_name)
            else :
                msg_v.append(col_m + '\nWarning: Microcode #%d is corrupted!' % mc_nr + col_e)
                mc_path = '%s!Bad_%s.bin' % (extr_dir_via, mc_name)
        elif len(mc_data) < mc_len :
            msg_v.append(col_m + '\nWarning: Microcode #%d is truncated!' % mc_nr + col_e)
            mc_path = '%s!Bad_%s.bin' % (extr_dir_via, mc_name)
        elif mc_at_db is None :
            msg_v.append(col_g + '\nNote: Microcode #%d is not in the database!%s' % (mc_nr, report_msg(6)) + col_e)
            mc_path = '%s!New_%s.bin' % (extr_dir_via, mc_name)
        else :
            mc_path = '%s%s.bin' % (extr_dir_via, mc_name)
        
        save_mc_file(mc_path, mc_data, mc_chk_mce)

        cross_list_v.append((mc_nr, mc_bgn, mc_bgn + mc_len))

    msg_v = chk_mc_cross(cross_list_v, msg_v)

    if str(pt) != pt_empty :
        pt.title = col_c + 'VIA' + col_e
        if match_list_i or match_list_a or match_list_f : print()
        print(pt)
    for msg in msg_v: print(msg)
    
    # Freescale Microcodes
    
    match_list_f += pat_fsl.finditer(reading)
    
    total += len(match_list_f)
    
    pt, pt_empty = mc_table(['#', 'Name', 'SoC Model', 'SoC Major', 'SoC Minor', 'Size', 'Offset'], True, 1)
    
    for match_ucode_f in match_list_f :
        
        # Microcode Variable Initialization
        mc_reserved_all = 0
        mc_latest = None
        
        mc_bgn = match_ucode_f.start()
        
        mc_bgn -= 4 # Pattern starts from 5th byte for performance (Signature QEF)
        
        mc_hdr = get_struct(reading, mc_bgn, FSL_MC_Header)
        
        name = mc_hdr.Name.decode('utf-8')
        
        model = '%0.4d' % mc_hdr.Model
        
        major = mc_hdr.Major
        
        minor = mc_hdr.Minor
        
        mc_len = mc_hdr.TotalSize
        
        mc_data = reading[mc_bgn:mc_bgn + mc_len]
        
        mc_chk = int.from_bytes(mc_data[-0x4:], 'big')
        
        # Remove false results, based on checksum
        if not mc_chk:
            total -= 1

            continue # Next microcode
        
        mc_reserved_all += (mc_hdr.Reserved0 + mc_hdr.Reserved1)
        
        if param.print_hdr : mc_hdr.mc_print()
        
        qe_off = fsl_hdr_size # Header size
        for _ in range(mc_hdr.CountMC) :
            qe_hdr = get_struct(mc_data, qe_off, FSL_MC_Entry)
            mc_reserved_all += (qe_hdr.Reserved0 + qe_hdr.Reserved1)
            if param.print_hdr : qe_hdr.mc_print()
            qe_off += fsl_mod_size # Entry size
            
        if param.print_hdr : continue # No more info to print, next microcode
        
        mc_name = 'soc%s_rev%s.%s_sig[%s]_%0.8X' % (model, major, minor, name, mc_chk)
        mc_nr += 1
        
        # Check if any Reserved fields are not empty/0
        if mc_reserved_all != 0 :
            msg_f.append(col_m + '\nWarning: Microcode #%d has non-empty Reserved fields!%s' % (mc_nr, report_msg(9)) + col_e)
            copy_file_with_warn()
        
        mc_at_db = (cursor.execute('SELECT * FROM FSL WHERE name=? AND model=? AND major=? AND minor=? AND size=? AND checksum=?',
                   (name, model, major, minor, '%0.8X' % mc_len, '%0.8X' % mc_chk,))).fetchone()
        
        mc_is_mod = mc_at_db[7] if mc_at_db else 0 # Get microcode modded state
        
        mc_chk_mce = adler32(mc_data) # Custom Freescale Microcode Checksum
        
        mc_hash_mce = sha256(mc_data) # Custom Freescale Microcode Hash
        
        if param.build_db :
            if mc_at_db is None :
                db_new_MCE()
                
                cursor.execute('INSERT INTO FSL (name, model, major, minor, size, checksum, adler32, sha256) VALUES (?,?,?,?,?,?,?,?)',
                              (name, model, major, minor, '%0.8X' % mc_len, '%0.8X' % mc_chk, '%0.8X' % mc_chk_mce, mc_hash_mce))
                
                connection.commit()
            
                print(col_g + '\nAdded Freescale: %s\n' % mc_name + col_e)
            
            continue # Next microcode
            
        # Rename input file based on the DB structured name
        if param.give_db_name :
            if in_file not in temp_mc_paths : mc_db_name(in_file, mc_name, mc_nr)
            
            continue # Next microcode
        
        # Build Microcode Repository (All)
        if param.build_repo :
            build_mc_repo('FSL', mc_name)
            
            continue # Next microcode
        
        # Check if Microcode is marked as OEM/User modified in DB
        if mc_at_db and mc_is_mod : msg_f = chk_mc_mod(mc_nr, msg_f, mc_at_db[8])
        
        row = [mc_nr, name, model, major, minor, '0x%X' % mc_len, '0x%X' % mc_bgn]
        pt.add_row(row)
        
        # Check Microcode Checksum (Adler32 > CRC32)
        mc_chk_ok = mc_chk if mc_at_db and mc_chk_mce == int(mc_at_db[6], 16) else crc32(mc_data[:-4], 0xFFFFFFFF) ^ 0xFFFFFFFF
        
        # Create extraction folder
        if not os.path.exists(extr_dir_fsl) : os.makedirs(extr_dir_fsl)
        
        if mc_chk_ok != mc_chk :
            msg_f.append(col_m + '\nWarning: Microcode #%d is corrupted!' % mc_nr + col_e)
            mc_path = '%s!Bad_%s.bin' % (extr_dir_fsl, mc_name)
        elif len(mc_data) < mc_len :
            msg_f.append(col_m + '\nWarning: Microcode #%d is truncated!' % mc_nr + col_e)
            mc_path = '%s!Bad_%s.bin' % (extr_dir_fsl, mc_name)
        elif mc_at_db is None :
            msg_f.append(col_g + '\nNote: Microcode #%d is not in the database!%s' % (mc_nr, report_msg(6)) + col_e)
            mc_path = '%s!New_%s.bin' % (extr_dir_fsl, mc_name)
        else :
            mc_path = '%s%s.bin' % (extr_dir_fsl, mc_name)
        
        save_mc_file(mc_path, mc_data, mc_chk_mce)

        cross_list_f.append((mc_nr, mc_bgn, mc_bgn + mc_len))

    msg_f = chk_mc_cross(cross_list_f, msg_f)

    if str(pt) != pt_empty :
        pt.title = col_y + 'Freescale' + col_e
        if match_list_i or match_list_a or match_list_v : print()
        print(pt)
    for msg in msg_f: print(msg)

    if mc_conv_data :
        print(col_y + 'Note: Detected Intel Microcode Container...' + col_e)
    elif total == 0 and in_file in temp_mc_paths :
        print(col_r + 'Error: File should contain CPU microcodes!%s' % report_msg(7) + col_e)
        copy_file_with_warn()
    elif total == 0 :
        print('File does not contain CPU microcodes')

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
