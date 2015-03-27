#!/usr/bin/env python2
# original code from: https://github.com/paulhsu/readelf.py/blob/master/readelf.py
# (modified for my purpose)
import struct
import json
import sys

offsets = []
symbols = [
	'_ZNK6Pickle9ReadInt16EPPvPs',
	'_ZNK6Pickle10ReadUInt16EPPvPt',
	'_ZNK6Pickle7ReadIntEPPvPi',
	'_ZNK6Pickle10ReadUInt32EPPvPj',
	'_ZNK6Pickle9ReadInt64EPPvPx',
	'_ZNK6Pickle10ReadUInt64EPPvPy',
	'_ZNK6Pickle8ReadLongEPPvPl',
	'_ZNK6Pickle9ReadBytesEPPvPPKcij',
	'_ZNK6Pickle8ReadSizeEPPvPj',
	'_ZNK6Pickle8ReadDataEPPvPPKcPi',
	'_ZNK6Pickle10ReadStringEPPvPSs',
	'_ZNK6Pickle10ReadLengthEPPvPi',
	'_ZNK6Pickle8ReadBoolEPPvPb',
]

config = {"settings": {"libc": "libc.so", "helper": "/data/libarmhook.so"}, "hooks": []}

elf_class = None
end_char = None
shidx_strtab = None

def read_elf_header(f):
	global elf_class
	global end_char

	fmt_ident = '16s'
	fmt32 = 'HHIIIIIHHHHHH'
	fmt64 = 'HHIQQQIHHHHHH'

	fields = ['e_ident', 'e_type', 'e_machine', 'e_version', 'e_entry',
		'e_phoff', 'e_shoff', 'e_flags', 'e_ehsize', 'e_phentsize',
		'e_phnum', 'e_shentsize', 'e_shnum', 'e_shstrndx']

	f.seek(0)
	ident_data = f.read(struct.calcsize(fmt_ident))
	fmt = None

	if ord(ident_data[4]) == 1:
		elf_class = 32
		fmt = fmt32
		data = f.read(struct.calcsize(fmt32))
	elif ord(ident_data[4]) == 2:
		elf_class = 64
		fmt = fmt64
		data = f.read(struct.calcsize(fmt64))

	if ord(ident_data[5]) == 1: #little-endian
		fmt = '<' + fmt_ident + fmt
		end_char = '<'
	elif ord(ident_data[5]) == 2: #big-endian
		fmt = '>' + fmt_ident + fmt
		end_char = '>'

	return dict(zip(fields,struct.unpack(fmt,ident_data+data)))

def read_sh_headers(f, elf_hdr):
	fmt = '@IIIIIIIIII'

	fmt32 = 'IIIIIIIIII'
	fmt64 = 'IIQQQQIIQQ'
	fields = ['sh_name_idx', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset',
	'sh_size', 'sh_link', 'sh_info', 'sh_addralign', 'sh_entsize' ]
	sh_hdrs = []
	f.seek(elf_hdr['e_shoff'])

	for shentid in range(elf_hdr['e_shnum']):
		data = f.read(elf_hdr['e_shentsize'])
		sh_hdrs.append(dict(zip(fields,struct.unpack(fmt,data))))

	shstrndx_hdr = sh_hdrs[elf_hdr['e_shstrndx']]
	f.seek(shstrndx_hdr['sh_offset'])
	shstr = f.read(shstrndx_hdr['sh_size'])
	idx = 0

	for hdr in sh_hdrs:
		offset = hdr['sh_name_idx']
		hdr['sh_name'] = shstr[offset:offset+shstr[offset:].index(chr(0x0))]

		global shidx_strtab

		#if '.debug_str' == hdr['sh_name']:
		if '.strtab' == hdr['sh_name']:
			shidx_strtab = idx

		idx += 1

	return sh_hdrs

def search_symtab(f, elf_hdr, sh_hdrs):
	# read.symtab
	fmt = None
	fmt32 = 'IIIBBH'
	fmt64 = 'IBBHQQ'

	fields = None
	fields32 = ['st_name_idx','st_value','st_size','st_info','st_other','st_shndx']
	fields64 = ['st_name_idx','st_info','st_other','st_shndx','st_value','st_size']

	if elf_class == 32:
		fmt = fmt32
		fields = fields32
	elif elf_class == 64:
		fmt = fmt64
		fields = fields64

	fmt = end_char + fmt
	strtab_hdr = sh_hdrs[shidx_strtab]
	f.seek(strtab_hdr['sh_offset'])

	strtab_str = f.read(strtab_hdr['sh_size'])
	symtabs = []

	indexes = [strtab_str.index(item) for item in symbols]

	for hdr in sh_hdrs:
		if '.symtab' in hdr['sh_name']:
			f.seek(hdr['sh_offset'])
			tabsize = hdr['sh_size']

			while tabsize != 0:
				entsize = struct.calcsize(fmt)

				syment = dict(zip(fields,struct.unpack(fmt,f.read(entsize))))

				syment['st_bind'] = syment['st_info'] >> 4
				syment['st_type'] = syment['st_info'] & 0xf
				syment['st_vis'] = syment['st_other'] & 0x3

				offset = syment['st_name_idx']

				if offset in indexes:
					syment['st_name'] = strtab_str[offset:offset+strtab_str[offset:].index(chr(0x0))]
					create_hook(syment)

				if (len(config["hooks"]) == len(symbols)):
					return

				tabsize -= entsize

def create_hook(syment):
	if syment['st_value'] in offsets:
		sys.stderr.write("Symbol: " + syment['st_name'] + ", offset: " + str(syment['st_value']) + " already hooked\n")
		return

	hook = {"base": "libxul.so", "library": "/data/libpickle.so"}
	hook["relative"] = syment['st_value']
	hook["handler"] = syment['st_name']

	config["hooks"].append(hook)

	offsets.append(syment['st_value'])

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print_help(sys.argv[0])

	open_name = sys.argv[1]
	f = open(open_name,'rb')

	hdr = read_elf_header(f)
	shs = read_sh_headers(f, hdr)

	search_symtab(f, hdr, shs)

	print "\n" + json.dumps(config, indent=4)

