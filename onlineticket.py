# -*- coding: utf-8 -*-
import zlib

#utils
dict_str = lambda d: "\n"+"\n".join(["%s:\t%s" % (k, str_func(v).replace("\n", "\n\t")) for k,v in d.iteritems()])
list_str = lambda l: "\n"+"\n".join(["%d:\t%s" % (i, str_func(v).replace("\n", "\n\t")) for i,v in enumerate(l)])
str_func = lambda v: {dict: dict_str, list: list_str}.get(type(v), str if isinstance(v, DataBlock) else repr)(v)

class DataBlock:
    generic = [
	('head', 6),
	('universal', 2),
	('length', 4)
	]
    fields = []
    def __init__(self, data, offset=0):
	self.stream = data
	self.offset = offset
	self.header = self.dict_read(self.generic)
	self.data = self.dict_read(self.fields)
    
    def __str__(self):
	return "%s\t%s%s" % (self.__class__.__name__, dict_str(self.header).replace("\n", "\n\t"),
	    dict_str(self.data).replace("\n", "\n\t"))
    
    def read(self, l):
	res = self.stream[self.offset:self.offset+l]
	self.offset += l
	return res
    
    def dict_read(self, directory):
	res = {}
	for val in directory:
	    key = val[0]
	    l   = val[1]
	    if type(l) != int:
		l = l(self, res)
	    dat = self.read(l)
	    if len(val) > 2 and val[2] is not None:
		dat = val[2].get(dat)
	    res[key] = dat
	    if len(val) > 3:
		dat = val[3](self, res)
	    res[key] = dat
	return res

class OT_U_HEAD(DataBlock):
    fields = [
		('carrier', 4),
		('auftragsnummer', 8),
		('padding', 12),
		('creation_date', 8),
		('creation_time', 4),
		('TBD0', 1),
		('start_country', 2),
		('dest_country', 2)
	     ]

class OT_0080ID(DataBlock):
    fields = [
		('ausweis_typ', 2, {'01': 'CC', '04': 'BC', '07': 'EC'}),
		('ziffer_ausweis', 4)
	     ]

class OT_0080BL(DataBlock):
    def read_sblocks(self, res):
	ret = {}
	for i in range(int(res['data_count'])):
	    assert self.read(1) == "S"
	    typ = self.read(3)
	    l   = int(self.read(4))
	    ret[typ] = self.read(l)
	return ret
    
    def read_auftraege(self, res):
	fields = [
		    ('certificate', 11),
		    ('padding', 11),
		    ('valid_from', 8),
		    ('valid_to', 8),
		    ('serial', 8)
		 ]
	ret = []
	for i in range(int(res['auftrag_count'])):
	    ret.append(self.dict_read(fields))
	
	return ret
    
    fields = [
		('TBD0', 2),
		('auftrag_count', 1),
		('blocks', 0, None, read_auftraege),
		('data_count', 2),
		('data', 0, None, read_sblocks)
	     ]

def read_block(data, offset):
    block_types = {'U_HEAD': OT_U_HEAD,
		   '0080ID': OT_0080ID,
		   '0080BL': OT_0080BL}
    return block_types[data[offset:offset+6]](data, offset)

readot = lambda x: ''.join([chr(int(i,16)) for i in x.split(" ")])

class HashBlock(DataBlock):
    generic = [
		('type', 1),
		('length', 1),
		('hash', lambda self, res: ord(res['length']))
	      ]

def read_blocks(data, read_func):
    offset = 0
    ret = []
    while offset != len(data):
	block = read_func(data, offset)
	offset = block.offset
	ret.append(block)
    return ret

class OT(DataBlock):
    generic = [
	('terminal', 3),
	('type', 2),
	('carrier', 4),
	('length', 6),
	('hash_length', 1),
	('hashes', lambda self, res: ord(res['hash_length']), None,
	    lambda self, res: read_blocks(res['hashes'], HashBlock)),
	('padding', 0, None,
	    lambda self, res: self.read(4 - self.offset%4)) #dword padding
	      ]
    fields = [
	('data_length', 4),
	('ticket', 0, None,
	    lambda self, res: read_blocks(zlib.decompress(self.read(int(res['data_length']))), read_block))
	]

stb=lambda x: ' '.join([bin(ord(i)) for i in x])

if __name__ == '__main__':
    ots = [OT(readot(i)) for i in open("tickets")]
    print list_str(ots) #[i for i in ots])

    