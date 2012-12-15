# -*- coding: utf-8 -*-
# Parser für Online-Tickets der Deutschen Bahn nach ETF-918.3
# Copyright by Hagen Fritsch, 2009-2012

import zlib
import datetime
from pyasn1.codec.ber import decoder

#utils
dict_str = lambda d: "\n"+"\n".join(["%s:\t%s" % (k, str_func(v).replace("\n", "\n\t")) for k,v in d.iteritems()])
list_str = lambda l: "\n"+"\n".join(["%d:\t%s" % (i, str_func(v).replace("\n", "\n\t")) for i,v in enumerate(l)])
str_func = lambda v: {dict: dict_str, list: list_str}.get(type(v), str if isinstance(v, DataBlock) else repr)(v)

date_parser = lambda x: datetime.datetime.strptime(x, "%d%m%Y")
datetime_parser = lambda x: datetime.datetime.strptime(x, "%d%m%Y%H%M")

class DataBlock(object):
    """
    A DataBlock with a standard-header. The base for custom implementations.
    Also provides features for easy definition of custom fields.
    """
    generic = [
        ('head', 6),
        ('version', 2, int),
        ('length', 4, int)
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
                dat = val[2].get(dat, dat) if type(val[2]) == dict else val[2](dat)
            res[key] = dat
            if len(val) > 3:
                dat = val[3](self, res)
            res[key] = dat
        return res

class GenericBlock(DataBlock):
    """A DataBlock whose content is unknown."""
    def __init__(self, *args, **kwargs):
        super(GenericBlock, self).__init__(*args,**kwargs)
        self.data['unknown_content'] = self.read(self.header['length'] - 12)

class OT_U_HEAD(DataBlock):
    fields = [
                ('carrier', 4, int),
                ('auftragsnummer', 8),
                ('padding', 12),
                ('creation_date', 12, datetime_parser),
                ('flags', 1, lambda x: ",".join(
                    ['international'] if int(x) & 1 else [] +
                    ['edited'] if int(x) & 2 else [] +
                    ['specimen'] if int(x) & 4 else [])),
                ('language', 2),
                ('language_2', 2)
             ]


class OT_0080VU(GenericBlock):
    """Appearing on some newer DB tickets. Content yet unknown."""
    pass

class OT_0080ID(DataBlock):
    fields = [
                ('ausweis_typ', 2, {
                    '01': 'CC', '04': 'BC', '07': 'EC', '09': 'Personalausweis',
                    '11': 'Bonus.card business'}),
                ('ziffer_ausweis', 4)
             ]

class OT_0080BL(DataBlock):
    def read_sblocks(self, res):
        
        def passagier_parser(x):
            x = [int(i) for i in x.split('-')]
            return {'Erwachsene': x[0],'Bahncards':x[1],'Bahncard':{0: 0, 19: 50, 78: 50, 49: 25}[int(x[2])]}
        
        ident = lambda x: x
        
        typen = {
            '001': ('Preismodell',ident),
            '002': ('Produktklasse Gesamtticket',{'0': 'C', '1': 'B', '2': 'A'}),
            '003': ('Produktklasse Hinfahrt',ident),
            '004': ('Produktklasse Rückfahrt',ident),
            '009': ('Passagiere', passagier_parser),
            '012': ('Kinder', int),
            '014': ('Klasse', lambda x: int(x[-1])),
            '015': ('H-Start-Bf',ident),
            '016': ('H-Ziel-Bf',ident),
            '017': ('R-Start-Bf',ident),
            '018': ('R-Ziel-Bf',ident),
            '019': ('Vorgangsnr./Flugscheinnr.',ident),
            '020': ('Vertragspartner',ident),
            '021': ('VIA',ident),
            '023': ('Personenname',ident),
            '026': ('Preisart', {'12': 'Normalpreis', '13': 'Sparpreis', '3': 'Rail&Fly'}),
            '027': ('CC-#/Ausweis-ID',ident),
            '028': ('Vorname, Name', lambda x: x.split("#")),
                }
                
        ret = {}
        
        for i in range(res['data_count']):
            assert self.read(1) == "S"
            typ = self.read(3)
            l   = int(self.read(4))
            dat = self.read(l)
            
            typ, mod = typen.get(typ, (typ,ident))
            dat = mod.get(dat, dat) if type(mod) == dict else mod(dat)
            
            ret[typ] = dat
        return ret
    
    def read_auftraege(self, res):
        fields = [
                    ('certificate', 11),
                    ('padding', 11),
                    ('valid_from', 8, date_parser),
                    ('valid_to', 8, date_parser),
                    ('serial', 8, lambda x: int(x.split('\x00')[0]))
                 ]
        ret = []
        for i in range(res['auftrag_count']):
            ret.append(self.dict_read(fields))
        
        return ret
    
    fields = [
                ('TBD0', 2),
                # '00' bei Schönem WE-Ticket / Ländertickets / Quer-Durchs-Land
                # '02' bei Normalpreis Produktklasse C/B, aber auch Ausnahmen
                # '03' bei normalem IC/EC/ICE Ticket
                # '04' Hinfahrt A, Rückfahrt B; Rail&Fly ABC; Veranstaltungsticket; auch Ausnahmen
                # '05' bei Facebook-Ticket
                ('auftrag_count', 1, int),
                ('blocks', 0, None, read_auftraege),
                ('data_count', 2, int),
                ('data', 0, None, read_sblocks)
             ]

class OT_U_TLAY(DataBlock):
    def read_fields(self, res):
        fields = [
                    ('line', 2, int),
                    ('column', 2, int),
                    ('height', 2, int),
                    ('width', 2, int),
                    ('formating', 1, {
                        '0': 'default',
                        '1': 'bold',
                        '2': 'italic', 
                        '3': 'bold & italic',
                        '4': 'small font (the "132-font" in RCT-2)',
                        '5': 'small + bold',
                        '6': 'small + italic',
                        '7': 'small + bold + italic'}),
                    ('text_length', 4, int),
                    ('text', lambda self, res: res['text_length'])
                 ]
        ret = []
        for i in range(res['field_count']):
            ret.append(self.dict_read(fields))
        
        return ret
    
    fields = [
                ('standard', 4),
                ('field_count', 4, int),
                ('fields', 0, None, read_fields)
             ]

class OT(DataBlock):
    generic = [
        ('header', 3),
        ('version', 2, int),
        ('carrier', 4, int),
        ('key_id', 5),
        ('signature', 0, None,
            lambda self, res: decoder.decode(self.read(50))),
        #('padding', 0, None, lambda self, res: self.read(4 - self.offset%4)) #dword padding
              ]
    fields = [
        ('data_length', 4, int),
        ('ticket', 0, None,
            lambda self, res: read_blocks(zlib.decompress(self.read(res['data_length'])), read_block))
        ]

def read_block(data, offset):
    block_types = {'U_HEAD': OT_U_HEAD,
                   'U_TLAY': OT_U_TLAY,
                   '0080ID': OT_0080ID,
                   '0080BL': OT_0080BL,
                   '0080VU': OT_0080VU}
    block_type = data[offset:offset+6]
    return block_types.get(block_type, GenericBlock)(data, offset)

readot = lambda x: ''.join([chr(int(i,16)) for i in x.strip().split(" ")])

def read_blocks(data, read_func):
    offset = 0
    ret = []
    while offset != len(data):
        block = read_func(data, offset)
        offset = block.offset
        ret.append(block)
    return ret

def fix_zxing_(data):
    """
    ZXing parser seems to return weird results.
    See http://code.google.com/p/zxing/issues/detail?id=1260#c4 from which
    the fix here is derived.
    """
    out = data[:]
    out_counter = 0
    reducer = 0
    for i in xrange(len(data)):
        out[out_counter] = data[i] + reducer
        if data[i] == 0xc3:
            reducer = 0x40
        elif data[i] == 0xc2:
            reducer = 0
        else:
            reducer = 0
            out_counter += 1
    return out[:out_counter]

def fix_zxing(data):
    return ''.join(map(chr, fix_zxing_(map(ord, data))))
           
stb=lambda x: ' '.join([bin(ord(i)) for i in x])

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print 'Usage: %s [ticket_files]' % sys.argv[0]
    ots = {}
    for ticket in sys.argv[1:]:
        try:
            tickets = [readot(i) for i in open(ticket)]
        except:
            tickets = [open(ticket).read()]
        for ot in tickets:
            try:
                ots.setdefault(ticket, []).append(OT(ot))
            except Exception, e:
                try:
                    ots.setdefault(ticket, []).append(OT(fix_zxing(ot)))
                except Exception, f:
                    sys.stderr.write('ORIGINAL: %s\nZXING: %s\n%s: Error: %s (orig); %s (zxing)\n' %
                        (repr(ot), repr(fix_zxing(ot)), ticket, e, f))
    print dict_str(ots)

    # Some more sample functionality:
    # 1. Sort by date
    #tickets = reduce(list.__add__, ots.values())
    #tickets.sort(lambda a, b: cmp(a.data['ticket'][0].data['creation_date'], b.data['ticket'][0].data['creation_date']))
    #print list_str(tickets)
