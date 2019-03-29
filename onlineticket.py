#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Parser für Online-Tickets der Deutschen Bahn nach ETF-918.3
# Copyright by Hagen Fritsch, 2009-2017

import datetime
import re
import struct
import zlib
import base64
from Crypto.Hash import SHA1
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Math.Numbers import Integer

import os
import asn1 # pip install asn1
import requests # for downloading public key
import xml.etree.ElementTree as ET # for parsing public key file

#utils
dict_str = lambda d: "\n"+"\n".join(["%s:\t%s" % (k, str_func(v).replace("\n", "\n")) for k,v in d.items()])
list_str = lambda l: "\n"+"\n".join(["%d:\t%s" % (i, str_func(v).replace("\n", "\n")) for i,v in enumerate(l)])
str_func = lambda v: {dict: dict_str, list: list_str}.get(type(v), str if isinstance(v, DataBlock) else repr)(v)

# Core datatypes:
uint8 = ord
uint16 = lambda x: x[1] | x[0] << 8
uint24 = lambda x: x[2] | x[1] << 8 | x[0] << 16
uint32 = lambda x: x[3] | x[2] << 8 | x[1] << 16 | x[0] << 24


DEBUG = 0
def debug(tag, arg, *extra):
    if DEBUG: print(tag, arg, *extra, "\n")
    return arg

date_parser = lambda x: datetime.datetime.strptime(debug('date', x).decode('utf-8'), "%d%m%Y")
german_date_parser = lambda x: datetime.datetime.strptime(x.decode('utf-8'), "%d.%m.%Y")
datetime_parser = lambda x: datetime.datetime.strptime(x.decode('utf-8'), "%d%m%Y%H%M")

def DateTimeCompact(data):
  """Based on https://web.archive.org/web/20101206213922/http://www.kcefm.de/imperia/md/content/kcefm/kcefmvrr/2010_02_12_kompendiumvrrfa2dvdv_1_4.pdf"""
  day, time = struct.unpack('>HH', data)
  year = 1990 + (day >> 9)
  month = (day >> 5) & 0xf
  day = day & 0x1f
  hour = time >> 11
  minute = (time >> 5) & 0x3f
  second = time & 0x1f
  # Since hour may be 24 which is not accepted by datetime, we add it manually.
  return datetime.datetime(year, month, day, 0, minute, second) + datetime.timedelta(0, 3600*hour)


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
                if type(val[2]) == dict:
                  dat = val[2].get(dat, dat)
                else:
                  try:
                    dat = val[2](dat)
                  except Exception as e:
                    print('Couldn\'t decode', val, repr(dat), self.__class__)
                    print(dict_str(res))
                    raise
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
                ('carrier', 4),
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


class OT_0080VU_Tag(DataBlock):
  generic = [
               ('tag', 1, uint8), # 0xdc
               # This may be ASN.1 TLV structure in which case additional
               # length parsing for long fields may be required some day.
               ('length', 1, uint8),
               ('type', 1, uint8),
               ('org_id', 2, uint16),
               ('data', lambda self, res: res['length'] - 3)
            ]

class OT_0080VU(DataBlock):
  """Elektronischer Fahrschein (EFS) nach VDV-KA."""

  def read_tag(self, _, res):
    data = OT_0080VU_Tag(res['list_raw']).header
    if data['tag'] == 0xdc:
      if data['length'] == 3 + 3:
        return uint24(data['data'])
      if data['length'] == 3 + 2:
        return uint16(data['data'])
    print('WARNING: Unexpected station data:')
    print(dict_str(data))
    return data

  def read_efs(self, res):
    fields = [
                ('berechtigungs_nr', 4, uint32),
                ('kvp_organisations_id', 2, uint16),
                ('produkt_nr', 2, uint16),
                ('pv_organisations_id', 2, uint16),
                ('valid_from', 4, DateTimeCompact),
                ('valid_to', 4, DateTimeCompact),
                ('preis', 3, uint24),
                ('sam_seqno', 4, uint32),
                ('list_length', 1, uint8),
                ('list_raw', lambda self, res: res['list_length']),
                ('station_id', 0, None, self.read_tag)
                # The IBNR. 3 == Bayern-Ticket
              ]
    ret = []
    for i in range(res['efs_anzahl']):
        ret.append(self.dict_read(fields))

    return ret

  fields = [
              ('terminal_id', 2, uint16),
              ('sam_id', 3, uint24),
              ('personen_anzahl', 1, uint8),
              ('efs_anzahl', 1, uint8),
              ('efs', 0, None, read_efs)
            ]


class OT_0080ID(DataBlock):
    fields = [
                ('ausweis_typ', 2, {
                    '01': 'CC', '04': 'BC', '07': 'EC',
                    '08': 'Bonus.card business',
                    '09': 'Personalausweis',
                    '10': 'Reisepass',
                    '11': 'bahn.bonus Card'}),
                ('ziffer_ausweis', 4)
             ]

class OT_0080BL(DataBlock):
    def read_sblocks(self, res):

        def passagier_parser(x):
            x = [int(i) for i in x.split('-')]
            return {
              'Erwachsene': x[0],
              'Bahncards': x[1],
              'Bahncard': {
                  0: 0,
                  19: 50,
                  78: 50,
                  49: 25,
                  27: 'Einsteiger BahnCard 25 (Abo frei)',
                  39: 'Einsteiger BahnCard 25 (mit Abo)',
                }[int(x[2])]
            }

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
            '031': ('Gültig von', german_date_parser),
            '032': ('Gültig bis', german_date_parser),
            '035': ('Start-Bf-ID', int),
            '036': ('Ziel-Bf-ID', int),
            '040': ('Anzahl Personen', int),
            '041': ('TBD EFS Anzahl', int),
                }

        ret = {}

        for i in range(res['data_count']):
            assert self.read(1) == b"S"
            typ = self.read(3)
            l   = int(self.read(4))
            dat = self.read(l)

            typ, mod = typen.get(typ, (typ,ident))
            dat = mod.get(dat, dat) if type(mod) == dict else mod(dat)

            ret[typ] = dat
        return ret

    def read_auftraege(self, res):
        version_2_fields = [
                    ('certificate', 11),
                    ('padding', 11),
                    ('valid_from', 8, date_parser),
                    ('valid_to', 8, date_parser),
                    ('serial', 8, lambda x: int(x.split(b'\x00')[0]))
                 ]
        # V3: 10102017 10102017 265377293\x00 12102017 12102017 265377294\x00
        version_3_fields = [
                    ('valid_from', 8, date_parser),
                    ('valid_to', 8, date_parser),
                    ('serial', 10, lambda x: int(x.split(b'\x00')[0]))
                 ]
        fields = version_2_fields if self.header['version'] < 3 else version_3_fields
        return [self.dict_read(fields) for i in range(res['auftrag_count'])]

    fields = [
                ('TBD0', 2),
                # '00' bei Schönem WE-Ticket / Ländertickets / Quer-Durchs-Land
                # '00' bei Vorläufiger BC
                # '02' bei Normalpreis Produktklasse C/B, aber auch Ausnahmen
                # '03' bei normalem IC/EC/ICE Ticket
                # '04' Hinfahrt A, Rückfahrt B; Rail&Fly ABC; Veranstaltungsticket; auch Ausnahmen
                # '05' bei Facebook-Ticket, BC+Sparpreis+neue BC25 (Ticket von 2011)
                # '18' bei Kauf via Android App
                ('auftrag_count', 1, int),
                ('blocks', 0, None, read_auftraege),
                ('data_count', 2, int),
                ('data', 0, None, read_sblocks)
             ]

class OT_1180AI(DataBlock):
    """Appears in Touch&Travel tickets.
       Field names have been inferred from the RCT2 output."""
    fields = [
        ('customer?', 7),
        ('vorgangs_num', 8),
        ('unknown1', 5),
        ('unknown2', 2),
        ('full_name', 20),
        ('adults#', 2, int),
        ('children#', 2, int),
        ('unknown3', 2),
        ('description', 20),
        ('ausweis?', 10),
        ('unknown4', 7),
        ('valid_from', 8),
        ('valid_to?', 8),
        ('unknown5', 5),
        ('start_bf', 20),
        ('unknown6', 5),
        ('ziel_bf?', 20),
        ('travel_class', 1, int),
        ('unknown7', 6),
        ('unknown8', 1),
        ('issue_date', 8),
    ]

class OT_U_TLAY(DataBlock):
    CSI = '\x1b[' # Escape sequence

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

    def __str__(self):
      """Actually render the TLAY."""
      fields = self.data['fields']
      fields.sort(key=lambda f: f.get('line', 0) * 100 + f.get('column', 0))
      line = -1
      res = []
      for field in fields:
        new_line = field.get('line', line)
        if new_line > line:
          res.append('\n' * (new_line - line))
          line = new_line
        if 'column' in field:
          res.append(self.CSI + '%dG' % (field['column']))
        formating = field.get('formating', '')
        if 'bold' in formating:
          res.append(self.CSI + '1m')
        if 'small' in formating:
          res.append(self.CSI + '2m')
        if 'italic' in formating:
          res.append(self.CSI + '3m')
        res.append(field.get('text', ''))
        res.append(self.CSI + 'm')

      return 'OT_U_TLAY (len: %d, version: %d, fields: %d)' % (
          self.header['length'], self.header['version'], len(fields)) + ''.join(res)

    def __repr__(self):
      return super(OT_U_TLAY, self).__repr__()

    fields = [
                ('standard', 4),
                ('field_count', 4, int),
                ('fields', 0, None, read_fields)
             ]


class OT_RAWJSN(DataBlock):
    """A data block containing raw json data."""
    def __init__(self, *args, **kwargs):
        super(OT_RAWJSN, self).__init__(*args,**kwargs)
        json_data = self.read(self.header['length'] - 12)
        import json
        try:
          self.data.update(json.loads(json_data))
        except:
          # json is likely unhappy about keys missing quotes
          # (e.g. {key: 'value'} instead of {'key': 'value'})
          import yaml
          try:
            self.data.update(yaml.load(json_data))
          except:
            # yaml is likely unhappy about missing spaces after colons
            # (e.g. {key:'value'} instead of {key: 'value'})
            try:
              with_spaces = re.sub(r'([,{][^}:]+?):([{[0-9\'"])', r'\1: \2', json_data)
              self.data.update(yaml.load(with_spaces))
            except:
              print('Couldn\'t decode JSON data', repr(json_data))
              raise


class OT(DataBlock):
    generic = [
        ('header', 3),
        ('version', 2),
        ('carrier', 4),
        ('key_id', 5),
        ('signature', 50),
        # ('signature', 0, None,
        #     lambda self, res: decoder.decode(self.read(50))),
        #('padding', 0, None, lambda self, res: self.read(4 - self.offset%4)) #dword paddng
              ]
    fields = [
        ('data_length', 4, int),
        ('ticket', 0, None,
            lambda self, res: read_blocks(
              zlib.decompress(self.read(res['data_length'])), read_block))
        ]

def read_block(data, offset):
    block_types = {b'U_HEAD': OT_U_HEAD,
                   b'U_TLAY': OT_U_TLAY,
                   b'0080ID': OT_0080ID,
                   b'0080BL': OT_0080BL,
                   b'0080VU': OT_0080VU,
                   b'1180AI': OT_1180AI,
                   b'RAWJSN': OT_RAWJSN}
    block_type = debug('block_type', data[offset:offset+6], repr(data[offset:]))
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

def fix_zxing(data):
    """
    ZXing parser seems to return utf-8 encoded binary data.
    See also http://code.google.com/p/zxing/issues/detail?id=1260#c4
    """
    return data.decode('utf-8').encode('latin1')


def get_pubkey(issuer, keyid, force_update=False):
  keyfilename = 'keys.xml'
  if (not os.path.isfile(keyfilename)) or force_update:
    print("Downloading new keys.")
    certurl = 'https://railpublickey.uic.org/download.php'
    xmlpubkeys = requests.get(certurl).text
    with open(keyfilename, 'w') as xmlout:
      xmlout.write(xmlpubkeys)
  else:
    print("Reading existing keys from disk.")
    with open(keyfilename, 'r') as xmlin:
      xmlpubkeys = xmlin.read()

  root = ET.fromstring(xmlpubkeys)

  issuer = issuer.decode('utf-8').lstrip('0')
  keyid = keyid.decode('utf-8').lstrip('0')

  for child in root:
    ic = child.find('issuerCode').text
    xid = child.find('id').text
    if ic == issuer and xid == keyid:
      return child.find('publicKey').text

  sys.stderr.write("Public key not found!")
  return None

def verifysig(message, signature, pubkey):
  # get r and s out of the ASN-1
  decoder = asn1.Decoder()
  decoder.start(signature)
  tag, seq = decoder.read()
  decoder.start(seq)
  tag, r = decoder.read()
  tag, s = decoder.read()

  rbytes = Integer(r).to_bytes()
  sbytes = Integer(s).to_bytes()

  verifykey = DSA.import_key(base64.b64decode(pubkey))

  h = SHA1.new(message)
  verifier = DSS.new(verifykey, 'fips-186-3')

  try:
    verifier.verify(h, rbytes+sbytes)
    print("Signature is valid.")
    return True
  except ValueError:
    print("Signature NOT valid.")
    return False



if __name__ == '__main__':
  import sys
  if len(sys.argv) < 2:
      print('Usage: %s [ticket_files]' % sys.argv[0])
  ots = {}
  for ticket in sys.argv[1:]:
      try:
          tickets = [readot(i) for i in open(ticket)]
      except:
          tickets = [open(ticket, 'rb').read()]
      for ot in tickets:
          try:
              ots.setdefault(ticket, []).append(OT(ot))
          except Exception as e:
              try:
                  ots.setdefault(ticket, []).append(OT(fix_zxing(ot)))
              except Exception as f:
                  sys.stderr.write('ORIGINAL: %s\nZXING: %s\n%s: Error: %s (orig); %s (zxing)\n' %
                      (repr(ot), repr(fix_zxing(ot)), ticket, e, f))
                  raise
  print(dict_str(ots))


  for ot in ots:
    for ticket in ots[ot]:
      issuer = ticket.header['carrier']
      keyid = ticket.header['key_id']
      pubkey = get_pubkey(issuer, keyid)
      if pubkey:
        signature = ticket.header['signature']
        rawticket = ticket.stream[68:]
        verifysig(rawticket, signature, pubkey)


  # Some more sample functionality:
  # 1. Sort by date
  #tickets = reduce(list.__add__, ots.values())
  #tickets.sort(lambda a, b: cmp(a.data['ticket'][0].data['creation_date'], b.data['ticket'][0].data['creation_date']))
  #print(list_str(tickets))

