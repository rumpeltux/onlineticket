#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Parser für Online-Tickets der Deutschen Bahn nach ETF-918.3

import csv
import datetime
import logging
import os
import re
import struct
import zlib

import logging

logger = logging.getLogger(__name__)

try: # pip install pycryptodome
    from Cryptodome.Hash import SHA1
    from Cryptodome.Hash import SHA224
    from Cryptodome.Hash import SHA256
    from Cryptodome.PublicKey import DSA
    from Cryptodome.Signature import DSS
    from Cryptodome.Math.Numbers import Integer
except:
    try:
        from Crypto.Hash import SHA
        logger.error('Please remove the deprecated python3-crypto package and install python3-pycryptodome instead.')
        exit(1)
    except:
        logger.warning('signature verification is disabled due to missing pycryptodome package.')
    SHA1, SHA224, SHA256, DSA, DSS, Integer = None, None, None, None, None, None

try: # pip install pyasn1
    import pyasn1.codec.der.decoder as asn1
except:
    logger.info('signature verification is disabled due to missing pyasn1 package.')
    asn1 = None

#utils
dict_str = lambda d: "\n"+"\n".join(["%s:\t%s" % (k, str_func(v).replace("\n", "\n")) for k,v in d.items()])
list_str = lambda l: "\n"+"\n".join(["%d:\t%s" % (i, str_func(v).replace("\n", "\n")) for i,v in enumerate(l)])
str_func = lambda v: {dict: dict_str, list: list_str}.get(type(v), str if isinstance(v, DataBlock) else repr)(v)

# Core datatypes:
uint8 = ord
uint16 = lambda x: x[1] | x[0] << 8
uint24 = lambda x: x[2] | x[1] << 8 | x[0] << 16
uint32 = lambda x: x[3] | x[2] << 8 | x[1] << 16 | x[0] << 24


def debug(tag: str, arg, *extra):
    logger.debug(repr((tag, arg, *extra)))
    return arg

date_parser = lambda x: datetime.datetime.strptime(debug('date', x).decode('ascii'), "%d%m%Y")
german_date_parser = lambda x: datetime.datetime.strptime(x, "%d.%m.%Y")
datetime_parser = lambda x: datetime.datetime.strptime(x.decode('ascii'), "%d%m%Y%H%M")

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
                    logger.warning('Couldn\'t decode (%s, %s, %s):\n%s',
                                  val, repr(dat), self.__class__, dict_str(res))
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
    logger.warning('Unexpected station data:\n' + dict_str(data))
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
            typ = self.read(3).decode('ascii')
            l   = int(self.read(4))
            dat = self.read(l).decode('utf8')

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
                        b'0': 'default',
                        b'1': 'bold',
                        b'2': 'italic',
                        b'3': 'bold & italic',
                        b'4': 'small font (the "132-font" in RCT-2)',
                        b'5': 'small + bold',
                        b'6': 'small + italic',
                        b'7': 'small + bold + italic'}),
                    ('text_length', 4, int),
                    ('text', lambda self, res: res['text_length'], lambda x: x.decode())
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
              logger.warning('Couldn\'t decode JSON data', repr(json_data))
              raise


class SignatureVerificationError(Exception):
    pass

def get_pubkey(issuer, keyid):
    if get_pubkey.certs is None:
        certs_filename = os.path.join(os.path.dirname(__file__), 'certs.csv')
        if not os.path.exists(certs_filename):
            raise SignatureVerificationError(
                f'certificate store not found: {certs_filename}\n'
                'Use download_keys.py to create it.')
        get_pubkey.certs = {}
        with open(certs_filename) as certsfile:
            certreader = csv.reader(certsfile, delimiter='\t')
            for cert_issuer, xid, pubkey in certreader:
                get_pubkey.certs[(int(cert_issuer), int(xid))] = pubkey
    try:
        return get_pubkey.certs[(int(issuer), int(keyid))]
    except KeyError:
        raise SignatureVerificationError(f'Public key not found (issuer={issuer}, keyid={keyid})')

get_pubkey.certs = None

def verifysig(message, version, signature, pubkey):
    if DSS is None or asn1 is None:  # pycryptodome package is missing
        raise SignatureVerificationError('Signature verification disabled')
    if not signature:
      raise SignatureVerificationError('Signature asn1 parsing error.')

    r, s = signature

    if version <= 1:
      rbytes = int.to_bytes(r, 20, byteorder='big')
      sbytes = int.to_bytes(s, 20, byteorder='big')
      h = SHA1.new(message)
    else:
      rbytes = int.to_bytes(r, 32, byteorder='little')
      sbytes = int.to_bytes(s, 32, byteorder='little')
      # TODO: According to this document, the payload can be SHA224 or SHA256. So do we really need to verify the signature twice?!
      #       https://www.kcd-nrw.de/fileadmin/user_upload/01_Ergebnisdokument_Deutschlandticket_UIC__V1.02.pdf
      #       Hardcoded to SHA256 for now, because the October 2023 and December 2023 Deutsche Bahn tickets all have SHA256
      #h = SHA224.new(message)
      h = SHA256.new(message)

    verifykey = DSA.import_key(pubkey)
    verifier = DSS.new(verifykey, 'fips-186-3')

    try:
        verifier.verify(h, rbytes+sbytes)
        return True
    except ValueError as e:
        raise SignatureVerificationError("Signature NOT valid: " + str(e))

class OT(DataBlock):
    def signature_decode(self, res):
      '''Extracts the signature (r,s) tuple.'''
      if int(res['version']) <= 1:
        # UIC 1.0: (r,s) are stored in an ASN 1.0 structure
        # TODO: Is this code correct? How can we know that the ASN.1 structure will be exactly 50 bytes, if (r,s) can have different lengths? Or is somewhere specified that there is a badding after the ASN.1 structure?
        if not asn1: return None
        signature_length = 50
        signature_bytes = self.read(signature_length)
        try:
          decoded = asn1.decode(signature_bytes)[0]
        except Exception as e:
           return (repr(e), signature_bytes)
        return (int(decoded[0]), int(decoded[1]))
      else:
        # "Die Werte bei Version 2 müssen zwingend 32 Byte groß sein und nötigenfalls mit vorangestellten Nullbytes aufgefüllt werden."
        decoded = [0, 0]
        decoded[0] = self.read(32)
        decoded[0] = int.from_bytes(decoded[0], byteorder='little', signed=False)
        decoded[1] = self.read(32)
        decoded[1] = int.from_bytes(decoded[1], byteorder='little', signed=False)
        return (int(decoded[0]), int(decoded[1]))

    def signature_validity(self, res):
      if len(self.stream) - self.offset - res['data_length'] > 0:
          return 'INVALID (trailing data)'
      if len(self.stream) - self.offset - res['data_length'] < 0:
          return 'INVALID (incomplete ticket data)'
      if type(res['signature'][0]) != int:
         return 'INVALID (asn1 decode error)'
      try:
          pubkey = get_pubkey(issuer=res['carrier'],
                              keyid=res['key_id'])
          result = verifysig(self.stream[self.offset:], int(res['version']), res['signature'], pubkey)
      except SignatureVerificationError as e:
          return str(e)

      return 'VALID' if result else 'INVALID'

    generic = [
        ('header', 3),
        ('version', 2),
        ('carrier', 4),
        ('key_id', 5),
        ('signature', 0, None, signature_decode),
        ('data_length', 4, int),
        ('signature_validity', 0, None, signature_validity),
    ]

    fields = [
        ('ticket', 0, None, lambda self, res: read_blocks(
              zlib.decompress(self.read(self.header['data_length'])), read_block)),
    ]


def read_block(data, offset):
    # TODO: Decode UIC 2.0 U_FLEX (encoded in ASN.1 UPER). Example implementation: https://github.com/karlheinzkurt/ticket-decoder/blob/master/source/lib/uic918/detail/source/RecordU_FLEX.cpp
    block_types = {b'U_HEAD': OT_U_HEAD,
                   b'U_TLAY': OT_U_TLAY,
                   b'0080ID': OT_0080ID,
                   b'0080BL': OT_0080BL,
                   b'0080VU': OT_0080VU,
                   b'1180AI': OT_1180AI,
                   b'RAWJSN': OT_RAWJSN}
    block_type = debug('block_type', data[offset:offset+6], repr(data[offset:]))
    return block_types.get(block_type, GenericBlock)(data, offset)


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
    data = data.decode('utf-8').encode('latin1')
    # zxing parsing also adds a newline to the end of the file. remove that.
    if data.endswith(b'\n'):
      data = data[:-1]
    return data

if __name__ == '__main__':
  import argparse
  import sys

  parser = argparse.ArgumentParser()
  parser.add_argument('ticket_files', nargs='+')
  parser.add_argument('-a', '--auto-zxing', action='store_true',
                      help='Automatically detect whether zxing preprocessing is required.')
  parser.add_argument('-d', '--debug', help='Enable debug logging', action='store_true')
  parser.add_argument('-q', '--quiet', help='Less verbose logging', action='store_true')
  parser.add_argument('-z', '--zxing', help='Enable zxing preprocessing.', action='store_true')
  args = parser.parse_args()

  if args.quiet:
    logger.setLevel(logging.ERROR)
  elif args.debug:
    logger.setLevel(logging.DEBUG)
  else:
    logger.setLevel(logging.INFO)

  ots = {}
  for ticket in args.ticket_files:
    try:
      tickets = [bytes.fromhex(line) for line in open(ticket)]
    except:
      content = open(ticket, 'rb').read()
      tickets = [content]
    for line_no, binary_ticket in enumerate(tickets):
      logger.info(f'File: {ticket}\tLine: {line_no + 1}')
      ot = None
      try:
        if args.zxing:
           binary_ticket = fix_zxing(binary_ticket)
        ot = OT(binary_ticket)
      except Exception as e:
        if not args.zxing or args.auto_zxing:
          try:
            fixed = fix_zxing(binary_ticket)
            ot = OT(fixed)
          except Exception as f:
            sys.stderr.write('ORIGINAL: %s\nZXING: %s\n%s: Error: %s (orig); %s (zxing)\n' %
                (repr(ot), repr(fixed), ticket, e, f))
            raise
          if not args.auto_zxing:
            print('\nERROR: The ticket could not be parsed, but succeeded with zxing '
                  'preprocessing. Rerun the script with the --zxing (or --auto-zxing) flag.\n', file=sys.stderr)
        if not ot or not args.auto_zxing:
          raise
        
      print(ot)
      ots.setdefault(ticket, []).append(ot)

  # Some more sample functionality:
  # 1. Sort by date
  #tickets = reduce(list.__add__, ots.values())
  #tickets.sort(lambda a, b: cmp(a.data['ticket'][0].data['creation_date'], b.data['ticket'][0].data['creation_date']))
  #print(list_str(tickets))
