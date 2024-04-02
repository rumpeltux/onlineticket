#!/usr/bin/env python3
"""Lädt öffentliche Schlüssel zur Signaturprüfung herunter."""
import csv
import itertools
import xml.etree.ElementTree as ET
import requests

def get_uic_certs():
  certurl = 'https://railpublickey.uic.org/download.php'
  xmlpubkeys = requests.get(certurl).text

  root = ET.fromstring(xmlpubkeys)

  for child in root:
    issuer = int(child.find('issuerCode').text)
    xid = int(child.find('id').text)
    pubkey = child.find('publicKey').text
    pubkey = f'-----BEGIN CERTIFICATE-----\n{pubkey}\n-----END CERTIFICATE-----'
    yield (issuer, xid, pubkey)

def get_db_certs():
  base_url = 'https://sourceforge.net/p/dbuic2vdvbc/code/ci/master/tree/certs/production/'
  issuer = 80
  for xid in [1,6,7,8]:
    pubkey = requests.get(f'{base_url}{issuer:04}{xid:05}.pem?format=raw').text
    yield (issuer, xid, pubkey)

if __name__ == '__main__':
  with open('certs.csv', 'w') as certsfile:
    certwriter = csv.writer(certsfile, delimiter='\t')
    for issuer, xid, pubkey in itertools.chain(
        get_uic_certs(),
        get_db_certs()):
      certwriter.writerow((issuer, xid, pubkey))
