'''
Created on Jun 3, 2022

@author: boogie
'''
from x5092json import x509parser
from collections import OrderedDict
import binascii
import asn1
import os
import argparse
import sys


IECROLES = {0: "VIEWER",
            1: "OPERATOR",
            2: "ENGINEER",
            3: "INSTALLER",
            4: "SECADM",
            5: "SECAUD",
            6: "RBACMNT",
            -31648: "SIEMENS ADMIN",
            -20537: "SIEMENS GUEST",
            -102: "SIEMENS SWITCHING AUTHORITY",
            -104: "SIEMENS INTERLOCKING MODE"}

OID_62351 = "1.0.62351.8.1"
OID_10070 = "1.2.840.10070.8.1"


def recparseoid(value, ret):
    decoder = asn1.Decoder()
    decoder.start(value)
    while not decoder.eof():
        subkey, subvalue = decoder.read()
        if subkey.typ == 32:
            subret = []
            ret.append(recparseoid(subvalue, subret))
        else:
            ret.append(subvalue)
    return ret


def parseoid(oid, subitem):
    if oid in [OID_62351, OID_10070]:
        oid = f"IECUserRoles({oid})"
        value = []
        for tokenid, token in enumerate(recparseoid(binascii.unhexlify(subitem["value"]["hex"]), [])[0]):
            roles = []
            for roleid, role in enumerate(token[0]):
                roles.append({"value": OrderedDict(RoleID=f"{role} {IECROLES.get(role, '')}"),
                              "oid": {"name": str(roleid)}})
            value.append({"value": OrderedDict(userRole=roles,
                                               aor=token[1],
                                               revision=token[2],
                                               roleDefinition=token[3]
                                               ),
                          "oid": {"name": f"UserRole{tokenid}"}
                          })
        subitem["value"] = value
    return oid, subitem


def parsekv(k, v):
    if isinstance(v, list):
        for subitem in v:
            name = subitem.get("oid", {}).get("name") or \
                   subitem.get('dotted_string') or \
                   subitem.get("type")
            if name == "Unknown OID":
                name = subitem["oid"]["dotted_string"]
                name, subitem = parseoid(name, subitem)
            elif name is None:
                print(f"Unknown encoding: {subitem}")
                continue
            value = subitem.get("value") or subitem.get(f"{name.lower()}_value")
            for ret in parsekv(f"{k}/{name}", value):
                    yield ret
    elif isinstance(v, OrderedDict):
        for subk, subv in v.items():
            for ret in parsekv(f"{k}/{subk}", subv):
                yield ret
    else:
        yield k, v


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses x509 pem certificates and prints IEC 6251 based access tokens')
    parser.add_argument('certfile', type=str, nargs='?', default=None, help='path to pem certfile')
    parser.add_argument('--hextoken', type=str, default=None, help='parse only the token which is an hexstring')
    args = parser.parse_args()

    certob = None
    if args.certfile:
        if not os.path.exists(args.certfile):
            print(f"{args.certfile} does not exist")
            sys.exit(2)
        with open(args.certfile, mode='rb') as f:
            cert = x509parser.load_certificate(f)
        certob = x509parser.parse(cert)
    elif args.hextoken:
        certob = {"token": [{"value": {"hex": args.hextoken.replace(" ", "")},
                             "oid": {"name": "Unknown OID",
                                     "dotted_string": OID_62351}}]}
    if certob:
        for k, v in certob.items():
            for k, v in parsekv(k, v):
                print(f"{k}: {v}")
