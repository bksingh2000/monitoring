from flask import Flask
from flask import request
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1905 import EndOfMibView
from collections import defaultdict
import codecs
import binascii

app = Flask(__name__) #creating the Flask class object   

def defdict_to_dict(defdict, finaldict):
    for k, v in defdict.items():
        if isinstance(v, defaultdict):
            finaldict[k] = defdict_to_dict(v, {})
        else:
            finaldict[k] = v
    return finaldict

def hex2Str(str):
    str = str[2:]
    decode_hex = codecs.getdecoder("hex_codec")
    return decode_hex(str)

def to_text(value):
    if value is None:
        return []
    return [str(p) for p in value]

def decode_hex(hexstring):
    if len(hexstring) < 3:
        return hexstring
    if hexstring[:2] == "0x":
        return to_text(binascii.unhexlify(hexstring[2:]))
    return hexstring

def hex_to_str(hexStr):
    try:
        hex = hexStr[2:]
        bytes_object = bytes.fromhex(hex)
        ascii_string = bytes_object.decode("ASCII")
        return ascii_string
    except Exception as ex:
        return hexStr

class DefineOid(object):
    def __init__(self, dotprefix=False):
        if dotprefix:
            dp = "."
        else:
            dp = ""

        # From SNMPv2-MIB 
        self.sysDescr = dp + "1.3.6.1.2.1.1.1.0"
        self.sysObjectId = dp + "1.3.6.1.2.1.1.2.0"
        self.sysUpTime = dp + "1.3.6.1.2.1.1.3.0"
        self.sysContact = dp + "1.3.6.1.2.1.1.4.0"
        self.sysName = dp + "1.3.6.1.2.1.1.5.0"
        self.sysLocation = dp + "1.3.6.1.2.1.1.6.0"

        # From IF-MIB
        self.ifIndex = dp + "1.3.6.1.2.1.2.2.1.1"
        self.ifDescr = dp + "1.3.6.1.2.1.2.2.1.2"
        self.ifMtu = dp + "1.3.6.1.2.1.2.2.1.4"
        self.ifSpeed = dp + "1.3.6.1.2.1.2.2.1.5"
        self.ifPhysAddress = dp + "1.3.6.1.2.1.2.2.1.6"
        self.ifAdminStatus = dp + "1.3.6.1.2.1.2.2.1.7"
        self.ifOperStatus = dp + "1.3.6.1.2.1.2.2.1.8"
        self.ifInOctets = dp + "1.3.6.1.2.1.2.2.1.10"
        self.ifOutOctets = dp + "1.3.6.1.2.1.2.2.1.16"
        self.ifInErr = dp + "1.3.6.1.2.1.2.2.1.14"
        self.ifOutErr = dp + "1.3.6.1.2.1.2.2.1.20"
        self.ifAlias = dp + "1.3.6.1.2.1.31.1.1.1.18"

        # From IP-MIB
        self.ipAdEntAddr = dp + "1.3.6.1.2.1.4.20.1.1"
        self.ipAdEntIfIndex = dp + "1.3.6.1.2.1.4.20.1.2"
        self.ipAdEntNetMask = dp + "1.3.6.1.2.1.4.20.1.3"

def lookup_adminstatus(int_adminstatus):
    adminstatus_options = {
        1: 'up',
        2: 'down',
        3: 'testing'
    }
    if int_adminstatus in adminstatus_options:
        return adminstatus_options[int_adminstatus]
    return ""


def lookup_operstatus(int_operstatus):
    operstatus_options = {
        1: 'up',
        2: 'down',
        3: 'testing',
        4: 'unknown',
        5: 'dormant',
        6: 'unknown',
        7: 'lowerLayerDown'
    }
    if int_operstatus in operstatus_options:
        return operstatus_options[int_operstatus]
    return ""

# Use p to prefix OIDs with a dot for polling
p = DefineOid(dotprefix=True)
# Use v without a prefix to use with return values
v = DefineOid(dotprefix=False)

def Tree():
    return defaultdict(Tree)

results = Tree()
 
@app.route('/snmp/api/', methods=['GET', 'POST']) #decorator drfines the   
def home():  
    if request.method == 'POST':
        try:
            # print(request.POST)
            host = request.POST.get("hostname")
            snmp_cstr = request.POST.get("cstring")
            # print(host, snmp_cstr)
            auth = cmdgen.CommunityData(snmp_cstr)
            cmdGen = cmdgen.CommandGenerator()
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                auth,
                cmdgen.UdpTransportTarget((host, 161)),
                cmdgen.MibVariable(p.sysDescr,),
                cmdgen.MibVariable(p.sysObjectId,),
                cmdgen.MibVariable(p.sysUpTime,),
                cmdgen.MibVariable(p.sysContact,),
                cmdgen.MibVariable(p.sysName,),
                cmdgen.MibVariable(p.sysLocation,),
                lookupMib=False
            )
            if errorIndication:
                return {"error":True, "message":str(errorIndication)}

            for oid, val in varBinds:
                current_oid = oid.prettyPrint()
                current_val = val.prettyPrint()
                if current_oid == v.sysDescr:
                    results['sysdescr'] = hex_to_str(current_val)
                elif current_oid == v.sysObjectId:
                    results['sysobjectid'] = current_val
                elif current_oid == v.sysUpTime:
                    results['sysuptime'] = current_val
                elif current_oid == v.sysContact:
                    results['syscontact'] = current_val
                elif current_oid == v.sysName:
                    results['sysname'] = current_val
                elif current_oid == v.sysLocation:
                    results['syslocation'] = current_val
                # print(current_oid, current_val)

            errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
                auth,
                cmdgen.UdpTransportTarget((host, 161)),
                cmdgen.MibVariable(p.ifInOctets,),
                cmdgen.MibVariable(p.ifOutOctets,),
                cmdgen.MibVariable(p.ifInErr,),
                cmdgen.MibVariable(p.ifOutErr,),
                cmdgen.MibVariable(p.ifIndex,),
                cmdgen.MibVariable(p.ifDescr,),
                cmdgen.MibVariable(p.ifMtu,),
                cmdgen.MibVariable(p.ifSpeed,),
                cmdgen.MibVariable(p.ifPhysAddress,),
                cmdgen.MibVariable(p.ifAdminStatus,),
                cmdgen.MibVariable(p.ifOperStatus,),
                cmdgen.MibVariable(p.ipAdEntAddr,),
                cmdgen.MibVariable(p.ipAdEntIfIndex,),
                cmdgen.MibVariable(p.ipAdEntNetMask,),
                cmdgen.MibVariable(p.ifAlias,),
                lookupMib=False
            )

            if errorIndication:
                return {"error":True, "message":str(errorIndication)}

            interface_indexes = []

            all_ipv4_addresses = []
            ipv4_networks = Tree()

            for varBinds in varTable:
                for oid, val in varBinds:
                    if isinstance(val, EndOfMibView):
                        continue
                    current_oid = oid.prettyPrint()
                    current_val = val.prettyPrint()
                    # print(current_oid, current_val)
                    if v.ifIndex in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        # print(ifIndex,current_val)
                        results['interfaces'][ifIndex]['ifindex'] = current_val
                        interface_indexes.append(ifIndex)
                    if v.ifDescr in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['name'] = hex_to_str(current_val)
                    if v.ifMtu in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['mtu'] = current_val
                    if v.ifSpeed in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['speed'] = current_val
                    if v.ifPhysAddress in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['mac'] = decode_hex(current_val)
                    if v.ifAdminStatus in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['adminstatus'] = lookup_adminstatus(int(current_val))
                    if v.ifOperStatus in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['operstatus'] = lookup_operstatus(int(current_val))

                    if v.ifInOctets in current_oid: 
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['inOctect'] = int(current_val)
                    if v.ifOutOctets in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['outOctect'] = int(current_val)

                    if v.ifInErr in current_oid: 
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['inErr'] = int(current_val)
                    if v.ifOutErr in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['outErr'] = int(current_val)

                    if v.ipAdEntAddr in current_oid:
                        curIPList = current_oid.rsplit('.', 4)[-4:]
                        curIP = ".".join(curIPList)
                        ipv4_networks[curIP]['address'] = current_val
                        all_ipv4_addresses.append(current_val)
                    if v.ipAdEntIfIndex in current_oid:
                        curIPList = current_oid.rsplit('.', 4)[-4:]
                        curIP = ".".join(curIPList)
                        ipv4_networks[curIP]['interface'] = current_val
                    if v.ipAdEntNetMask in current_oid:
                        curIPList = current_oid.rsplit('.', 4)[-4:]
                        curIP = ".".join(curIPList)
                        ipv4_networks[curIP]['netmask'] = current_val

                    if v.ifAlias in current_oid:
                        ifIndex = int(current_oid.rsplit('.', 1)[-1])
                        results['interfaces'][ifIndex]['description'] = current_val
            # print(results)

            interface_to_ipv4 = {}

            for ipv4_network in ipv4_networks:
                current_interface = ipv4_networks[ipv4_network]['interface']
                current_network = {
                    'address': ipv4_networks[ipv4_network]['address'],
                    'netmask': ipv4_networks[ipv4_network]['netmask']
                }
                if current_interface not in interface_to_ipv4:
                    interface_to_ipv4[current_interface] = []
                    interface_to_ipv4[current_interface].append(current_network)
                else:
                    interface_to_ipv4[current_interface].append(current_network)

            for interface in interface_to_ipv4:
                results['interfaces'][int(interface)]['ipv4'] = interface_to_ipv4[interface]

            results['all_ipv4_addresses'] = all_ipv4_addresses

            data = defdict_to_dict(results, {})

            return {"error":False,"data": data}
        except Exception as err:
            return {"error":True,"data": "Some thing went wrong. Reason: " + str(err)}
    else:
        return {'data': 'GET REQUEST'}