"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
from model.attributes import IPv4, DomainName, URLVerbatim
from model.misp_event import MISPEvent
from model.misp_tag import MISPTag


class C2Server(MISPEvent):

    def __init__(self, organisation_name, organisation_uuid, threat_level_id, published, info, date):
        MISPEvent.__init__(self, organisation_name, organisation_uuid, threat_level_id, published, info, date)
        self.append_tags(MISPTag("#ffc000", True, "tlp:amber"))

    @staticmethod
    def parse(misp_event, val):
        if isinstance(misp_event, C2Server) and isinstance(val, list):
            index = 1
            length = len(val)
            for item in val:
                if item["data_type"] == 'IPv4':
                    try:
                        ipv4 = IPv4.parse(item)
                        misp_event.append_attribute(ipv4)
                    except ValueError:
                        print("Error parsing TIE IOC(IPv4)")
                elif item["data_type"] == "IPv6":
                    pass
                elif item["data_type"] == "DomainName":
                    try:
                        dn = DomainName.parse(item)
                        misp_event.append_attribute(dn)
                    except ValueError:
                        print("Error parsing TIE IOC(DomainName)")
                elif item["data_type"] == "URLVerbatim":
                    try:
                        url = URLVerbatim.parse(item)
                        misp_event.append_attribute(url)
                    except ValueError:
                        print("Error parsing TIE IOC(URLVerbatim)")
                else:
                    raise ValueError("C2Server events only supports attributes with type IPv4, IPv6, DomainName," +
                                     "URLVerbatim")
                # Print Index
                if index % 10 == 0 or index == length:
                    print('Attribute: ' + str(index) + ' from ' + str(length))
                index += 1
        else:
            raise ValueError("Given event must be a C2Server event")



