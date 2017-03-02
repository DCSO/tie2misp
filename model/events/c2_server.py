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
                try:
                    if item["data_type"] == 'IPv4':
                        ipv4 = IPv4.parse(item)
                        misp_event.append_attribute(ipv4)
                    elif item["data_type"] == "IPv6":
                        pass
                    elif item["data_type"] == "DomainName":
                        dn = DomainName.parse(item)
                        misp_event.append_attribute(dn)
                        pass
                    elif item["data_type"] == "URLVerbatim":
                        url = URLVerbatim.parse(item)
                        misp_event.append_attribute(url)
                        pass
                    else:
                        raise ValueError("C2Server events only supports attributes with type IPv4, IPv6, DomainName," +
                                         "URLVerbatim")
                    if index%10 == 0 or index == length:
                        print('Attribute: ' + str(index) + ' from ' + str(length))
                    index += 1
                except ValueError:
                    print("Error parsing TIE Items")

                #print(item["data_type"])
        else:
            raise ValueError("Given event must be a C2Server event")



