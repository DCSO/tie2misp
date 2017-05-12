"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
from model.attributes import IPv4, DomainName, URLVerbatim, MD5, SHA1, SHA256
from model.misp_event import MISPEvent, MISPAttribute


class C2Server(MISPEvent):

    def __init__(self, organisation_name, organisation_uuid, threat_level_id, published, info, date):
        MISPEvent.__init__(self, organisation_name, organisation_uuid, threat_level_id, published, info, date)
        #self.append_tags(MISPTag("#ffc000", True, "tlp:amber"))


    """
    Parses attributes from the given tie as misp event
    """
    @staticmethod
    def parse(misp_event, val, tags):
        if isinstance(misp_event, C2Server) and isinstance(val, list):
            index = 1
            length = len(val)
            for item in val:
                attr = None
                if item["data_type"] == 'IPv4':
                    try:
                        attr = IPv4.parse(item)
                        MISPAttribute.add_attribute_tag(attr, tags.c2tags_attr, 'attr_ipv4')
                    except ValueError:
                        print("Error parsing TIE IOC(IPv4)")
                elif item["data_type"] == "IPv6":
                    # Not implemented yet
                    pass
                elif item["data_type"] == "DomainName":
                    try:
                        attr = DomainName.parse(item)
                        MISPAttribute.add_attribute_tag(attr, tags.c2tags_attr, 'attr_domainname')
                    except ValueError:
                        print("Error parsing TIE IOC(DomainName)")
                elif item["data_type"] == "URLVerbatim":
                    try:
                        attr = URLVerbatim.parse(item)
                        MISPAttribute.add_attribute_tag(attr, tags.c2tags_attr, 'attr_url_verbatim')
                    except ValueError:
                        print("Error parsing TIE IOC(URLVerbatim)")
                elif item["data_type"] == 'ExactHash':
                    try:
                        value = ""
                        value = item["value"]
                        if value.startswith('md5'):
                            attr = MD5.parse(item)
                            MISPAttribute.add_attribute_tag(attr, tags.c2tags_attr, 'attr_md5')
                        elif value.startswith('sha1'):
                            attr = SHA1.parse(item)
                            MISPAttribute.add_attribute_tag(attr, tags.c2tags_attr, 'attr_sha1')
                        elif value.startswith('sha256'):
                            attr = SHA256.parse(item)
                            MISPAttribute.add_attribute_tag(attr, tags.c2tags_attr, 'attr_sha256')
                        else:
                            raise ValueError('Error parsing ExactHash - Value must be from type md5,sha1 or sha256')

                    except ValueError:
                        print("Error parsing TIE IOC(ExactHash)")

                if attr is not None:
                    # finally append attribute to event

                    misp_event.append_attribute(attr)
                else:
                    raise ValueError("C2Server events only supports attributes with type IPv4, IPv6, DomainName," +
                                     "URLVerbatim")
                # Print Index
                if index % 10 == 0 or index == length:
                    print('Attribute: ' + str(index) + ' from ' + str(length))
                index += 1
        else:
            raise ValueError("Given event must be a C2Server event")


