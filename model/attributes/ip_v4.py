"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
from model import MISPAttribute


class IPv4(MISPAttribute):
    def __init__(self):
        MISPAttribute.__init__(self)
        self.data_type = "IPv4"

    def serialize(self):
        dt = datetime.datetime.now()
        json_object = dict()
        json_object['category'] = 'Network activity'
        json_object['comment'] = self.comment
        json_object['uuid'] = self.id
        json_object['timestamp'] = dt.strftime("%s")
        json_object['to_ids'] = True
        json_object['value'] = self.value.replace('/32', '')
        json_object['type'] = 'ip-dst'

        return json_object

    @staticmethod
    def parse(item):
        ipv4 = IPv4()
        ipv4.actors = item["actors"]
        ipv4.families = item["families"]
        ipv4.value = item["value"]
        ipv4.id = item["id"]
        ipv4.severity = item["max_severity"]
        ipv4.confidence = item["max_confidence"]

        # replace 'mdf:' in front of the hash
        if ipv4.value.find('/32', 0, len(ipv4.value)) :
            ipv4.value = ipv4.value.replace('/32', '')

        return ipv4

    def upload(self, misp, event, config):
        attr = misp.add_ipdst(event, self.value, self.category, True, self.comment, None, False)
        if config.attr_tagging:
            self.upload_tags(misp, attr)
