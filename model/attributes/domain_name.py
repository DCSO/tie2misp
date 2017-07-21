"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
from model import MISPAttribute


class DomainName(MISPAttribute):
    def __init__(self):
        MISPAttribute.__init__(self)
        self.data_type = "DomainName"

    def serialize(self):
        dt = datetime.datetime.now()
        json_object = dict()
        json_object['category'] = 'Network activity'
        json_object['comment'] = self.comment
        json_object['uuid'] = self.id
        json_object['timestamp'] = dt.strftime("%s")
        json_object['to_ids'] = True
        json_object['value'] = self.value
        json_object['type'] = 'domain'

        return json_object

    @staticmethod
    def parse(item):
        dn = DomainName()
        dn.actors = item["actors"]
        dn.families = item["families"]
        dn.value = item["value"]
        dn.id = item["id"]
        dn.severity = item["max_severity"]
        dn.confidence = item["max_confidence"]
        return dn

    def upload(self, misp, event, config):
        if self.severity >= config.base_severity and self.confidence >= config.base_confidence:
            attr = misp.add_domain(event, self.value, self.category, True, self.comment, None, False)
            if config.attr_tagging:
                self.upload_tags(misp, attr)
