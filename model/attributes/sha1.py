"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
from model import MISPAttribute


class SHA1(MISPAttribute):
    def __init__(self):
        MISPAttribute.__init__(self)
        self.data_type = "SHA1"

    def serialize(self):
        dt = datetime.datetime.now()
        json_object = dict()
        json_object['category'] = 'Payload delivery'
        json_object['comment'] = self.comment
        json_object['uuid'] = self.id
        json_object['timestamp'] = dt.strftime("%s")
        json_object['to_ids'] = True
        json_object['value'] = self.value
        json_object['type'] = 'sha1'

        return json_object

    @staticmethod
    def parse(item):
        sha1 = SHA1()
        sha1.actors = item["actors"]
        sha1.families = item["families"]
        sha1.value = item["value"]
        sha1.id = item["id"]
        sha1.severity = item["max_severity"]
        sha1.confidence = item["max_confidence"]

        # replace 'mdf:' in front of the hash
        if sha1.value.startswith('sha1:'):
            sha1.value = sha1.value.replace('sha1:', '')

        return sha1

    def upload(self, misp, event, config):
        if self.severity >= config.base_severity and self.confidence >= config.base_confidence:
            attr = misp.add_hashes(event, self.category, None, None, self.value, None, None, self.comment, True, None, False)
            if config.attr_tagging:
                self.upload_tags(misp, attr)
