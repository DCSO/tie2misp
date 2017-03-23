"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
from model import MISPAttribute


class SHA256(MISPAttribute):
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
        json_object['type'] = 'sha256'

        return json_object

    @staticmethod
    def parse(item):
        sha256 = SHA256()
        sha256.actors = item["actors"]
        sha256.families = item["families"]
        sha256.value = item["value"]
        sha256.id = item["id"]
        sha256.severity = item["max_severity"]
        sha256.confidence = item["max_confidence"]

        # replace 'mdf:' in front of the hash
        if sha256.value.startswith('sha256:'):
            sha256.value = sha256.value.replace('sha256:', '')

        return sha256

    def upload(self, misp, event):
        misp.add_hashes(event, self.category, None, None, None, self.value, None, self.comment, True, None, False)
