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
        comment = self.data_type + ' - Confidence: ' + str(self.confidence)

        if not self.families:
            comment += ' - Families: '
            i = 0
            for item in self.families:
                comment += item
                i += 1
                # Add comma after each family except the last one
                if len(self.families) < 1:
                    comment += ', '

        json_object['comment'] = comment
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

    def upload(self, misp, event):
        misp.add_hashes(event, self.category, None, None, self.value, None, None, self.comment, True, None, False)
