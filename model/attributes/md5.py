"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
from model import MISPAttribute


class MD5(MISPAttribute):
    def __init__(self):
        MISPAttribute.__init__(self)
        self.data_type = "MD5"

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
        json_object['type'] = 'md5'

        return json_object

    @staticmethod
    def parse(item):
        md5 = MD5()
        md5.actors = item["actors"]
        md5.families = item["families"]
        md5.value = item["value"]
        md5.id = item["id"]
        md5.severity = item["max_severity"]
        md5.confidence = item["max_confidence"]

        # replace 'mdf:' in front of the hash
        if md5.value.startswith('md5:'):
            md5.value = md5.value.replace('md5:', '')

        return md5

    def upload(self, misp, event):
        misp.add_hashes(event, self.category, None, self.value, None, None, None, self.comment, True, None, False)
