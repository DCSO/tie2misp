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
        json_object['value'] = self.value.replace('/32', '')
        json_object['type'] = 'ip-dst'

        return json_object
        # return {'category': 'Network activity', 'comment': self.data_type + ' - Confidence: ' +
        #        self.confidence, 'uuid': self.id, 'timestamp': dt.strftime("%s"), 'to_ids': 'true',
        #        'value': self.value, 'type': 'ip-dst'}

    @staticmethod
    def parse(item):
        ipv4 = IPv4()
        ipv4.actors = item["actors"]
        ipv4.families = item["families"]
        ipv4.value = item["value"]
        ipv4.id = item["id"]
        ipv4.severity = item["max_severity"]
        ipv4.confidence = item["max_confidence"]
        return ipv4

    def upload(self, misp, event):
        misp.add_ipdst(event, self.value, self.category, True, self.comment, None, False)
