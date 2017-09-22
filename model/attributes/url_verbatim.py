"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
from model import MISPAttribute


class URLVerbatim(MISPAttribute):
    def __init__(self):
        MISPAttribute.__init__(self)
        self.data_type = "URLVerbatim"

    def serialize(self):
        dt = datetime.datetime.now()
        json_object = dict()
        json_object['category'] = 'Network activity'
        json_object['comment'] = self.comment
        json_object['uuid'] = self.id
        json_object['timestamp'] = dt.strftime("%s")
        json_object['to_ids'] = True
        json_object['value'] = self.value
        json_object['type'] = 'url'

        return json_object

    @staticmethod
    def parse(item):
        url = URLVerbatim()
        url.actors = item["actors"]
        url.families = item["families"]
        url.value = item["value"]
        url.id = item["id"]
        url.severity = item["max_severity"]
        url.confidence = item["max_confidence"]
        url.category = 'Network activity'
        return url

    def upload(self, misp, event, config):
        if self.severity >= config.base_severity and self.confidence >= config.base_confidence:
            attr = misp.add_url(event, self.value, self.category, True, self.comment, None, False)
            if config.attr_tagging:
                self.upload_tags(misp, attr)
