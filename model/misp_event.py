"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import datetime
import json
import uuid
from abc import ABCMeta, abstractstaticmethod, abstractmethod
from .misp_attribute import MISPAttribute
from pymisp import PyMISP
import logging


class MISPEvent(metaclass=ABCMeta):
    def __init__(self, organisation_name, organisation_uuid, threat_level_id, published, info, date):
        dt = datetime.datetime.now()

        if not organisation_name or not organisation_uuid:
            raise ValueError('Organisation Name and UUID must be set')

        if not threat_level_id:
            raise ValueError('Threat Level must be set')

        if not info:
            raise ValueError('Info must be set')

        self.__Info = date.strftime("%Y%m%d ") + info
        self.__PublishTimestamp = dt.strftime("%s")
        self.__Timestamp = dt.strftime("%s")
        self.__Analysis = 2
        self.__Attribute = list()
        self.__Tags = list()
        self.__Published = published
        self.__Orgc = {'name': organisation_name, 'uuid': organisation_uuid}
        self.__Threat_Level_ID = threat_level_id
        self.__UUID = uuid.uuid1()
        self.__Date = dt.strftime("%Y-%m-%d")

    # Getter
    @property
    def uuid(self):
        return self.__UUID

    @property
    def threat_level_id(self):
        return self.__Threat_Level_ID

    @property
    def published(self):
        return self.__Published

    @property
    def publish_timestamp(self):
        return self.__PublishTimestamp

    @property
    def timestamp(self):
        return self.__Timestamp

    @property
    def attributes(self):
        return self.__Attribute

    @property
    def analysis(self):
        return self.__Analysis

    @property
    def tags(self):
        return self.__Tags

    @property
    def orgc(self):
        return self.__Orgc

    @property
    def date(self):
        return self.__Date

    @property
    def info(self):
        return self.__Info

    # Setter
    @published.setter
    def published(self, value):
        self.__Published = value

    @threat_level_id.setter
    def threat_level_id(self, value):
        self.__Threat_Level_ID = value

    @analysis.setter
    def analysis(self, value):
        self.__Analysis = value

    @staticmethod
    @abstractstaticmethod
    def parse(misp_event, val, tags):
        pass

    def serialize(self):
        json_object = dict()
        json_object['info'] = self.info
        json_object['publish_timestamp'] = self.publish_timestamp
        json_object['timestamp'] = self.timestamp
        json_object['analysis'] = self.analysis

        list_attr = list()
        for item in self.attributes:
            list_attr.append(item.serialize())

        list_tags = list()
        for item in self.tags:
            list_tags.append(item.serialize())

        json_object['Attribute'] = list_attr
        json_object['Tag'] = list_tags
        json_object['published'] = self.published
        json_object['date'] = self.date
        json_object['Orgc'] = self.orgc
        json_object['threat_level_id'] = self.threat_level_id
        json_object['uuid'] = str(self.uuid)

        return json.dumps({"Event": json_object})

    # Attributes handling
    def append_attribute(self, attribute):
        if not isinstance(attribute, MISPAttribute):
            raise ValueError('attribute must be a child of Model.MISPAttribute')

        self.__Attribute.append(attribute)

    # Tag handling
    def append_tags(self, tag):
        self.__Tags.append(tag)

    # PyMISP Functions
    def upload(self, config):
        misp = PyMISP(config.misp_api_url, config.misp_api_key, False, debug=False)
        event = misp.new_event(0, config.event_base_thread_level, 2, self.info)

        # Upload all given event tags
        for tag in self.tags:
            misp.tag(event['Event']['uuid'], tag)

        index = 1
        length = len(self.attributes)
        logging.info("Uploading " + str(length) + " Attributes ")

        for attr in self.attributes:
            if index % 10 == 0 or index == length:
                logging.info('Attribute: ' + str(index) + ' from ' + str(length))
            attr.upload(misp, event, config)
            index += 1






