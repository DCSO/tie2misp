"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
from abc import ABCMeta, abstractmethod, abstractstaticmethod


class MISPAttribute(metaclass=ABCMeta):
    def __init__(self):
        self.__Actors = {}
        self.__Families = {}
        self.__Max_Confidence = 0
        self.__Id = ""
        self.__Severity = 0
        self.__Country = {}
        self.__Category = ""
        self.__Data_Type = ""
        self.__Value = ""
        self.__Tags = list()

    # Getter
    @property
    def actors(self):
        return self.__Actors

    @property
    def families(self):
        return self.__Families

    @property
    def confidence(self):
        return self.__Max_Confidence

    @property
    def id(self):
        return self.__Id

    @property
    def severity(self):
        return self.__Severity

    @property
    def country(self):
        return self.__Country

    @property
    def category(self):
        return self.__Category

    @property
    def data_type(self):
        return self.__Data_Type

    @property
    def value(self):
        return self.__Value

    @property
    def tags(self):
        return self.__Tags

    # Setter
    @actors.setter
    def actors(self, value):
        self.__Actors = value

    @families.setter
    def families(self, value):
        self.__Families = value

    @confidence.setter
    def confidence(self, value):
        self.__Max_Confidence = value

    @id.setter
    def id(self, value):
        self.__Id = value

    @severity.setter
    def severity(self, value):
        self.__Severity = value

    @country.setter
    def country(self, value):
        self.__Country = value

    @category.setter
    def category(self, value):
        self.__Category = value

    @value.setter
    def value(self, value):
        self.__Value = value

    @data_type.setter
    def data_type(self, value):
        self.__Data_Type = value

    # Abstract methods
    @abstractmethod
    def serialize(self):
        pass

    @staticmethod
    @abstractstaticmethod
    def parse(item):
        pass

    @abstractmethod
    def upload(self, misp, event, config):
        pass

    # Tag handling
    def append_tags(self, tag):
        self.__Tags.append(tag)

    @property
    def comment(self):
        val = self.data_type + ' - Confidence: ' + str(self.confidence)

        if len(self.families) > 0:
            val += ' - Families: '
            i = 0
            for item in self.families:
                val += item
                i += 1
                # Add comma after each family except the last one
                if len(self.families) < 1:
                    val += ', '
        return val

    def upload_tags(self, misp, event):

        # Get Attribute UUID
        uuid = None
        attr_list = event['Attribute']
        if len(attr_list) > 0:
            # for attr in attr_list:
                if self.value in attr_list['value']:
                    uuid = attr_list['uuid']

        # Upload all given attribute tags
        if len(self.tags) > 0 and uuid is not None:
            for tag in self.tags:
                misp.tag(uuid, tag)

    @staticmethod
    def add_attribute_tag(attribute, tags, pattern):
        if len(tags) > 0:
            if pattern in tags:
                for val in tags[pattern]:
                    tag = tags[pattern][val]
                    attribute.append_tags(tag)
        return attribute
