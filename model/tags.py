"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import yaml
import warnings


class Tags:
    def __init__(self):
        #self.__base_tags = dict()
        self.__c2tags_base = None
        self.__c2tags_attr = dict()
        self.__malwaretags_base = None
        self.__malwaretags_attr = dict()


    @property
    def c2tags_base(self):
        return self.__c2tags_base

    @property
    def c2tags_attr(self):
        return self.__c2tags_attr

    @property
    def malwaretags_base(self):
        return self.__malwaretags_base

    @property
    def malwaretags_attr(self):
        return self.__malwaretags_attr

    @c2tags_base.setter
    def c2tags_base(self, value):
        self.__c2tags_base = value

    @c2tags_attr.setter
    def c2tags_attr(self, value):
        self.__c2tags_attr = value

    @malwaretags_base.setter
    def malwaretags_base(self, value):
        self.__malwaretags_base = value

    @malwaretags_attr.setter
    def malwaretags_attr(self, value):
        self.__malwaretags_attr = value

    @staticmethod
    def parse(tagfile):

        tags = Tags()

        # Load Config
        tag_file = open(tagfile, "r", encoding="utf-8")
        raw_tags = yaml.load(tag_file)

        if "c2_attribute_tags" in raw_tags:
            c2tags = raw_tags["c2_attribute_tags"]
            for item in c2tags:
                i = c2tags[item]
                if item == 'base_tags' and isinstance(i, dict):
                    tags.c2tags_base = i
                if item == 'attr_domainname' and isinstance(i, dict):
                    tags.c2tags_attr['attr_domainname'] = i
                if item == 'attr_url_verbatim' and isinstance(i, dict):
                    tags.c2tags_attr['attr_url_verbatim'] = i
                if item == 'attr_ipv4' and isinstance(i, dict):
                    tags.c2tags_attr['attr_ipv4'] = i
                if item == 'attr_ipv6' and isinstance(i, dict):
                    tags.c2tags_attr['attr_ipv6'] = i


        if "malware_attribute_tags" in raw_tags:
            malwaretags = raw_tags["malware_attribute_tags"]
            for item in malwaretags:
                i = malwaretags[item]
                if item == 'base_tags' and isinstance(i, dict):
                    tags.malwaretags_base = i
                if item == 'attr_hash' and isinstance(i, dict):
                    tags.malwaretags_attr['attr_hash'] = i
                if item == 'attr_url_verbatim' and isinstance(i, dict):
                    tags.malwaretags_attr['attr_url_verbatim'] = i
                if item == 'attr_domainname' and isinstance(i, dict):
                    tags.malwaretags_attr['attr_domainname'] = i

        return tags


