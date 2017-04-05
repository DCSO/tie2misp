"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import yaml
import warnings


class Tags:
    def __init__(self):
        self.__base_tags = list()
        self.__attr_c2tags = list()
        self.__attr_malwaretags = list()

    @staticmethod
    def parse(tagfile):
        tags = Tags()

        # Load Config
        tag_file = open(tagfile, "r", encoding="utf-8")
        raw_tags = yaml.load(tag_file)

        if "event_base_tags" in raw_tags:
            btags = raw_tags["event_base_tags"]
            for item in btags:
                print(btags[item])

        if "c2_attribute_tags" in raw_tags:
            c2tags = raw_tags["c2_attribute_tags"]
            for item in c2tags:
                for val in c2tags[item]:
                    print(c2tags[item][val])

        if "malware_attribute_tags" in raw_tags:
            malwaretags = raw_tags["malware_attribute_tags"]
            for item in malwaretags:
                for val in malwaretags[item]:
                    print(malwaretags[val][item])

