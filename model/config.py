"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import yaml


class Config:
    def __init__(self):
        self.__TIE_ApiUrl = ""
        self.__TIE_ApiKey = ""
        self.__MISP_ApiUrl = ""
        self.__MISP_ApiKey = ""
        self.__MISP_VerifyCert = ""
        self.__Org_Name = ""
        self.__Org_UUID = ""
        self.__Event_Base_Threat_Level = ""
        self.__Event_Published = ""
        self.__Event_Info_C2Server = ""
        self.__Event_Info_Malware = ""
        self.__Attr_ToIDS = ""
        self.__URL_Categories = ""
        self.__URL_IOCs = ""

    # --- Getter
    @property
    def tie_api_url(self):
        return self.__TIE_ApiUrl

    @property
    def tie_api_key(self):
        return self.__TIE_ApiKey

    @property
    def org_name(self):
        return self.__Org_Name

    @property
    def org_uuid(self):
        return self.__Org_UUID

    @property
    def event_base_thread_level(self):
        return self.__Event_Base_Threat_Level

    @property
    def event_published(self):
        return self.__Event_Published

    @property
    def event_info_c2server(self):
        return self.__Event_Info_C2Server

    @property
    def event_info_malware(self):
        return self.__Event_Info_Malware

    @property
    def attr_to_ids(self):
        return self.__Attr_ToIDS

    @property
    def url_categories(self):
        return self.__URL_Categories

    @property
    def url_iocs(self):
        return self.__URL_IOCs

    @property
    def misp_api_url(self):
        return self.__MISP_ApiUrl

    @property
    def misp_api_key(self):
        return self.__MISP_ApiKey

    @property
    def misp_verify_cert(self):
        return self.__MISP_VerifyCert

    # --- Setter

    @tie_api_url.setter
    def tie_api_url(self, value):
        self.__TIE_ApiKey = value

    @tie_api_key.setter
    def tie_api_key(self, value):
        self.__TIE_ApiUrl = value

    @org_name.setter
    def org_name(self, value):
        self.__Org_Name = value

    @org_uuid.setter
    def org_uuid(self, value):
        self.__Org_UUID = value

    @event_base_thread_level.setter
    def event_base_thread_level(self, value):
        self.__Event_Base_Threat_Level = value

    @event_published.setter
    def event_published(self, value):
        self.__Event_Published = value

    @event_info_c2server.setter
    def event_info_c2server(self, value):
        self.__Event_Info_C2Server = value

    @event_info_malware.setter
    def event_info_malware(self, value):
        self.__Event_Info_Malware = value

    @attr_to_ids.setter
    def attr_to_ids(self, value):
        self.__Attr_ToIDS = value

    @url_categories.setter
    def url_categories(self, value):
        self.__URL_Categories = value

    @url_iocs.setter
    def url_iocs(self, value):
        self.__URL_IOCs = value

    @misp_api_url.setter
    def misp_api_url(self, value):
        self.__MISP_ApiUrl = value

    @misp_api_key.setter
    def misp_api_key(self, value):
        self.__MISP_ApiKey = value

    @misp_verify_cert.setter
    def misp_verify_cert(self, value):
        self.__MISP_VerifyCert = value

    @staticmethod
    def parse(configfile):
        conf = Config()

        # Load Config
        config_file = open(configfile, "r", encoding="utf-8")
        configs = yaml.load(config_file)

        # Config Values
        conf.tie_api_key = configs["base"]["tie_apiurl"]
        conf.tie_api_url = configs["base"]["tie_apikey"]
        conf.misp_api_url = configs["base"]["misp_apiurl"]
        conf.misp_api_key = configs["base"]["misp_apikey"]
        conf.org_name = configs["organisation"]["name"]
        conf.org_uuid = configs["organisation"]["uuid"]
        conf.event_base_thread_level = configs["events"]["base_threat_level"]
        conf.event_published = configs["events"]["published"]
        conf.event_info_c2server = configs["events"]["info_c2server"]
        conf.event_info_malware = configs["events"]["info_malware"]
        conf.attr_to_ids = configs["attributes"]["to_ids"]

        conf.url_categories = "categories"
        conf.url_iocs = "iocs"
        return conf