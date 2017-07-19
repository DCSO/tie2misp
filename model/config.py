"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import yaml
import logging


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
        self.__Attr_Tagging = False
        self.__URL_Categories = ""
        self.__URL_IOCs = ""
        self.__Log_Lvl = 40

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
    def attr_tagging(self):
        return self.__Attr_Tagging

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

    @property
    def log_lvl(self):
        return self.__Log_Lvl

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

    @attr_tagging.setter
    def attr_tagging(self, value):
        self.__Attr_Tagging = value

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

    @log_lvl.setter
    def log_lvl(self, value):
        self.__Log_Lvl = value

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
        conf.log_lvl = configs["base"]["log_lvl"]
        conf.org_name = configs["organisation"]["name"]
        conf.org_uuid = configs["organisation"]["uuid"]
        conf.event_base_thread_level = configs["events"]["base_threat_level"]
        conf.event_published = configs["events"]["published"]
        conf.event_info_c2server = configs["events"]["info_c2server"]
        conf.event_info_malware = configs["events"]["info_malware"]
        conf.attr_to_ids = configs["attributes"]["to_ids"]
        conf.attr_tagging = configs["attributes"]["tagging"]

        conf.url_categories = "categories"
        conf.url_iocs = "iocs"

        conf.value_check()

        return conf

    def value_check(self):
        # Mandatory fields
        if self.tie_api_key is None or self.tie_api_key == "":
            raise RuntimeError("No TIE API key found. An API Key is mandatory to start tie2misp")
        if self.tie_api_url is None or self.tie_api_url == "":
            raise RuntimeError("No TIE URL found. An URL is mandatory to start tie2misp")

        # Optional fields
        if self.log_lvl is None or not isinstance(self.log_lvl, int):
            if self.log_lvl < 0 or self.log_lvl > 50:
                logging.warning("False log level defined - log level should equal or between 0 and 50 - setting log level to default value")
            else:
                logging.warning("False log level defined - log level should be an integer value equal or between 0 and 50 - setting log level to default value")

            self.log_lvl = 20

        if self.misp_api_key is None or self.misp_api_key == "":
            logging.warning("No MISP API key found. TIE2MISP will only work with --file flag")
        if self.misp_api_url is None or self.misp_api_url == "":
            logging.warning("No MISP URL found. TIE2MISP will only work with --file flag")
        if self.org_name is None or self.org_name == "":
            logging.warning("No organisation name is defined. MISP require a organisation name to work properly")
        if self.org_uuid is None or len(self.org_uuid) <= 10:
            logging.warning("No organisation UUID is set or UUID is to short. MISP require a organisation UUID to work properly")
        if self.event_base_thread_level is None or self.event_base_thread_level == "":
            logging.warning("No base thread level is set. Its recommended to set a proper base threat level. Threat level is set to 3.")
            self.event_base_thread_level = "3"
        if self.event_published is None or self.event_published == "":
            logging.warning("No publishing parameter ist set. Its recommended to set a proper publishing parameter. Publishing is set to False")
            self.event_published = "False"
        if self.event_info_c2server is None or self.event_info_c2server == "":
            logging.warning("No C2 Server info lable is set. Its recommended to set a proper C2 server info. Set default name.")
            self.event_info_c2server = "TIE Daily C2Server"
        if self.event_info_malware is None or self.event_info_malware == "":
            logging.warning("No C2 Server info lable is set. Its recommended to set a proper C2 server info. Set default name.")
            self.__Event_Info_Malware = "TIE Daily Malware"
        if self.attr_tagging is None or self.attr_tagging == "":
            logging.warning("No option to tag attributes found. Its recommended to define it with True or False")
            self.attr_tagging = False


