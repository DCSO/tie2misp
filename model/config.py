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
        self.__Base_Confidence = 60
        self.__Base_Severity = 3

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

    @property
    def base_confidence(self):
        return self.__Base_Confidence

    @property
    def base_severity(self):
        return self.__Base_Severity

    # --- Setter

    @tie_api_url.setter
    def tie_api_url(self, value):
        self.__TIE_ApiUrl = value

    @tie_api_key.setter
    def tie_api_key(self, value):
        self.__TIE_ApiKey = value

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

    @base_confidence.setter
    def base_confidence(self, value):
        self.__Base_Confidence = value

    @base_severity.setter
    def base_severity(self, value):
        self.__Base_Severity = value

    @staticmethod
    def parse(configfile):
        conf = Config()
        configs = None
        ERROR_BASE_STR = "Error parsing config.yml: "

        try:
            # Load Config
            config_file = open(configfile, "r", encoding="utf-8")
            configs = yaml.load(config_file)
        except:
            Config.raise_error_critical("Config file could not found. Please create a config file!")

        # Config Values
        # Parsing Base Values
        if "base" in configs:
            base_vals = configs["base"]
            # Critical Values
            conf.tie_api_url = Config.get_config_value_critical(base_vals, "tie_apiurl")
            conf.tie_api_key = Config.get_config_value_critical(base_vals, "tie_apikey")

            # Optional Values
            conf.misp_api_url = Config.get_config_value_optional(base_vals, "misp_apiurl", None)
            conf.misp_api_key = Config.get_config_value_optional(base_vals, "misp_apikey", None)
            conf.base_severity = Config.get_config_value_optional(base_vals, "base_severity", 1)
            conf.base_confidence = Config.get_config_value_optional(base_vals, "base_confidence", 60)
            conf.log_lvl = Config.get_config_value_optional(base_vals, "log_lvl", 20)

            # Addtional Checks
            conf.log_lvl = Config.check_integer(conf.log_lvl, 20, 0, 50)
            conf.base_confidence = Config.check_integer(conf.base_confidence, 60, 0, 100)
            conf.base_severity = Config.check_integer(conf.base_severity, 1, 0, 5)
        else:
            Config.raise_error_critical("Could not found base values")

        # Parsing Organisation Values
        if "organisation" in configs:
            organisation_vals = configs["organisation"]
            # Optional Values
            conf.org_name = Config.get_config_value_optional(organisation_vals, "name", None)
            conf.org_uuid = Config.get_config_value_optional(organisation_vals, "uuid", None)
        else:
            Config.raise_error_critical("Could not found organisation values")

        # Parsing Event Values
        if "events" in configs:
            event_vals = configs["events"]
            # Optional Values
            conf.event_base_thread_level = Config.get_config_value_optional(event_vals, "base_threat_level", 3)
            conf.event_published = Config.get_config_value_optional(event_vals, "published", "False")
            conf.event_info_c2server = Config.get_config_value_optional(event_vals, "info_c2server", "TIE Daily C2Server")
            conf.event_info_malware = Config.get_config_value_optional(event_vals, "info_malware", "TIE Daily Malware")
        else:
            Config.raise_error_critical("Could not found event values")

        # Parsing Attribute Values
        if "attributes" in configs:
            attr_vals = configs["attributes"]
            conf.attr_to_ids = Config.get_config_value_optional(attr_vals, "to_ids", "True")
            conf.attr_tagging = Config.get_config_value_optional(attr_vals, "tagging", "True")
        else:
            Config.raise_error_critical("Could not found attributes values ")

        conf.url_categories = "categories"
        conf.url_iocs = "iocs"

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

    @staticmethod
    def raise_error_critical(error_str):
        ERROR_BASE_STR = "Error parsing config.yml: "
        logging.error(ERROR_BASE_STR + error_str)
        raise RuntimeError(ERROR_BASE_STR + error_str)

    @staticmethod
    def raise_error_warning(error_str):
        ERROR_BASE_STR = "Warning parsing config.yml: "
        logging.warning(ERROR_BASE_STR + error_str)

    @staticmethod
    def get_config_value_critical(val_dict, key):
        if key in val_dict:
            val = val_dict[key]
            if val is None or val == "":
                Config.raise_error_critical("Value for Key: " + key + " - could not found or is empty. A proper key and value is mandatory to start tie2misp")
            else:
                return val
        else:
            Config.raise_error_critical("Key: " + key + " - could not found. A proper key and value is mandatory to start tie2misp")

    @staticmethod
    def get_config_value_optional(val_dict, key, default_val=None):
        if key in val_dict:
            val = val_dict[key]
            if val is None or val == "":
                if default_val is None:
                    Config.raise_error_warning("Key: " + key + " - could not been found or value is empty. A proper key and value is strongly recommended")
                    val = None
                else:
                    Config.raise_error_warning("Key: " + key + " - could not been found or value is empty. Using the default value - " + str(default_val))
                    val = default_val



    @staticmethod
    def check_integer(val, default_value, boundary_left=None, boundary_right=None):
        error = False
        if val is None or not isinstance(val, int):
            error = True
        else:
            if boundary_left is not None:
                if val < boundary_left:
                    error = True

            if boundary_right is not None:
                if val > boundary_right:
                    error = True

        if error:
            logging.warning("Value is not correct or not an integer value - using the default value.")
            val = default_value

        return val






