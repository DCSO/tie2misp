"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import requests
from requests import HTTPError, ConnectionError, ConnectTimeout
from model import Config
from model.events import C2Server, Malware
from datetime import datetime, timedelta
import logging
import sys


class Loader:

    @staticmethod
    def start(conf, tags, type, startdate, file, noupload):

        # Building Auth Header
        conf_authHeader = {'Authorization': 'Bearer ' + conf.tie_api_key}

        # Building URL
        date_since = startdate.strftime("%Y-%m-%d")
        dt = startdate + timedelta(days=1)
        date_until = dt.strftime("%Y-%m-%d")
        category = None
        finished = True
        event = None
        connection_error = False

        # Eventtype
        if type == 'c2server':
            event = C2Server(conf.org_name, conf.org_uuid, conf.event_base_thread_level, conf.event_published,
                             conf.event_info_c2server, startdate)
            category = 'c2-server'
        elif type == 'malware':
            event = Malware(conf.org_name, conf.org_uuid, conf.event_base_thread_level, conf.event_published,
                            conf.event_info_malware, startdate)
            category = 'malware'

        url = conf.tie_api_url + conf.url_iocs + "?category=" + category + "&created_since=" + date_since + '&created_until=' + date_until

        index = 0
        connection_retrys = 1
        while finished:
            try:
                logging.info("Querry URL: " + url)
                myResponse = requests.get(url, headers=conf_authHeader)
                # For successful API call, response code will be 200 (OK)
                if myResponse.ok:
                    # print(myResponse.status_code)
                    # Loading the response data into a dict variable
                    # json.loads takes in only binary or string variables so using content to fetch binary content
                    # Loads (Load String) takes a Json file and converts into python data structure
                    # (dict or list, depending on JSON)

                    try:
                        jsonResponse = myResponse.json()

                        # Check if there are more values
                        if 'has_more' in jsonResponse:
                            val = jsonResponse['has_more']
                            if val is not True:
                                finished = False
                                logging.info("There are no more attributes")
                                logging.info("#### Finished #####")
                                break
                            else:
                                if isinstance(myResponse.links, dict):
                                    res = myResponse.links["next"]
                                    url = res["url"]
                                    logging.info("#### Continue #####")
                        if 'iocs' in jsonResponse:
                            val = jsonResponse['iocs']
                            logging.info("Parsing... - Offset: " + str(index) + " to " + str(index + len(val)))
                            index += len(val)

                            if type == 'c2server':
                                C2Server.parse(event, val, tags)
                            elif type == 'malware':
                                Malware.parse(event, val, tags)
                        else:
                            logging.warning("TIE answered with an empty reply")

                    except ValueError:
                        logging.error("Error:\nInvalid or empty JSON Response")
                elif myResponse.status_code >= 500 and myResponse.status_code <= 550:
                    logging.warning("It seems there are connection issues with TIE at the moment")
                    logging.warning("Status-Code: " + str(myResponse.status_code) + " - Try: " + connection_retrys + " from 5")

                    connection_retrys += 1
                    if connection_retrys < 6:
                        continue
                    else:
                        logging.error("TIE seems not to be available at the moment or connection is interrupted")
                        raise ConnectionError

                else:
                    # If response code is not ok (200), print the resulting http error code with description
                    logging.error("Error:")
                    logging.error(myResponse.content)
                    myResponse.raise_for_status()
            except (HTTPError, ConnectionError, ConnectTimeout) as e:
                logging.error("Error:")
                logging.error("TIE seems not to be available at the moment or connection is interrupted")
                connection_error = True
                finished = False

        # TIE is available?
        if not noupload and not connection_error and conf.misp_api_key is not None and conf.misp_api_url is not None:
            # Add Base Tags
            if isinstance(event, C2Server):
                if tags.c2tags_base is not None:
                    for val in tags.c2tags_base:
                        event.append_tags(tags.c2tags_base[val])
            elif isinstance(event, Malware):
                if tags.malwaretags_base is not None:
                    for val in tags.c2tags_base:
                        event.append_tags(tags.c2tags_base[val])

            if not noupload:
                # Load things up
                event.upload(conf)

            if file:
                # Serialize event as MISP Event
                json_output = event.serialize()
                outfile = type + "_" + str(event.uuid) + ".json"
                logging.info(outfile)
                with open(outfile, "w") as text_file:
                    text_file.write(json_output)
        else:
            if not noupload and not connection_error:
                logging.warning("Can not upload event. MISP API key or MISP API URL is missing")

    @staticmethod
    def init_logger(logPath, fileName, logLvl, consoleLog, fileLog):

        logger = logging.getLogger()
        logger.setLevel(logLvl)
        formatter = logging.Formatter('%(asctime)s [%(levelname)-5.5s]  %(message)s')

        consoleHandler = logging.StreamHandler(sys.stdout)

        consoleHandler.setFormatter(formatter)
        logger.addHandler(consoleHandler)

        if consoleLog is False:
            consoleHandler.setLevel(logLvl)
        else:
            consoleHandler.setLevel(100)

        if fileLog is False:
            fileHandler = logging.FileHandler("{0}/{1}.log".format(logPath, fileName))
            fileHandler.setFormatter(formatter)
            fileHandler.setLevel(logLvl)
            logger.addHandler(fileHandler)

