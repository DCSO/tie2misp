"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import requests
from requests import HTTPError, ConnectionError, ConnectTimeout
from model import Config
from model.events import C2Server, Malware, Actor, Family
from datetime import datetime, timedelta
import logging
import sys


class Loader:

    @staticmethod
    def start(conf, tags, type, startdate, file, noupload, searchfile, proxy_misp_addr, proxy_tie_addr):

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

        elif type == 'actor':
            event = Actor(conf.org_name, conf.org_uuid, conf.event_base_thread_level, conf.event_published,
                             conf.event_info_actor, startdate)
            category = 'actor'

        elif type == 'family':
            event = Family(conf.org_name, conf.org_uuid, conf.event_base_thread_level, conf.event_published,
                          conf.event_info_family, startdate)
            category = 'family'

        # Buildung parameters
        payload = dict()
        if category == 'c2-server' or category == 'malware':
            payload['category'] = category
            payload['created_since'] = date_since
            payload['created_until'] = date_until

        else:
            attr_list = ''
            count = 0
            for l in searchfile:
                if count is 0:
                    attr_list += l
                else:
                    attr_list += ',' + l
                count += 1
            attr_list = attr_list.replace('\n', '')
            if category is 'actor':
                payload['actor'] = attr_list
            else:
                payload['family'] = attr_list

        url = conf.tie_api_url + conf.url_iocs
        index = 0
        connection_retrys = 1
        while finished:
            try:
                myResponse = requests.get(url, params=payload, headers=conf_authHeader, proxies=proxy_tie_addr)
                # For successful API call, response code will be 200 (OK)
                if myResponse.ok:
                    # print(myResponse.status_code)
                    # Loading the response data into a dict variable
                    # json.loads takes in only binary or string variables so using content to fetch binary content
                    # Loads (Load String) takes a Json file and converts into python data structure
                    # (dict or list, depending on JSON)

                    try:
                        jsonResponse = myResponse.json()

                        # check is TIE Response is complete
                        response_has_more = None
                        response_iocs = None
                        response_params = None
                        if 'has_more' in jsonResponse and 'iocs' in jsonResponse and 'params' in jsonResponse:
                            response_has_more = jsonResponse['has_more']
                            response_iocs = jsonResponse['iocs']
                            response_params = jsonResponse['params']
                        else:
                            raise ValueError("Error: TIE answered with an invalid or empty JSON Response")

                        # parsing received IOC's
                        logging.info("Parsing... - Offset: " + str(index) + " to " + str(index + len(response_iocs)))
                        index += len(response_iocs)

                        if type == 'c2server':
                            C2Server.parse(event, response_iocs, tags)
                        elif type == 'malware':
                            Malware.parse(event, response_iocs, tags)
                        elif type == 'actor':
                            Actor.parse(event, response_iocs, tags)
                        elif type == 'family':
                            Family.parse(event, response_iocs, tags)

                        if response_has_more is not True:
                            finished = False
                            logging.info("There are no more attributes")
                            logging.info("#### Finished #####")
                            break
                        else:
                            if isinstance(myResponse.links, dict):
                                res = myResponse.links["next"]
                                url = res["url"]
                                logging.info("#### Continue #####")

                    except ValueError:
                        logging.error("Error: Invalid or empty JSON Response")
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

            # Load things up
            try:
                event.upload(conf, proxy_misp_addr)
            except Exception as e:
                logging.error("Error uploading event to MISP. Something went wrong...\n")

        else:
            if not noupload and not connection_error:
                logging.warning("Can not upload event. MISP API key or MISP API URL is missing")

        if file:
            # Serialize event as MISP Event
            json_output = event.serialize()
            outfile = type + "_" + str(event.uuid) + ".json"
            logging.info("Saved attributes as JSON-File: " + outfile)
            with open(outfile, "w") as text_file:
                text_file.write(json_output)

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

