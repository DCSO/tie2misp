"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import requests
from requests import HTTPError, ConnectionError, ConnectTimeout
from model import Config
from model.events import C2Server, Malware
from datetime import datetime, timedelta


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
        while finished:
            try:
                print("Querry URL: " + url)
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

                        for key in jsonResponse:
                            val = jsonResponse[key]
                            if "has_more" in key:
                                index += 1
                                if val is not True:
                                    # We are done
                                    finished = False
                                    print("#### Finished #####")
                                    break
                                else:
                                    if isinstance(myResponse.links, dict):
                                        res = myResponse.links["next"]
                                        url = res["url"]
                                        print("#### Continue #####")
                            else:
                                if isinstance(val, list) and "params" not in key:
                                    print("Parsing... - Index: " + str(index))
                                    if type == 'c2server':
                                        C2Server.parse(event, val, tags)
                                    elif type == 'malware':
                                        Malware.parse(event, val, tags)

                    except ValueError:
                        print("Error:")
                        print("Invalid or empty JSON Response")

                else:
                    # If response code is not ok (200), print the resulting http error code with description
                    print("Error: \n")
                    print(myResponse.content)
                    myResponse.raise_for_status()
            except (HTTPError, ConnectionError, ConnectTimeout) as e:
                print("Error:")
                print("TIE seems not to be available at the moment or connection is interrupted")
                connection_error = True
                finished = False

        # TIE is available?
        if not connection_error:
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
                print(outfile)
                with open(outfile, "w") as text_file:
                    text_file.write(json_output)

