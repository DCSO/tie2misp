"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import requests
from model import Config
from model.events import C2Server, Malware
from datetime import datetime, timedelta


class Loader:

    @staticmethod
    def start(conf, type, startdate, file, noupload):

        # Building Auth Header
        conf_authHeader = {'Authorization': 'Bearer ' + conf.tie_api_key}

        # Building URL
        date_since = startdate.strftime("%Y-%m-%d")
        dt = startdate + timedelta(days=1)
        date_until = dt.strftime("%Y-%m-%d")
        url = conf.tie_api_url + conf.url_iocs + "?category=c2-server&created_since=" + date_since + '&created_until=' + date_until

        finished = True
        event = None

        # Eventtype
        if type == 'c2server':
            event = C2Server(conf.org_name, conf.org_uuid, conf.event_base_thread_level, conf.event_published,
                             conf.event_info_c2server, startdate)
        elif type == 'malware':
            event = Malware(conf.org_name, conf.org_uuid, conf.event_base_thread_level, conf.event_published,
                            conf.event_info_malware, startdate)

        index = 0
        while finished:
            # myResponse = requests.get(url, headers=authHeader, params=query)
            myResponse = requests.get(url, headers=conf_authHeader)
            # print(query)
            # For successful API call, response code will be 200 (OK)
            if myResponse.ok:
                # print(myResponse.status_code)
                # Loading the response data into a dict variable
                # json.loads takes in only binary or string variables so using content to fetch binary content
                # Loads (Load String) takes a Json file and converts into python data structure
                # (dict or list, depending on JSON)

                try:
                    # print(myResponse.json())
                    # jsonResponse = json.loads(myResponse.json())
                    jsonResponse = myResponse.json()

                    # print(jsonResponse)

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
                                C2Server.parse(event, val)

                except ValueError:
                    print("Error:")
                    print("Invalid or empty JSON Response")

            else:
                # If response code is not ok (200), print the resulting http error code with description
                print("Error: \n")
                print(myResponse.content)
                myResponse.raise_for_status()

        if not noupload:
            # Load things up
            event.upload(conf)

        if file:
            # Serialize event as MISP Event
            json_output = event.serialize()
            # print(json_output)
            outfile = "c2server_" + str(event.uuid) + ".json"
            print(outfile)
            with open(outfile, "w") as text_file:
                text_file.write(json_output)

