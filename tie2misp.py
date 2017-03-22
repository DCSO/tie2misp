"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
import click
from datetime import datetime, timedelta
from model import Config
from loader import Loader


@click.command()
@click.argument('type')
@click.option('--delay', default=0, help='Specify a delay from which data should be analyzed starting at the current '
                                         'date.\n\n As example:\n The current date is 2017-03-16 (YYYY-MM-DD). With '
                                         '--delay 1 the parser would start at 2017-03-15')
@click.option('--file', is_flag=True, help='If used, the parser will create an JSON event file with all processed '
                                           'attributes.')
@click.option('--noupload', is_flag=True, help='If used, the parser will not upload the processed attributes to the '
                                               'MISP. Usefull in combination with --file to create only a local output '
                                               'file.')
@click.option('--date', help='If a date is set, instead of using the actual date the parser will use the '
                             'given date. The date must be given in the following format YYYY-MM-DD.')
def startup(type, delay, file, noupload, date):
    error = False
    given_date = ''
    """
    Starting the Parser with a given type of events that should be created.

    Choseable types:
    c2server, malware, actors
    """
    if type == 'c2server':
        pass
    elif type == 'malware':
        pass
    else:
        error = True
        click.echo('Wrong Argument! Type \'python tie2misp.py --help\' for more information\'s')

    # Parsing date
    if date is not None:
        try:
            given_date = datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            click.echo('Date could not be parsed. Please use the following format YYYY-MM-DD')
            error = True

    if isinstance(delay, int):
        if delay >= 0:
            pass
        else:
            click.echo('Delay must be an unsigned integer value')
            error = True
    else:
        click.echo('Delay must be an unsigned integer value')
        error = True

    if not error:
        # Loading config file
        conf = Config.parse("settings/config.yml")
        # calculate start date
        if given_date != '':
            Loader.start(conf, type, given_date, file, noupload)
        else:
            dt = datetime.now() - timedelta(days=delay)
            Loader.start(conf, type, dt, file, noupload)


if __name__ == '__main__':
    startup()
