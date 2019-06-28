from datetime import *
import time
import argparse
import sys
from termcolor import colored
import textwrap

######################################
# CTF Time Banner
######################################
def banner():
    print colored("""\

    _____  _______  ______  _    _
   / ____||__   __||  ____|| |  (_)
  | |        | |   | |__   | |_  _  _ __ ___    ___
  | |        | |   |  __|  | __|| || '_ ` _ \  / _ \ .
  | |____    | |   | |     | |_ | || | | | | ||  __/
   \_____|   |_|   |_|      \__||_||_| |_| |_| \___|

    """,'green').encode('utf-8')

######################################
# Print Upcomming CTFs
######################################
def upcomming_ctf(len):

    #### Get current date
    today = date.today()

    #### Get timestamp
    date_info = str(today).split('-')
    current_time = datetime(int(date_info[0]), int(date_info[1]), int(date_info[2]), 0, 0)
    one_year = datetime(int(date_info[0])+1, int(date_info[1]), int(date_info[2]), 0, 0)
    ts = (time.mktime(current_time.timetuple()))
    fs = (time.mktime(one_year.timetuple()))
    print '[*] Today:',current_time
    print "[*] Unix Timestamp: ",int(ts)

    #### Get upcomming CTFs
    import requests
    base_addr = 'https://ctftime.org/api/v1/events/'
    payload = {'limit':str(len), 'start':str(int(ts)), 'finish':str(int(fs))}
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    r = requests.get(base_addr, params=payload, headers=headers)
    r_data = r.json()

    #### Parse response data
    #import json
    for i in r_data:
        print '='*40
        print '[>] ',colored(i['title'], 'green')
        print '[>] ',colored(i['url'],'white')
        print '[>] ',i['start']
        print '[>] ',i['finish']
        print '[>] ','ID=',i['id']

######################################
# Print Top Teams
######################################
def top_teams():
    import requests
    base_addr = 'https://ctftime.org/api/v1/top/'
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    r = requests.get(base_addr, headers=headers)
    r_data = r.json()

    # Print Top 10 teams
    print '='*40
    for i in range(1,11):
        print ('[{}] ' + r_data['2019'][i-1]['team_name']).format(i)


######################################
# Print Event Details
######################################
def ctf_info(id):
    import requests
    base_addr = 'https://ctftime.org/api/v1/events/' + str(id) + '/'
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    r = requests.get(base_addr, headers=headers)
    r_data = r.json()

    print '='*40
    print '[#] ',colored('Title:','green'),r_data['title']
    print '[>] ','Link:',colored(r_data['url'],'white')
    print '[>] ','Organizers:',r_data['organizers'][0]['name']
    print ''
    prefix = "[>]  Description: "
    preferredWidth = 100
    wrapper = textwrap.TextWrapper(initial_indent=prefix, width=preferredWidth,
                                   subsequent_indent=' '*len(prefix))
    message = r_data['description'].replace('<br>','').split('\n')[0]
    print wrapper.fill(message)
    for i in r_data['description'].replace('<br>','').split('\n')[1:]:
        message = i
        wrapper = textwrap.TextWrapper(initial_indent=' '*18, width=preferredWidth,
                                       subsequent_indent=' '*len(prefix))
        print wrapper.fill(message)
    print ''
    print '[>] ','Start:',r_data['start']
    print '[>] ','Finish:',r_data['finish']
    print '[>] ',colored('COUNTDOWN:','green'),'WIP'
    print '[>] ','Participants:',r_data['participants']
    print '[>] ','Weight:',r_data['weight']
    print '[>] ','ID:',r_data['id']
    print '[>] ','Format:',r_data['format']
    print '[>] ','CTFtime url:',r_data['live_feed']

if __name__ == "__main__":

    # Dispay the ascii art
    banner()

    # parse params
    if '-upcomming' in sys.argv or '-u' in sys.argv:
        if len(sys.argv) == 3:
            upcomming_ctf(sys.argv[2])
        else:
            print colored('Ussage:','red') + '  ctf-time -upcomming (or -u) <number_of_events>'

    elif '-teams' in sys.argv or '-t' in sys.argv:
        top_teams()

    elif '-info' in sys.argv or '-i' in sys.argv:
        if len(sys.argv) == 3:
            ctf_info(sys.argv[2])
        else:
            print colored('Ussage:','red') + '  ctf-time -info (or -i) <event_id>'

    else:
        print colored('Ussage:','red')
        print '    > ctf-time -upcomming (or -u) <number_of_events>'
        print '    > ctf-time -teams (or -t)'
        print '    > ctf-time -info (or -i) <event_id>'
        exit(0)
