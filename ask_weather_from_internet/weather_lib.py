import datetime
import urllib.request
import codecs
import re

HTML_TAG_CLOCK = 'klokken'
HTML_TAG_TEMP  = 'temperature plus'
REG_LAST_ITEM  = r'.*>(.*)</td>'

def write_to_file(output):
    file = codecs.open("Output.txt", "w", "utf-8")
    file.write(output)
    file.close()

def weather_fetch_from_web():
    full_api_url = 'https://www.yr.no/sted/Sverige/Stockholm/Stockholm/'
    url = urllib.request.urlopen(full_api_url)
    output = url.read().decode('utf-8')
    url.close()
    return output

def get_info_by_tag(line, tag):
    if tag in line:
        matchObj = re.match(REG_LAST_ITEM, line)
        if matchObj: return matchObj.group(1)
    return None
        
def weather_info_analyze():
    output = weather_fetch_from_web()
    weather_info_list = list()
    clock_info = None
    for line in output.split('\n'):
        if clock_info == None:
            clock_info = get_info_by_tag(line, HTML_TAG_CLOCK)
        else:
            info = get_info_by_tag(line, HTML_TAG_TEMP)
            if info != None:
                weather_info_list.append((clock_info.strip(), info))
                clock_info = None
    return weather_info_list


def gen_weather_dict():
    weather_list = weather_info_analyze()
    len_weather_list = len(weather_list)
    
    weather_dict = dict()
    weather_dict[0] = weather_list[: len_weather_list - 8]
    weather_dict[1] = weather_list[len_weather_list - 8 : len_weather_list-4]
    weather_dict[2] = weather_list[len_weather_list - 4 : len_weather_list]
    return weather_dict


def difference_between_two_days(date_string):
    date_seperates = date_string.split('-')
    now = datetime.datetime.now().date()
    day_date = datetime.date(int(date_seperates[0]), int(date_seperates[1]), int(date_seperates[2]))
    delta = day_date - now
    return delta.days


def get_weather(data):
    return gen_weather_dict()[difference_between_two_days(data)]