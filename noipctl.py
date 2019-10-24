#!/usr/bin/env python

import json
import argparse
import re
import logging
import time
import traceback

from base64 import encodestring as b64encode

try:
    from urllib.parse import quote as urlquote
    from urllib.request import urlopen
except ImportError:  # python2?
    from urllib import quote as urlquote
    from urllib2 import urlopen

VERSION         = "0.1.0"

# do not use HTTP since credentials will be sent unencrypted!
SCHEME          = "https"
NOIP_HOST       = "dynupdate.no-ip.com"
UPDATE_SCRIPT   = "ducupdate.php"
SETTINGS_SCRIPT = "settings.php"
#GETIP_URL       = "http://ipinfo.io/ip"
GETIP_URL       = "http://ip1.dynupdate.no-ip.com"

DELAY           = 900

RE_IPv4         = re.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})")


parser = argparse.ArgumentParser(description=
    "Updater for dynamic DNS provider <https://www.noip.com>.",
    epilog=
    "Config values take precedence over defaults, while "
    "values provided via command-line take precedence over config values")

parser.add_argument('command', metavar='command', type=str,
                    choices=['get-ip', 'get-hosts', 'update', 'daemon'],
                    help='Action to be done (%(choices)s).')

parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION))

parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                    help='Be verbose (output debug-level messages)')
parser.add_argument('-s', '--silent', dest='silent', action='store_true',
                    help='Be silent (do not output messages)')

parser.add_argument('-c', '--config', type=str, dest='config_path',
                    help='Path to configuration file')

parser.add_argument('-u', '--username', type=str, dest='username',
                    help='Username or email for authentication')
parser.add_argument('-p', '--password', type=str, dest='password',
                    help='Password for authentication')

parser.add_argument('--ip', dest='ip', type=str,
                    help='IP to be set. '
                    'If omitted, IP will be determined using separate http request')
parser.add_argument('--hosts', dest='hosts', type=str, nargs='*',
                    help='Hosts to be updated (FQDN). '
                    'If omitted, all hosts from the account (settings script) will be taken')
parser.add_argument('--groups', dest='groups', type=str, nargs='*',
                    help='Groups of hosts to be updated')

parser.add_argument('--scheme', dest='scheme', type=str, choices=['http', 'https'],
                    help='URL scheme for requests (default {})'.format(SCHEME))
parser.add_argument('--noip-host', dest='noip_host', type=str,
                    help='Hostname for requests (default {})'.format(NOIP_HOST))
parser.add_argument('--update-script', dest='update_script', type=str,
                    help='Remote script for dyndns updating (default {})'.format(UPDATE_SCRIPT))
parser.add_argument('--settings-script', dest='settings_script', type=str,
                    help='Remote script for account settings (default {})'.format(SETTINGS_SCRIPT))
parser.add_argument('--getip-url', dest='getip_url', type=str,
                    help='Page that displays actual external IP (default {})'.format(GETIP_URL))

parser.add_argument('--delay', dest='delay', type=int,
                    help='Delay in seconds between IP change check, '
                    'only matters for command <daemon> (default {})'.format(DELAY))


handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '[%(levelname)s] %(message)s'))
logging.root.addHandler(handler)

args = parser.parse_args()

if args.verbose:
    logging.root.setLevel(logging.DEBUG)
elif args.silent:
    logging.root.setLevel(logging.CRITICAL)
else:
    logging.root.setLevel(logging.INFO)

if args.config_path is not None:
    logging.debug("Reading config from %s", args.config_path)
    with open(args.config_path, "r") as fcfg:
        config = json.loads(fcfg.read().decode())
    logging.debug("Config read with %s field(s)", len(config))
else:
    logging.debug("No config present")
    config = {}


def get_option(name, default=None):
    if hasattr(args, name) and getattr(args, name) is not None:
        return getattr(args, name)
    if name in config:
        return config[name]
    return default


scheme = get_option("scheme", SCHEME)
noip_host = get_option("noip_host", NOIP_HOST)
update_script = get_option("update_script", UPDATE_SCRIPT)
settings_script = get_option("settings_script", SETTINGS_SCRIPT)
getip_url = get_option("getip_url", GETIP_URL)

logging.debug("Using scheme <%s>, noip_host <%s>, update_script <%s>, "
              "settings_script <%s>, getip_url <%s>",
              scheme, noip_host, update_script, settings_script, getip_url)

ip = get_option("ip")
hosts = get_option("hosts")
groups = get_option("groups")

logging.debug("IP: %s, hosts: %s, groups: %s", ip, hosts, groups)

delay = get_option("delay", DELAY)

logging.debug("Delay between IP checks (for daemon mode): %s seconds", delay)

username = get_option("username")
password = get_option("password")

logging.debug("Username: %s, password present: %s", username,
              "yes" if password is not None else "no")


def get_ip():
    logging.debug("Getting IP from URL %s", getip_url)
    request = urlopen(getip_url)
    response = request.read()
    logging.debug("response code: %s, response length: %s", 
                  request.getcode(), len(response))
    match = RE_IPv4.search(response.decode())
    if match is None:
        logging.debug("Can't find match")
    else:
        logging.debug("found match: %s", match.group(0))
    return match.group(0)


def build_query(username, password, hosts=[], ip=None):
    request = "username={}&pass={}".format(
        urlquote(username),
        urlquote(password))
    for host in hosts:
        request += "&h[]={}".format(host)
    if ip is not None:
        request += "&ip={}".format(ip)
    b64 = b64encode(request.encode())
    encoded = b64.replace(b'\n', b'').decode()
    query = "requestL={}".format(encoded)
    return query


def get_hosts(username, password):
    from xml.dom.minidom import parseString
    
    hosts = []
    
    logging.debug("Getting hosts for user %s", username)
    
    query = build_query(username, password)
    url = "{scheme}://{host}/{script}?{query}".format(
        scheme=scheme,
        host=noip_host,
        script=settings_script,
        query=query)
    request = urlopen(url)
    response = request.read()
    logging.debug("response code: %s, response length: %s", 
                  request.getcode(), len(response))
    
    dom = parseString(response.decode())
    for domain in dom.getElementsByTagName("domain"):
        domain_name = domain.getAttribute("name")
        logging.debug("parsing domain '%s'", domain_name)
        for host in domain.getElementsByTagName("host"):
            host_name = host.getAttribute("name")
            group_name = host.getAttribute("group")
            logging.debug("parsing host '%s' with group '%s'", host_name, group_name)
            hosts.append({
                "domain": domain_name,
                "host": host_name,
                "group": group_name,
                "fqdn": "{}.{}".format(host_name, domain_name)
            })
    
    return hosts


def update(username, password, groups=None, fqdns=None, ip=None):
    results = {}
    
    if fqdns is None:
        logging.debug("No hosts given, trying to read account info")
        hosts = get_hosts(username, password)
        fqdns = [host["fqdn"] for host in hosts
                 if groups is None or host["group"] in groups]
        logging.info("Autodetected FQDNs for updating: %s", fqdns)
    
    if ip is None:
        logging.debug("No IP given, trying to autodetect")
        ip = get_ip()
        logging.info("Autodetected IP: %s", ip)
    
    logging.debug("Updatung dyndns for user %s, hosts %s, ip %s", 
                  username, fqdns, ip)
    
    query = build_query(username, password, fqdns, ip)
    url = "{scheme}://{host}/{script}?{query}".format(
        scheme=scheme,
        host=noip_host,
        script=update_script,
        query=query)
    request = urlopen(url)
    response = request.read()
    logging.debug("response code: %s, response length: %s", 
                  request.getcode(), len(response))
    response = response.decode()
    
    for nline, line in enumerate(response.split('\n')):
        if len(line.strip()) == 0:
            continue
        parts = line.split(':')
        if len(parts) != 2:
            logging.error("Unexpected line #%s in response: %s", nline, line)
            continue
        fqdn, result = parts
        logging.debug("Result for host %s: %s", fqdn, result)
        results[fqdn] = bool(int(result))
    
    return results


if args.command == "get-ip":
    logging.info("get-ip: %s", get_ip())
    
elif args.command == "get-hosts":
    logging.info("get-hosts: %s",
        json.dumps(get_hosts(username, password),
            sort_keys=True, indent=2))
    
elif args.command == "update":
    logging.info("update: %s",
        json.dumps(update(username, password, groups, hosts, ip),
            sort_keys=True, indent=2))
    
elif args.command == "daemon":
    logging.info("Starting daemon")
    last_ip = ip
    while True:
        try:
            current_ip = get_ip()
            if current_ip == ip:
                logging.debug("IP is unchanged (%s)", ip)
            else:
                ip = current_ip
                logging.info("New IP detected: %s", ip)
                results = update(username, password, groups, hosts, ip)
                logging.info("Update results: %s", results)
        except Exception as ex:
            logging.error("Exception: %s", ex)
            logging.debug(traceback.print_exc())
        logging.debug("Sleeping for %s sec", delay)
        time.sleep(delay)
