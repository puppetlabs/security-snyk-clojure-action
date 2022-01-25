#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import logging
import xml.etree.ElementTree as ET
from base64 import b64encode as b64e

TO_REPLACE = {
    "artifactory": "https://artifactory.delivery.puppetlabs.net",
    "builds": "https://builds.delivery.puppetlabs.net",
}
REPLACE_WITH = "https://builds-portal.puppet.net"

class AuthError(Exception):
    def __init__(self, value):
        self.value = value
 
    def __str__(self):
        return(repr(self.value))

class VulnReport():
    def _getVulnID(self, vuln)->str:
        '''returns the CVE ids'''
        id_string = vuln['id']
        try:
            cveid = vuln['identifiers']['CVE']
            cveid = '|'.join(cveid)
            if cveid:
                id_string = f'{id_string}|{cveid}'
        except KeyError:
            pass
        return id_string
        
    def __init__(self, vuln: dict):
        self._vuln = vuln
        # name
        try:
            self.package_name = vuln['packageName']
        except KeyError:
            try:
                self.package_name = vuln['moduleName']
            except KeyError:
                self.package_name = 'UKNOWN'
        # version
        try:
            self.version = vuln['version']
        except KeyError:
            self.version = 'UNKNOWN'
        # vuln id
        self.vuln_string = self._getVulnID(vuln)
    
    def __eq__(self, other):
        if isinstance(other, VulnReport):
            return self.__key() == other.__key()
        return NotImplemented

    def __key(self):
        s_ids = self.vuln_string.split(',')
        s_ids.sort()
        v_sorted = ','.join(s_ids)
        return (self.package_name, self.version, v_sorted)
    
    def __hash__(self) -> int:
        return hash(self.__key())

    def __str__(self):
        return f'{self.package_name}-{self.version}: {self.vuln_string}'
    def __repr__(self) -> str:
        return self.__str__()

def configure_password(key, filepath="./pom.xml"):
    settings_xml = '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">\n'
    settings_xml += "<servers>\n"
    # parse the xml
    logging.notice("starting XML parse")
    tree = ET.parse(filepath)
    root = tree.getroot()
    repos = root.findall('{http://maven.apache.org/POM/4.0.0}repositories')[0]
    for repo in repos:
        url = repo.find('{http://maven.apache.org/POM/4.0.0}url')
        id = repo.find('{http://maven.apache.org/POM/4.0.0}id')
        if url.text.startswith("https://artifactory.delivery.puppetlabs.net/"):
            username = "artifactory"
        elif url.text.startswith("https://builds.delivery.puppetlabs.net"):
            username = "builds"
        else:
            logging.notice(f"skipping: {url.text}")
            continue
        settings_xml += "\t<server>\n"
        settings_xml += f"\t\t<id>{id.text}</id>\n"
        settings_xml += f"\t\t<configuration>\n\t\t<httpHeaders>\n\t\t\t<property>\n"
        settings_xml += f"\t\t\t\t<name>Authorization</name>\n"
        auth_header = "Basic " + b64e(f"{username}:{key}".encode('utf-8')).decode('utf-8')
        settings_xml += f"\t\t\t\t<value>{auth_header}</value>\n"
        settings_xml += f"\t\t\t</property>\n\t\t</httpHeaders>\n\t\t</configuration>\n"
        settings_xml += "\t</server>\n"
            
    # "close" settings
    settings_xml += "</servers>\n"
    settings_xml += "</settings>\n"
    logging.notice("finished XML parse")
    # find and replace the url
    logging.notice("starting url replacement")
    with open(filepath, 'r') as f:
        pomtext = f.read()
    for _, replace in TO_REPLACE.items():
        pomtext = pomtext.replace(replace, REPLACE_WITH)
    with open(filepath, 'w') as f:
        f.write(pomtext)
    logging.notice("finished url replacement")
    with open('./settings.xml', 'w') as f:
        f.write(settings_xml)
    logging.notice("finished writing settings xml")
    
def addLoggingLevel(levelName, levelNum, methodName=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.
    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.
    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present 
    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5
    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
       raise AttributeError('{} already defined in logging module'.format(levelName))
    if hasattr(logging, methodName):
       raise AttributeError('{} already defined in logging module'.format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
       raise AttributeError('{} already defined in logger class'.format(methodName))
    
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)
    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)

def _confLogger(level=logging.INFO-1):
    logger = logging.getLogger()
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    # ::notice file={name},line={line},endLine={endLine},title={title}::{message}
    # NOTE: no {endline} or {title} available by default
    formatter = logging.Formatter('::%(levelname)s file=%(filename)s,line=%(lineno)d::%(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    # add notice handler
    addLoggingLevel('notice', logging.INFO+1)

def auth_snyk(s_token: str):
    # auth snyk
    auth_result = subprocess.call(['/puppet/snyk', 'auth', s_token])
    if auth_result != 0:
        logging.error(f"Error authenticating to snyk. Return code: {auth_result}")
        raise AuthError("error authenticating")

def _setOutput(name:str, value:str):
    #echo "::set-output name=action_fruit::strawberry"
    print(f'::set-output name={name}::{value}')

if __name__ == "__main__":
    _confLogger()
    # get our env vars
    s_token = os.getenv("INPUT_SNYKTOKEN")
    if not s_token:
        raise ValueError("no snyk token")
    no_monitor = os.getenv('INPUT_NOMONITOR')
    if not no_monitor:
        no_monitor=False
    else:
        no_monitor=True
    s_org = os.getenv("INPUT_SNYKORG")
    if not s_org and not no_monitor:
        raise ValueError("no snyk org")
    s_proj = os.getenv("INPUT_SNYKPROJECT")
    if not s_proj and not no_monitor:
        raise ValueError("no snyk org")
    rproxy_key = os.getenv("INPUT_RPROXYKEY")
    if not rproxy_key :
        raise ValueError("no rproxy key")
    workdir = os.getenv("GITHUB_WORKSPACE")
    if not workdir:
        raise ValueError("no github workspace!")
    snyk_policy = os.getenv("INPUT_SNYKPOLICY")
    os.chdir(workdir)
    # auth snyk
    try:
        auth_snyk(s_token)
    except AuthError as e:
        logging.error("Couldn't authenticate snyk")
        raise e
    # generate a pom file
    try:
        subprocess.call(['lein.sh','pom'])
    except Exception as e:
        logging.error(f"Couldn't generate pom file")
        raise e
    # replace the url with the reverse proxy
    configure_password(rproxy_key)
    # scan the file with snyk
    try:
        try:
            logging.notice("Running snyk test")
            args = ['/puppet/snyk', 
                'test', 
                '--severity-threshold=medium', 
                '--json', 
                '--file=pom.xml', 
                '--', 
                '"-s=settings.xml"'
            ]
            if snyk_policy:
                policyarg = f'--policy-path={snyk_policy}'
                args.insert(2, policyarg)
            test_res = subprocess.run(args, stdout=subprocess.PIPE, check=False, timeout=900)
        except subprocess.TimeoutExpired as e:
            logging.error('Timeout expired running snyk test')
            sys.exit(1)
        test_res = test_res.stdout.decode('utf-8')
        test_res = json.loads(test_res)
        if not no_monitor:
            snyk_org = f'--org={s_org}'
            snyk_proj = f'--project-name={s_proj}'
            args = ['/puppet/snyk', 
                'monitor', 
                '--file=pom.xml', 
                snyk_org, 
                snyk_proj, 
                '--', 
                '"-s=settings.xml"'
            ]
            logging.notice("running snyk monitor")
            monitor_res = subprocess.call(args)
            if monitor_res != 0:
                logging.error(f'Error running snyk monitor!')
    except Exception as e:
        logging.error('Error running snyk test or monitor')
        raise e
    # parse the results
    licenses_errors = set()
    vulns = set()
    try:
        for lic, _v in test_res['licensesPolicy']['orgLicenseRules'].items():
            licenses_errors.add(lic)
    except KeyError:
        logging.error(f"Error parsing licenses!")
    try:
        for vuln in test_res['vulnerabilities']:
            if not vuln['id'].startswith('snyk:lic:'):
                vulns.add(VulnReport(vuln))
    except KeyError:
        logging.error(f"Error parsing vulns!")
    logging.notice('finishing run and setting outputs')
    if vulns:
        _setOutput('vulns', vulns)
    else:
        _setOutput('vulns', '')
