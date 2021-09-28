#!/usr/bin/env python3
import json
import os
import subprocess
import logging

class AuthError(Exception):
    def __init__(self, value):
        self.value = value
 
    def __str__(self):
        return(repr(self.value))

class VulnReport():
    def _getVulnID(self, vuln)->str:
        '''returns the CVE ids'''
        try:
            cveid = vuln['identifiers']['CVE']
            cveid = ','.join(cveid)
            return cveid
        except KeyError:
            try:
                id = vuln['id']
                return id
            except KeyError:
                return 'UNKNOWN'
        
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
    auth_result = subprocess.call(['/usr/local/bin/snyk', 'auth', s_token])
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
    workdir = os.getenv("GITHUB_WORKSPACE")
    if not workdir:
        raise ValueError("no github workspace!")
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
    # scan the file with snyk
    try:
        test_res = subprocess.run(['/puppet/snyk', 'test', '--severity-threshold=medium', '--json'], stdout=subprocess.PIPE, check=False).stdout
        test_res = test_res.decode('utf-8')
        test_res = json.loads(test_res)
        if not no_monitor:
            snyk_org = f'--org={s_org}'
            snyk_proj = f'--project-name={s_proj}'
            monitor_res = subprocess.call(['/puppet/snyk', 'monitor', snyk_org, snyk_proj])
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
            vulns.add(VulnReport(vuln))
    except KeyError:
        logging.error(f"Error parsing vulns!")
    if vulns:
        _setOutput('vulns', vulns)
    else:
        _setOutput('vulns', '')
    logging.notice('finished run')
