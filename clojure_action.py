#!/usr/bin/env python3
import logging
import os
import subprocess
import sys
import json

OPT_ARGS = {
    'INPUT_SNYKPOLICY': '--policy-path={evar}',
    'INPUT_SNYKORG': '--org={evar}',
    'INPUT_SNYKPROJECT': '--project={evar}'
}

class AuthError(Exception):
    def __init__(self, value):
        self.value = value
 
    def __str__(self):
        return(repr(self.value))

def _exit_set_error(retcode=1):
    fo = _getOutput('failure', 'true')
    vo = _getOutput('vulns', '')
    sys.exit(retcode)

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

def _getArgs():
    # setup the args for snyk
    snykArgs = ["snyk",
                "test",
                "--file=pom.xml",
                "--json"]
    # setup the optional args
    for e, s in OPT_ARGS.items():
        e_val = os.getenv(e)
        if e_val:
            newarg = s.format(evar=e_val)
            logging.info(f"setting new arg: {newarg}")
            snykArgs.append(newarg)
    # if there are additional args split em up and add em
    additional_args = os.getenv('INPUT_SNYKADDITIONALARGS')
    if additional_args:
        logging.info(f'adding additional snyk args: {additional_args}')
        snykArgs = snykArgs + additional_args.split(' ')
    target_ref = os.getenv("INPUT_SNYKTARGETREF")
    if target_ref:
        snykArgs.append(f'--target-reference="{target_ref}"')
    logging.info(f"snyk args: {','.join(snykArgs)[:]}")
    return snykArgs

def _auth_snyk(s_token: str):
    # auth snyk
    auth_result = subprocess.call(['/puppet/snyk', 'auth', s_token])
    if auth_result != 0:
        logging.error(f"Error authenticating to snyk. Return code: {auth_result}")
        raise AuthError("error authenticating")

def _run_lein():
    '''we should already be in the working directory before calling this'''
    args = ['lein', 'pom']
    try:
        lein_res = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=900)
        if lein_res.returncode != 0:
            logging.error('Error calling lein pom.')
            logging.error(f'lein stderr: {lein_res.stderr.decode("utf-8")}')
            _exit_set_error(1)
    except subprocess.TimeoutExpired:
        logging.error("lein pom timed out")
        _exit_set_error(1)

def _runSnyk(args):
    noMonitor = bool(os.getenv("INPUT_NOMONITOR"))
    logging.info(f'noMonitor is: {noMonitor}')
    # run test
    try:
        test_res = subprocess.run(args, stdout=subprocess.PIPE, check=False, timeout=900)
    except subprocess.TimeoutExpired as e:
        logging.error("snyk command timed out")
        _exit_set_error(1)
    logging.info(f'snyk test finished. Retcode: {test_res.returncode}')
    if test_res.returncode > 1:
        logging.error("snyk returned a failure return code")
        logging.debug(f'\n\n===\n\n{test_res}\n\n===\n\n')
        _exit_set_error(1)
    test_res = test_res.stdout.decode('utf-8')
    logging.debug(f'\n\n===\n\n{test_res}\n\n===\n\n')
    test_res = json.loads(test_res)
    if not noMonitor:
        logging.debug('running snyk monitor')
        try:
            monargs = args
            monargs[1] = 'monitor'
            mon_res = subprocess.run(monargs, stdout=subprocess.PIPE, check=False, timeout=900)
            if mon_res.returncode != 0:
                logging.warning(f"snyk monitor returned return code: {mon_res.returncode}")
        except subprocess.TimeoutExpired as e:
            logging.error("snyk command timed out")
        logging.info(f'snyk monitor finished. Retcode: {mon_res.returncode}')
    return test_res

def _isLicenseIssue(vuln):
    try:
        return vuln.get('id', '').startswith('snyk:lic:')
    except:
        return True

def _parseResults(test_res):
    vulns = test_res.get('vulnerabilities', [])
    if vulns:
        vulns = [v for v in vulns if not _isLicenseIssue(v)]
    ov = []
    for vuln in vulns:
        o = {
            'ID': vuln.get('id', 'UNKNOWN'),
            'Title': vuln.get('title', 'UNKNOWN'),
            'Name': vuln.get('name', 'UNKNOWN'),
            'Severity': vuln.get('severity', 'UNKNOWN'),
        }
        if o['ID'] != 'UNKNOWN':
            o['URL'] = f'https://snyk.io/vuln/{o["ID"]}'
        ov.append(o)
    return ov

def _pprint_results(vulns):
    lines = []
    for vuln in vulns:
        line=''
        for k,v in vuln.items():
            line = line + f"{k}: {v}\n"
        lines.append(line)
    return "=====\n".join(lines)

def _getOutput(name:str, value:str):
    #echo "::set-output name=action_fruit::strawberry"
    value = value.replace('\n','%0A')
    print(f'::set-output name={name}::{value}')

if __name__ == "__main__":
    if os.getenv("INPUT_DEBUG") or os.getenv("DEBUG"):
        _confLogger(logging.DEBUG-1)
    else:
        _confLogger()
    # change into the correct dir
    workdir = os.getenv("GITHUB_WORKSPACE")
    if not workdir:
        logging.error("No github workspace set!")
        raise ValueError("no github workspace!")
    os.chdir(workdir)
    # auth snyk
    _auth_snyk(os.getenv("INPUT_SNYKTOKEN"))
    # run lein
    _run_lein()
    # get the snyk args
    snykArgs = _getArgs()
    # run snyk
    test_res = _runSnyk(snykArgs)
    # parse the results for vulnerabilities
    vulns = _parseResults(test_res)
    output = _pprint_results(vulns)
    output = _getOutput('vulns', output)
    print(output)
    fo = _getOutput('failure', 'false')
    print(fo)
    
    