import logging
import base64
import json
import os, subprocess, sys
import splunk.rest as rest
import splunk.entity as entity
from splunk.util import normalizeBoolean, readSplunkFile
from splunk.persistconn.application import PersistentServerConnectionApplication

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s',
                    filename=os.path.join(os.environ.get('SPLUNK_HOME'), 'var', 'log', 'splunk',
                                          'auth_deployment_server.log'),
                    filemode='a')

logger = logging.getLogger('splunk.rest')
splunk_home     = os.path.normpath(os.environ["SPLUNK_HOME"])
isWindows  = ("win32" == sys.platform)

#Borrowed from splunk.cli.cli_common
def decrypt(value):
    """Decrypts encrypted conf values, e.g. sslPassword.
       Encrypted values start with $1$ (RC4) or $7$ (AES-GCM)"""
    launcher_path = os.path.join(splunk_home, "bin", "splunk")
    if isWindows:
        launcher_path += ".exe"
    # show-decrypted CLI command added in 7.2.x
    cmd = [launcher_path, 'show-decrypted', '--value', value]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if sys.version_info >= (3, 0):
        out = out.decode()
        err = err.decode()
    # p.returncode is always 0 so check stderr
    if err:
        logger.error(
            'Failed to decrypt value: {}, error: {}'.format(value, err))
        return None
    return out.strip()

def flatten_query_params(params):
    flattened = {}
    for i, j in params:
        flattened[i] = flattened.get(i) or j
    return flattened


class handler(PersistentServerConnectionApplication):
    def __init__(self, command_line, command_arg):
        PersistentServerConnectionApplication.__init__(self)

    def _unauthorised(self):
        return {'payload': "Incorrect shared secret", 'status': 401}

    def handle(self, in_string):
        request = json.loads(in_string)

        query_params = flatten_query_params(request['query'])
        sessionKey = request['system_authtoken']
        logger.warning(sessionKey)

        name = query_params['name']
        supplied_pass4SymmKey = query_params['pass4SymmKey']

        settings = entity.getEntity('/configs/conf-server', 'deployment', sessionKey=sessionKey)
        encrypted_pass4SymmKey = settings.get('pass4SymmKey')

        splunk_secret = readSplunkFile('etc/auth/splunk.secret')[0]
        expected_pass4SymmKey = decrypt(encrypted_pass4SymmKey)

        #        expected_pass4SymmKey = expected_pass4SymmKey
        if supplied_pass4SymmKey != expected_pass4SymmKey:
            return self._unauthorised()
        else:
            download_url = "{}services/streams/deployment?name={}".format(rest.makeSplunkdUri(), name)
            app_resp, app_download = rest.simpleRequest(download_url, method='POST')
            #        logger.warning(app_resp)
            payload = base64.b64encode(app_download)
            resp = {
                'payload_base64': payload,
                'headers' : {
                    'status' : app_resp['status'],
                    'File-Name' : app_resp['file-name']
                }
            }
            return resp