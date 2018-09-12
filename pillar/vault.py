# -*- coding: utf-8 -*-
"""
Use Vault secrets as a Pillar source

Example Configuration
---------------------

The Vault server should be defined in the master config file with the
following options:

.. code-block:: yaml

    ext_pillar:
      - vault:
          url: https://vault:8200
          config: Local path or salt:// URL to secret configuration file
          token: Explicit token for token authentication
          app_id: Application ID for app-id authentication
          user_id: Explicit User ID for app-id authentication
          user_file: File to read for user-id value
          role_id: Role ID for AppRole authentication
          secret_id: Explicit Secret ID for AppRole authentication
          secret_file: File to read for secret-id value
          unset_if_missing: Leave pillar key unset if Vault secret not found

The ``url`` parameter is the full URL to the Vault API endpoint.

The ``config`` parameter is the path or salt:// URL to the secret map YML file.

The ``token`` parameter is an explicit token to use for authentication, and it
overrides all other authentication methods.

The ``app_id`` parameter is an Application ID to use for app-id authentication.

The ``user_id`` parameter is an explicit User ID to pair with ``app_id`` for
app-id authentication.

The ``user_file`` parameter is the path to a file on the master to read for a
``user-id`` value if ``user_id`` is not specified.

The ``role_id`` parameter is a Role ID to use for AppRole authentication.

The ``secret_id`` parameter is an explicit Role ID to pair with ``role_id`` for
AppRole authentication.

The ``secret_file`` parameter is the path to a file on the master to read for a
``secret-id`` value if ``secret_id`` is not specified.

The ``unset_if_missing`` parameter determins behavior when the Vault secret is
missing or otherwise inaccessible. If set to ``True``, the pillar key is left
unset. If set to ``False``, the pillar key is set to ``None``. Default is
``False``

Mapping Vault Secrets to Minions
--------------------------------

The ``config`` parameter, above, is a path to the YML file which will be
used for mapping secrets to minions. The map uses syntax similar to the
top file:

.. code-block:: yaml

    'filter':
      'variable': 'path'
      'variable': 'path?key'
    'filter':
      'variable': 'path?key'


Each ``filter`` is a compound matcher:
    https://docs.saltstack.com/en/latest/topics/targeting/compound.html

``variable`` is the name of the variable which will be injected into the
pillar data.

``path`` is the path the desired secret on the Vault server.

``key`` is optional. If specified, only this specific key will be returned
for the secret at ``path``. If unspecified, the entire secret json structure
will be returned.


.. code-block:: yaml

    'web*':
      'ssl_cert': '/secret/certs/domain?certificate'
      'ssl_key': '/secret/certs/domain?private_key'
    'db* and G@os.Ubuntu':
      'db_pass': '/secret/passwords/database

"""

# Import stock modules
from __future__ import absolute_import
import base64
import logging
import os
import yaml

# Import salt modules
import salt.loader
import salt.minion
import salt.template
import salt.utils.minions

# Attempt to import the 'hvac' module
try:
    import hvac
    HAS_HVAC = True
except ImportError:
    HAS_HVAC = False

# Set up logging
LOG = logging.getLogger(__name__)

# Default config values
CONF = {
    'url': 'https://vault:8200',
    'config': '/srv/salt/secrets.yml',
    'token': None,
    'app_id': None,
    'user_id': None,
    'user_file': None,
    'role_id': None,
    'secret_id': None,
    'secret_file': None,
    'unset_if_missing': False
}

def __virtual__():
    """ Only return if hvac is installed
    """
    if HAS_HVAC:
        return True
    else:
        LOG.error("Vault pillar requires the 'hvac' python module")
        return False


def _get_id_from_file(source="/.vault-id"):
    """ Reads a UUID from file (default: /.vault-id)
    """
    source = os.path.abspath(os.path.expanduser(source))
    LOG.debug("Reading '%s' for user_id", source)

    user_id = ""

    # pylint: disable=invalid-name
    if os.path.isfile(source):
        fd = open(source, "r")
        user_id = fd.read()
        fd.close()

    return user_id.rstrip()


def _authenticate(conn):
    """ Determine the appropriate authentication method and authenticate
        for a token, if necesssary.
    """

    # Check for explicit token, first
    if CONF["token"]:
        conn.token = CONF["token"]

    # Check for explicit AppRole authentication
    elif CONF["role_id"]:
        if CONF["secret_id"]:
            secret_id = CONF["secret_id"]
        elif CONF["secret_file"]:
            secret_id = _get_id_from_file(source=CONF["secret_file"])
        else:
            secret_id = _get_id_from_file()

        # Perform AppRole authentication
        result = conn.auth_approle(CONF["role_id"], secret_id)
        # Required until https://github.com/ianunruh/hvac/pull/90
        # is merged, due in hvac 0.3.0
        conn.token = result['auth']['client_token']

    # Check for explicit app-id authentication
    elif CONF["app_id"]:
        # Check possible sources for user-id
        if CONF["user_id"]:
            user_id = CONF["user_id"]
        elif CONF["user_file"]:
            user_id = _get_id_from_file(source=CONF["user_file"])
        else:
            user_id = _get_id_from_file()

        # Perform app-id authentication
        conn.auth_app_id(CONF["app_id"], user_id)

    # TODO: Add additional auth methods here

    # Check for token in ENV
    elif os.environ.get('VAULT_TOKEN'):
        conn.token = os.environ.get('VAULT_TOKEN')


def couple(location, conn):
    """
    If location is a dictionary, loop over its keys, and call couple() for each key
    If location is a string, return the value looked up from vault.
    """
    coupled_data = {}
    if isinstance(location, basestring):
        try:
            (path, key) = location.split('?', 1)
        except ValueError:
            (path, key) = (location, None)
        secret = conn.read(path)
        if key:
            secret = secret["data"].get(key, None)
            prefix = "base64:"
            if secret and secret.startswith(prefix):
                secret = base64.b64decode(secret[len(prefix):]).rstrip()
        if secret or not CONF["unset_if_missing"]:
            return secret
    elif isinstance(location, dict):
        for return_key, real_location in location.items():
            coupled_data[return_key] = couple(real_location, conn)
    if coupled_data or not CONF["unset_if_missing"]:
        return coupled_data



def ext_pillar(minion_id, pillar, *args, **kwargs):
    """ Main handler. Compile pillar data for the specified minion ID
    """
    vault_pillar = {}

    # Load configuration values
    for key in CONF:
        if kwargs.get(key, None):
            CONF[key] = kwargs.get(key)

    # Resolve salt:// fileserver path, if necessary
    if CONF["config"].startswith("salt://"):
        local_opts = __opts__.copy()
        local_opts["file_client"] = "local"
        minion = salt.minion.MasterMinion(local_opts)
        CONF["config"] = minion.functions["cp.cache_file"](CONF["config"])

    # Read the secret map
    renderers = salt.loader.render(__opts__, __salt__)
    raw_yml = salt.template.compile_template(CONF["config"], renderers, 'jinja', whitelist=[], blacklist=[])
    if raw_yml:
        secret_map = yaml.safe_load(raw_yml.getvalue()) or {}
    else:
        LOG.error("Unable to read secret mappings file '%s'", CONF["config"])
        return vault_pillar

    if not CONF["url"]:
        LOG.error("'url' must be specified for Vault configuration")
        return vault_pillar

    # Connect and authenticate to Vault
    conn = hvac.Client(url=CONF["url"])
    _authenticate(conn)

    # Apply the compound filters to determine which secrets to expose for this minion
    ckminions = salt.utils.minions.CkMinions(__opts__)
    for filter, secrets in secret_map.items():
        minions =  ckminions.check_minions(filter, "compound")
        if 'minions' in minions:
            # In Salt 2018 this is now in a kwarg
            minions = minions['minions']
        if minion_id in minions:
            for variable, location in secrets.items():
                return_data = couple(location, conn)
                if return_data:
                    vault_pillar[variable] = return_data


    return vault_pillar
