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
          config: /path/to/secret/definition.yml
          token: Explicit token for token authentication
          app_id: Application ID for app-id authentication
          user_id: Explicit User ID for app-id authentication
          user_file: File to read for user-id value
          unset_if_missing: Leave pillar key unset if Vault secret not found

The ``url`` parameter is the full URL to the Vault API endpoint.

The ``config`` parameter is the path to the secret map YML file on the master.

The ``token`` parameter is an explicit token to use for authentication, and it
overrides all other authentication methods.

The ``app_id`` parameter is an Application ID to use for app-id authentication.

The ``user_id`` parameter is an explicit User ID to pair with ``app_id`` for
app-id authentication.

The ``user_file`` parameter is the path to a file on the master to read for a
``user-id`` value if ``user_id`` is not specified.

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


def _get_user_id(source="~/.vault-id"):
    """ Reads a UUID from file (default: ~/.vault-id)
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

    # Check for explicit app-id authentication
    elif CONF["app_id"]:
        # Check possible sources for user-id
        if CONF["user_id"]:
            user_id = CONF["user_id"]
        elif CONF["user_file"]:
            user_id = _get_user_id(source=CONF["user_file"])
        else:
            user_id = _get_user_id()

        # Perform app-id authentication
        conn.auth_app_id(CONF["app_id"], user_id)

    # TODO: Add additional auth methods here

    # Check for token in ENV
    elif os.environ.get('VAULT_TOKEN'):
        conn.token = os.environ.get('VAULT_TOKEN')


def ext_pillar(minion_id, pillar, *args, **kwargs):
    """ Main handler. Compile pillar data for the specified minion ID
    """
    vault_pillar = {}

    # Load configuration values
    for key in CONF:
        if kwargs.get(key, None):
            CONF[key] = kwargs.get(key)

    # Read the secret map
    renderers = salt.loader.render(__opts__, __salt__)
    raw_yml = salt.template.compile_template(CONF["config"], renderers, 'jinja')
    if raw_yml:
        secret_map = yaml.safe_load(raw_yml.getvalue()) or {}
    else:
        LOG.error("Unable to read secret mappings file '%s'", CONF["config"])
        return vault_pillar

    if not CONF["url"]:
        LOG.error("'url' must be specified for Vault configuration");
        return vault_pillar

    # Connect and authenticate to Vault
    conn = hvac.Client(url=CONF["url"])
    _authenticate(conn)
    
    # Apply the compound filters to determine which secrets to expose for this minion
    ckminions = salt.utils.minions.CkMinions(__opts__)
    for filter, secrets in secret_map.items():
        if minion_id in ckminions.check_minions(filter, "compound"):
            for variable, location in secrets.items():

                # Determine if a specific key was requested
                try:
                    (path, key) = location.split('?', 1)
                except ValueError:
                    (path, key) = (location, None)

                # Return only the key value, if requested, otherwise return
                # the entire secret json structure
                secret = conn.read(path)
                if key:
                    secret = secret["data"].get(key, None)

                    # Decode base64 data, if detected
                    prefix = "base64:"
                    if secret.startswith(prefix):
                        secret = base64.b64decode(secret[len(prefix):]).rstrip()

                if secret or not CONF["unset_if_missing"]:
                    vault_pillar[variable] = secret

    return vault_pillar
