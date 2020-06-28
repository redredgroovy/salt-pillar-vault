# salt-pillar-vault
Hashicorp Vault pillar module for Saltstack with flexible minion targeting using a familiar top-file syntax. 

Requirements
------------
* `hvac` python module (>= v0.2.17)


Example Configuration
---------------------

Your Vault server should be defined in the master config file with the
following options:

```yaml
    ext_pillar:
      - vault:
          url: https://vault:8200
          config: Path or salt:// URL to vault secret mapping configuration
          unset_if_missing: (optional) Leave pillar key unset if Vault secret not found
          
          memcached_socket: (optional) Path to a unix socket, e.g. /var/run/memcached/memcached.sock
          memcached_expiration: (optional) Number of seconds to cache secrets for e.g. 60
          memcached_timeout: (optional) Number of seconds to wait before timing out e.g. 1
          
          token: (optional) Explicit token for token authentication
          token_file: (optional) File containing a Vault token to use

          app_id: (optional) Application ID for app-id authentication
          user_id: (optional) Explicit User ID for app-id authentication
          user_file: (optional) File to read for user-id value

          role_id: (optional) Role ID for AppRole authentication
          secret_id: (optional) Explicit Secret ID for AppRole authentication
          secret_file: (optional) File to read for secret-id value

            
```

The ``url`` parameter is the full URL to the Vault API endpoint.

The ``config`` parameter is the path or salt:// URL to the secret map YML file to be parsed by the master.

The `unset_if_missing` parameter determines behavior when the Vault secret is
missing or otherwise inaccessible. If set to ``True``, the pillar key is left
unset. If set to ``False``, the pillar key is set to ``None``. Default is
``False``

The ``token`` parameter is an explicit token to use for authentication and it
overrides all other authentication methods.

The ``token_file`` parameter is the path to a file containing a token, such
as output by Vault Agent.

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


Mapping Vault Secrets to Minions
--------------------------------

The `config` parameter, above, is a path to the YML file which will be
used for mapping secrets to minions. The map uses syntax similar to the
top file, and will be processed as a Jinja template:

```yaml
    'filter':
      'variable': 'path'
      'variable': 'path?key'
    'filter':
      'variable': 'path?key'
```

Each `filter` is a compound matcher:
    https://docs.saltstack.com/en/latest/topics/targeting/compound.html

`variable` is the name of the variable which will be injected into the
pillar data.

`path` is the path the desired secret on the Vault server.

`key` is optional. If specified, only this specific key will be returned
for the secret at `path`. If unspecified, the entire secret json structure
will be returned.


```yaml
    'web*':
      'ssl_cert': '/secret/certs/domain?certificate'
      'ssl_key': '/secret/certs/domain?private_key'
    'db* and G@os.Ubuntu':
      'db_pass': '/secret/passwords/database'
    '*':
      'my_key': '/secret/certs/{{ grains.id }}?private_key'
```

Authors
-------

- [Derek Moore](http://github.com/redredgroovy) - Author
