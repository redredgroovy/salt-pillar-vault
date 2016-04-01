# salt-pillar-vault
Saltstack external pillar for Hashicorp Vault with flexible minion targeting

Requirements
------------
* `hvac` python module (>= v0.2.8) 


Example Configuration
---------------------

Your Vault server should be defined in the master config file with the
following options:

```yaml
    ext_pillar:
      - vault:
          url: https://vault:8200
          config: /path/to/secret/definition.yml
          token: (optional) Explicit token for token authentication
          app_id: (optional) Application ID for app-id authentication
          user_id: (optional) Explicit User ID for app-id authentication
          user_file: (optional) File to read for user-id value
          unset_if_missing: (optional) Leave pillar key unset if Vault secret not found
```

The `url` parameter is the full URL to the Vault API endpoint.

The `config` parameter is the path to the secret map YML file on the master.

The `token` parameter is an explicit token to use for authentication, and it
overrides all other authentication methods.

The `app_id` parameter is an Application ID to use for app-id authentication.

The `user_id` parameter is an explicit User ID to pair with ``app_id`` for
app-id authentication.

The `user_file` parameter is the path to a file on the master to read for a
``user-id`` value if `user_id` is not specified.

The `unset_if_missing` parameter determines behavior when the Vault secret is
missing or otherwise inaccessible. If set to ``True``, the pillar key is left
unset. If set to ``False``, the pillar key is set to ``None``. Default is
``False``

Mapping Vault Secrets to Minions
--------------------------------

The `config` parameter, above, is a path to the YML file which will be
used for mapping secrets to minions. The map uses syntax similar to the
top file:

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
      'db_pass': '/secret/passwords/database
```

Authors
-------

- [Derek Moore](http://github.com/redredgroovy) - Author
