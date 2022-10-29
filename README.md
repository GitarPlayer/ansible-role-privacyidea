# ansible-role-privacyidea

[![CI](https://github.com/GitarPlayer/ansible-role-privacyidea/actions/workflows/ci.yml/badge.svg)](https://github.com/GitarPlayer/ansible-role-privacyidea/actions/workflows/ci.yml)

An Ansible Role that installs Privacyidea RHEL/AlmaLinux 8

## Requirements

This role only configures privacyIDEA and neither the database (mysql,postgres) nor the webserver (apache,nginx). This is done for maximum flexibility of the role. You can use any supported webserver or database (clustered or not) and any ansible role you deem suitable. But this means the role requires at minimum a webserver linux (`websrv_user`)user and a SQLAlchemy compatible database with the right database (`pi_db_hostname`), user (`pi_db_user`)and password (`pi_db_secret`) configured.

If you are using Apache and MySQL, I recommend using the `geerlingguy.apache` role to install apache, and the `geerlingguy.mysql` role. In my end-to-end testing I use both roles so you can always look there for guidance or in the example playbook below. This basic setup is guaranteed to work and hardened (SELinux is setup properly and firewalling as well). On every commit to the main branch end-to-end testing is done to be sure the setup still works. See the geerlingguys roles README for more info.

## Python min version and Ansible min version
This role is tested against python versions: 3.8,3.9,3.10 and ansible versions: 6.0,6.1,6.2,6.3,6.4,6.5 with every commit to main or PR using tox-ansible.

## Role Variables

Available variables are listed below, along with default values (see `defaults/main.yml`):

    pi_venv_path: "/opt/privacyidea"

The path where the privacyIDEA virtualenv will be installed.

    pi_conf_path: "/etc/privacyidea"

The path where the privacyIDEA config files shall be stored.

    pi_log_path: "/var/log/privacyidea"

The path where the privacyIDEA log will be stored. This is not the same as the nginx/apache access and error logs. 

    pi_version: '3.7.4'

The privacyIDEA version that should be installed. 

    python_version: 3.9

The python version that should be used to install privacyIDEA. Defaults to 3.9. Supported are [3.9]

    pi_linux_user: "privacyidea"

The linux system account name that should be created for privacyIDEA.

    separate_db: true

Boolean which determines if the database should be hosted on the privacyIDEA node or if the database is hosted on a different node (the database connection string changes depending on the logic).

    pi_db_user: "pi"

The name of the database user for privacyIDEA. The role expects to be able to login with that user on the database (be it remotely or locally).

    pi_db_secret: "encryptme"

The password of the aforementioned privacyIDEA database user. Please consider using ansible-vault to not store any unencrypted secrets in your inventory or using HashiCorp Vault.

    pi_db_hostname: ""

The node that hosts the privacyIDEA database. Could be localhost, the FQDN to the database or an IP.

    pi_logfile: 'privacyidea.log'
    pi_auditfile: 'audit.log'

The name of the privacyIDEA log/audit file.

    pi_logconfig: 'logging.yml'

The name of the log configuration file.

    use_mail_logging: false

Whether to send certain events via mail.

    mail_host

The mail host.

    from_addr

The host that the mails should be sent from.

    to_addresses

A yaml array of mail addressed to send emails to. For example:
```yaml
to_addresses:
  - fake1@fake.com
  - fake2@fake.com
```

    mail_subject

The subject of the mail.

    mail_level

Which priority and above should be sent via mail.

    log_backup_count: 5
    audit_log_backup_count: 14
    
How many log/audit log rotations to keep.
    
    log_max_bytes: 1000000
    audit_log_max_bytes: 10000000

How big a log/audit log should be to trigger log rotation

    log_level: 'INFO'
    loggers_handlers_level: 'INFO'
    root_level: 'WARNING'

I have to confirm with PrivacyIDEA what these do exactly.

    websrv_user: 'apache'

The username of the webserver user. This user will be added to the pi_linux_user group so the websever process is allowed to read the privacyIDEA files.

    superuser_realm: '["super", "administrators"]'
    sqlalchemy_engine_options:  '{"max_identifier_length": 128}'
    pi_audit_sql_uri:  ''
    pi_audit_sql_truncate: 'True'
    

Sensible defaults from the privacyIDEA config file. Please consult the privacyIDEA documentation for further information [privacyIDEA DOC](https://privacyidea.readthedocs.io/en/latest/installation/system/inifile.html).

    secret_key:  "encryptme"

This is used to encrypt the auth_token. Please consider using ansible-vault to not store any unencrypted secrets in your inventory or using HashiCorp Vault.

    pi_pepper: "encrpyme" 

This is used to encrypt the admin passwords. Please consider using ansible-vault to not store any unencrypted secrets in your inventory or using HashiCorp Vault.

    extra_parameters: |
      PI_UI_DEACTIVATED = False
      PI_CSS = '/location/of/theme.css'

 (optional: you can add whatever additional configuration lines you'd like in here). This is so there is no need to template every possible privacyIDEA config key possible. 
 
 The | denotes a multiline scalar block in YAML, so newlines are preserved in the resulting configuration file output.

    pi_admin: 'encryptme'
    pi_admin_pass: 'encryptme'

The username and password of the local privacyIDEA admin. You can use this credentials to login. Please consider using ansible-vault to not store any unencrypted secrets in your inventory or using HashiCorp Vault.

## Dependencies

None.

## Example Playbook  
```yaml
---
- name: Install privacyIDEA
hosts: privacyidea
become: yes
vars_files:
    - vars/selinux.yml
    - vars/firewall.yml
roles: 
    - geerlingguy.apache 
    - role: gitarplayer.privacyidea
    vars:
        pi_db_hostname: 192.168.56.3
    - linux-system-roles.selinux
    - linux-system-roles.firewall
tasks:
    - name: include apache.yml
    include_vars: vars/apache.yml
    - name: apply geerlingguy.apache again with vars because of chicken egg problem
    include_role:
        name: geerlingguy.apache
```

*Inside `vars/selinux.yml`*:  
```yaml
---
# Use "targeted" SELinux policy type
selinux_policy: targeted
# Set "enforcing" mode
selinux_state: enforcing
# Switch some SELinux booleans
selinux_booleans:
- { name: 'httpd_can_network_connect_db', state: 'on', persistent: 'yes' }
- { name: 'httpd_can_connect_ldap', state: 'on', persistent: 'yes' }
selinux_fcontexts:
- { target: '{{ pi_log_path }}(/.*)?', setype: 'httpd_log_t', ftype: 'a' }
- { target: '{{ pi_conf_path }}(/.*)?', setype: 'httpd_config_t', ftype: 'a' }
selinux_restore_dirs:
- "{{ pi_log_path }}"
- "{{ pi_conf_path }}"
```

*Inside `vars/firewall.yml`*:  
```yaml
---
firewall:
- service: https
    state: enabled
```

*Inside `vars/apache.yml`*:  
```yaml
---
apache_vhosts_filename: "privacyidea.conf"
apache_global_vhost_settings: |
  TraceEnable off
  ServerSignature Off
  ServerTokens Prod
  WSGIPythonHome /opt/privacyidea
  WSGISocketPrefix /var/run/wsgi
apache_ssl_cipher_suite: "EECDH+AES256:DHE+AES256:EECDH+AES:EDH+AES:-SHA1:EECDH+RC4:EDH+RC4:RC4-SHA:AES256-SHA:!aNULL:!eNULL:!EXP:!LOW:!MD5"
apache_vhosts_ssl:
- servername: "privacyidea"
    documentroot: "/etc/privacyidea"
    certificate_file: "/etc/pki/tls/certs/localhost.crt"
    certificate_key_file: "/etc/pki/tls/private/localhost.key"
    apache_ssl_protocol: "All -SSLv2 -SSLv3"
    apache_options: "FollowSymLinks"
    apache_allow_override: "None"
    extra_parameters: |
      SSLEngine On
      SSLHonorCipherOrder On
      ErrorLog logs/ssl_error_log
      TransferLog logs/ssl_access_log
      LogLevel warn
      WSGIDaemonProcess privacyidea processes=1 threads=15 display-name=%{GROUP} user=privacyidea
      WSGIProcessGroup privacyidea
      WSGIPassAuthorization On
      WSGIScriptAlias / /etc/privacyidea/privacyideaapp.wsgi
      BrowserMatch "MSIE [2-5]" \
          nokeepalive ssl-unclean-shutdown \
          downgrade-1.0 force-response-1.0
      CustomLog logs/ssl_request_log \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"
```

*Inside `vars/mysql.yml`*:  
```yaml
---
mysql_databases:
- name: 'pi'
mysql_users: 
- name: 'pi'
    host: '192.168.56.2'
    password: 'password'
    priv: 'pi.*:ALL'
```
You can find all those vars in the default test scenario under molecule/default.



## License

MIT / BSD

## Author Information
This role was created in 2022 by [Christian Moore)