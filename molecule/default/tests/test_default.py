"""Role testing files using testinfra."""
import json # for getting the token

testinfra_hosts = ["privacyidea"]
import pytest


@pytest.mark.parametrize("path", [
    ("/opt/privacyidea"),
    ("/etc/privacyidea"),
    ("/var/log/privacyidea"),
])

def test_privacyidea_files(host, path):
    """Verify file permissions and owner and group """ 
    f = host.file(path)
    
    assert f.exists
    assert f.is_directory
    assert f.user == "privacyidea"
    assert f.group == "privacyidea"
    assert oct(f.mode) == '0o750' # oct int

def test_privacyidea_user(host):
    """Verify user is setup properly """
    u = host.user("privacyidea")
    assert u.exists
    assert u.home == '/opt/privacyidea'

def test_apache_user(host):
    """Verify apache user has correct group membership """
    u = host.user("apache")
    assert 'privacyidea' in u.groups 

@pytest.mark.parametrize("path,mode", [
    ("/etc/privacyidea/privacyideaapp.wsgi", "0o750"),
    ("/opt/privacyidea/lib64/python3.9/site-packages/private.pem", "0o400"),
    ("/opt/privacyidea/lib64/python3.9/site-packages/public.pem", "0o644"),
    ("/opt/privacyidea/lib64/python3.9/site-packages/enckey", "0o400"),
    ("/etc/privacyidea/pi.cfg", "0o640"),
    ("/opt/privacyidea/requirements.txt", "0o640"),
    ])

def test_privacy_config_files(host, path, mode):
    """Verify config files have right permissions and owner and group"""
    f = host.file(path)
    
    assert f.exists
    assert f.is_file
    assert f.user == "privacyidea"
    assert f.group == "privacyidea"
    assert oct(f.mode) == mode # oct int
  
@pytest.mark.parametrize("package", [
    # ("python39"),
    # ("python39-mod_wsgi"),
    ("python3-pexpect"),
    ])

def test_packages(host, package):
    """Verify packages are installed"""
    p = host.package(package)
    assert p.is_installed

def test_mod_wsgi(host):
    """Use python39-mod_wsgi for RHEL8 and python3-mod_wsgi for RHEL9"""

    result = host.ansible("setup", "filter=ansible_distribution_major_version")
    
    if result['ansible_facts']['ansible_distribution_major_version'] == "8":
        package_name = 'python39-mod_wsgi'
    else:
        package_name = 'python3-mod_wsgi'
    p = host.package(package_name)
    assert p.is_installed
    
def test_python(host):
    """Use python39 for RHEL8 and python3 for RHEL9"""

    result = host.ansible("setup", "filter=ansible_distribution_major_version")
    
    if result['ansible_facts']['ansible_distribution_major_version'] == "8":
        package_name = 'python39'
    else:
        package_name = 'python3'
    p = host.package(package_name)
    assert p.is_installed


@pytest.mark.parametrize("path,pattern" , [
    ("/etc/privacyidea/pi.cfg","^SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://pi:encryptme@192.168.56.3/pi'$"),
    ("/etc/privacyidea/pi.cfg","^PI_ENCFILE = '/opt/privacyidea/lib64/python3.9/site-packages/enckey'$"),
    ("/etc/privacyidea/pi.cfg","^PI_AUDIT_KEY_PRIVATE = '/opt/privacyidea/lib64/python3.9/site-packages/private.pem'$"),
    ("/etc/privacyidea/pi.cfg","^PI_AUDIT_KEY_PUBLIC = '/opt/privacyidea/lib64/python3.9/site-packages/public.pem'$"),
    ("/etc/privacyidea/pi.cfg","^PI_LOGCONFIG = '/etc/privacyidea/logging.yml'$"),
    ("/etc/privacyidea/pi.cfg","^PI_UI_DEACTIVATED = False$"),
    ])                               

def test_templates(host, path, pattern):
    """Verify files have been templated properly"""
    f = host.file(path)
    
    assert f.contains(pattern)


def test_pip_packages(host):
    """Verify correct privacyidea version has been installed"""
    p = host.pip_package("privacyidea", pip_path='/opt/privacyidea/bin/pip3')

    assert p.is_installed
    assert p.version == '3.7.3'

def admin_login(host):
    """Verify admin login works"""
    get_token = host.run(r"""curl -k -X POST https://privacyidea/auth -H "Content-Type: application/json" -d '{"username":"encryptme","password":"encryptme"}'""")
    token = json.loads(get_token.stdout)['result']['value']['token']
    return token

def test_verify_token(host):
    """Verify token works"""
    token = admin_login(host)
    result = host.run(f"""curl -k https://privacyidea/auth/rights -H 'Authorization: {token}'""")
    status_field = json.loads(result.stdout)['result']['status'] 
    assert status_field == True

def test_create_resolver(host):
    """Verify that it is possible to create a resolver"""
    get_uid = host.run("""grep vagrant /etc/passwd|cut -d ':' -f3""")
    make_flatfile = host.run(f"""/opt/privacyidea/bin/privacyidea-create-pwidresolver-user -u vagrant -i {get_uid.stdout.strip()} -p vagrant | sudo tee /etc/privacyidea/passwd""")
    assert make_flatfile.succeeded
    token = admin_login(host)
    create_resolver = host.run(f"""curl -k -X POST https://privacyidea/resolver/passwd -H 'Authorization: {token}' -H 'Content-Type: application/json' -d '{{"resolver":"passwd","type":"passwdresolver","Filename":"/etc/privacyidea/passwd"}}'""")
    status_field = json.loads(create_resolver.stdout)['result']['status'] 
    assert status_field == True

def test_create_realm(host):
    """Verify that it is possible to create a realm"""
    token = admin_login(host)
    post_realm = host.run(f"""curl -k -X POST https://privacyidea/realm/passwd -H 'Authorization: {token}' -H 'Content-Type: application/json' -d '{{"resolvers":"passwd","realm":"passwd"}}'""")
    status_field = json.loads(post_realm.stdout)['result']['status'] 
    assert status_field == True

# def test_vagrant_login(host):
#     """Verify that passwd resolver works"""
#     login = host.run("""curl -kvvv -X POST https://privacyidea/auth -H "Content-Type: application/json" -d '{{"username":"vagrant","password":"vagrant","realm":"passwd"}}'""")
#     print(login.stdout)
#     print(login.stderr)
#     assert login.succeeded
