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
    
    f = host.file(path)
    
    assert f.exists
    assert f.is_directory
    assert f.user == "privacyidea"
    assert f.group == "privacyidea"
    assert oct(f.mode) == '0o750' # oct int

def test_privacyidea_user(host):
    u = host.user("privacyidea")
    assert u.exists
    assert u.home == '/opt/privacyidea'

def test_apache_user(host):
    u = host.user("apache")
    assert 'privacyidea' in u.groups 

@pytest.mark.parametrize("path,mode", [
    ("/etc/privacyidea/privacyideaapp.wsgi", "0o750"),
    ("/opt/privacyidea/lib64/python3.8/site-packages/private.pem", "0o400"),
    ("/opt/privacyidea/lib64/python3.8/site-packages/public.pem", "0o644"),
    ("/opt/privacyidea/lib64/python3.8/site-packages/enckey", "0o400"),
    ("/etc/privacyidea/pi.cfg", "0o640"),
    ("/opt/privacyidea/requirements.txt", "0o640"),
    ])

def test_privacy_config_files(host, path, mode):
    f = host.file(path)
    
    assert f.exists
    assert f.is_file
    assert f.user == "privacyidea"
    assert f.group == "privacyidea"
    assert oct(f.mode) == mode # oct int
  
@pytest.mark.parametrize("package", [
    ("python38"),
    ("python38-mod_wsgi"),
    ("python3-pexpect"),
    ])

def test_packages(host, package):
    p = host.package(package)
    assert p.is_installed


@pytest.mark.parametrize("path,pattern" , [
    ("/etc/privacyidea/pi.cfg","^SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://pi:encryptme@192.168.56.3/pi'$"),
    ("/etc/privacyidea/pi.cfg","^PI_ENCFILE = '/opt/privacyidea/lib64/python3.8/site-packages/enckey'$"),
    ("/etc/privacyidea/pi.cfg","^PI_AUDIT_KEY_PRIVATE = '/opt/privacyidea/lib64/python3.8/site-packages/private.pem'$"),
    ("/etc/privacyidea/pi.cfg","^PI_AUDIT_KEY_PUBLIC = '/opt/privacyidea/lib64/python3.8/site-packages/public.pem'$"),
    ("/etc/privacyidea/pi.cfg","^PI_LOGFILE = '/var/log/privacyidea/privacyidea.log'$"),
    ])                               

def test_templates(host, path, pattern):
    f = host.file(path)
    
    assert f.contains(pattern)


def test_pip_packages(host):
    p = host.pip_package("privacyidea", pip_path='/opt/privacyidea/bin/pip3')

    assert p.is_installed
    assert p.version == '3.7.3'

def test_admin_login(host):
    get_token = host.run(r"""curl -k -X POST https://privacyidea/auth -H "Content-Type: application/json" -d '{"username":"encryptme","password":"encryptme"}'""")
    
    assert get_token.succeeded
    response = json.loads(get_token.stdout)
    global token
    token = response["result"]["value"]["token"]

#def create_resolver(host):
#    create_resolver = host.run(rf"""export TOKEN={token} curl -k -X POST https://privacyidea/resolver/ -H "Authorization: $TOKEN" -H 'Content-Type: application/json' -d '{"resolver":"passwd","type":"passwdresolver","Filename":"/etc/passwd"}'""")
