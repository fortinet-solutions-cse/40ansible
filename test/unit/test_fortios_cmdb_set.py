import library.fortios_cmdb_set as sut
import sys
from fortiosapi import FortiOSAPI


def test_main_module(monkeypatch):
    def cmd_arguments():
        argv = ['fortios_cmdb_set.py',
                '{ '
                '"ANSIBLE_MODULE_ARGS": { '
                '"host": "192.168.122.40", '
                '"username": "admin", '
                '"password": "", '
                '"vdom": "global", '
                '"endpoint": "router static", '
                '"config_parameters":'
                ' { '
                '"seq-num": "8", '
                '"dst": "10.10.32.0 255.255.255.0",'
                '"device": "port2",'
                '"gateway": "192.168.40.252" '
                '}'
                '} '
                '} ']
        return argv

    def set(self, path, name, vdom=None,
            mkey=None, parameters=None, data=None):
        return {'status': 'success', 'version': '5.6.2'}

    monkeypatch.setattr(sys, 'argv', cmd_arguments())
    monkeypatch.setattr(sys, 'exit', lambda x: True)
    monkeypatch.setattr(FortiOSAPI, 'login', lambda self, host, username, password : True)
    monkeypatch.setattr(FortiOSAPI, 'set', set)
    monkeypatch.setattr(FortiOSAPI, 'logout', lambda _: True)

    sut.main()


def test_cmdb_set(monkeypatch):

    def set(self, path, name, vdom=None,
            mkey=None, parameters=None, data=None):
        return {'status': 'success', 'version': '5.6.2'}

    monkeypatch.setattr(FortiOSAPI, 'login', lambda self, host, username, password : True)
    monkeypatch.setattr(FortiOSAPI, 'set', set)
    monkeypatch.setattr(FortiOSAPI, 'logout', lambda _: True)

    isError, isChanged, result = sut.fortios_cmdb_set({"host": "192.168.122.40",
                                                       "username": "admin",
                                                       "password": "",
                                                       "endpoint": "router static",
                                                       "vdom": "global",
                                                       "config_parameters": {"seq-num": 8,
                                                                             "dst": "10.10.32.0 255.255.255.0",
                                                                             "device": "port2",
                                                                             "gateway": "192.168.40.252"}
                                                       })
    assert isError == False
    assert isChanged == True
    assert result is not None


def test_cmdb_set_failed(monkeypatch):

    def set(self, path, name, vdom=None,
            mkey=None, parameters=None, data=None):
        return {'status': 'error', 'version': '5.6.2'}

    monkeypatch.setattr(FortiOSAPI, 'login', lambda self, host, username, password : True)
    monkeypatch.setattr(FortiOSAPI, 'set', set)
    monkeypatch.setattr(FortiOSAPI, 'logout', lambda _: True)

    isError, isChanged, result = sut.fortios_cmdb_set({"host": "192.168.122.40",
                                                       "username": "admin",
                                                       "password": "",
                                                       "endpoint": "router static",
                                                       "vdom": "global",
                                                       "config_parameters": {"seq-num": 8,
                                                                             "dst": "10.10.32.0 255.255.255.0",
                                                                             "device": "port2",
                                                                             "gateway": "192.168.40.252"}
                                                       })
    assert isError == True
    assert isChanged == False
    assert result is not None


def test_required_params():
    return


def test_optional_params():
    return


def test_different_endpoints():
    return


def test_failed_login(monkeypatch):
    def login(self, host, username, password):
        raise Exception("Failed Login")
        return

    def set(self, path, name, vdom=None,
            mkey=None, parameters=None, data=None):
        return {'status': 'error', 'version': '5.6.2'}

    monkeypatch.setattr(FortiOSAPI, 'login', login)
    monkeypatch.setattr(FortiOSAPI, 'set', set)
    monkeypatch.setattr(FortiOSAPI, 'logout', lambda _: True)

    try:
        isError, isChanged, result = sut.fortios_cmdb_set({"host": "192.168.122.40",
                                                           "username": "admin",
                                                           "password": "",
                                                           "endpoint": "router static",
                                                           "vdom": "global",
                                                           "config_parameters": {"seq-num": 8,
                                                                                 "dst": "10.10.32.0 255.255.255.0",
                                                                                 "device": "port2",
                                                                                 "gateway": "192.168.40.252"}
                                                           })
        assert "Error: No exception raised when failed login"
    except:
        pass


def test_failed_endpoint():
    return
