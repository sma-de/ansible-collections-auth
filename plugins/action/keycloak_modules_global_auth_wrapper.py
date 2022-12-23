
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import collections


from ansible.module_utils.six import string_types
##from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.plugins.action_base import BaseAction


##display = Display()


class ActionModule(BaseAction):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        ## TODO: support client id and token based auth wrapping
        tmp.update({
          'module': (list(string_types)),
          'params': ([collections.abc.Mapping], {}),

          ## wrapped keycloak module auth args
          'auth_keycloak_url': {
            'type': list(string_types) + [type(None)],
            'defaulting': {
               'ansvar': ['smabot_auth_keycloak_auth_url'],
               'fallback': None,
            },
          },

          'auth_realm': {
            'type': list(string_types),
            'defaulting': {
               'ansvar': ['smabot_auth_keycloak_auth_realm'],
               'fallback': 'master',
            },
          },

          'auth_username': {
            'type': list(string_types) + [type(None)],
            'defaulting': {
               'ansvar': ['smabot_auth_keycloak_auth_username'],
               'fallback': None,
            },
          },

          'auth_password': {
            'type': list(string_types) + [type(None)],
            'defaulting': {
               'ansvar': ['smabot_auth_keycloak_auth_password'],
               'fallback': None,
            },
          },

          'validate_certs': {
            'type': [bool, type(None)],
            'defaulting': {
               'ansvar': ['smabot_auth_keycloak_validate_certs'],
               'fallback': None,
            },
          },
        })

        return tmp


    def run_specific(self, result):
        module = self.get_taskparam('module')
        params = self.get_taskparam('params')

        pwraps = [
          'auth_keycloak_url',
          'auth_realm',
          'auth_username',
          'auth_password',
          'validate_certs',
        ]

        for ap in pwraps:
            tmp = self.get_taskparam(ap)

            if tmp is None:
                continue  # skip unset param

            # forward auth param to module
            params[ap] = tmp

        result.update(self.exec_module(module,
          modargs=params, ignore_error=True
        ))

        return result

