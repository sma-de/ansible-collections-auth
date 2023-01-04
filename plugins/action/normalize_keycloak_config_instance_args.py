
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc
import copy
from urllib.parse import urlparse
import os

from ansible.errors import AnsibleOptionsError
##from ansible.module_utils.six import iteritems, string_types

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import default_param_value
from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import ConfigNormalizerBaseMerger, NormalizerBase, NormalizerNamed, DefaultSetterConstant, DefaultSetterOtherKey

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import SUBDICT_METAKEY_ANY, setdefault_none, get_subdict, merge_dicts

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert



class ConfigRootNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ConnectionNormer(pluginref),
          RealmInstanceNormer(pluginref),
          UserFederationInstanceNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)


class ConnectionNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['validate_certs'] = DefaultSetterConstant(True)

    @property
    def config_path(self):
        return ['connection']


class RealmInstanceNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          RealmInstanceConfigNormer(pluginref),
        ]

        super(RealmInstanceNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['realms', 'realms', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'id'


class RealmInstanceConfigNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(RealmInstanceConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['state'] = DefaultSetterConstant('present')

    @property
    def config_path(self):
        return ['config']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['id'] = pcfg['id']

        setdefault_none(my_subcfg, 'realm', my_subcfg['id'])
        return my_subcfg


class UserFederationInstanceNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          UserFederationInstanceMapperInstNormer(pluginref),
          UserFederationInstanceConfigNormer(pluginref),
          UserFederationInstanceRealmInstNormer(pluginref),
        ]

        super(UserFederationInstanceNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['user_federations', 'federations', SUBDICT_METAKEY_ANY]

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        for k,v in my_subcfg['realms'].items():
            c = copy.deepcopy(my_subcfg['config'])
            merge_dicts(c, v['config'])

            v['config'] = c
            v['taskname'] = "{} in realm {}".format(my_subcfg['name'], v['realm'])

        return my_subcfg


class UserFederationInstanceMapperInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          UserFederationInstanceMapperInstConfigNormer(pluginref),
        ]

        super(UserFederationInstanceMapperInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['mappers', SUBDICT_METAKEY_ANY]


class UserFederationInstanceMapperInstConfigNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(UserFederationInstanceMapperInstConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['config'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['config']

    def _handle_provider_user_attribute_ldap_mapper(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']

        setdefault_none(c, 'user.model.attribute', my_subcfg['name'])
        setdefault_none(c, 'is.mandatory.in.ldap', True)
        setdefault_none(c, 'read.only', True)
        setdefault_none(c, 'always.read.value.from.ldap', False)

        # TODO: this name is seemingly wrong, this is still to clear when this becomes necessary one day
        ##setdefault_none(c, 'is.binary.attribute', False)

        return my_subcfg

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['name'] = pcfg['name']

        tmp = getattr(self,
          "_handle_provider_{}".format(my_subcfg['providerId'].replace('-', '_')),
          None
        )

        if tmp:
            tmp(cfg, my_subcfg, cfgpath_abs)

        return my_subcfg


class UserFederationInstanceConfigNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(UserFederationInstanceConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['provider_id'] = DefaultSetterConstant('ldap')
        self.default_setters['state'] = DefaultSetterConstant('present')
        self.default_setters['config'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['config']

    def _handle_provider_specifics_ldap(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']

        setdefault_none(c, 'vendor', 'other')
        setdefault_none(c, 'enabled', True)
        setdefault_none(c, 'debug', False)
        setdefault_none(c, 'importEnabled', True)
        setdefault_none(c, 'syncRegistrations', False)
        setdefault_none(c, 'authType', 'none')
        setdefault_none(c, 'validatePasswordPolicy', False)

        setdefault_none(c, 'allowKerberosAuthentication', False)
        setdefault_none(c, 'useKerberosForPasswordAuthentication', False)

        ## note: the following settings have no default in upstream
        ##   module but are mandatory to set if one asks the keycloak api
        setdefault_none(c, 'editMode', 'READ_ONLY')

        return my_subcfg

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        setdefault_none(my_subcfg, 'name', pcfg['name'])

        pid = my_subcfg['provider_id']

        tmp = getattr(self, '_handle_provider_specifics_{}'.format(pid), None)

        if tmp:
            my_subcfg = tmp(cfg, my_subcfg, cfgpath_abs)

        return my_subcfg

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        # add normed mappers to final upstream module params/config
        mappers_lst = []
        for k, v in pcfg['mappers'].items():
            mappers_lst.append(v['config'])

        my_subcfg['mappers'] = mappers_lst

        return my_subcfg


class UserFederationInstanceRealmInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(UserFederationInstanceRealmInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['config'] = DefaultSetterConstant({})

    @property
    def name_key(self):
        return 'realm'

    @property
    def config_path(self):
        return ['realms', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['config']['realm'] = my_subcfg['realm']
        return my_subcfg


class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(ConfigRootNormalizer(self),
            *args,
            ##default_merge_vars=[
            ##   'smabot_hashivault_config_instance_args_extra'
            ##],
            ##extra_merge_vars_ans=['smabot_hashivault_config_instance_args_extra'],
            **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_auth_keycloak_config_instance_args'

