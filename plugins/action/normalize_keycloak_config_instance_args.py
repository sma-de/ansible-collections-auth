
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


MAGIC_KEY_REALM_ALL = "__all__"


class ConfigRootNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ConnectionNormer(pluginref),
          RealmsNormer(pluginref),
          GroupsNormer(pluginref),
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


class RealmsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          RealmInstanceNormer(pluginref),
        ]

        super(RealmsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['realms'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['realms']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## any keycloak server comes on default with a preset
        ## master realm and for normalizing purposes it is good
        ## to have it explicitly set here even when no custom user
        ## config is associated with it
        setdefault_none(my_subcfg['realms'], 'master', None)
        return my_subcfg


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
        return ['realms', SUBDICT_METAKEY_ANY]

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


class RealmAttachableNormer(NormalizerBase, abc.ABC):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          RealmSettingsInstNormer(pluginref),
        ]

        super(RealmAttachableNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    @abc.abstractmethod
    def cfg_toplvl_distance(self):
        pass

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        unset = object()

        rs = setdefault_none(my_subcfg, 'realms', {})

        # optionally handle MAGIC_KEY_REALM_ALL to add this item to
        # all realms defined
        tmp = rs.pop(MAGIC_KEY_REALM_ALL, unset)

        if tmp != unset:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs,
              level=self.cfg_toplvl_distance
            )

            for k,v in pcfg['realms']['realms'].items():
                t2 = tmp
                t3 = rs.get(v['id'], None)

                # on default uses any custom realm overwrite settings
                # given for MAGIC_KEY_REALM_ALL for all realms,
                # optionally merge this settings with specific settings
                # given for a specific realm (with all settings being
                # lower prio defaults)
                if t2:
                    t2 = copy.deepcopy(t2)

                if t3:
                    merge_dicts(t2, t3)

                rs[v['id']] = t2

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        for k,v in my_subcfg['realms'].items():
            c = copy.deepcopy(my_subcfg['config'])
            merge_dicts(c, v['config'])

            v['config'] = c
            v['taskname'] = "{} in realm {}".format(my_subcfg['name'], v['realm'])

        return my_subcfg


class GroupsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          GroupInstanceNormer(pluginref),
        ]

        super(GroupsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['groups']

    # build ordered flat list of all groups needed by this
    # role groups processing
    def _build_grplist(self, cur_grps, grplst=None):
        if grplst is None:
            grplst = []

        for k,v in cur_grps.items():
            for rk,rv in v['realms'].items():
                grplst.append(rv)
            self._build_grplist(v['subgroups'], grplst=grplst)

        return grplst

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['_grplist'] = self._build_grplist(my_subcfg['groups'])
        return my_subcfg


class GroupInstanceNormer(RealmAttachableNormer, NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (SubGroupInstanceNormer, True),
        ]

        super(GroupInstanceNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['config'] = DefaultSetterConstant({})
        self.default_setters['toplvl'] = DefaultSetterConstant(True)
        self.default_setters['subgroups'] = DefaultSetterConstant({})

    @property
    def cfg_toplvl_distance(self):
        return 3

    @property
    def config_path(self):
        return ['groups', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg = super(GroupInstanceNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        my_subcfg['config']['name'] = my_subcfg['name']
        return my_subcfg


class SubGroupInstanceNormer(GroupInstanceNormer):

    NORMER_CONFIG_PATH = ['subgroups', SUBDICT_METAKEY_ANY]

    def __init__(self, pluginref, *args, **kwargs):
        super(SubGroupInstanceNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['toplvl'] = DefaultSetterConstant(False)
        self._subgrp_lvls = None

    @property
    def cfg_toplvl_distance(self):
        return super(SubGroupInstanceNormer, self).cfg_toplvl_distance\
          + self._subgrp_lvls

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg = super(SubGroupInstanceNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        realms = my_subcfg.get('realms', None)

        ## build parent chain for current subgroup
        parent_chain = []
        first_p = True

        level = 2
        while True:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=level)
            parent_chain.insert(0, pcfg['name'])

            if not realms and first_p:
                # inherit realm settings from parent when no own are set
                realms = copy.deepcopy(pcfg['realms'])

            first_p = False

            if pcfg['toplvl']:
                break

            level += 2

        my_subcfg['parent_chain'] = parent_chain
        my_subcfg['config']['parents'] = parent_chain

        my_subcfg['realms'] = realms

        self._subgrp_lvls = len(parent_chain) * 2
        return my_subcfg


class UserFederationInstanceNormer(RealmAttachableNormer, NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          UserFederationInstanceMapperInstNormer(pluginref),
          UserFederationInstanceConfigNormer(pluginref),
        ]

        super(UserFederationInstanceNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def cfg_toplvl_distance(self):
        return 3

    @property
    def config_path(self):
        return ['user_federations', 'federations', SUBDICT_METAKEY_ANY]


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


class RealmSettingsInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(RealmSettingsInstNormer, self).__init__(
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

