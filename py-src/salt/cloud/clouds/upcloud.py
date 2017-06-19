
'''

Upcloud Cloud Module
====================

Used to control UpCloud VPS provider

:depends:
  * upcloud-python-api

:configuration:
  Required provider parameters:

  * ``api_user``
  * ``password``

  Other parameters:

   * ``ssh_pubkey``: a key to copy to the new machine
   * ``location``: which datacenter to use,
   * ``size``: one of plan_XXX or the numeric sizes, call `salt-cloud --list-sizes upcloud` to find out the sizes
   * ``extra_storage``: a list of blank max_iops disk to add, with size
                        in gigabytes.
   * ``login_user``: the user to create for login
   * ``ip_addresses``: configuration about network interfaces/ip addresses. Each contains a
                       ``access`` with `public` or `private`, and a ``family`` with either
                        ``IPv4`` or IPv6``
   * ``control_from_inside``: if we should connect back using one of the inner interfaces. This won't
                       work if the salt minion is at an outside network, the default is False but
                       that won't work if there is no public ip address

'''

# Import Python libs
from __future__ import absolute_import
import copy
import logging
import pprint
import time
import re
import yaml

# Import salt libs
import salt.config as config
from salt.exceptions import SaltCloudSystemExit
import salt.utils.cloud


# Development aid: mock salt-provider parameters
if salt.config is None:
    __utils__ = {}
    __active_provider_name__ = ''
    __opts__ = ''


# Import 3rd-party libs
HAS_LIBS = False
try:
    import upcloud_api
    from upcloud_api import Server, Storage, ZONE, login_user_block
    HAS_LIBS = True
except ImportError:
    pass


# TO-DO: Is this a good idea?
# For the record, this is Ubuntu Server 16.04 LTS (Xenial Xerus)
DEFAULT_IMAGE='01000000-0000-4000-8000-000030060200'
DEFAULT_SIZE='1core__1024MB'


__virtualname__ = 'upcloud'


# Get logging started
log = logging.getLogger(__name__)


def get_configured_provider():
    '''
    Return the first configured instance.
    '''
    return config.is_provider_configured(
        __opts__,
        __active_provider_name__ or __virtualname__,
        ('api_user', 'password')
    )


def get_dependencies():
    '''
    Warn if dependencies aren't met.
    '''
    return config.check_driver_dependencies(
        __virtualname__,
        {'upcloud': HAS_LIBS}
    )


def create(vm_):
    '''
    Create a single Upcloud VM.
    '''
    name = vm_['name']
    try:
        # Check for required profile parameters before sending any API calls.
        if vm_['profile'] and config.is_profile_configured(__opts__,
                                                           __active_provider_name__ or 'upcloud',
                                                           vm_['profile'],
                                                           vm_=vm_) is False:
            return False
    except AttributeError:
        pass

    if _validate_name(name) is False:
        return False

    __utils__['cloud.fire_event'](
        'event',
        'starting create',
        'salt/cloud/{0}/creating'.format(name),
        args=_filter_event('creating', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    log.info('Creating Cloud VM {0}'.format(name))

    root_login_user = login_user_block(
        username='saltuser',
        ssh_keys=[get_pub_key(vm_)],
        create_password=False
    )

    server_kwargs = {}

    manager = _get_manager(vm_)

    location = vm_.get('location')

    ## TO-DO: Add support for cloning

    image = vm_.get('image', DEFAULT_IMAGE)

    extra_storage = vm_.get('extra_storage', [])

    storage = [
        # Primary, holds the operating system
        Storage(uuid=image)
    ] + [ Storage(size=s) for s in extra_storage ]

    size_dict = _parse_size( vm_.get('size', DEFAULT_SIZE) )

    server_kwargs.update(size_dict)

    # Let's take care of any network configuration
    ip_addresses = vm_.get('ip_addresses', [])

    control_from_inside = vm_.get('control_from_inside', False)

    server_kwargs['zone'] = location
    server_kwargs['hostname'] = vm_.get('hostname', name)
    server_kwargs['storage_devices'] = storage
    server_kwargs['ip_addresses'] = ip_addresses

    server_obj = Server(**server_kwargs)

    __utils__['cloud.fire_event'](
        'event',
        'requesting instance',
        'salt/cloud/{0}/requesting'.format(name),
        args=_filter_event('requesting', server_kwargs,
                                             ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    log.debug('vm_kwargs: {0}'.format(server_kwargs))

    create_server_result = manager.create_server(server_obj)

    log.info('create_server_result: {0}'.format(create_server_result))


def _get_manager(vm_=None):
    if vm_ is not None:
        api_user = vm_['api_user']
        password = vm_['password']
    else:
        api_user = config.get_cloud_config_value('api_user',
                                                 get_configured_provider(),
                                                 __opts__,
                                                 search_global=False)
        password = config.get_cloud_config_value('password',
                                                 get_configured_provider(),
                                                 __opts__,
                                                 search_global=False)
    manager = upcloud_api.CloudManager(api_user, password)
    manager.authenticate()
    return manager


def avail_locations(call=None):
    '''
    Return available Upcloud datacenter locations.
    CLI Example:
    .. code-block:: bash
        salt-cloud --list-locations my-upcloud-config
        salt-cloud -f avail_locations my-upcloud-config
    '''
    from salt.cloud.exceptions import SaltCloudException
    if call == 'action':

        raise SaltCloudException(
            'The avail_locations function must be called with -f or --function.'
        )

    manager = _get_manager()
    zones = manager.get_zones()


    ret = {}
    for item in zones['zones']['zone']:
        ret[item['id'].encode('ascii')] = item

    return ret


def avail_sizes(call=None):
    """
    Upcloud is very flexible, but this returns the preconfigured sizes
    """
    manager = _get_manager()
    sizes = manager.get_server_sizes()

    ret = {}
    for sz in sizes['server_sizes']['server_size']:
        sz_name = str(sz['core_number']) + 'cores__' + str(int(sz['memory_amount']) ) + "MB"
        ret[sz_name] = sz

    plans = manager.get_request('/plan')
    for plan in plans['plans']['plan']:
        plan_id = 'plan_' + plan['name']
        ret[plan_id] = plan

    return ret


def _parse_size(sz_str):
    r = re.compile(r'([0-9]+)cores__([0-9]+)MB')
    mo = re.match('plan_(.*)', sz_str)
    if mo:
        return {
            'plan': mo.group(1)
        }
    mo = re.match(r, sz_str)
    if mo:
        return {
            'core_number': int( mo.group(1) ),
            'memory_amount': int( mo.group(2) ),
            'plan': 'custom'
        }


def avail_images(call=None):
    """
    REturns available upcloud templates
    """
    from salt.cloud.exceptions import SaltCloudException
    if call == 'action':

        raise SaltCloudException(
            'The avail_locations function must be called with -f or --function.'
        )

    manager = _get_manager()
    templates = manager.get_storages(storage_type='template')

    ret = {}
    for storage in templates:
        ret[storage.uuid] = {
            attr: getattr( storage, attr )
            for attr in storage.ATTRIBUTES if hasattr(storage, attr)
        }

    return ret


def script(vm_):
    '''
    Return the script deployment object
    '''
    return salt.utils.cloud.os_script(
        config.get_cloud_config_value('script', vm_, __opts__),
        vm_,
        __opts__,
        salt.utils.cloud.salt_config_to_yaml(
            salt.utils.cloud.minion_config(__opts__, vm_)
        )
    )


def _validate_name(name):
    """
    Checks if the provided name fits Upcloud labeling parameters, which from what
    I see matches any hostname

    :param: name
        The VM name to validate
    """
    hostname = str(name)
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def get_pub_key(vm_):
    r'''
    Return the SSH pubkey.
    vm\_
        The configuration to obtain the public key from.
    '''
    return config.get_cloud_config_value(
        'ssh_pubkey', vm_, __opts__, search_global=False
    )


def _filter_event_internal(*args, **kwargs):
    """
    Filler  function to compensate for the upcoming release
    """
    result = {
        '_args': args,

    }
    result.update(kwargs)
    return result


def _filter_event(*args, **kwargs):
    f = __utils__.get('cloud.filter_event', _filter_event_internal)
    return f(*args, **kwargs)
