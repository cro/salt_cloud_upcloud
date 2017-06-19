
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
        args=__utils__['cloud.filter_event']('creating', vm_, ['name', 'profile', 'provider', 'driver']),
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

    server_obj = Server(**server_kwargs)

    manager.create_server(server_obj)


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
    for item in zones:
        name = item['LOCATION']
        ret[name] = item

    return ret


################# STUFF TO DELETE ################################
def _old_create(vm_):

    data = {}
    kwargs = {'name': name}

    plan_id = None
    size = vm_.get('size')
    if size:
        kwargs['size'] = size
        plan_id = get_plan_id(kwargs={'label': size})

    datacenter_id = None
    location = vm_.get('location')
    if location:
        try:
            datacenter_id = get_datacenter_id(location)
        except KeyError:
            # Linode's default datacenter is Dallas, but we still have to set one to
            # use the create function from Linode's API. Dallas's datacenter id is 2.
            datacenter_id = 2

    clonefrom_name = vm_.get('clonefrom')
    cloning = True if clonefrom_name else False
    if cloning:
        linode_id = get_linode_id_from_name(clonefrom_name)
        clone_source = get_linode(kwargs={'linode_id': linode_id})

        kwargs = {
            'clonefrom': clonefrom_name,
            'image': 'Clone of {0}'.format(clonefrom_name),
        }

        if size is None:
            size = clone_source['TOTALRAM']
            kwargs['size'] = size
            plan_id = clone_source['PLANID']

        if location is None:
            datacenter_id = clone_source['DATACENTERID']

        # Create new Linode from cloned Linode
        try:
            result = clone(kwargs={'linode_id': linode_id,
                                   'datacenter_id': datacenter_id,
                                   'plan_id': plan_id})
        except Exception as err:
            log.error(
                'Error cloning \'{0}\' on Linode.\n\n'
                'The following exception was thrown by Linode when trying to '
                'clone the specified machine:\n'
                '{1}'.format(
                    clonefrom_name,
                    err
                ),
                exc_info_on_loglevel=logging.DEBUG
            )
            return False
    else:
        kwargs['image'] = vm_['image']

        # Create Linode
        try:
            result = _query('linode', 'create', args={
                'PLANID': plan_id,
                'DATACENTERID': datacenter_id
            })
        except Exception as err:
            log.error(
                'Error creating {0} on Linode\n\n'
                'The following exception was thrown by Linode when trying to '
                'run the initial deployment:\n'
                '{1}'.format(
                    name,
                    err
                ),
                exc_info_on_loglevel=logging.DEBUG
            )
            return False

    if 'ERRORARRAY' in result:
        for error_data in result['ERRORARRAY']:
            log.error('Error creating {0} on Linode\n\n'
                    'The Linode API returned the following: {1}\n'.format(
                        name,
                        error_data['ERRORMESSAGE']
                        )
                    )
            return False

    __utils__['cloud.fire_event'](
        'event',
        'requesting instance',
        'salt/cloud/{0}/requesting'.format(name),
        args=__utils__['cloud.filter_event']('requesting', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    node_id = _clean_data(result)['LinodeID']
    data['id'] = node_id

    if not _wait_for_status(node_id, status=(_get_status_id_by_name('brand_new'))):
        log.error(
            'Error creating {0} on LINODE\n\n'
            'while waiting for initial ready status'.format(name),
            exc_info_on_loglevel=logging.DEBUG
        )

    # Update the Linode's Label to reflect the given VM name
    update_linode(node_id, update_args={'Label': name})
    log.debug('Set name for {0} - was linode{1}.'.format(name, node_id))

    # Add private IP address if requested
    private_ip_assignment = get_private_ip(vm_)
    if private_ip_assignment:
        create_private_ip(node_id)

    # Define which ssh_interface to use
    ssh_interface = _get_ssh_interface(vm_)

    # If ssh_interface is set to use private_ips, but assign_private_ip
    # wasn't set to True, let's help out and create a private ip.
    if ssh_interface == 'private_ips' and private_ip_assignment is False:
        create_private_ip(node_id)
        private_ip_assignment = True

    if cloning:
        config_id = get_config_id(kwargs={'linode_id': node_id})['config_id']
    else:
        # Create disks and get ids
        log.debug('Creating disks for {0}'.format(name))
        root_disk_id = create_disk_from_distro(vm_, node_id)['DiskID']
        swap_disk_id = create_swap_disk(vm_, node_id)['DiskID']

        # Create a ConfigID using disk ids
        config_id = create_config(kwargs={'name': name,
                                          'linode_id': node_id,
                                          'root_disk_id': root_disk_id,
                                          'swap_disk_id': swap_disk_id})['ConfigID']

    # Boot the Linode
    boot(kwargs={'linode_id': node_id,
                 'config_id': config_id,
                 'check_running': False})

    node_data = get_linode(kwargs={'linode_id': node_id})
    ips = get_ips(node_id)
    state = int(node_data['STATUS'])

    data['image'] = kwargs['image']
    data['name'] = name
    data['size'] = size
    data['state'] = _get_status_descr_by_id(state)
    data['private_ips'] = ips['private_ips']
    data['public_ips'] = ips['public_ips']

    # Pass the correct IP address to the bootstrap ssh_host key
    if ssh_interface == 'private_ips':
        vm_['ssh_host'] = data['private_ips'][0]
    else:
        vm_['ssh_host'] = data['public_ips'][0]

    # If a password wasn't supplied in the profile or provider config, set it now.
    vm_['password'] = get_password(vm_)

    # Make public_ips and private_ips available to the bootstrap script.
    vm_['public_ips'] = ips['public_ips']
    vm_['private_ips'] = ips['private_ips']

    # Send event that the instance has booted.
    __utils__['cloud.fire_event'](
        'event',
        'waiting for ssh',
        'salt/cloud/{0}/waiting_for_ssh'.format(name),
        args={'ip_address': vm_['ssh_host']},
        transport=__opts__['transport']
    )

    # Bootstrap!
    ret = __utils__['cloud.bootstrap'](vm_, __opts__)

    ret.update(data)

    log.info('Created Cloud VM \'{0}\''.format(name))
    log.debug(
        '\'{0}\' VM creation details:\n{1}'.format(
            name, pprint.pformat(data)
        )
    )

    __utils__['cloud.fire_event'](
        'event',
        'created instance',
        'salt/cloud/{0}/created'.format(name),
        args=__utils__['cloud.filter_event']('created', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    return


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
