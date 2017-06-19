# salt_cloud_upcloud

Allows for provisioning  UpCloud virtual servers with salt.

## Pre-requisites

Install the following:

  - upcloud-python-api
  
(You can just use `pip install upcloud-api` for that).

## Configuration

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
                       
## Implementation status

So far only the most basic functionality has been implemented, more to come.


## Bad Git hygiene

The first few commits have been incredible boring, that's because because we were deploying 
the scripts for testing via the CI/CD pipeline. Sorry ;-(
