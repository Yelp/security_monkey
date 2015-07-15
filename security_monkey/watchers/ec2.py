#     Copyright 2015 Yelp, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.watchers.ec2
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Quentin Long <qlo@yelp.com>

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.constants import TROUBLE_REGIONS
from security_monkey.exceptions import InvalidAWSJSON
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app

import json
import boto
from boto.ec2 import regions


class EC2(Watcher):
    index = 'ec2'
    i_am_singular = 'EC2 Instance'
    i_am_plural = 'EC2 Instances'

    def __init__(self, accounts=None, debug=False):
        super(EC2, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        """
        :returns: item_list - list of EC2 instances.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception

        """
        self.prep_for_slurp()

        item_list = []
        exception_map = {}
        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            for region in regions():
                app.logger.debug("Checking {}/{}/{}".format(EC2.index, account, region.name))
                try:
                    ec2 = connect(account, 'ec2', region=region)
                    all_instances = self.wrap_aws_rate_limited_call(
                        ec2.get_only_instances
                    )
                except Exception as e:
                    if region.name not in TROUBLE_REGIONS:
                        exc = BotoConnectionIssue(str(e), 'ec2', account, region.name)
                        self.slurp_exception((self.index, account, region.name), exc, exception_map)
                    continue
                app.logger.debug("Found {} {}".format(len(all_instances), EC2.i_am_plural))
                for instance in all_instances:

                    if self.check_ignore_list(instance.id):
                        continue

                    groups = [{'id': group.id, 'name': group.name} for group in instance.groups]
                    instance_info = {'tags': dict(instance.tags),
                                     'type': instance.instance_type,
                                     'vpc_id': instance.vpc_id,
                                     'subnet_id': instance.subnet_id,
                                     'security_groups': groups,
                                     'id': instance.id,
                                     'dns_name': instance.private_dns_name}
                    name = instance.tags.get('Name')
                    if not name:
                        name = instance.private_dns_name
                    item = EC2Item(region=region.name, account=account, name=name,
                                   config=instance_info)
                    item_list.append(item)
        return item_list, exception_map


class EC2Item(ChangeItem):
    def __init__(self, region=None, account=None, name=None, config={}):
        super(EC2Item, self).__init__(
            index=EC2.index,
            region=region,
            account=account,
            name=name,
            new_config=config)
