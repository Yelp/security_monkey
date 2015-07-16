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
.. module: security_monkey.auditors.ec2
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Quentin Long <qlo@yelp.com>

"""

from security_monkey.auditor import Auditor
from security_monkey.watchers.ec2 import EC2
from security_monkey.datastore import Item, Technology
from security_monkey import app

import yaml

# Valid teams as of 7/16
BACKUP_TEAM_LIST = ['operations', 'revenue', 'dba', 'community', 'hardware', 'ad_delivery', 'biz_data', 'growth', 'pcde', 'consumer_services', 'ad_backend', 'ad_targeting', 'releng', 'bizapp', 'spam', 'seatme', 'neteng', 'platform', 'noop', 'smi', 'test', 'statmonster', 'ugc_abuse', 'dowser', 'service_infra', 'biz', 'i18n', 'distributed_systems', 'search_infra', 'mobile', 'log_infra', 'biz_infra', 'perf_metrics', 'corpeng', 'payments', 'paasta', 'webcore', 'security', 'bam', 'consumer', 'biz_engagement', 'partnerships']


class EC2Auditor(Auditor):
    index = EC2.index
    i_am_singular = EC2.i_am_singular
    i_am_plural = EC2.i_am_plural
    users = []
    teams = []

    def find_valid_creators(self):
        """
        Finds the names of all tracked users and saves them for validating creator tags.
        """
        iamuser = Technology.query.filter(Technology.name == 'iamuser').first()
        query = Item.query.filter(Item.tech_id == iamuser.id)
        self.users = [user.name for user in query.all()]

    def find_valid_owners(self):
        """
        Find valid values for the owner tag. This is the set of teams defined in sensu_Handler::teams in hieradata/common.yaml.
        When Security Monkey is deployed, this file should be available at /nail/security_monkey/common.yaml.
        """
        try:
            with open('/nail/security_monkey/common.yaml', 'r') as common:
                common_data = yaml.load(common.read())
                self.teams = common_data['sensu_handlers::teams'].keys()
        except Exception as e:
            # Use a backup list of teams
            app.logger.error("Error trying to read /nail/security_monkey/common.yaml: {0}".format(e))
            self.teams = BACKUP_TEAM_LIST

    def __init__(self, accounts=None, debug=False):
        super(EC2Auditor, self).__init__(accounts=accounts, debug=debug)
        self.find_valid_owners()
        self.find_valid_creators()

    def check_for_owner_tag(self, ec2item):
        """
        alert on missing owner tag.
        """
        tag = "EC2 instance has no owner tag"
        severity = 3
        tags = ec2item.config.get('tags', {})
        if 'owner' not in tags:
            self.add_issue(severity, tag, ec2item, notes=None)

    def check_for_creator_tag(self, ec2item):
        """
        alert on missing creator tag.
        """
        tag = "EC2 instance has no creator tag"
        severity = 3
        tags = ec2item.config.get('tags', {})
        if 'creator' not in tags:
            self.add_issue(severity, tag, ec2item, notes=None)

    def check_valid_owner_tag(self, ec2item):
        """
        alert on an owner tag that is not a valid team name, as defined by sensu_handlers::teams
        """
        tag = "EC2 instance has an owner tag which doesn't match a team"
        severity = 2
        tags = ec2item.config.get('tags', {})
        if 'owner' in tags:
            owner = tags['owner'].replace('@yelp.com', '').replace('-', '_')
            if owner not in self.teams:
                notes = 'Owner tag is {0}'.format(tags['owner'])
                self.add_issue(severity, tag, ec2item, notes=notes)

    def check_valid_creator_tag(self, ec2item):
        """
        alert on an creator tag that is not an iamuser
        """
        tag = "EC2 instance has an creator tag which doesn't match an existing iamuser"
        severity = 2
        tags = ec2item.config.get('tags', {})
        if 'creator' in tags:
            creator = tags['creator'].replace('@yelp.com', '')
            if creator not in self.users:
                notes = 'Creator tag is {0}'.format(tags['creator'])
                self.add_issue(severity, tag, ec2item, notes=notes)
