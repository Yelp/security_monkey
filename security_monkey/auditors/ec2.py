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


class EC2Auditor(Auditor):
    index = EC2.index
    i_am_singular = EC2.i_am_singular
    i_am_plural = EC2.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(EC2Auditor, self).__init__(accounts=accounts, debug=debug)

    def check_tags(self, ec2item):
        """
        alert on missing owner tag.
        """
        tag = "EC2 instance has no owner tag"
        severity = 1
        tags = ec2item.config.get('tags', {})
        if 'owner' not in tags:
            self.add_issue(severity, tag, ec2item, notes=None)

