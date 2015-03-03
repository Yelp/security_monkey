"""
.. module: security_monkey.jirasync
    :platform: Unix
    :synopsis: Creates and updates JIRA tickets based on current issues

.. version:: $$VERSION$$
.. moduleauthor:: Quentin Long <qlo@yelp.com>

"""
import datetime
import hashlib
import yaml

from jira.client import JIRA
from sqlalchemy import func

from security_monkey.datastore import Account, Technology, AuditorSettings, ItemAudit
from security_monkey import app, db

class JiraSync(object):
    """ Syncs auditor issues with JIRA tickets. """
    def __init__(self, jira_file):
        try:
            with open(jira_file) as jf:
                data = jf.read()
                data = yaml.load(data)
                self.account = data['account']
                self.password = data['password']
                self.project = data['project']
                self.server = data['server']
                self.issue_type = data['issue_type']
                self.url = data['url']
        except KeyError as e:
            app.logger.error('JIRA sync configuration missing required field: {}'.format(e))
        except IOError as e:
            app.logger.error('Error opening JIRA sync configuration file: {}'.format(e))
        except yaml.scanner.ScannerError as e:
            app.logger.error('JIRA sync configuration file contains malformed YAML: {}'.format(e))

        try:
            self.client = JIRA(self.server, basic_auth=(self.account, self.password))
        except Exception as e:
            raise Exception("Error connecting to JIRA: %s" %(str(e)[:1024]))

    def add_or_update_issue(self, issue, technology, account, count):
        """ Searches for existing tickets based on a hash of the constructed summary. If one exists,
        it will update the count and preserve any leading description text. If not, it will create a ticket. """
        summary = '{0} - {1} - {2}'.format(issue, technology, account)
        # Searching by text in JIRA sucks, instead of matching the summary field, search for summary hash
        summary_hash = hashlib.sha1(summary).digest().encode('base64')[:16]
        jql = 'project={0} and text~"{1}"'.format(self.project, summary_hash)
        issues = self.client.search_issues(jql)

        url = "{0}/#/issues/-/{1}/{2}/-/True/{3}/1/25".format(self.url, technology, account, issue)
        description = ("This ticket was automatically created by Security Monkey. DO NOT EDIT ANYTHING BELOW THIS LINE\n"
                      "Number of issues: {0}\n"
                      "Account: {2}\n"
                      "{3}\n"
                      "[View on Security Monkey|{4}]\n"
                      "Last updated: {1}".format(count, datetime.datetime.now().isoformat(), account, summary_hash, url))


        if len(issues):
            for issue in issues:
                # Make sure we found the exact ticket
                if issue.fields.summary == summary:
                    old_desc = issue.fields.description
                    old_desc = old_desc[:old_desc.find('This ticket was automatically created by Security Monkey')]
                    issue.update(description = old_desc + description)
                    app.logger.debug("Updated issue {}".format(summary))
                    return

        jira_args = {'project': {'key': self.project},
                     'issuetype': {'name': self.issue_type},
                     'summary': summary,
                     'description': description}

        try:
            issue = self.client.create_issue(**jira_args)
            app.logger.debug("Created issue {}".format(summary))
        except Exception as e:
            app.logger.error("Error creating ticket: {}".format(e))

    def sync_issues(self):
        """ Runs add_or_update_issue for every AuditorSetting. """
        query = AuditorSettings.query.join(
             (Technology, Technology.id == AuditorSettings.tech_id)
         ).join(
             (Account, Account.id == AuditorSettings.account_id)
         )

         for auditorsetting in query.all():
             self.add_or_update_issue(auditorsetting.issue_text,
                                      auditorsetting.technology.name,
                                      auditorsetting.account.name,
                                      len(auditorsetting.issues))
