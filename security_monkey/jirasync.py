import datetime
import yaml
import getpass
from jira.client import JIRA
from jira.exceptions import JIRAError
from security_monkey.datastore import Account, Technology, AuditorSettings
from security_monkey import app, db

class JiraSync(object):
    """ Syncs auditor issues with JIRA tickets. """
    def __init__(self, jira_file):
        with open(jira_file) as jf:
            data = jf.read()
            data = yaml.load(data)
            self.account = data['account']
            self.password = getpass.getpass('Password for %s: ' %(self.account))
            self.project = data['project']
            self.server = data['server']
            self.issue_type = data['issue_type']
            self.url = data['url']

        try:
            self.client = JIRA(self.server, basic_auth=(self.account, self.password))
        except JIRAError as e:
            raise EAException("Error connecting to JIRA: %s" %(str(e)[:1024]))

    def add_or_update_issue(self, issue, technology, account, count):
        summary = '{0} - {1} - {2}'.format(issue, technology, account)
        summary_hash = hashlib.sha1(summary).digest().encode('base64')[:16]
        jql = 'project=pincushion and text~"{1}"'.format(self.project, summary_hash)
        issues = self.client.search_issues(jql)
        
        url = "{0}/#/issues/-/{1}/{2}/-/True/{3}/1/25".format(self.url, technology, account, issue)
        description = ("This ticket was automatically created by Security Monkey. DO NOT EDIT ANYTHING BELOW THIS LINE\n"
                      "Number of issues: {0} (Last updated: {1})\n"
                      "Account: {2}\n"
                      "{3}\n"
                      "[View on Security Monkey|{4}]\n".format(count, datetime.datetime.now().isoformat(), account, summary_hash, url))

        
        if len(issues):
            # JQL returns partial matches, find the ticket with the exact summary
            for issue in issues:
                if issue.fields.summary == summary:
                    old_desc = issue.fields.description
                    old_desc = old_desc[:old_desc.find('This ticket was automatically created by Security Monkey')]
                    issue.update(description = old_desc + description)
                    return
                
        jira_args = {'project': {'key': self.project},
                     'issuetype': {'name': self.issue_type},
                     'summary': summary,
                     'description': description}

        try:
            issue = self.client.create_issue(**jira_args)
        except JIRAError as e:
            print "Error creating ticket", e

    def sync_issues(self):
        stmt = db.session.query(
            ItemAudit.auditor_setting_id,
            func.count('*').label('issue_count')
        ).group_by(
            ItemAudit.auditor_setting_id
        ).subquery()

        query = AuditorSettings.query.join(
            (stmt, AuditorSettings.id == stmt.c.auditor_setting_id)
        ).join(
            (Technology, Technology.id == AuditorSettings.tech_id)
        ).join(
            (Account, Account.id == AuditorSettings.account_id)
        )

        for auditorsetting in query.all():
            self.add_or_update_issue(auditorsetting.AuditorSettings.issue_text,
                                     auditorsetting.Technology.name,
                                     auditorsetting.Account.name,
                                     auditorsetting.issue_count)
 


if __name__ == '__main__':
    a = JiraSync('jira.yaml')
    a.add_update_issue('Test issue', 'iamuser', 'systems+awsdev+ec2', 5)

