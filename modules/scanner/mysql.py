from recon.core.module import BaseModule
from recon.mixins.threads import ThreadingMixin
from socket import gethostbyaddr

import MySQLdb

class Module(BaseModule, ThreadingMixin):

	meta = {
		'name': 'MySQL Login Scanner',
		'author': 'James Luther (jamisl@gmail.com)',
		'description': 'Tests credentials against specified hosts.',
		'comments': (
			'This is a mysql scanner to test login of credentials',
		),
		'options': (
			('rhosts', 'default', True, 'Hosts you wish to try against.'),
			('username', None, True, 'Username you wish to try'),
			('password', None, True, 'Password you wish to try'),
		),
	}
	
	def module_run(self):
		user = self.options['username']
		password = self.options['password']
		rhosts = self.options['rhosts']
		hosts = []
		if rhosts == 'default':
			query = self.query('SELECT ip_address from ports ' +
			                   'where port is 3306')
			for ip in query:
				hosts.append(ip[0])
		elif rhosts.split(" ")[0] == 'port':
		    query = self.query('SELECT ip_address from ports '
			'where port is {}'.format(rhosts.split(' ')[1]))
			for ip in query:
			    hosts.append(ip[0])
		elif rhosts == 'all':
		    query = self.query('SELECT ip_address from hosts '
			'where ip_address is not Null')
		    for ip in query:
			    hosts.append(ip[0])
		else:
		    hosts.append(rhosts)
		self.thread(hosts, user, password)
		
	def module_thread(self, host, user, password):
	    try:
		    self.verbose('Trying host: ' +
			'{0} with User: {1} and Password: {2}'.format(host, user, password))
		    db = MySQLdb.connect(host, user, password)
			self.alert('Login successful for {}').format(host))
			db.close()
		    try:
			    name = gethostbyaddr(host)[0]
			except:
			    name = ''
			try:
			    self.add_credentials(ip_address=host, username=user,
				                     password=password)
				self.add_hosts(ip_address=host, host=name)
			except:
			    self.error('Unable to add results to database.')
		except Exception:
		    self.error('Login failed for host: {}'.format(host))