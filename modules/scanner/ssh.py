from recon.core.module import BaseModule
from recon.mixins.threads import ThreadingMixin

from pexpect import pxssh
from socket import gethostbyaddr


class Module(BaseModule, ThreadingMixin):
    meta = {
	    'name': 'SSH Login Scanner',
		'author': 'James Luther',
		'description': 'Tests credentials against specified hosts.',
		'comments': (
		    'This is an ssh scanner to test login passwords. The default rhosts is all with port 22 open',
		),
		'options': (
		    ('rhosts', 'default', True, 'Hosts you wish to try against (tuple, all, default, port number [ex: port 22])'),
			('username', None, True, 'Username you wish to try'),
			('password', None, True, 'Password  you wish to try'),
		),
	}
	
	def module_run(self):
	    user = self.options['username']
		password = self.options['password']
		rhosts = self.options['rhosts']
		hosts = []
		if rhosts == 'default':
		    query = self.query('SELECT ip_address from ports where port is 22')
			for ip in query:
			    hosts.append(ip[0])
		elif rhosts.split(' ')[0] == 'port':
		    query = self.query('SELECT ip_address from ports where port is {}'.format(rhosts.split(' ')[1]))
			for ip in query:
			    hosts.append(ip[0])
		elif rhosts == 'all':
		    query = self.query('SELECT ip_address from hosts where ip_address is not Null')
			for ip in query:
			    hosts.append(ip[0])
		else:
		    hosts.append(rhosts)
		self.thread(hosts, user, password)
		
	def module_thread(self, host, user, password):
	    s = pxssh.pxssh()
		try:
		    self.verbose('Trying host: {0} with User: {1} and Password: {2}'.format(host, user, password))
			s.login(host, user, password)
			self.alert('Login successful for {}'.format(host))
			try:
			    name = gethostbyaddr(host)[0]
			except:
			    name = ''
			try:
			    self.verbose('Adding host: {} to credentials.'.format(host))
				self.add_credentials(ip_address=host, username=user, password=password)
				self.add_hosts(ip_address=host, host=name)
			except Exception as e:
			    self.error('Unable to add credentials. Error: {}'.format(e))
			s.logout()
		except Exception:
		    self.error('Login failed for host: {}'.format(host))