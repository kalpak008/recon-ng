from recon.core.module import BaseModule
from recon.mixins.threads import ThreadingMixin

import os
import pexpect
from socket import gethostbyaddr


class Module(BaseModule, ThreadingMixin):
    meta = {
	    'name': 'SSH Login Scanner',
		'author': 'James Luther',
		'description': 'Tests credentials against specified hosts.',
		'comments': (
		    'This is an ssh scanner to test pubkey logins. The default rhosts is all with port 22 open',
		),
		'options': (
		    ('rhosts', 'default', True, 'Hosts you wish to try against (tuple, all, default, port number [ex: port 22])'),
			('username', None, True, 'Username you wish to try'),
			('keypath', None, True, 'Path to key to try'),
		),
	}
	
	def module_run(self):
	    user = self.options['username']
		key = self.options['keypath']
		rhosts = self.options['rhosts']
		hosts = []
		if not os.path.exists(key):
		    raise RuntimeError("File does not exist {}'.format(key))
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
		self.thread(hosts, user, key)
		
	def module_thread(self, host, user, key):
	    denied = "Permission denied"
		new = "Are you sure you want to continue"
		closed = "Connection closed by remote host"
		resolve = "Could not resolve hostname"
		password = "{0}@{1}'s password:".format(user, host)
		connect = "ssh {0}@{1} -i {2} -o PasswordAuthentication=no".format(user, host, key)
		try:
		    self.verbose('Trying host: {0} with User: {1} and Key: {2}'.format(host, user, key))
			c = pexpect.spawn(connect)
			r = c.expect([pexpect.TIMEOUT, denied, new, closed, resolve, password, '$', '#', ])
			if r is 2:
			    c.sendline('yes')
			if r is 3:
			    self.error('Login failed for host: {}'.format(host))
			if r is 4:
			    self.error('Login failed for host: {}'.format(host))
			if r > 5:
			    self.alert('Login successful for {}'.format(host))
				c.sendline('exit')
			    try:
			        name = gethostbyaddr(host)[0]
			    except:
			        name = ''
			    try:
			        self.verbose('Adding host: {} to credentials.'.format(host))
				    self.add_credentials(ip_address=host, username=user, password=key)
				    self.add_hosts(ip_address=host, host=name)
			    except Exception as e:
			        self.error('Unable to add credentials. Error: {}'.format(e))
		except Exception:
		    self.error('Login failed for host: {}'.format(host))