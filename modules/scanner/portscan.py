from recon.core.module import BaseModule
from recon.mixins.threads import ThreadingMixin

from socket import *

class module(BaseModule, ThreadingMixin):

	meta = {
		'name': 'TCP Port Scanner',
		'author': 'James Luther',
		'description': 'TCP Port scanner that loads data into your workspace',
		'comments': (
			'This is a simple tcp scanner',
		),
		'options': (
			('rhosts', 'all', True, 'Hosts you wish to scan. Default is all hosts'),
			('rports', 'all', True, 'Ports you want to include (1-65535 is default)'),
		),
	}
	
	def module_run(self):
		rports = self.option['rports']
		rhosts = self.option['rhosts']
		ips = []
		if str(rports) > 2:
			ports = rports.split(',')
		else:
			ports = [rports]
		if rhosts == 'all':
			query = self.query('SELECT ip_address from hosts where ip_address is not Null')
			for ip in query:
			    ips.append(ip[0])
		else:
			ips.append(rhosts)
		if rports == "all":
			ports = list(range(1, 65535))
		for ip in ips:
			self.thread(ports, ip)
			
	def module_thread(self, port, ip):
		sock = socket(AF_INET, SOCK_STREAM)
		try:
			self.verbose('Scanning host: {0} Port: {1}'.format(ip, port))
			sock.connect((ip, int(port)))
			sock.send(' \r\n')
			results = sock.recv(100)
			self.alert('Found open port: {0} Banner: {1}'.format(port, results.strip('\r\n')))
			sock.close()
			try:
				name = gethostbyaddr(ip)[0]
			except:
				name = ""
			try:
				self.add_ports(ip_address=ip, host=name, port=port, banner=results.strip('\r\n'), protocol='tcp')
				self.add_hosts(ip_address=ip, host=name)
			except:
				self.error('Unable to add results to database')
		except:
			self.verbose('Port: {} closed.'.fromat(port))