# this is experimental!
import asyncio
import copy
import ssl
import platform
import traceback
from typing import Callable
from asysocks.unicomm.protocol.socks5 import SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5PlainAuth, \
	SOCKS5AuthFailed, SOCKS5PlainAuthReply, SOCKS5ReplyType, SOCKS5Request, SOCKS5Reply, \
	SOCKS5ServerErrorReply


from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget
from asysocks.unicomm.common.packetizers import Packetizer, StreamPacketizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL
from asysocks.unicomm.common.connection import UniConnection, UniUDPConnection
from asysocks.unicomm import logger
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.protocol.server.udp import UDPProtocol
import ipaddress


class ProxyChainError(Exception):
	def __init__(self, innerexception, message="Something failed setting up the proxy chain! See innerexception for more details"):
		self.innerexception = innerexception
		self.message = message
		super().__init__(self.message)


class UniServer:
	def __init__(self, target:UniTarget, packetizer:Packetizer, bindtype:int = None, handoff:bool = False):
		self.target = target
		self.bindtype = bindtype
		# ADSCAN: handoff mode. The server binds nothing; connections accepted by
		# an external owner of the port (ADscan's listener broker) are fed in
		# through ``handle_accepted_stream`` and dispatched exactly as if this
		# server had accepted them (same packetizer, same TLS handshake).
		self.handoff = handoff
		self.packetizer = packetizer
		self.bind_progress_evt = asyncio.Event()
		self.connection_queue = asyncio.Queue()
		self.udpprotocol = None
		self.udptransport = None
		self.udpsocket = None

	def get_interface_from_ip(self):
		try:
			import netifaces
		except:
			logger.warning('netifaces not found! Install it with "pip install netifaces"')
			return []
		
		interfaces = []
		for interface in netifaces.interfaces():
			addresses = netifaces.ifaddresses(interface)
			# Check for IPv4 addresses
			if netifaces.AF_INET in addresses:
				for addr_info in addresses[netifaces.AF_INET]:
					if addr_info['addr'] == self.target.ip or self.target.ip in ['','0.0.0.0', '::', '::0']:
						interfaces.append(interface)
			# Check for IPv6 addresses
			if netifaces.AF_INET6 in addresses:
				for addr_info in addresses[netifaces.AF_INET6]:
					if addr_info['addr'] == self.target.ip or self.target.ip in ['','0.0.0.0', '::', '::0']:
						interfaces.append(interface)
		return interfaces
	
	def get_ips_from_interface(self, interface:str, ip_version:int = 4):
		try:
			import netifaces
		except:
			logger.warning('netifaces not found! Install it with "pip install netifaces"')
			return []
		
		ips = []
		if ip_version == 4:
			addresses = netifaces.ifaddresses(interface)
			if netifaces.AF_INET in addresses:
				for addr_info in addresses[netifaces.AF_INET]:
					ips.append(addr_info['addr'])
		elif ip_version == 6:
			addresses = netifaces.ifaddresses(interface)
			if netifaces.AF_INET6 in addresses:
				for addr_info in addresses[netifaces.AF_INET6]:
					ips.append(addr_info['addr'])
		return ips
	
	async def run_socks5(self, proxy:UniProxyTarget, connection:UniConnection, timeout:int = None):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		stream_task = asyncio.create_task(connection.stream())
		sname = proxy.get_sname()
		tname = proxy.get_tname()
		methods = [SOCKS5Method.NOAUTH]
		if proxy.credential is not None and proxy.credential.username is not None and proxy.credential.password is not None:
			methods.append(SOCKS5Method.PLAIN)
			#methods = [SOCKS5Method.PLAIN]
		try:
			nego = SOCKS5Nego.from_methods(methods)
			logger.debug('[SOCKS5 %s][SETUP] Sending negotiation command to server' % sname)
			await connection.write(nego.to_bytes())

			rep_nego = await asyncio.wait_for(
				SOCKS5NegoReply.from_streamreader(connection.packetizer), 
				timeout = timeout
			)
			logger.debug(
				'[SOCKS5 %s] Got negotiation reply! Server choosen auth type: %s' % (sname, rep_nego.METHOD.name)
			)
			
			if rep_nego.METHOD == SOCKS5Method.PLAIN:
				if proxy.credential is None or proxy.credential.username is None or proxy.credential.password is None:
					raise Exception('SOCKS5 %s] server requires PLAIN authentication, but no credentials were supplied!' % sname)
				
				logger.debug('[SOCKS5 %s]Preforming plaintext auth' % sname)
				await connection.write(
					SOCKS5PlainAuth.construct(
						proxy.credential.username, 
						proxy.credential.password
					).to_bytes()
				)
				rep_data = await asyncio.wait_for(
					connection.packetizer.readexactly(2),
					timeout = timeout
				)

				if rep_data == b'':
					raise SOCKS5AuthFailed() #raise Exception('Plaintext auth failed! Bad username or password')

				rep_nego = SOCKS5PlainAuthReply.from_bytes(rep_data)

				if rep_nego.STATUS != SOCKS5ReplyType.SUCCEEDED:
					raise SOCKS5AuthFailed() #raise Exception('Plaintext auth failed! Bad username or password')

			elif rep_nego.METHOD == SOCKS5Method.GSSAPI:
				raise Exception('[SOCKS5 %s] server requires GSSAPI authentication, but it\'s not supported at the moment' % sname)

			logger.debug('[SOCKS5 %s] Opening channel to %s' % (sname, tname))

			await connection.write(
				SOCKS5Request.from_target(
					proxy
				).to_bytes()
			)
			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(connection.packetizer), 
				timeout=timeout
			)
			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				logger.info('[SOCKS5 %s] remote end failed to connect to proxy! Reson: %s' % (sname, rep.REP.name))
				raise SOCKS5ServerErrorReply(rep.REP)
			
			if proxy.protocol.name.startswith('SERVER') is False:
				logger.debug('[SOCKS5 %s] Successfully set up the connection to the endpoint %s ' % (sname,tname))
				return True, None
			
			logger.debug('[SOCKS5 %s] BIND first set completed, port %s available!' % (sname , rep.BIND_PORT))
			#bind in progress, waiting for a second reply to notify us that the remote endpoint connected back.
			
			self.bind_port = rep.BIND_PORT
			self.bind_progress_evt.set() #notifying that the bind port is now available on the socks server to be used
			if proxy.only_bind is True:
				return True, None

			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(connection.packetizer), 
				timeout=timeout
			)

			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				logger.info('[SOCKS5 %s] remote end failed to connect to proxy! Reson: %s' % (sname, rep.REP.name))
				raise SOCKS5ServerErrorReply(rep.REP)
			return True, None

		except Exception as e:
			logger.debug('[SOCKS5 %s] Error in run_socks5 %s' % (sname, e))
			return False, e
		finally:
			if stream_task is not None:
				stream_task.cancel()
	
	async def create_link(self):
		remote_writer = None
		remote_reader = None

		try:
			if len(self.target.proxies) > 1:
				logger.debug('Start chaining...')
				
			if len(self.target.proxies) == 1:
				if self.target.proxies[0].protocol == UniProxyProto.SERVER_WSNET:
					from wsnet.pyodide.tcpserver import WSNetworkTCPServer
					if self.target.protocol == UniProto.SERVER_TCP:
						return await WSNetworkTCPServer(self.__handle_connection, self.target.get_ip_or_hostname(), self.target.port, bindtype = 1, reuse_ws = True).run()
					elif self.target.protocol == UniProto.SERVER_SSL_TCP:
						return await WSNetworkTCPServer(self.__handle_connection_ssl, self.target.get_ip_or_hostname(), self.target.port, bindtype = 1, reuse_ws = True).run()
					else:
						raise Exception('WSNET unimplemented proto %s' % self.target.protocol)
				elif self.target.proxies[0].protocol in [UniProxyProto.SERVER_SOCKS5_TCP, UniProxyProto.CLIENT_SSL_SOCKS5_TCP, UniProxyProto.SERVER_SOCKS5_UDP, UniProxyProto.SERVER_SSL_SOCKS5_UDP]:
					#### SOCKS TCP BIND only allows one (1) connection at a time!!!!!! This is a limitation in the RFC
					try:
						ttarget = UniTarget(self.target.proxies[0].server_ip, self.target.proxies[0].server_port, protocol=UniProto.CLIENT_TCP)							
						client = UniClient(ttarget, StreamPacketizer())
						connection = await client.connect()
						_, err = await asyncio.wait_for(self.run_socks5(self.target.proxies[0], connection), timeout=self.target.proxies[-1].timeout)
						if err is not None:
							raise err
						if self.target.protocol == UniProto.SERVER_TCP:
							connection.change_packetizer(copy.deepcopy(self.packetizer))
							await self.connection_queue.put(connection)
							return connection, None
						elif self.target.protocol == UniProto.SERVER_SSL_TCP:
							ssl_ctx = self.target.get_ssl_context(ssl.PROTOCOL_TLS_SERVER)
							packetizer = PacketizerSSL(ssl_ctx, packetizer)
							await packetizer.do_handshake(connection.packetizer, connection, server_side=True)
							connection = UniConnection(connection.packetizer, connection, packetizer)
							await self.connection_queue.put(connection)
							return connection, None

					except asyncio.TimeoutError:
						raise Exception('Proxy Connection establishment timeout')
				else:
					raise Exception("Unsupported proxy protocol %s" % self.target.proxies[0].protocol)
			else:
				raise NotImplementedError()
				client_target = self.target.get_preproxy()
				client = UniClient(client_target, Packetizer())
				connection = await client.connect()

			raise Exception('Should not be here!')		
		except Exception as e:
			logger.exception('[create_link]')
			if remote_writer is not None:
				remote_writer.close()
			raise

	async def handle_accepted_stream(self, reader, writer):
		"""Serve one connection accepted by an external listener (handoff mode)."""
		if self.target.protocol == UniProto.SERVER_SSL_TCP:
			await self.__handle_connection_ssl(reader, writer)
		else:
			await self.__handle_connection(reader, writer)

	async def __handoff_queue(self):
		while True:
			connection = await self.connection_queue.get()
			yield connection

	async def tcp_dispatcher_handoff(self, connection_callback:Callable[[UniConnection], None]):
		while True:
			connection = await self.connection_queue.get()
			asyncio.create_task(connection_callback(connection))

	async def __handle_connection(self, reader, writer):
		packetizer = copy.deepcopy(self.packetizer)
		connection = UniConnection(reader, writer, packetizer)
		await self.connection_queue.put(connection)
		#await connection.closed_evt.wait()

	async def __handle_connection_ssl(self, reader, writer):
		ssl_ctx = None
		try:
			packetizer = copy.deepcopy(self.packetizer)
			ssl_ctx = self.target.get_ssl_context(ssl.PROTOCOL_TLS_SERVER)
			packetizer = PacketizerSSL(ssl_ctx, packetizer)
			await packetizer.do_handshake(reader, writer, server_side=True)
			connection = UniConnection(reader, writer, packetizer)
			await self.connection_queue.put(connection)
			#await connection.closed_evt.wait()
		finally:
			if ssl_ctx is not None:
				del ssl_ctx

	async def start_generic_udp_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, self.target.get_ip_or_hostname(), self.target.port, bindtype = 1, reuse_ws = True)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, wsnetserver.writer, None
			import socket
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.bind((self.target.get_ip_or_hostname(), self.target.port))
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, sock, None
		except Exception as e:
			return None, None, None, e			  

	async def start_llmnr_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, self.target.hostname, 5355, bindtype = 2, reuse_ws = False)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, wsnetserver.writer, None
			
			import socket
			import struct
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

			sock.bind(('', 5355))
			llmnr_addr = "224.0.0.252"
			llmnr_addr6 = "FF02:0:0:0:0:0:1:3"

			# IPv4
			for ip in self.get_ips_from_interface(self.target.hostname, 4):
				mreq = socket.inet_aton(llmnr_addr) + socket.inet_aton(ip)
				sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

			# IPv6
			try:
				if_index = socket.if_nametoindex(self.target.hostname)
				mreq6 = socket.inet_pton(socket.AF_INET6, llmnr_addr6) + struct.pack('@I', if_index)
				sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq6)
			except Exception as e:
				pass
			
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, sock, None
		except Exception as e:
			return None, None, None, e
		
	async def start_mdns_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, self.target.hostname, 5353, bindtype = 4, reuse_ws = False)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, wsnetserver.writer, None
			
			import socket
			import struct
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			mdns_addr = "224.0.0.251"
			mdns_addr6 = "FF02::FB"
			sock.bind(('', 5353))

			# IPv4
			for ip in self.get_ips_from_interface(self.target.hostname, 4):
				mreq = socket.inet_aton(mdns_addr) + socket.inet_aton(ip)
				sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

			# IPv6
			try:
				if_index = socket.if_nametoindex(self.target.hostname)
				mreq6 = socket.inet_pton(socket.AF_INET6, mdns_addr6) + struct.pack('@I', if_index)
				sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq6)
			except Exception as e:
				pass
			
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, sock, None
		except Exception as e:
			return None, None, None, e
		
	async def start_nbtns_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, self.target.hostname, 137, bindtype = 3, reuse_ws = False)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, wsnetserver.writer, None
			
			import socket
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			for ip in self.get_ips_from_interface(self.target.hostname, 4):
				sock.bind((ip, 137))
				break
			
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, sock, None
		except Exception as e:
			return None, None, None, e
		
	async def sendto(self, data, addr):
		if self.udpsocket is None:
			raise Exception('UDP Server not started!')
		if asyncio.iscoroutine(self.udpsocket.sendto) is True:
			await self.udpsocket.sendto(data, addr)
		else:
			self.udpsocket.sendto(data, addr)
	
	async def start_udp_server(self):
		if self.udpsocket is not None:
			return True, None
		
		try:
			if self.bindtype == 1:
				self.udptransport, self.udpprotocol, self.udpsocket, err = await self.start_generic_udp_server()
				if err is not None:
					raise err
					
			elif self.bindtype == 2:
				self.udptransport, self.udpprotocol, self.udpsocket, err = await self.start_llmnr_server()
				if err is not None:
					raise err
					
			elif self.bindtype == 3:
				self.udptransport, self.udpprotocol, self.udpsocket, err = await self.start_nbtns_server()
				if err is not None:
					raise err

			elif self.bindtype == 4:
				self.udptransport, self.udpprotocol, self.udpsocket, err = await self.start_mdns_server()
				if err is not None:
					raise err

			else:
				raise Exception('Unsupported bindtype %s' % self.bindtype)
			
			return True, None
		except Exception as e:
			return None, e

	async def serve(self):
		server = None
		serverobj = None
		try:

			if self.target.protocol == UniProto.SERVER_UDP:
				_, err = await self.start_udp_server()
				if err is not None:
					raise err

				while True:
					socket, data, addr = await self.udpprotocol.in_queue.get()
					yield UniUDPConnection(socket, data, addr)
			
			else:
				if len(self.target.proxies) > 0:
					server, err = await self.create_link()
					if err is not None:
						raise err
					while not server.closed_evt.is_set():
						connection = await self.connection_queue.get()
						yield connection
					
				elif self.handoff is True and self.target.protocol in [UniProto.SERVER_TCP, UniProto.SERVER_SSL_TCP]:
					async for connection in self.__handoff_queue():
						yield connection
				else:
					if self.target.protocol in [UniProto.SERVER_TCP, UniProto.SERVER_SSL_TCP]:
						if self.target.protocol == UniProto.SERVER_TCP:
							server = await asyncio.start_server(self.__handle_connection, self.target.get_ip_or_hostname(), self.target.port)
						elif self.target.protocol == UniProto.SERVER_SSL_TCP:
							server = await asyncio.start_server(self.__handle_connection_ssl, self.target.get_ip_or_hostname(), self.target.port)
						while server.is_serving():
							connection = await self.connection_queue.get()
							yield connection
					else:
						raise Exception('Unknown protocol "%s"' % self.target.protocol)
		finally:
			if server is not None:
				try:
					server.close()
				except:
					pass
			if self.udpprotocol is not None:
				try:
					self.udpprotocol.close()
				except:
					pass
			if self.udpsocket is not None:
				try:
					self.udpsocket.close()
				except:
					pass
			
	
	async def udp_dispatcher(self, connection_callback:Callable[[UniUDPConnection], None]):
		try:
			while True:
				socket, data, addr = await self.udpprotocol.in_queue.get()
				x = asyncio.create_task(connection_callback(UniUDPConnection(socket, data, addr)))
		finally:
			if self.udptransport is not None:
				try:
					self.udptransport.close()
				except Exception as e:
					pass
			if self.udpprotocol is not None:
				try:
					self.udpprotocol.close()
				except Exception as e:
					pass
			if self.udpsocket is not None:
				try:
					self.udpsocket.close()
				except Exception as e:
					pass

	async def tcp_dispatcher(self, server, connection_callback:Callable[[UniConnection], None]):
		try:
			while not server.closed_evt.is_set():
				connection = await self.connection_queue.get()
				x = asyncio.create_task(connection_callback(connection))
		finally:
			if server is not None:
				try:
					server.close()
				except:
					pass

	async def tcp_dispatcher_builtin(self, server, connection_callback:Callable[[UniConnection], None]):
		try:
			while server.is_serving():
				connection = await self.connection_queue.get()
				x = asyncio.create_task(connection_callback(connection))
		finally:
			if server is not None:
				try:
					server.close()
				except:
					pass


	async def serve_callback(self, connection_callback:Callable[[UniConnection], None]):
		server = None
		try:
			if self.target.protocol == UniProto.SERVER_UDP:
				_, err = await self.start_udp_server()
				if err is not None:
					raise err

				dispatcher_task = asyncio.create_task(self.udp_dispatcher(connection_callback))
			
			else:
				if len(self.target.proxies) > 0:
					server, err = await self.create_link()
					if err is not None:
						raise err
					
					dispatcher_task = asyncio.create_task(self.tcp_dispatcher(server, connection_callback))

				elif self.handoff is True and self.target.protocol in [UniProto.SERVER_TCP, UniProto.SERVER_SSL_TCP]:
					dispatcher_task = asyncio.create_task(self.tcp_dispatcher_handoff(connection_callback))
				else:
					if self.target.protocol in [UniProto.SERVER_TCP, UniProto.SERVER_SSL_TCP]:
						if self.target.protocol == UniProto.SERVER_TCP:
							server = await asyncio.start_server(self.__handle_connection, self.target.get_ip_or_hostname(), self.target.port)
						elif self.target.protocol == UniProto.SERVER_SSL_TCP:
							server = await asyncio.start_server(self.__handle_connection_ssl, self.target.get_ip_or_hostname(), self.target.port)
						dispatcher_task = asyncio.create_task(self.tcp_dispatcher_builtin(server, connection_callback))

					else:
						raise Exception('Unknown protocol "%s"' % self.target.protocol)

			return dispatcher_task, None
		except Exception as e:
			return None, e


async def amain():
	import logging

	logger.setLevel(logging.DEBUG)
	proxy = UniProxyTarget()
	proxy.server_ip = '127.0.0.1'
	proxy.server_port = 1080
	proxy.protocol = UniProxyProto.SERVER_SOCKS5_TCP
	target = UniTarget('0.0.0.0', 9999, UniProto.SERVER_TCP, proxies=[proxy])
	packetizer = Packetizer()

	server = UniServer(target, packetizer)
	async for connection in server.serve():
		print('Client connected!')
		async for data in connection.read():
			print(data)




def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()