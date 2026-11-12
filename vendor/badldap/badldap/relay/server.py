from asysocks.unicomm.server import UniServer
from badldap.network.packetizer import LDAPPacketizer
from badldap.relay.serverconnection import LDAPRelayServerConnection
import asyncio

async def _noop_log_callback(msg: str) -> None:
	pass

class LDAPServerSettings:
	def __init__(self, gssapi_factory, log_callback=_noop_log_callback):
		self.gssapi_factory = gssapi_factory
		self.log_callback = log_callback

	@property
	def gssapi(self):
		return self.gssapi_factory()

class LDAPRelayServer:
	def __init__(self, target, settings, handoff = False):
		self.target = target
		self.settings = settings
		# ADSCAN: handoff mode binds nothing; ADscan's listener broker owns the
		# port and feeds each routed connection to ``handle_stream``.
		self.handoff = handoff
		self.server = None
		self.serving_task = None
		self.connections = {}
		self.conn_ctr = 0

	def get_ctr(self):
		self.conn_ctr += 1
		return self.conn_ctr

	async def print(self, msg):
		if self.settings.log_callback is not None:
			await self.settings.log_callback(f'[LDAPRELAY] {msg}')

	async def __handle_connection(self):
		try:
			async for connection in self.server.serve():
				await self.print('[INF] Got new connection!')
				smbconnection = LDAPRelayServerConnection(self.settings, connection)
				self.connections[self.get_ctr()] = smbconnection
				asyncio.create_task(smbconnection.run())

		except Exception as e:
			await self.print('[ERR] %s' % e)
			return

	async def run(self):
		self.server = UniServer(self.target, LDAPPacketizer(), handoff = self.handoff)
		self.serving_task = asyncio.create_task(self.__handle_connection())
		return self.serving_task

	async def handle_stream(self, reader, writer):
		"""Serve one connection accepted by an external listener (handoff mode)."""
		await self.server.handle_accepted_stream(reader, writer)

# ADSCAN log-hygiene: removed the upstream ``test_relay_queue`` / ``amain`` /
# ``if __name__ == '__main__':`` self-test harness. It printed relayed auth
# queue items and SMB login errors raw to stdout (``print(item)`` could surface
# relayed credential material, bypassing telemetry). The runtime ADscan path
# only uses ``LDAPRelayServer`` above, whose ``print()`` routes through the
# sanctioned ``log_callback`` channel. Deleting the harness removes a latent
# stdout-leak path with zero runtime value.
