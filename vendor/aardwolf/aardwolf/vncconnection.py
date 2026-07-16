
#
#
# TODO: Better keyboard handling
# TODO: Add more rectangle decoding options
# TODO: Add more security handshake options (all of the RFC is already implemented, so only custom are to be added)

import io
import asyncio
import traceback
from struct import pack, unpack
from typing import cast

from aardwolf import logger
from aardwolf.transport.tcpstream import TCPStream
from unicrypto.symmetric import DES, MODE_ECB

from aardwolf.commons.target import RDPTarget
from aardwolf.commons.queuedata import RDPDATATYPE, RDP_KEYBOARD_SCANCODE, RDP_KEYBOARD_UNICODE, \
	RDP_MOUSE, RDP_VIDEO, RDP_CLIPBOARD_READY, RDP_CLIPBOARD_DATA_TXT, RDP_CLIPBOARD_NEW_DATA_AVAILABLE, \
	RDP_BEEP
from aardwolf.extensions.RDPECLIP.protocol.formatlist import CLIPBRD_FORMAT
from aardwolf.protocol.vnc.keyboard import *
from aardwolf.keyboard import VK_MODIFIERS
from aardwolf.keyboard.layoutmanager import KeyboardLayoutManager
from aardwolf.commons.queuedata.constants import MOUSEBUTTON, VIDEO_FORMAT
from aardwolf.commons.iosettings import RDPIOSettings
from badauth.common.credentials import UniCredential
from badauth.common.constants import asyauthSecret
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.connection import UniConnection
from asysocks.unicomm.common.packetizers import StreamPacketizer

from PIL import Image
try:
	from PIL.ImageQt import ImageQt
except ImportError:
	logger.debug('No Qt installed! Converting to qt will not work')

# librlers is an OPTIONAL Rust extension (setup.py declares it optional=True) that
# aardwolf compiles from its own source for VNC/RDP bitmap decompression. If the
# rust toolchain is absent at build time it is silently skipped, so this module
# must import it defensively — otherwise the hard import breaks `import aardwolf`
# entirely (commons/factory imports VNCConnection), taking down RDP AUTH too even
# though auth never needs bitmap decode. Mirrors the guard already in
# utils/rectconvert.py. The two call sites below (mask_rgbx/decode_rre) are
# VNC-decode only and raise a clear error if reached without librlers.
try:
	import librlers
except ImportError:
	librlers = None  # type: ignore[assignment]

# https://datatracker.ietf.org/doc/html/rfc6143

RAW_ENCODING = 0
COPY_RECTANGLE_ENCODING = 1
RRE_ENCODING = 2
CORRE_ENCODING = 4
HEXTILE_ENCODING = 5
ZLIB_ENCODING = 6
TIGHT_ENCODING = 7
ZLIBHEX_ENCODING = 8
TRLE_ENCODING = 15
ZRLE_ENCODING = 16

class VNCConnection:
	def __init__(self, target:RDPTarget, credentials:UniCredential, iosettings:RDPIOSettings):
		self.target = target
		self.credentials = credentials
		self.authapi = None
		self.iosettings = iosettings
		self.__connection:UniConnection = None
		self.shared_flag = False
		self.client_version = '003.008'
		self.server_version = None
		self.server_name = None
		self.disconnected_evt = asyncio.Event() #this will be set if we disconnect for whatever reason
		self.server_supp_security_types = []
		self.__selected_security_type = 1 if self.credentials.stype == asyauthSecret.NONE else 2 #currently we only support these 2
		self.__refresh_screen_task = None
		self.__reader_loop_task = None
		self.__external_reader_task = None
		self.__use_pyperclip = False

		# these are the main queues with which you can communicate with the server
		# ext_out_queue: yields video data
		# ext_in_queue: expects keyboard/mouse data
		self.ext_out_queue = asyncio.Queue()
		self.ext_in_queue = asyncio.Queue()

		self.__reader = None
		self.__writer = None


		self.bpp = None
		self.bypp = None
		self.depth = None
		self.bigendian = None
		self.truecolor = None 
		self.redmax = None 
		self.greenmax = None
		self.bluemax = None
		self.redshift = None 
		self.greenshift = None
		self.blueshift = None
		self.width = None
		self.height = None
		self.__desktop_buffer = None
		self.desktop_buffer_has_data = False

		self.__vk_to_vnckey = {
			'VK_BACK' : KEY_BackSpace,
			'VK_ESCAPE' : KEY_Escape,
			'VK_TAB' : KEY_Tab,
			'VK_RETURN' : KEY_Return,
			'VK_INSERT' : KEY_Insert,
			'VK_DELETE' : KEY_Delete,
			'VK_HOME' : KEY_Home,
			'VK_END' : KEY_End,
			'VK_PRIOR' : KEY_PageUp,
			'VK_NEXT' : KEY_PageDown,
			'VK_LEFT' : KEY_Left,
			'VK_UP' : KEY_Up,
			'VK_RIGHT' : KEY_Right,
			'VK_DOWN' : KEY_Down,
			'VK_HOME' : KEY_Home,
			'VK_F1' : KEY_F1,
			'VK_F2' : KEY_F2,
			'VK_F3' : KEY_F3,
			'VK_F4' : KEY_F4,
			'VK_F5' : KEY_F5,
			'VK_F6' : KEY_F6,
			'VK_F7' : KEY_F7,
			'VK_F8' : KEY_F8,
			'VK_F9' : KEY_F9,
			'VK_F10' : KEY_F10,
			'VK_F11' : KEY_F11,
			'VK_F12' : KEY_F12,
			#'VK_F13' : KEY_F13,
			#'VK_F14' : KEY_F14,
			#'VK_F15' : KEY_F15,
			#'VK_F16' : KEY_F16,
			#'VK_F17' : KEY_F17,
			#'VK_F18' : KEY_F18,
			#'VK_F19' : KEY_F19,
			#'VK_F20' : KEY_F20,
			'VK_LSHIFT' : KEY_ShiftLeft,
			'VK_RSHIFT' : KEY_ShiftRight,
			'VK_LCONTROL' : KEY_ControlLeft,
			'VK_RCONTROL' : KEY_ControlRight,
			'VK_LWIN' : KEY_Super_L,
			'VK_RWIN' : KEY_Super_R,
			'VK_LMENU' : KEY_AltLeft,
			'VK_RMENU' : KEY_AltRight,
			'VK_SCROLL' : KEY_Scroll_Lock,
			#'????' : KEY_Sys_Req,
			'VK_NUMLOCK' : KEY_Num_Lock,
			'VK_CAPITAL' : KEY_Caps_Lock,
			'VK_PAUSE' : KEY_Pause,
			#'????' : KEY_Super_L,
			#'????' : KEY_Super_R,
			#'????' : KEY_Hyper_L,
			#'????' : KEY_Hyper_R,
			#'????' : KEY_KP_0,
			#'????' : KEY_KP_1,
			#'????' : KEY_KP_2,
			#'????' : KEY_KP_3,
			#'????' : KEY_KP_4,
			#'????' : KEY_KP_5,
			#'????' : KEY_KP_6,
			#'????' : KEY_KP_7,
			#'????' : KEY_KP_8,
			#'????' : KEY_KP_9,
			#'????': KEY_KP_Enter,
			'VK_MULTIPLY': KEY_KP_Multiply,
			'VK_ADD': KEY_KP_Add,
			'VK_SUBTRACT': KEY_KP_Subtract,
			'VK_DECIMAL' : KEY_KP_Decimal,
			'VK_DIVIDE' : KEY_KP_Divide,
			'VK_SNAPSHOT' : KEY_Print,
			'VK_DBE_NOCODEINPUT' : KEY_KP_Divide,
		}

		self.__keyboard_layout = KeyboardLayoutManager().get_layout_by_shortname(self.iosettings.client_keyboard)
	
	async def terminate(self):
		try:
			if self.__writer is not None:
				await self.__writer.close()
			if self.__refresh_screen_task is not None:
				self.__refresh_screen_task.cancel()
			if self.__reader_loop_task is not None:
				self.__reader_loop_task.cancel()
			if self.__external_reader_task is not None:
				self.__external_reader_task.cancel()
			
			return True, None
		except Exception as e:
			traceback.print_exc()
			return None, e
		finally:
			self.disconnected_evt.set()
	
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await asyncio.wait_for(self.terminate(), timeout = 5)
	
	def get_extra_info(self):
		# to have the same interface as RDP
		return None
	
	async def connect(self):
		"""
		Performs the entire connection sequence 
		"""
		try:
			packetizer = StreamPacketizer()
			client = UniClient(self.target, packetizer)
			self.__connection = await client.connect()
			asyncio.create_task(self.__connection.stream())
			self.__reader = self.__connection.packetizer
			self.__writer = self.__connection

			logger.debug('Performing banner exchange')
			_, err = await self.__banner_exchange()
			if err is not None:
				raise err
			logger.debug('Banner exchange OK')

			logger.debug('Performing security handshake')
			_, err = await self.__security_handshake()
			if err is not None:
				raise err
			logger.debug('Security handshake OK')

			logger.debug('Authenticating')
			_, err = await self.__authenticate()
			if err is not None:
				raise err
			logger.debug('Authentication OK')

			logger.debug('Setting up clipboard')
			_, err = await self.__setup_clipboard()
			if err is not None:
				raise err
			
			logger.debug('Client init')
			_, err = await self.__client_init()
			if err is not None:
				raise err
			logger.debug('Client init OK')

			logger.debug('Starting internal comm channels')
			self.__reader_loop_task = asyncio.create_task(self.__reader_loop())
			self.__external_reader_task = asyncio.create_task(self.__external_reader())
			logger.debug('Sending cliboard ready signal') #to emulate RDP clipboard functionality
			msg = RDP_CLIPBOARD_READY()
			await self.ext_out_queue.put(msg)
			
			return True, None
		except Exception as e:
			await self.terminate()
			return None, e

	async def __setup_clipboard(self):
		if self.iosettings.clipboard_use_pyperclip is True:
			try:
				import pyperclip
			except ImportError:
				logger.debug('Could not import pyperclip! Copy-paste will not work!')
				self.__use_pyperclip = False
			else:
				self.__use_pyperclip = True
				if not pyperclip.is_available():
					logger.debug("pyperclip - Copy functionality available!")
		return True, None
	
	async def __banner_exchange(self):
		try:
			banner = await self.__reader.readuntil(b'\n')
			self.server_version = banner[4:-1].decode()
			logger.debug('Server version: %s' % self.server_version)
			version_reply = b'RFB %s\n' % self.client_version.encode()
			logger.debug('Version reply: %s' % version_reply)
			await self.__writer.write(version_reply)
			return True, None
		except Exception as e:
			return None, e

	async def __security_handshake(self):
		try:
			no_sec_types = await self.__reader.readexactly(1)
			no_sec_types = ord(no_sec_types)
			if no_sec_types == 0:
				logger.debug('Server sent empty support security types, connection will terminate soon')
				err_string_size = await self.__reader.readexactly(1)
				err_string_size = ord(err_string_size)
				err_string = await self.__reader.readexactly(err_string_size)
				err_string = err_string.decode()
				raise Exception(err_string)
			sec_types = await self.__reader.readexactly(no_sec_types)
			for sectype in sec_types:
				self.server_supp_security_types.append(sectype)
			
			if self.__selected_security_type not in self.server_supp_security_types:
				raise Exception('Clound\'t find common authentication type. Client supports: %s Server supports: %s' % (self.__selected_security_type, ','.join([str(x) for x in self.server_supp_security_types])))


			return True, None
		except Exception as e:
			return None, e

	async def __authenticate(self):
		try:
			if self.__selected_security_type == 0:
				logger.debug('Invalid authentication type!!!')
				raise Exception('Invalid authentication type')
			
			elif self.__selected_security_type == 1:
				# nothing to do here
				logger.debug('Selecting NULL auth type')

			
			elif self.__selected_security_type == 2:
				logger.debug('Selecting default VNC auth type')
				await self.__writer.write(bytes([self.__selected_security_type]))
				challenge = await self.__reader.readexactly(16)

				# no username used here, but we support RDP as well
				password = self.credentials.secret
				if self.credentials.secret is None:
					password = self.credentials.username
				
				password = password.ljust(8, '\x00').encode('ascii')
				password = password[:8]
				# converting password to key
				newkey = b''
				for ki in range(len(password)):
					bsrc = password[ki]
					btgt = 0
					for i in range(8):
						if bsrc & (1 << i):
							btgt = btgt | (1 << 7 - i)
					newkey+= bytes([btgt])
				ctx = DES(newkey, mode = MODE_ECB, IV = None)
				response = ctx.encrypt(challenge)
				await self.__writer.write(response)

			else:
				raise Exception('Unsupported security type selected!')
			
			auth_result = await self.__reader.readexactly(4)
			auth_result = int.from_bytes(auth_result, byteorder = 'big', signed=False)
			if auth_result != 0:
				logger.debug('Auth Failed! Auth result: %s' % auth_result)
				err_string_size = await self.__reader.readexactly(4)
				err_string_size = int.from_bytes(err_string_size, byteorder = 'big', signed=False)
				err_string = await self.__reader.readexactly(err_string_size)
				err_string = err_string.decode()
				raise Exception(err_string)
			logger.debug('Auth OK!')
			return True, None
		except Exception as e:
			return None, e
	
	async def __client_init(self):
		try:
			# sending client init
			await self.__writer.write(bytes([int(self.shared_flag)]))
			# reading server_init
			framebuffer_width = await self.__reader.readexactly(2)
			self.width = int.from_bytes(framebuffer_width, byteorder = 'big', signed = False)
			framebuffer_height = await self.__reader.readexactly(2)
			self.height = int.from_bytes(framebuffer_height, byteorder = 'big', signed = False)
			pixel_format_raw = await self.__reader.readexactly(16)
			self.bpp, self.depth, self.bigendian, self.truecolor, \
			self.redmax, self.greenmax, self.bluemax, self.redshift, \
			self.greenshift, self.blueshift = unpack("!BBBBHHHBBBxxx", pixel_format_raw)
			self.bypp = self.bpp // 8  # calc bytes per pixel

			name_string_size = await self.__reader.readexactly(4)
			name_string_size = int.from_bytes(name_string_size, byteorder = 'big', signed=False)
			name_string = await self.__reader.readexactly(name_string_size)
			self.server_name = name_string.decode()


			self.__desktop_buffer = Image.new(mode="RGBA", size=(self.width, self.height))
			_, err = await self.set_encodings(self.iosettings.vnc_encodings)
			if err is not None:
				raise err
			
			# don't change this!!!!
			await self.set_pixel_format()
			await self.framebuffer_update_request()
			
			self.__refresh_screen_task = asyncio.create_task(self.__refresh_screen_loop())
			return True, None
		except Exception as e:
			return None, e
	
	async def send_key_virtualkey(self, vk:str, is_pressed:bool, is_extended:bool, scancode_hint:int = None, modifiers = VK_MODIFIERS(0)):
		try:
			if vk is None:
				return await self.send_key_scancode(scancode_hint, is_pressed, is_extended, modifiers=modifiers)
			#print('Got VK: %s' % vk)
			if vk in self.__vk_to_vnckey:
				keycode = self.__vk_to_vnckey[vk]
				return await self.send_key_char(keycode, is_pressed)
			else:
				return await self.send_key_scancode(scancode_hint, is_pressed, is_extended, modifiers=modifiers)
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def send_key_scancode(self, scancode, is_pressed, is_extended, modifiers = VK_MODIFIERS(0)):
		try:
			keycode = None
			if modifiers == VK_MODIFIERS(0):
				vk = self.__keyboard_layout.scancode_to_vk(scancode)
				if vk is not None and vk in self.__vk_to_vnckey:
					keycode = self.__vk_to_vnckey[vk]
			if keycode is None:
				keycode = self.__keyboard_layout.scancode_to_char(scancode, modifiers)
				if keycode is None:
					raise Exception('Failed to resolv key! SC: %s MOD: %s' % (scancode, modifiers))

				elif keycode is not None and len(keycode) == 1:
					keycode = ord(keycode)
				elif keycode is not None and len(keycode) > 1:
					raise Exception('LARGE! Keycode %s resolved to: %s' % (scancode , repr(keycode)))
				else:
					raise Exception('This key is too special! Can\'t resolve it! SC: %s' % scancode)

			return await self.send_key_char(keycode, is_pressed)
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def send_key_char(self, char, is_pressed):
		try:
			msg = pack("!BBxxI", 4, int(is_pressed), char)
			await self.__writer.write(msg)
			return True, None
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def send_mouse(self, button:MOUSEBUTTON, xPos:int, yPos:int, is_pressed:bool):
		try:
			if xPos < 0 or yPos < 0:
				return True, None

			buttoncode = 0
			if button == MOUSEBUTTON.MOUSEBUTTON_LEFT:
				buttoncode = 1
			elif button == MOUSEBUTTON.MOUSEBUTTON_MIDDLE:
				buttoncode = 2
			elif button == MOUSEBUTTON.MOUSEBUTTON_RIGHT:
				buttoncode = 3
			
			buttonmask = 0
			if is_pressed is True:
				if buttoncode == 1: buttonmask &= ~1
				if buttoncode == 2: buttonmask &= ~2
				if buttoncode == 3: buttonmask &= ~4
				if buttoncode == 4: buttonmask &= ~8
				if buttoncode == 5: buttonmask &= ~16
			else:
				if buttoncode == 1: buttonmask |= 1
				if buttoncode == 2: buttonmask |= 2
				if buttoncode == 3: buttonmask |= 4
				if buttoncode == 4: buttonmask |= 8
				if buttoncode == 5: buttonmask |= 16
			
			msg = pack("!BBHH", 5, buttonmask, xPos, yPos)
			await self.__writer.write(msg)
			return True, None
		except Exception as e:
			traceback.print_exc()
			return None, e

	def get_desktop_buffer(self, encoding:VIDEO_FORMAT = VIDEO_FORMAT.PIL):
		"""Makes a copy of the current desktop buffer, converts it and returns the object"""
		try:
			image = self.__desktop_buffer.copy()
			if encoding == VIDEO_FORMAT.PIL:
				return image
			elif encoding == VIDEO_FORMAT.RAW:
				return image.tobytes()
			elif encoding == VIDEO_FORMAT.PNG:
				img_byte_arr = io.BytesIO()
				image.save(img_byte_arr, format='PNG')
				return img_byte_arr.getvalue()
			else:
				raise ValueError('Output format of "%s" is not supported!' % encoding)
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def __external_reader(self):
		# This coroutine handles keyboard/mouse/clipboard etc input from the user
		# It wraps the data in it's appropriate format then dispatches it to the server
		try:
			while not self.disconnected_evt.is_set():
				indata = await self.ext_in_queue.get()
				if indata is None:
					logger.debug('External queue got None, upper layer is exiting!')
					await self.terminate()
					return
				if indata.type == RDPDATATYPE.KEYSCAN:
					indata = cast(RDP_KEYBOARD_SCANCODE, indata)
					if indata.vk_code is not None:
						await self.send_key_virtualkey(indata.vk_code, indata.is_pressed, indata.is_extended, scancode_hint=indata.keyCode, modifiers=indata.modifiers)
					else:
						await self.send_key_scancode(indata.keyCode, indata.is_pressed, indata.is_extended, modifiers=indata.modifiers)
					
					
					
					
					#modifiers = indata.modifiers
					#
					### emulating keys...
					#keycode = None
					#try:
					#	if indata.keyCode is None and indata.vk_code is None:
					#		print('No keycode found! ')
					#		continue
					#
					#	if indata.vk_code is not None:
					#		vk_code = indata.vk_code
					#	else:
					#		vk_code = self.__keyboard_layout.scancode_to_vk(indata.keyCode)
					#	print('Got VK: %s' % vk_code)
					#	if vk_code is None:
					#		print('Could not map SC to VK! SC: %s' % indata.keyCode)
					#	if vk_code is not None and vk_code in self.__vk_to_vnckey:
					#		keycode = self.__vk_to_vnckey[vk_code]
					#		print('AAAAAAAA %s' % hex(keycode))
					#
					#	if keycode is None:
					#		keycode = self.__keyboard_layout.scancode_to_char(indata.keyCode, modifiers)
					#		print(keycode)
					#		if keycode is None:
					#			print('Failed to resolv key! SC: %s VK: %s' % (indata.keyCode, vk_code))
					#			continue
					#		elif keycode is not None and len(keycode) == 1:
					#			keycode = ord(keycode)
					#			print('Keycode %s resolved to: %s' % (indata.keyCode , repr(keycode)))
					#		elif keycode is not None and len(keycode) > 1:
					#			print('LARGE! Keycode %s resolved to: %s' % (indata.keyCode , repr(keycode)))
					#			continue
					#		else:
					#			print('This key is too special! Can\'t resolve it! SC: %s VK: %s' % (indata.keyCode, vk_code))
					#			continue
					#	
					#except Exception as e:
					#	traceback.print_exc()
					#	continue
					#
					#if indata.keyCode is not None:
					#	print('Original kk  : %s [%s]' % (indata.keyCode, hex(indata.keyCode)))
					#print('Final keycode: %s' % hex(keycode))
					#print('Is pressed   : %s' % indata.is_pressed)
					#if keycode is not None:
					#	msg = pack("!BBxxI", 4, int(indata.is_pressed), keycode)
					#	self.__writer.write(msg)
				
				elif indata.type == RDPDATATYPE.KEYUNICODE:
					indata = cast(RDP_KEYBOARD_UNICODE, indata)
					keycode = indata.char
					if not isinstance(keycode, int):
						if len(keycode) == 1:
							keycode = ord(keycode)
						else:
							# I hope you know what you're doing here...
							keycode = int.from_bytes(bytes.fromhex(keycode), byteorder = 'big', signed = False)
					await self.send_key_char(keycode, indata.is_pressed)
			
				elif indata.type == RDPDATATYPE.MOUSE:
					#PointerEvent
					indata = cast(RDP_MOUSE, indata)
					if indata.xPos < 0 or indata.yPos < 0:
						continue
					
					await self.send_mouse(indata.button, indata.xPos, indata.yPos, indata.is_pressed)

				elif indata.type == RDPDATATYPE.CLIPBOARD_DATA_TXT:
					try:
						indata = cast(RDP_CLIPBOARD_DATA_TXT, indata)
						txtdata = indata.data.encode('latin-1')
						msg = pack("!BxxxI", 6, len(txtdata))
						msg += txtdata
						await self.__writer.write(msg)
					except Exception as e:
						traceback.print_exc()
						continue

		except asyncio.CancelledError:
			return None, None

		except Exception as e:
			traceback.print_exc()
			await self.terminate()
			return None, e

	async def __refresh_screen_loop(self):
		# Periodically sends a framebufferupdate request to the server
		# Potentially not the best way to do it

		while not self.disconnected_evt.is_set():
			try:
				await self.framebuffer_update_request(incremental=1)
				await asyncio.sleep(1/self.iosettings.vnc_fps)
			except asyncio.CancelledError:
				return
			except Exception as e:
				break

	async def __send_rect(self, x, y, width, height, image:Image):
		try:
			#updating desktop buffer to have a way to copy rectangles later
			self.desktop_buffer_has_data = True
			if self.width == width and self.height == height:
				self.__desktop_buffer = image
			else:
				self.__desktop_buffer.paste(image, [x, y, x+width, y+height])
			
			if self.iosettings.video_out_format == VIDEO_FORMAT.RAW:
				image = image.tobytes()
			
			elif self.iosettings.video_out_format == VIDEO_FORMAT.PNG:
				img_byte_arr = io.BytesIO()
				image.save(img_byte_arr, format='PNG')
				image = img_byte_arr.getvalue()
			else:
				raise ValueError('Output format of "%s" is not supported!' % self.iosettings.video_out_format)
									
			rect = RDP_VIDEO()
			rect.x = x
			rect.y = y
			rect.width = width
			rect.height = height
			rect.bitsPerPixel = self.bpp
			rect.is_compressed = False
			rect.data = image
			await self.ext_out_queue.put(rect)

		except Exception as e:
			await self.terminate()
			return None, e

	async def __reader_loop(self):
		try:
			while True:
				msgtype = await self.__reader.readexactly(1)
				msgtype = ord(msgtype)
				if msgtype == 0:
					# Framebufferupdate message from the server
					# 
					num_rect = await self.__reader.readexactly(3)
					num_rect = int.from_bytes(num_rect[1:], byteorder = 'big', signed = False)
					for _ in range(num_rect):
						rect_hdr = await self.__reader.readexactly(12)
						(x, y, width, height, encoding) = unpack("!HHHHI", rect_hdr)
						if encoding == RAW_ENCODING:
							try:
								data = await self.__reader.readexactly(width*height*self.bypp)
								data = librlers.mask_rgbx(data)
								image = Image.frombytes('RGBA', [width, height], bytes(data))
								await self.__send_rect(x,y,width, height, image)
							except Exception as e:
								traceback.print_exc()
								return

						elif encoding == COPY_RECTANGLE_ENCODING:
							try:
								data = await self.__reader.readexactly(4)
								(srcx, srcy) = unpack("!HH", data)								
								newrect = self.__desktop_buffer.crop([srcx, srcy, srcx+width, srcy+height])
								await self.__send_rect(x,y,width,height, newrect)
								continue
							except Exception as e:
								traceback.print_exc()
								return


						elif encoding == RRE_ENCODING:
							try:
								raw_data = b''
								sub_rect_num = await self.__reader.readexactly(4)
								raw_data += sub_rect_num
								sub_rect_num = int.from_bytes(sub_rect_num, byteorder = 'big', signed = False)
								backgroud_pixel = await self.__reader.readexactly(self.bypp)
								raw_data += backgroud_pixel
								
								if sub_rect_num > 0:
									subrect_size = (self.bypp + 8)*sub_rect_num
									data = await self.__reader.readexactly(subrect_size)
									raw_data += data
								
								raw_out = librlers.decode_rre(raw_data, width, height, self.bypp)
								raw_out = bytes(raw_out)
								
								rect = Image.frombytes('RGBA', [width, height], raw_out)
								await self.__send_rect(x,y, width, height, rect)

								#### This is the pure-python version of RRE, kept here as a reminder
								#### It's a bit slow compared to the C implementation
								##
								## sub_rect_num = await self.__reader.readexactly(4)
								## sub_rect_num = int.from_bytes(sub_rect_num, byteorder = 'big', signed = False)
								## backgroud_pixel = await self.__reader.readexactly(self.bypp)
								## r,g,b,a = unpack("BBBB", backgroud_pixel)
								## a = 255
								## rect = Image.new('RGBA', [width, height])
								## rect.paste((r,g,b,a), [0,0, width, height])
								## 
								## format = "!%dsHHHH" % self.bypp
								## for _ in range(sub_rect_num):
								## 	data = await self.__reader.readexactly(self.bypp + 8)
								## 	(color, subx, suby, subwidth, subheight) = unpack(format, data)
								## 	r,g,b,a = unpack("BBBB", color)
								## 	a = 255
								## 	rect.paste((r,g,b,a), [subx,suby, subx+subwidth, suby+subheight])
								## await self.__send_rect(x,y, width, height, rect)
							except Exception as e:
								raise e
						
						
						elif encoding == TRLE_ENCODING:
							raise NotImplementedError()

						else:
							raise Exception('Unknown encoding %s' % encoding)

				elif msgtype == 1:
					# Colormap messages are only used in certain encoding formats, 
					# none of which are currently implemented
					# but the decoding process works
					hdr = await self.__reader.readexactly(5)
					(_, firstcolor, numcolor) = unpack("!BHH", hdr)
					for _ in range(numcolor):
						color_raw = await self.__reader.readexactly(6)
						(red, green, blue) = unpack("!HHH", color_raw)
				
				elif msgtype == 2:
					# Server sent a Bell command, should cause a beep
					msg = RDP_BEEP()
					await self.ext_out_queue.put(msg)
				
				elif msgtype == 3:
					# Server side has updated the clipboard
					
					# Signaling clipboard data (to simulate RDP functionality)
					msg = RDP_CLIPBOARD_NEW_DATA_AVAILABLE()
					await self.ext_out_queue.put(msg)

					# processing clipboard data
					hdr = await self.__reader.readexactly(7)
					(_,_,_, cliplen ) = unpack("!BBBI", hdr)
					cliptext = await self.__reader.readexactly(cliplen)
					cliptext = cliptext.decode('latin-1') #latin-1 is per RFC
					logger.debug('Got clipboard test: %s' % repr(cliptext))
					if self.__use_pyperclip is True:
						import pyperclip
						pyperclip.copy(cliptext)
					
					msg = RDP_CLIPBOARD_DATA_TXT()
					msg.data = cliptext
					msg.datatype = CLIPBRD_FORMAT.CF_UNICODETEXT
					await self.ext_out_queue.put(msg)
				
				else:
					raise Exception('Unexpected message tpye %s' % msgtype)
					
			return True, None
		except Exception as e:
			await self.terminate()
			return None, e

	async def set_encodings(self, list_of_encodings = [2, 1, 0]):
		"""Sends a setencoding message to the server, indicating the types of image encodings we support"""
		try:
			if list_of_encodings is None:
				list_of_encodings = [2, 1, 0]
			enc_encodings = b''
			for encoding in list_of_encodings:
				enc_encodings += encoding.to_bytes(4, byteorder = 'big', signed = True)
			sendbuff = pack("!BxH", 2, len(list_of_encodings)) + enc_encodings
			await self.__writer.write(sendbuff)
			return True, None
		except Exception as e:
			return None, e
		

	async def set_pixel_format(self, bpp=32, depth=24, bigendian=0, truecolor=1, redmax=255, greenmax=255, bluemax=255, redshift=0, greenshift=8, blueshift=16):
		"""Sends a setpixelformat message to the server, letting the server know our preferred image data encodings"""

		pixformat = pack("!BBBBHHHBBBxxx", bpp, depth, bigendian, truecolor, redmax, greenmax, bluemax, redshift, greenshift, blueshift)
		await self.__writer.write(b'\x00\x00\x00\x00' + pixformat)
		# rember these settings
		self.bpp, self.depth, self.bigendian, self.truecolor = bpp, depth, bigendian, truecolor
		self.redmax, self.greenmax, self.bluemax = redmax, greenmax, bluemax
		self.redshift, self.greenshift, self.blueshift = redshift, greenshift, blueshift
		self.bypp = self.bpp // 8  # calc bytes per pixel
		# ~ print self.bypp

	async def framebuffer_update_request(self, x=0, y=0, width=None, height=None, incremental=0):
		"""Sends a framebufferupdaterequest message to the server, indicating the area to be updated"""
		if width is None:
			width = self.width - x

		if height is None:
			height = self.height - y

		await self.__writer.write(pack("!BBHHHH", 3, incremental, x, y, width, height))

async def amain():
	try:
		logger.setLevel(1)
		from aardwolf.commons.factory import RDPConnectionFactory
		from aardwolf.commons.iosettings import RDPIOSettings

		iosettings = RDPIOSettings()
		iosettings.video_out_format = VIDEO_FORMAT.RAW
		
		url = 'vnc+plain-password://alma:alma@10.10.10.102:5900'
		url = RDPConnectionFactory.from_url(url)
		connection = url.get_connection(iosettings)

		_, err = await connection.connect()
		if err is not None:
			raise err

		while True:
			await asyncio.sleep(10)

		return True, None
	except Exception as e:
		traceback.print_exc()
		return None, e

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()