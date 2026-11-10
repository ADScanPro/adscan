# Async DCOM Interface base classes for aiosmb
#
# Provides the base INTERFACE class that all DCOM interfaces inherit from,
# and CLASS_INSTANCE for managing interface metadata.
#

import socket
from struct import pack

from aiosmb import logger
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, \
    RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE, DCERPCException
from aiosmb.dcerpc.v5.dtypes import NULL

from aiosmb.dcerpc.v5.dcom.dcomrt import (
    OBJREF, OBJREF_STANDARD, OBJREF_HANDLER, OBJREF_CUSTOM, OBJREF_EXTENDED,
    FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_CUSTOM, FLAGS_OBJREF_EXTENDED,
    SORF_NOPING, STRINGBINDING, DCOMSessionError, ORPCTHIS
)
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnectionManager


class CLASS_INSTANCE:
    """
    Holds metadata about a DCOM class instance.
    
    Contains:
    - CID (causality ID) for making DCOM calls
    - String bindings for connecting to the object's OXID
    - Authentication settings
    """
    
    def __init__(self, ORPCthis, stringBindings):
        self._string_bindings = stringBindings
        # Store just the CID from ORPCthis - we'll create fresh ORPCTHIS for each request
        if hasattr(ORPCthis, '__getitem__'):
            self._cid = ORPCthis['cid']
        else:
            # Fallback if ORPCthis is not a proper structure
            self._cid = ORPCthis
        self._auth_type = RPC_C_AUTHN_WINNT
        self._auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    
    def get_cid(self):
        """Get the causality ID for DCOM calls"""
        return self._cid
    
    def get_ORPCthis(self):
        """Create a fresh ORPCTHIS structure for a DCOM request"""
        orpc_this = ORPCTHIS()
        orpc_this['cid'] = self._cid
        orpc_this['extensions'] = NULL
        orpc_this['flags'] = 0
        return orpc_this
    
    def get_string_bindings(self):
        return self._string_bindings
    
    def get_auth_level(self):
        """Get effective auth level, adjusting for auth type constraints.

        Mirrors impacket ``dcomrt.CLASS_INSTANCE.get_auth_level`` byte for byte:
        a server ``authnHint`` below packet privacy is kept at packet INTEGRITY
        for NTLM (``RPC_C_AUTHN_WINNT``) and raised to privacy for
        Kerberos/Negotiate. Interfaces whose server requires an encrypted
        binding regardless of the hint (the Certificate Services interfaces)
        call :meth:`INTERFACE.require_packet_privacy`, which sets the level to
        packet privacy explicitly, exactly as Certipy does with
        ``get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)``.
        """
        if RPC_C_AUTHN_LEVEL_NONE < self._auth_level < RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
            if self._auth_type == RPC_C_AUTHN_WINNT:
                return RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
            else:
                return RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        return self._auth_level
    
    def set_auth_level(self, level):
        self._auth_level = level
    
    def get_auth_type(self):
        return self._auth_type
    
    def set_auth_type(self, auth_type):
        self._auth_type = auth_type


class INTERFACE:
    """
    Base class for all DCOM interface proxies.
    
    Manages:
    - Connection to the object's OXID (Object Exporter ID)
    - Interface binding and context switching
    - Request marshaling with ORPC headers
    - Object lifetime tracking
    
    All specific DCOM interfaces (IRemUnknown, IWbemServices, etc.) 
    inherit from this class.
    """
    
    def __init__(self, cinstance=None, objRef=None, ipidRemUnknown=None, 
                 iPid=None, oxid=None, oid=None, target=None,
                 interfaceInstance=None):
        """
        Initialize interface proxy.
        
        Can be initialized either from another interface instance (copy)
        or from individual components.
        """
        self._manager = DCOMConnectionManager.get_instance()
        
        if interfaceInstance is not None:
            # Copy from existing interface
            self._target = interfaceInstance.get_target()
            self._iPid = interfaceInstance.get_iPid()
            self._oid = interfaceInstance.get_oid()
            self._oxid = interfaceInstance.get_oxid()
            self._cinstance = interfaceInstance.get_cinstance()
            self._objRef = interfaceInstance.get_objRef()
            self._ipidRemUnknown = interfaceInstance.get_ipidRemUnknown()
        else:
            if target is None:
                raise ValueError('target is required')
            
            self._target = target
            self._iPid = iPid
            self._oid = oid
            self._oxid = oxid
            self._cinstance = cinstance
            self._objRef = objRef
            self._ipidRemUnknown = ipidRemUnknown
            
            if objRef is not None:
                self._process_interface(objRef)
    
    def _process_interface(self, data):
        """Parse OBJREF and extract interface information"""
        objRefType = OBJREF(data)['flags']
        objRef = None
        
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(data)
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(data)
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(data)
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(data)
        else:
            logger.error(f"Unknown OBJREF Type! 0x{objRefType:x}")
            return
        
        if objRefType != FLAGS_OBJREF_CUSTOM:
            # Register OID for pinging if not marked NOPING
            if objRef['std']['flags'] & SORF_NOPING == 0:
                # Use asyncio.create_task since we're not in async context
                import asyncio
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self._manager.add_oid(self._target, objRef['std']['oid']))
                except RuntimeError:
                    # No running loop - defer registration
                    pass
            
            self._iPid = objRef['std']['ipid']
            self._oid = objRef['std']['oid']
            self._oxid = objRef['std']['oxid']
            
            if self._oxid is None:
                raise ValueError('OXID is None - invalid OBJREF')
    
    # Property accessors
    def get_oxid(self):
        return self._oxid
    
    def set_oxid(self, oxid):
        self._oxid = oxid
    
    def get_oid(self):
        return self._oid
    
    def set_oid(self, oid):
        self._oid = oid
    
    def get_target(self):
        return self._target
    
    def get_iPid(self):
        return self._iPid
    
    def set_iPid(self, iPid):
        self._iPid = iPid
    
    def get_objRef(self):
        return self._objRef
    
    def set_objRef(self, objRef):
        self._objRef = objRef
    
    def get_ipidRemUnknown(self):
        return self._ipidRemUnknown
    
    def get_cinstance(self):
        return self._cinstance
    
    def set_cinstance(self, cinstance):
        self._cinstance = cinstance
    
    def require_packet_privacy(self):
        """Bind this object's OXID at RPC_C_AUTHN_LEVEL_PKT_PRIVACY.

        Some DCOM servers refuse anything below an encrypted binding. The AD CS
        server (certsrv, ``ICertRequestD`` / ``ICertAdminD`` / ``ICertAdminD2``)
        is one: it advertises ``authnHint`` 5 (packet integrity), which
        :meth:`CLASS_INSTANCE.get_auth_level` keeps at integrity under NTLM,
        and then answers ``E_ACCESSDENIED`` (0x80070005) to every call, even
        from a Domain Admin. Kerberos already lands on privacy, so this only
        changes the NTLM wire level. Certipy sets the same level on the same
        class instance right after activation.

        Must run before the first request on the object: the binding level is
        fixed when the OXID connection is opened, and an existing connection is
        reused by alter-context, which cannot raise it.
        """
        if self._cinstance is None:
            return
        self._cinstance.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        conn_info = self._manager.get_oxid_connection(self._target, self._oxid)
        if conn_info is not None:
            current = getattr(conn_info['dce'], 'auth_level', None)
            if current is not None and current < RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                logger.debug(
                    'require_packet_privacy: OXID connection already open at '
                    f'auth level {current}; the new level applies to the next connection only'
                )

    def get_dce_rpc(self) -> DCERPC5Connection:
        """Get the DCE/RPC connection for this interface's OXID"""
        conn_info = self._manager.get_oxid_connection(self._target, self._oxid)
        if conn_info:
            return conn_info['dce']
        return None
    
    def _is_fqdn(self):
        """Check if target is a FQDN (not IPv4 or IPv6)"""
        try:
            socket.inet_aton(self._target)
            return False  # It's IPv4
        except socket.error:
            pass
        
        if ':' in self._target:
            return False  # It's IPv6
        
        return True  # It's a FQDN
    
    async def connect(self, iid=None):
        """
        Establish or reuse connection to the object's OXID.
        
        Args:
            iid: Interface ID to bind to
        
        Returns:
            (True, None) on success
            (None, Exception) on failure
        """
        try:
            logger.debug(f'connect() called: target={self._target}, oxid={self._oxid.hex() if isinstance(self._oxid, bytes) else self._oxid}, iid={iid.hex() if isinstance(iid, bytes) else iid}')
            
            conn_info = self._manager.get_oxid_connection(self._target, self._oxid)
            
            if conn_info is not None:
                # Existing connection - check if we need to alter context
                dce = conn_info['dce']
                current_binding = conn_info['currentBinding']
                
                logger.debug(f'Existing connection found: currentBinding={current_binding.hex() if isinstance(current_binding, bytes) else current_binding}')
                
                if current_binding == iid:
                    # Already bound to correct interface
                    logger.debug('Already bound to correct interface')
                    return True, None
                else:
                    # Need to alter context for new interface
                    logger.debug(f'Altering context from {current_binding.hex() if isinstance(current_binding, bytes) else current_binding} to {iid.hex() if isinstance(iid, bytes) else iid}')
                    _, err = await dce.bind(iid, alter=1)
                    if err is not None:
                        raise err
                    # Update the binding in the manager
                    self._manager.update_oxid_binding(self._target, self._oxid, dce, iid)
                    return True, None
            
            # Create new connection to OXID
            string_bindings = self._cinstance.get_string_bindings()
            string_binding = None
            is_target_fqdn = self._is_fqdn()
            
            logger.debug(f'Target system is {self._target}, isFQDN={is_target_fqdn}')
            
            for str_binding in string_bindings:
                logger.debug(f'StringBinding: {str_binding["aNetworkAddr"]}')
                
                if str_binding['wTowerId'] == 7:  # TCP
                    addr = str_binding['aNetworkAddr']
                    
                    # Parse port if present
                    if '[' in addr:
                        binding, _, binding_port = addr.partition('[')
                        binding_port = '[' + binding_port
                    else:
                        binding = addr
                        binding_port = ''
                    
                    # Check if binding matches target
                    if binding.upper().find(self._target.upper()) >= 0:
                        string_binding = f'ncacn_ip_tcp:{addr.rstrip(chr(0))}'
                        break
                    
                    # For FQDN targets, check hostname match
                    if is_target_fqdn:
                        target_hostname = self._target.upper().partition('.')[0]
                        if binding.upper().find(target_hostname) >= 0:
                            # Use our resolved target instead of NetBIOS name
                            string_binding = f'ncacn_ip_tcp:{self._target}{binding_port}'
                            break
            
            logger.debug(f'StringBinding chosen: {string_binding}')
            
            if string_binding is None:
                raise DCOMSessionError('Cannot find valid string binding to connect')
            
            # Create DCE/RPC connection
            target = DCERPCTarget.from_connection_string(
                string_binding,
                proxies=None,  # TODO: Get from manager
                hostname=self._target
            )
            
            # Get credentials from manager
            auth = self._manager.get_credentials(self._target)
            
            dce = DCERPC5Connection(auth, target)
            
            if iid is None:
                raise ValueError('IID is required')
            
            dce.set_auth_level(self._cinstance.get_auth_level())
            dce.set_auth_type(self._cinstance.get_auth_type())
            
            _, err = await dce.connect()
            if err is not None:
                raise err
            
            _, err = await dce.bind(iid)
            if err is not None:
                raise err
            
            if self._oxid is None:
                raise ValueError('OXID is None')
            
            # Register connection with manager
            self._manager.register_oxid_connection(self._target, self._oxid, dce, iid)
            
            return True, None
            
        except Exception as e:
            return None, e
    
    async def request(self, req, iid=None, uuid=None):
        """
        Make a DCOM request.
        
        Args:
            req: The request object (NDRCALL subclass)
            iid: Interface ID to use
            uuid: Optional UUID for the request
        
        Returns:
            (response, None) on success
            (None, Exception) on failure
        """
        try:
            # Validate cinstance
            if self._cinstance is None:
                raise DCOMSessionError(
                    f'DCOM request failed: _cinstance is None.\n'
                    f'  Request type: {type(req).__name__}\n'
                    f'  Interface: {type(self).__name__}'
                )
            
            # Get a fresh ORPCTHIS for this request
            req['ORPCthis'] = self._cinstance.get_ORPCthis()
            
            logger.debug(f'DCOM request: {type(req).__name__}, iid={iid.hex() if isinstance(iid, bytes) else iid}, uuid={uuid.hex() if isinstance(uuid, bytes) else uuid}')
            
            # Ensure connection
            _, err = await self.connect(iid)
            if err is not None:
                raise err
            
            dce = self.get_dce_rpc()
            if dce is None:
                raise DCOMSessionError('No DCE/RPC connection available')
            
            logger.debug(f'Making DCE/RPC request with opnum={req.opnum if hasattr(req, "opnum") else "unknown"}')
            
            resp, err = await dce.request(req, uuid)
            if err is not None:
                error_str = str(err)
                if 'RPC_E_DISCONNECTED' in error_str:
                    msg = f'{error_str}\n'
                    msg += "DCOM keep-alive pinging may not be working as expected.\n"
                    msg += "You cannot be idle for more than 14 minutes!\n"
                    msg += "You should reconnect and start again."
                    raise DCOMSessionError(msg)
                raise err
            
            return resp, None
            
        except Exception as e:
            # Add traceback info for debugging
            import traceback
            logger.debug(f'DCOM request exception: {type(e).__name__}')
            logger.debug(f'Traceback:\n{traceback.format_exc()}')
            return None, e
    
    async def disconnect(self):
        """
        Disconnect the interface's DCE/RPC connection.
        
        Returns:
            (True, None) on success
            (None, Exception) on failure
        """
        try:
            dce = self.get_dce_rpc()
            if dce is not None:
                await dce.disconnect()
            return True, None
        except Exception as e:
            return None, e
