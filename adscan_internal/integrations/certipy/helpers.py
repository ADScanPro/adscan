"""Certipy integration helpers.

Utility functions for working with Certipy tools including:
- Authentication string building
"""

from __future__ import annotations

from dataclasses import dataclass


def build_auth_certipy(
    domain: str,
    username: str,
    password: str,
) -> str:
    """Build the authentication string for Certipy commands.

    Certipy accepts either clear-text passwords or NT hashes. When an NT hash
    is used, it is passed with the ``-hashes`` flag.

    Args:
        domain: Domain name.
        username: The username.
        password: The password or NT hash (32 hexadecimal characters).

    Returns:
        Authentication string suitable for appending to Certipy commands.
    """
    # Check if it is an NT hash (32 hexadecimal characters)
    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )

    # Build the authentication part
    auth = f"-u '{username}'@{domain}"
    auth += f" -hashes :{password}" if is_hash else f" -p '{password}'"

    return auth


@dataclass(frozen=True)
class CertipyReqOptions:
    """Options required to build a ``certipy req`` command."""

    certipy_path: str
    auth: str
    pdc_ip: str
    target: str
    ca_name: str
    template: str
    dc_host: str | None = None
    key_size: int | None = None
    upn: str | None = None
    sid: str | None = None
    on_behalf_of: str | None = None
    pfx_path: str | None = None
    retrieve_request_id: str | None = None
    use_kerberos: bool = True
    pipe_yes: bool = True


def build_certipy_req_command(options: CertipyReqOptions) -> str:
    """Build a Certipy certificate request/retrieve command.

    Args:
        options: Structured options for the request command.

    Returns:
        Shell command string for Certipy ``req``.
    """
    prefix = "echo 'y' | " if options.pipe_yes else ""
    command = (
        f"{prefix}{options.certipy_path} req {options.auth} "
        f"-dc-ip {options.pdc_ip} -ns {options.pdc_ip} "
        f"-target {options.target}"
    )
    if options.use_kerberos:
        command = f"{command} -k"
    command = f"{command} -ca '{options.ca_name}'"
    if options.retrieve_request_id:
        command = f"{command} -retrieve {options.retrieve_request_id}"
    else:
        command = f"{command} -template '{options.template}'"
    if options.dc_host:
        command = f"{command} -dc-host {options.dc_host}"
    if options.upn:
        command = f"{command} -upn {options.upn}"
    if options.sid:
        command = f"{command} -sid {options.sid}"
    if options.key_size:
        command = f"{command} -key-size {int(options.key_size)}"
    if options.on_behalf_of:
        command = f"{command} -on-behalf-of '{options.on_behalf_of}'"
    if options.pfx_path:
        command = f"{command} -pfx '{options.pfx_path}'"
    return command


__all__ = [
    "build_auth_certipy",
    "build_certipy_req_command",
    "CertipyReqOptions",
]
