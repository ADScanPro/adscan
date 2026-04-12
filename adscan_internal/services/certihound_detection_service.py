"""Internal ADCS detection pipeline backed by CertiHound library primitives.

This service does not rely on BloodHound relationship queries. It collects ADCS
objects via CertiHound, runs ESC detections directly, and returns a normalized
JSON-serializable report that ADscan can persist and consume for attack-path
generation.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import os
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_warning_debug
from adscan_internal.services.altsecurityidentities_service import (
    AltSecurityIdentityUser,
    AltSecurityIdentitiesService,
)
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.certificate_mapping_service import CertificateMappingService
from adscan_internal.services.ldap_transport_service import execute_with_ldap_fallback
from adscan_internal.workspaces import read_json_file


CERTIHOUND_DETECTION_SCHEMA_VERSION = "certihound-detections-1.1"


class CertiHoundDetectionService(BaseService):
    """Run direct CertiHound-backed ADCS detections and normalize the results."""

    def _load_modules(self) -> dict[str, Any]:
        """Load CertiHound public and required internal modules lazily."""
        from certihound import (  # type: ignore  # pylint: disable=import-error
            ADCSCollector,
            LDAPConnection,
            LDAPConfig,
            detect_esc1,
            detect_esc2,
            detect_esc3_agent,
            detect_esc3_target,
            detect_esc4,
            detect_esc6,
            detect_esc7,
            detect_esc8,
            detect_esc9,
            detect_esc10,
            detect_esc11,
            detect_esc13,
            detect_esc14,
            detect_esc15,
            detect_esc16,
            detect_esc17,
        )
        from certihound.acl.parser import SecurityDescriptorParser  # type: ignore  # pylint: disable=import-error
        from certihound.detection.esc5 import detect_esc5  # type: ignore  # pylint: disable=import-error
        from certihound.detection.esc13 import (  # type: ignore  # pylint: disable=import-error
            enumerate_issuance_policies,
        )
        from certihound.output.edges import EdgeGenerator  # type: ignore  # pylint: disable=import-error
        from ldap3 import BASE  # type: ignore

        return {
            "ADCSCollector": ADCSCollector,
            "LDAPConnection": LDAPConnection,
            "LDAPConfig": LDAPConfig,
            "SecurityDescriptorParser": SecurityDescriptorParser,
            "EdgeGenerator": EdgeGenerator,
            "detect_esc1": detect_esc1,
            "detect_esc2": detect_esc2,
            "detect_esc3_agent": detect_esc3_agent,
            "detect_esc3_target": detect_esc3_target,
            "detect_esc4": detect_esc4,
            "detect_esc5": detect_esc5,
            "detect_esc6": detect_esc6,
            "detect_esc7": detect_esc7,
            "detect_esc8": detect_esc8,
            "detect_esc9": detect_esc9,
            "detect_esc10": detect_esc10,
            "detect_esc11": detect_esc11,
            "detect_esc13": detect_esc13,
            "detect_esc14": detect_esc14,
            "detect_esc15": detect_esc15,
            "detect_esc16": detect_esc16,
            "detect_esc17": detect_esc17,
            "enumerate_issuance_policies": enumerate_issuance_policies,
            "BASE": BASE,
        }

    def build_detection_report(
        self,
        *,
        target_domain: str,
        dc_address: str,
        username: str | None = None,
        password: str | None = None,
        use_kerberos: bool = False,
        use_ldaps: bool = True,
        shell: Any | None = None,
        registry_username: str | None = None,
        registry_credential: str | None = None,
        kerberos_target_hostname: str | None = None,
    ) -> dict[str, Any] | None:
        """Collect ADCS data and return a normalized internal detection report."""
        modules = self._load_modules()

        try:
            def _collect(connection: Any) -> dict[str, Any]:
                collector = modules["ADCSCollector"](connection)
                data = collector.collect_all()
                self._process_template_acls(
                    templates=data.templates,
                    security_descriptor_parser_cls=modules["SecurityDescriptorParser"],
                )
                self._process_ca_acls(
                    enterprise_cas=data.enterprise_cas,
                    security_descriptor_parser_cls=modules["SecurityDescriptorParser"],
                )
                enrichment_debug = self._enrich_enterprise_cas_for_detection(
                    data=data,
                    shell=shell,
                    target_domain=target_domain,
                    username=registry_username,
                    credential=registry_credential,
                    use_kerberos=use_kerberos,
                    kdc_host=kerberos_target_hostname or dc_address,
                )
                report = self._run_all_detections(
                    data=data,
                    connection=connection,
                    modules=modules,
                    shell=shell,
                    target_domain=target_domain,
                    dc_address=dc_address,
                    registry_username=registry_username,
                    registry_credential=registry_credential,
                    use_kerberos=use_kerberos,
                )
                report["domain"] = data.domain
                report["domain_sid"] = data.domain_sid
                report["generated_at"] = datetime.now(timezone.utc).isoformat()
                report["schema_version"] = CERTIHOUND_DETECTION_SCHEMA_VERSION
                report["enrichment"] = enrichment_debug
                return report

            report, _used_ldaps = execute_with_ldap_fallback(
                operation_name="CertiHound detection",
                target_domain=target_domain,
                dc_address=dc_address,
                config_cls=modules["LDAPConfig"],
                connection_cls=modules["LDAPConnection"],
                callback=_collect,
                username=username,
                password=password,
                use_kerberos=use_kerberos,
                prefer_ldaps=use_ldaps,
                kerberos_target_hostname=kerberos_target_hostname,
                allow_password_fallback_on_kerberos_failure=bool(
                    str(username or "").strip() and str(password or "").strip()
                ),
            )
            return report
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"CertiHound detection report generation failed: {type(exc).__name__}: {exc}"
            )
            return None

    def _enrich_enterprise_cas_for_detection(
        self,
        *,
        data: Any,
        shell: Any | None,
        target_domain: str,
        username: str | None,
        credential: str | None,
        use_kerberos: bool,
        kdc_host: str | None,
    ) -> dict[str, Any]:
        """Best-effort enrich CA objects with non-LDAP context before detection."""
        debug = {
            "registry": self._safe_apply_registry_flags_by_host(
                data=data,
                username=username,
                credential=credential,
                auth_domain=target_domain,
                use_kerberos=use_kerberos,
                kdc_host=kdc_host,
            ),
            "certipy": self._safe_apply_certipy_ca_hints(
                data=data,
                shell=shell,
                target_domain=target_domain,
            ),
        }
        return debug

    def _process_template_acls(
        self,
        *,
        templates: list[Any],
        security_descriptor_parser_cls: type[Any],
    ) -> None:
        """Populate template ACL-derived fields required by ESC detectors."""
        for template in templates:
            if not getattr(template, "security_descriptor_raw", b""):
                continue
            sd_parser = security_descriptor_parser_cls(template.security_descriptor_raw)
            template.aces = sd_parser.get_aces_for_bloodhound()
            rights = sd_parser.get_enrollment_rights()
            template.enrollment_principals = [r.sid for r in rights if r.can_enroll]

    def _process_ca_acls(
        self,
        *,
        enterprise_cas: list[Any],
        security_descriptor_parser_cls: type[Any],
    ) -> None:
        """Populate CA ACL-derived fields required by ESC detectors."""
        for ca in enterprise_cas:
            if not getattr(ca, "security_descriptor_raw", b""):
                continue
            sd_parser = security_descriptor_parser_cls(ca.security_descriptor_raw)
            ca.aces = sd_parser.get_aces_for_bloodhound()
            rights = sd_parser.get_enrollment_rights()
            ca.enrollment_principals = [r.sid for r in rights if r.can_enroll]

    def _run_all_detections(
        self,
        *,
        data: Any,
        connection: Any,
        modules: dict[str, Any],
        shell: Any | None = None,
        target_domain: str,
        dc_address: str,
        registry_username: str | None = None,
        registry_credential: str | None = None,
        use_kerberos: bool = False,
    ) -> dict[str, Any]:
        """Run all supported ESC detections and return normalized edges/metadata."""
        edge_generator = modules["EdgeGenerator"](data.domain_sid)
        issuance_policies = self._safe_enumerate_issuance_policies(
            connection=connection,
            enumerate_issuance_policies=modules["enumerate_issuance_policies"],
        )
        weak_altsecid_entries = self._safe_enumerate_weak_altsecurityidentities_users(
            connection=connection,
            target_domain=target_domain,
            shell=shell,
        )
        weak_altsecid_users = [entry.samaccountname for entry in weak_altsecid_entries]
        strong_cert_binding_enforced = (
            self._safe_resolve_strong_certificate_binding_enforcement(
                connection=connection,
                dc_address=dc_address,
                username=registry_username,
                credential=registry_credential,
                target_domain=target_domain,
                use_kerberos=use_kerberos,
            )
        )

        template_by_cn = {
            str(getattr(template, "cn", "")).strip(): template
            for template in data.templates
            if str(getattr(template, "cn", "")).strip()
        }
        template_by_dn = {
            str(getattr(template, "distinguished_name", "")).strip(): template
            for template in data.templates
            if str(getattr(template, "distinguished_name", "")).strip()
        }
        ca_by_dn = {
            str(getattr(ca, "distinguished_name", "")).strip(): ca
            for ca in data.enterprise_cas
            if str(getattr(ca, "distinguished_name", "")).strip()
        }

        template_metadata: dict[str, dict[str, Any]] = {
            str(getattr(template, "cn", "")).strip(): {
                "template_dn": str(getattr(template, "distinguished_name", "") or "").strip(),
                "min_key_length": int(getattr(template, "minimal_key_size", 0) or 0),
                "vulnerabilities": [],
            }
            for template in data.templates
            if str(getattr(template, "cn", "")).strip()
        }

        detection_edges: list[dict[str, Any]] = []

        def _record(
            edge: dict[str, Any] | None,
            *,
            template_names: list[str] | None = None,
            template_dns: list[str] | None = None,
            agent_templates: list[str] | None = None,
            target_templates: list[str] | None = None,
            ca_name: str | None = None,
            ca_dn: str | None = None,
            reasons: list[str] | None = None,
            extra_details: dict[str, Any] | None = None,
        ) -> None:
            if not isinstance(edge, dict):
                return
            details: dict[str, Any] = {
                "source": "certihound",
                "detector": "certihound",
            }
            if template_names:
                unique_templates = sorted({t for t in template_names if t}, key=str.lower)
                if unique_templates:
                    details["templates"] = unique_templates
                    if len(unique_templates) == 1:
                        details["template"] = unique_templates[0]
            if template_dns:
                unique_template_dns = sorted({t for t in template_dns if t}, key=str.lower)
                if unique_template_dns:
                    details["template_dns"] = unique_template_dns
            if agent_templates:
                details["agent_templates"] = sorted(
                    {t for t in agent_templates if t}, key=str.lower
                )
            if target_templates:
                details["target_templates"] = sorted(
                    {t for t in target_templates if t}, key=str.lower
                )
            if ca_name:
                details["enterpriseca_name"] = str(ca_name)
            if ca_dn:
                details["enterpriseca"] = str(ca_dn)
            if reasons:
                details["reasons"] = sorted({str(reason) for reason in reasons if reason})
            if isinstance(extra_details, dict):
                details.update(extra_details)
            detection_edges.append(
                {
                    "relation": str(edge.get("EdgeType") or "").strip(),
                    "start_object_id": str(edge.get("StartNode") or "").strip(),
                    "end_object_id": str(edge.get("EndNode") or "").strip(),
                    "details": details,
                }
            )

        # CA-level detections.
        for ca in data.enterprise_cas:
            ca_name = str(getattr(ca, "cn", "") or "").strip()
            ca_dn = str(getattr(ca, "distinguished_name", "") or "").strip()
            if getattr(ca, "security_descriptor_raw", b""):
                ca_sd_parser = modules["SecurityDescriptorParser"](ca.security_descriptor_raw)
                esc7_result = modules["detect_esc7"](ca, ca_sd_parser, data.domain_sid)
                if esc7_result:
                    for principal in esc7_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc7_edge(principal["sid"], ca),
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc7_result.reasons),
                        )

            esc8_result = modules["detect_esc8"](ca)
            if esc8_result:
                _record(
                    edge_generator.generate_adcsesc8_edge(
                        ca, esc8_result.web_enrollment_url
                    ),
                    ca_name=ca_name,
                    ca_dn=ca_dn,
                    reasons=list(esc8_result.reasons),
                    extra_details={
                        "webenrollmenturl": esc8_result.web_enrollment_url,
                        "ca_enrollment_principals": list(
                            getattr(ca, "enrollment_principals", []) or []
                        ),
                    },
                )

            esc11_result = modules["detect_esc11"](ca)
            if esc11_result:
                _record(
                    edge_generator.generate_adcsesc11_edge(ca),
                    ca_name=ca_name,
                    ca_dn=ca_dn,
                    reasons=list(esc11_result.reasons),
                    extra_details={
                        "ca_enrollment_principals": list(
                            getattr(ca, "enrollment_principals", []) or []
                        ),
                    },
                )

            golden_edge = edge_generator.generate_goldencert_edge(ca)
            if golden_edge:
                _record(
                    golden_edge,
                    ca_name=ca_name,
                    ca_dn=ca_dn,
                    reasons=["CA private key is exportable from the hosting computer."],
                )

        # Template-level detections.
        for ca in data.enterprise_cas:
            ca_name = str(getattr(ca, "cn", "") or "").strip()
            ca_dn = str(getattr(ca, "distinguished_name", "") or "").strip()

            esc3_agent_results: list[Any] = []
            esc3_target_results: list[Any] = []

            for template in data.templates:
                template_name = str(getattr(template, "cn", "") or "").strip()
                template_dn = str(getattr(template, "distinguished_name", "") or "").strip()
                metadata_entry = template_metadata.setdefault(
                    template_name,
                    {
                        "template_dn": template_dn,
                        "min_key_length": int(
                            getattr(template, "minimal_key_size", 0) or 0
                        ),
                        "vulnerabilities": [],
                    },
                )

                esc1_result = modules["detect_esc1"](template, ca, data.domain_sid)
                if esc1_result:
                    self._append_vulnerability(metadata_entry, "ESC1")
                    for principal_sid in esc1_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc1_edge(
                                principal_sid, template, ca
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc1_result.reasons),
                        )

                esc2_result = modules["detect_esc2"](template, ca, data.domain_sid)
                if esc2_result:
                    self._append_vulnerability(metadata_entry, "ESC2")
                    for principal_sid in esc2_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc2_edge(
                                principal_sid, template, ca
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc2_result.reasons),
                        )

                esc3_agent = modules["detect_esc3_agent"](template, ca, data.domain_sid)
                if esc3_agent:
                    self._append_vulnerability(metadata_entry, "ESC3-Agent")
                    esc3_agent_results.append(esc3_agent)

                esc3_target = modules["detect_esc3_target"](template, ca)
                if esc3_target:
                    self._append_vulnerability(metadata_entry, "ESC3-Target")
                    esc3_target_results.append(esc3_target)

                if getattr(template, "security_descriptor_raw", b""):
                    sd_parser = modules["SecurityDescriptorParser"](
                        template.security_descriptor_raw
                    )
                    esc4_result = modules["detect_esc4"](
                        template, ca, sd_parser, data.domain_sid
                    )
                    if esc4_result:
                        self._append_vulnerability(metadata_entry, "ESC4")
                        for principal in esc4_result.vulnerable_principals:
                            _record(
                                edge_generator.generate_adcsesc4_edge(
                                    principal["sid"], template, ca
                                ),
                                template_names=[template_name],
                                template_dns=[template_dn],
                                ca_name=ca_name,
                                ca_dn=ca_dn,
                                reasons=list(esc4_result.reasons),
                            )

                    esc15_result = modules["detect_esc15"](
                        template, ca, sd_parser, data.domain_sid
                    )
                    if esc15_result:
                        self._append_vulnerability(metadata_entry, "ESC15")
                        for principal in esc15_result.vulnerable_principals:
                            _record(
                                edge_generator.generate_adcsesc15_edge(
                                    principal["sid"], template, ca
                                ),
                                template_names=[template_name],
                                template_dns=[template_dn],
                                ca_name=ca_name,
                                ca_dn=ca_dn,
                                reasons=list(esc15_result.reasons),
                            )

                for esc6_result in modules["detect_esc6"](template, ca, data.domain_sid):
                    relation = f"ESC6{esc6_result.variant}"
                    self._append_vulnerability(metadata_entry, relation)
                    for principal_sid in esc6_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc6_edge(
                                principal_sid,
                                template,
                                ca,
                                variant=esc6_result.variant,
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc6_result.reasons),
                        )

                for esc9_result in modules["detect_esc9"](template, ca, data.domain_sid):
                    relation = f"ESC9{esc9_result.variant}"
                    self._append_vulnerability(metadata_entry, relation)
                    for principal_sid in esc9_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc9_edge(
                                principal_sid,
                                template,
                                ca,
                                variant=esc9_result.variant,
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc9_result.reasons),
                        )

                for esc10_result in modules["detect_esc10"](
                    template, ca, data.domain_sid
                ):
                    relation = f"ESC10{esc10_result.variant}"
                    self._append_vulnerability(metadata_entry, relation)
                    for principal_sid in esc10_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc10_edge(
                                principal_sid,
                                template,
                                ca,
                                variant=esc10_result.variant,
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc10_result.reasons),
                        )

                esc13_result = modules["detect_esc13"](
                    template, ca, data.domain_sid, issuance_policies
                )
                if esc13_result:
                    self._append_vulnerability(metadata_entry, "ESC13")
                    for principal_sid in esc13_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc13_edge(
                                principal_sid,
                                template,
                                ca,
                                esc13_result.issuance_policy_oid,
                                esc13_result.linked_group_dn,
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc13_result.reasons),
                            extra_details={
                                "issuancepolicyoid": esc13_result.issuance_policy_oid,
                                "linkedgroup": esc13_result.linked_group_dn,
                            },
                        )

                esc14_result = None
                if (
                    weak_altsecid_users
                    and strong_cert_binding_enforced is False
                ):
                    esc14_result = modules["detect_esc14"](
                        template,
                        ca,
                        data.domain_sid,
                        strong_cert_binding_enforced=False,
                        alt_security_identities_users=weak_altsecid_users,
                    )
                elif weak_altsecid_users:
                    print_info_debug(
                        "Skipping CertiHound ESC14 for template "
                        f"{mark_sensitive(template_name, 'template')} on "
                        f"{mark_sensitive(ca_name, 'ca_name')}: "
                        "strong certificate binding enforcement state is unknown."
                    )
                else:
                    print_info_debug(
                        "Skipping CertiHound ESC14 for template "
                        f"{mark_sensitive(template_name, 'template')} on "
                        f"{mark_sensitive(ca_name, 'ca_name')}: "
                        "no weak altSecurityIdentities mappings were found in LDAP."
                    )
                if esc14_result:
                    self._append_vulnerability(metadata_entry, "ESC14")
                    for principal_sid in esc14_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc14_edge(
                                principal_sid, template, ca
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc14_result.reasons),
                        )

                esc16_result = modules["detect_esc16"](template, ca, data.domain_sid)
                if esc16_result:
                    self._append_vulnerability(metadata_entry, "ESC16")
                    _record(
                        edge_generator.generate_adcsesc16_edge(template, ca),
                        template_names=[template_name],
                        template_dns=[template_dn],
                        ca_name=ca_name,
                        ca_dn=ca_dn,
                        reasons=list(esc16_result.reasons),
                    )

                esc17_result = modules["detect_esc17"](template, ca, data.domain_sid)
                if esc17_result:
                    self._append_vulnerability(metadata_entry, "ESC17")
                    for principal_sid in esc17_result.vulnerable_principals:
                        _record(
                            edge_generator.generate_adcsesc17_edge(
                                principal_sid, template, ca
                            ),
                            template_names=[template_name],
                            template_dns=[template_dn],
                            ca_name=ca_name,
                            ca_dn=ca_dn,
                            reasons=list(esc17_result.reasons),
                        )

            if esc3_agent_results and esc3_target_results:
                for agent_result in esc3_agent_results:
                    agent_template = template_by_cn.get(agent_result.template_name)
                    if agent_template is None:
                        continue
                    for target_result in esc3_target_results:
                        target_template = template_by_cn.get(target_result.template_name)
                        if target_template is None:
                            continue
                        reasons = list(agent_result.reasons) + list(target_result.reasons)
                        for principal_sid in agent_result.vulnerable_principals:
                            _record(
                                edge_generator.generate_adcsesc3_edge(
                                    principal_sid,
                                    agent_template,
                                    target_template,
                                    ca,
                                ),
                                template_names=[agent_result.template_name],
                                template_dns=[agent_result.template_dn],
                                agent_templates=[agent_result.template_name],
                                target_templates=[target_result.template_name],
                                ca_name=ca_name,
                                ca_dn=ca_dn,
                                reasons=reasons,
                            )

        # ESC5 object-control detections on PKI configuration objects.
        for esc5_result in self._detect_esc5_objects(
            connection=connection,
            domain_sid=data.domain_sid,
            modules=modules,
        ):
            for principal in esc5_result["vulnerable_principals"]:
                _record(
                    edge_generator.generate_adcsesc5_edge(
                        principal["sid"],
                        esc5_result["object_dn"],
                        esc5_result["object_type"],
                    ),
                    reasons=list(esc5_result["reasons"]),
                    extra_details={
                        "pkiobject": esc5_result["object_dn"],
                        "pkiobjecttype": esc5_result["object_type"],
                        "pkiobjectname": esc5_result["object_name"],
                    },
                )

        return {
            "edges": self._aggregate_edges(
                edges=detection_edges,
                template_by_dn=template_by_dn,
                ca_by_dn=ca_by_dn,
            ),
            "templates": template_metadata,
        }

    def _safe_apply_registry_flags_by_host(
        self,
        *,
        data: Any,
        username: str | None,
        credential: str | None,
        auth_domain: str,
        use_kerberos: bool,
        kdc_host: str | None,
    ) -> dict[str, Any]:
        """Enrich Enterprise CAs with registry-backed flags host by host."""
        enterprise_cas = list(getattr(data, "enterprise_cas", []) or [])
        if not enterprise_cas:
            return {"eligible_cas": 0, "hosts_attempted": 0, "cas_enriched": 0}
        if not str(username or "").strip():
            return {
                "eligible_cas": len(enterprise_cas),
                "hosts_attempted": 0,
                "cas_enriched": 0,
                "reason": "missing_username",
            }
        if not use_kerberos and not str(credential or "").strip():
            return {
                "eligible_cas": len(enterprise_cas),
                "hosts_attempted": 0,
                "cas_enriched": 0,
                "reason": "missing_credential",
            }

        grouped_by_host: OrderedDict[str, list[Any]] = OrderedDict()
        for ca in enterprise_cas:
            host = str(getattr(ca, "dns_hostname", "") or "").strip()
            if not host:
                continue
            grouped_by_host.setdefault(host.lower(), []).append(ca)

        if not grouped_by_host:
            return {
                "eligible_cas": len(enterprise_cas),
                "hosts_attempted": 0,
                "cas_enriched": 0,
                "reason": "missing_ca_hostnames",
            }

        hosts_attempted = 0
        cas_enriched = 0
        host_errors: list[str] = []
        for grouped_cas in grouped_by_host.values():
            host = str(getattr(grouped_cas[0], "dns_hostname", "") or "").strip()
            if not host:
                continue
            hosts_attempted += 1
            try:
                cas_enriched += self._apply_registry_flags_for_ca_host(
                    enterprise_cas=grouped_cas,
                    target_host=host,
                    username=str(username or "").strip(),
                    credential=str(credential or "").strip(),
                    auth_domain=str(auth_domain or "").strip(),
                    use_kerberos=use_kerberos,
                    kdc_host=str(kdc_host or "").strip() or None,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                host_errors.append(f"{host}: {type(exc).__name__}: {exc}")
                print_info_debug(
                    "[certihound] CA registry enrichment failed for "
                    f"{mark_sensitive(host, 'host')}: {type(exc).__name__}: {exc}"
                )

        result: dict[str, Any] = {
            "eligible_cas": len(enterprise_cas),
            "hosts_attempted": hosts_attempted,
            "cas_enriched": cas_enriched,
        }
        if host_errors:
            result["host_errors"] = host_errors
        return result

    def _apply_registry_flags_for_ca_host(
        self,
        *,
        enterprise_cas: list[Any],
        target_host: str,
        username: str,
        credential: str,
        auth_domain: str,
        use_kerberos: bool,
        kdc_host: str | None,
    ) -> int:
        """Apply registry-backed CA flags for all Enterprise CAs hosted on one server."""
        from certihound.rpc.ca_registry import CARegistryReader  # type: ignore  # pylint: disable=import-error
        from impacket.smbconnection import SMBConnection  # type: ignore

        connection = None
        enriched = 0
        try:
            connection = SMBConnection(
                remoteName=target_host,
                remoteHost=target_host,
                sess_port=445,
                timeout=10,
            )
            CertificateMappingService._authenticate_connection(  # type: ignore[attr-defined]
                connection=connection,
                username=username,
                credential=credential,
                auth_domain=auth_domain,
                auth_mode="kerberos" if use_kerberos else "password",
                kdc_host=kdc_host,
            )
            with CARegistryReader(connection) as reader:
                for ca in enterprise_cas:
                    ca_name = str(getattr(ca, "cn", "") or "").strip()
                    if not ca_name:
                        continue
                    flags = reader.read_ca_flags(
                        ca_name,
                        str(getattr(ca, "dns_hostname", "") or "").strip(),
                    )
                    if not flags.success:
                        continue
                    ca.is_user_specifies_san_enabled = flags.san_flag_enabled
                    ca.is_security_extension_disabled = (
                        flags.security_extension_disabled
                    )
                    base_flags = ca.flags if getattr(ca, "flags", None) is not None else 0
                    ca.flags = (base_flags & ~0x200) | (flags.interface_flags & 0x200)
                    enriched += 1
        finally:
            if connection is not None:
                try:
                    connection.logoff()
                except Exception:  # noqa: BLE001
                    pass
        return enriched

    def _safe_apply_certipy_ca_hints(
        self,
        *,
        data: Any,
        shell: Any | None,
        target_domain: str,
    ) -> dict[str, Any]:
        """Supplement CA objects with Certipy-derived non-LDAP context when available."""
        hints_by_key = self._load_certipy_ca_hints(shell=shell, target_domain=target_domain)
        if not hints_by_key:
            return {"eligible_cas": len(list(getattr(data, "enterprise_cas", []) or [])), "cas_enriched": 0}

        cas_enriched = 0
        for ca in list(getattr(data, "enterprise_cas", []) or []):
            matched_hint = self._match_certipy_ca_hint(ca=ca, hints_by_key=hints_by_key)
            if not matched_hint:
                continue
            changed = False
            if matched_hint.get("web_enrollment_enabled") and not bool(
                getattr(ca, "web_enrollment_enabled", False)
            ):
                ca.web_enrollment_enabled = True
                changed = True
            certipy_endpoints = list(matched_hint.get("enrollment_endpoints") or [])
            if certipy_endpoints:
                existing_endpoints = list(getattr(ca, "enrollment_endpoints", []) or [])
                merged = list(dict.fromkeys(existing_endpoints + certipy_endpoints))
                if merged != existing_endpoints:
                    ca.enrollment_endpoints = merged
                    changed = True
            if matched_hint.get("is_user_specifies_san_enabled") and not bool(
                getattr(ca, "is_user_specifies_san_enabled", False)
            ):
                ca.is_user_specifies_san_enabled = True
                changed = True
            enforce_encrypt_rpc = matched_hint.get("enforce_encrypt_rpc")
            if enforce_encrypt_rpc is not None:
                base_flags = getattr(ca, "flags", None)
                updated_flags = (base_flags or 0) & ~0x200
                if enforce_encrypt_rpc:
                    updated_flags |= 0x200
                if base_flags != updated_flags:
                    ca.flags = updated_flags
                    changed = True
            if changed:
                cas_enriched += 1

        return {
            "eligible_cas": len(list(getattr(data, "enterprise_cas", []) or [])),
            "cas_enriched": cas_enriched,
            "hints_loaded": len(hints_by_key),
        }

    def _match_certipy_ca_hint(
        self,
        *,
        ca: Any,
        hints_by_key: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Match one Enterprise CA to one Certipy CA hint entry."""
        candidate_keys = [
            str(getattr(ca, "cn", "") or "").strip().lower(),
            str(getattr(ca, "dns_hostname", "") or "").strip().lower(),
        ]
        for key in candidate_keys:
            if key and key in hints_by_key:
                return hints_by_key[key]
        return None

    def _load_certipy_ca_hints(
        self,
        *,
        shell: Any | None,
        target_domain: str,
    ) -> dict[str, dict[str, Any]]:
        """Load compact CA hints from the latest Certipy inventory JSON."""
        json_path = self._find_certipy_json_path(shell=shell, target_domain=target_domain)
        if not json_path:
            return {}
        try:
            data = read_json_file(json_path)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return {}

        certificate_authorities = data.get("Certificate Authorities")
        if not isinstance(certificate_authorities, dict):
            return {}

        hints: dict[str, dict[str, Any]] = {}
        for entry in certificate_authorities.values():
            if not isinstance(entry, dict):
                continue
            hint = self._build_certipy_ca_hint(entry)
            if not hint:
                continue
            for key in (
                str(entry.get("CA Name") or "").strip().lower(),
                str(entry.get("DNS Name") or "").strip().lower(),
            ):
                if key:
                    hints[key] = hint
        return hints

    def _find_certipy_json_path(
        self,
        *,
        shell: Any | None,
        target_domain: str,
    ) -> str | None:
        """Resolve the stable Certipy inventory JSON for one domain."""
        domain_data = getattr(shell, "domains_data", {}).get(target_domain, {})
        domain_dir = domain_data.get("dir") if isinstance(domain_data, dict) else None
        if not isinstance(domain_dir, str) or not domain_dir:
            return None
        adcs_dir = os.path.join(domain_dir, "adcs")
        if not os.path.isdir(adcs_dir):
            return None
        preferred = os.path.join(adcs_dir, "certipy_find_Certipy.json")
        if os.path.exists(preferred):
            return preferred
        candidates: list[tuple[float, str]] = []
        for name in os.listdir(adcs_dir):
            if not name.endswith("_Certipy.json"):
                continue
            path = os.path.join(adcs_dir, name)
            try:
                candidates.append((os.path.getmtime(path), path))
            except OSError:
                continue
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[0])[1]

    def _build_certipy_ca_hint(self, entry: dict[str, Any]) -> dict[str, Any] | None:
        """Extract CA-level detector hints from one Certipy CA inventory entry."""
        dns_name = str(entry.get("DNS Name") or "").strip()
        web_enrollment = entry.get("Web Enrollment")
        web_enabled = False
        endpoints: list[str] = []
        if isinstance(web_enrollment, dict):
            http_state = web_enrollment.get("http")
            if isinstance(http_state, dict) and http_state.get("enabled") is True:
                web_enabled = True
                if dns_name:
                    endpoints.append(f"http://{dns_name}/certsrv/")
            https_state = web_enrollment.get("https")
            if isinstance(https_state, dict) and https_state.get("enabled") is True:
                web_enabled = True
                if dns_name:
                    endpoints.append(f"https://{dns_name}/certsrv/")

        san_state = str(entry.get("User Specified SAN") or "").strip().lower()
        request_disposition = str(entry.get("Enforce Encryption for Requests") or "").strip().lower()
        vulnerabilities = entry.get("[!] Vulnerabilities") or {}
        if isinstance(vulnerabilities, dict) and "ESC8" in vulnerabilities:
            web_enabled = True
            if dns_name and not endpoints:
                endpoints.append(f"http://{dns_name}/certsrv/")

        if not any(
            (
                web_enabled,
                san_state == "enabled",
                request_disposition in {"enabled", "disabled"},
            )
        ):
            return None

        return {
            "web_enrollment_enabled": web_enabled,
            "enrollment_endpoints": endpoints,
            "is_user_specifies_san_enabled": san_state == "enabled",
            "enforce_encrypt_rpc": (
                True if request_disposition == "enabled"
                else False if request_disposition == "disabled"
                else None
            ),
        }

    def _safe_enumerate_issuance_policies(
        self,
        *,
        connection: Any,
        enumerate_issuance_policies: Any,
    ) -> dict[str, str]:
        """Best-effort load issuance policy OID mappings for ESC13."""
        try:
            policies = enumerate_issuance_policies(connection)
            return policies if isinstance(policies, dict) else {}
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return {}

    def _safe_enumerate_weak_altsecurityidentities_users(
        self,
        *,
        connection: Any,
        target_domain: str,
        shell: Any | None = None,
    ) -> list[AltSecurityIdentityUser]:
        """Return low-privileged enabled users with weak explicit mappings."""
        try:
            service = AltSecurityIdentitiesService()
            return service.find_users_with_weak_altsecurityidentities(
                connection=connection,
                domain=target_domain,
                shell=shell,
                enabled_only=True,
                low_privileged_only=True,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []

    def _safe_resolve_strong_certificate_binding_enforcement(
        self,
        *,
        connection: Any,
        dc_address: str,
        username: str | None = None,
        credential: str | None = None,
        target_domain: str,
        use_kerberos: bool = False,
    ) -> bool | None:
        """Return binding enforcement state when ADscan has a reliable source.

        LDAP template collection alone does not expose this domain controller
        setting. Attempt remote registry and return ``None`` when unavailable
        instead of assuming weak binding by default.
        """
        _ = connection
        if not str(dc_address or "").strip():
            return None
        if not str(username or "").strip():
            return None
        if not use_kerberos and not str(credential or "").strip():
            return None
        try:
            state = CertificateMappingService().read_dc_binding_state(
                target_host=str(dc_address).strip(),
                username=str(username or "").strip(),
                credential=str(credential or "").strip(),
                auth_domain=str(target_domain).strip(),
                use_kerberos=use_kerberos,
                kdc_host=str(dc_address).strip(),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return None
        return state.strong_binding_enforced


    def _detect_esc5_objects(
        self,
        *,
        connection: Any,
        domain_sid: str,
        modules: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Detect ESC5 on PKI configuration objects."""
        results: list[dict[str, Any]] = []
        config_dn = str(getattr(connection.config, "config_dn", "") or "").strip()
        if not config_dn:
            return results

        public_key_services_dn = f"CN=Public Key Services,CN=Services,{config_dn}"
        object_targets = [
            ("Public Key Services", public_key_services_dn, "container"),
            (
                "Certificate Templates",
                f"CN=Certificate Templates,{public_key_services_dn}",
                "container",
            ),
            (
                "Certification Authorities",
                f"CN=Certification Authorities,{public_key_services_dn}",
                "container",
            ),
            (
                "Enrollment Services",
                f"CN=Enrollment Services,{public_key_services_dn}",
                "container",
            ),
            ("NTAuthCertificates", f"CN=NTAuthCertificates,{public_key_services_dn}", "ntauth"),
            ("AIA", f"CN=AIA,{public_key_services_dn}", "container"),
        ]

        for object_name, object_dn, object_type in object_targets:
            try:
                connection.search(
                    search_base=object_dn,
                    search_filter="(objectClass=*)",
                    attributes=["cn", "distinguishedName", "nTSecurityDescriptor"],
                    search_scope=modules["BASE"],
                )
                entries = getattr(connection.connection, "entries", []) or []
                if not entries:
                    continue
                entry = entries[0]
                raw_sd = None
                try:
                    raw_sd = (
                        entry.entry_raw_attributes.get("nTSecurityDescriptor", [None])[0]
                    )
                except Exception:
                    raw_sd = None
                if not raw_sd:
                    continue
                sd_parser = modules["SecurityDescriptorParser"](raw_sd)
                esc5_result = modules["detect_esc5"](
                    object_name,
                    object_dn,
                    object_type,
                    sd_parser,
                    domain_sid,
                )
                if esc5_result:
                    results.append(
                        {
                            "object_name": esc5_result.object_name,
                            "object_dn": esc5_result.object_dn,
                            "object_type": esc5_result.object_type,
                            "vulnerable_principals": list(
                                esc5_result.vulnerable_principals
                            ),
                            "reasons": list(esc5_result.reasons),
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                continue

        return results

    def _aggregate_edges(
        self,
        *,
        edges: list[dict[str, Any]],
        template_by_dn: dict[str, Any],
        ca_by_dn: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Merge repeated principal->domain detections into stable edge records."""
        aggregated: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
        for edge in edges:
            relation = str(edge.get("relation") or "").strip()
            start_object_id = str(edge.get("start_object_id") or "").strip()
            end_object_id = str(edge.get("end_object_id") or "").strip()
            if not relation or not start_object_id or not end_object_id:
                continue
            key = (start_object_id, relation, end_object_id)
            record = aggregated.setdefault(
                key,
                {
                    "relation": relation,
                    "start_object_id": start_object_id,
                    "end_object_id": end_object_id,
                    "details": {
                        "source": "certihound",
                        "detector": "certihound",
                        "templates": [],
                        "template_dns": [],
                        "agent_templates": [],
                        "target_templates": [],
                        "reasons": [],
                        "enterprisecas": [],
                        "enterpriseca_dns": [],
                    },
                },
            )
            details = edge.get("details") if isinstance(edge.get("details"), dict) else {}
            merged_details = record["details"]
            for field_name in (
                "templates",
                "template_dns",
                "agent_templates",
                "target_templates",
                "reasons",
                "enterprisecas",
                "enterpriseca_dns",
            ):
                values = details.get(field_name)
                if isinstance(values, list):
                    existing = set(merged_details.get(field_name) or [])
                    existing.update(str(value) for value in values if str(value).strip())
                    merged_details[field_name] = sorted(existing, key=str.lower)

            ca_name = details.get("enterpriseca_name")
            if isinstance(ca_name, str) and ca_name.strip():
                existing = set(merged_details.get("enterprisecas") or [])
                existing.add(ca_name.strip())
                merged_details["enterprisecas"] = sorted(existing, key=str.lower)

            ca_dn = details.get("enterpriseca")
            if isinstance(ca_dn, str) and ca_dn.strip():
                existing = set(merged_details.get("enterpriseca_dns") or [])
                existing.add(ca_dn.strip())
                merged_details["enterpriseca_dns"] = sorted(existing, key=str.lower)

            for scalar_field in (
                "template",
                "enterpriseca_name",
                "enterpriseca",
                "linkedgroup",
                "issuancepolicyoid",
                "pkiobject",
                "pkiobjecttype",
                "pkiobjectname",
                "webenrollmenturl",
            ):
                value = details.get(scalar_field)
                if value not in (None, "", []):
                    merged_details[scalar_field] = value

        # Enrich single-template/template-DN cases.
        for record in aggregated.values():
            details = record["details"]
            templates = details.get("templates") or []
            if isinstance(templates, list) and len(templates) == 1:
                details["template"] = templates[0]
            template_dns = details.get("template_dns") or []
            if (
                isinstance(template_dns, list)
                and len(template_dns) == 1
                and isinstance(template_dns[0], str)
            ):
                template = template_by_dn.get(template_dns[0])
                if template is not None:
                    details.setdefault("template", str(getattr(template, "cn", "") or "").strip())
            ca_dns = details.get("enterpriseca_dns") or []
            if (
                isinstance(ca_dns, list)
                and len(ca_dns) == 1
                and isinstance(ca_dns[0], str)
            ):
                ca = ca_by_dn.get(ca_dns[0])
                if ca is not None:
                    details.setdefault(
                        "enterpriseca_name",
                        str(getattr(ca, "cn", "") or "").strip(),
                    )

        return list(aggregated.values())

    def _append_vulnerability(
        self,
        metadata_entry: dict[str, Any],
        vulnerability_name: str,
    ) -> None:
        """Append one vulnerability tag to template metadata without duplicates."""
        vulnerabilities = metadata_entry.setdefault("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
            metadata_entry["vulnerabilities"] = vulnerabilities
        if vulnerability_name not in vulnerabilities:
            vulnerabilities.append(vulnerability_name)
