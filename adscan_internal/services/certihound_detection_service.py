"""Internal ADCS detection pipeline backed by CertiHound library primitives.

This service does not rely on BloodHound relationship queries. It collects ADCS
objects via CertiHound, runs ESC detections directly, and returns a normalized
JSON-serializable report that ADscan can persist and consume for attack-path
generation.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from adscan_internal import telemetry
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import execute_with_ldap_fallback


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
                report = self._run_all_detections(
                    data=data,
                    connection=connection,
                    modules=modules,
                )
                report["domain"] = data.domain
                report["domain_sid"] = data.domain_sid
                report["generated_at"] = datetime.now(timezone.utc).isoformat()
                report["schema_version"] = "certihound-detections-1.0"
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
            )
            return report
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            self.logger.exception("CertiHound detection report generation failed")
            return None

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
    ) -> dict[str, Any]:
        """Run all supported ESC detections and return normalized edges/metadata."""
        edge_generator = modules["EdgeGenerator"](data.domain_sid)
        issuance_policies = self._safe_enumerate_issuance_policies(
            connection=connection,
            enumerate_issuance_policies=modules["enumerate_issuance_policies"],
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
                    },
                )

            esc11_result = modules["detect_esc11"](ca)
            if esc11_result:
                _record(
                    edge_generator.generate_adcsesc11_edge(ca),
                    ca_name=ca_name,
                    ca_dn=ca_dn,
                    reasons=list(esc11_result.reasons),
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

                esc14_result = modules["detect_esc14"](template, ca, data.domain_sid)
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
