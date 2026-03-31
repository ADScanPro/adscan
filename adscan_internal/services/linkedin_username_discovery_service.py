"""Internal LinkedIn employee discovery for focused Kerberos username generation.

This adapts the useful scraping logic from the vendored ``external_tools``
reference into an ADscan-native service so the CLI controls the UX directly.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
import urllib.parse
from pathlib import Path
from typing import Callable, Protocol

import requests
from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive


def _emit_debug(message: str) -> None:
    """Send one debug line through the centralized Rich debug channel."""
    try:
        print_info_debug(message)
    except Exception:
        pass


GEO_REGIONS: dict[str, str] = {
    "ar": "100446943",
    "at": "103883259",
    "au": "101452733",
    "be": "100565514",
    "bg": "105333783",
    "ca": "101174742",
    "ch": "106693272",
    "cl": "104621616",
    "de": "101282230",
    "dk": "104514075",
    "es": "105646813",
    "fi": "100456013",
    "fo": "104630756",
    "fr": "105015875",
    "gb": "101165590",
    "gf": "105001561",
    "gp": "104232339",
    "gr": "104677530",
    "gu": "107006862",
    "hr": "104688944",
    "hu": "100288700",
    "is": "105238872",
    "it": "103350119",
    "li": "100878084",
    "lu": "104042105",
    "mq": "103091690",
    "nl": "102890719",
    "no": "103819153",
    "nz": "105490917",
    "pe": "102927786",
    "pl": "105072130",
    "pr": "105245958",
    "pt": "100364837",
    "py": "104065273",
    "re": "104265812",
    "rs": "101855366",
    "ru": "101728296",
    "se": "105117694",
    "sg": "102454443",
    "si": "106137034",
    "tw": "104187078",
    "ua": "102264497",
    "us": "103644278",
    "uy": "100867946",
    "ve": "101490751",
}


@dataclass(frozen=True)
class LinkedInEmployee:
    """One employee-like search hit from LinkedIn."""

    full_name: str
    occupation: str


@dataclass(frozen=True)
class LinkedInCompanyInfo:
    """Minimal company info needed for employee collection."""

    company_id: str
    staff_count: int
    name: str
    website: str


@dataclass(frozen=True)
class LinkedInCollectionOptions:
    """Collection controls for LinkedIn employee discovery."""

    company_slug: str
    geoblast: bool = True
    depth: int | None = None
    sleep_seconds: float = 0.0


class LinkedInSessionInvalidError(RuntimeError):
    """Raised when a cached/authenticated LinkedIn session is no longer valid."""


class LinkedInSessionProvider(Protocol):
    """Protocol for obtaining an authenticated LinkedIn session."""

    def login_and_build_session(
        self,
        *,
        wait_for_user_ready: Callable[[], bool],
    ) -> requests.Session: ...


class LinkedInEmployeeCollector(Protocol):
    """Protocol for collecting employee names from LinkedIn."""

    def collect_employees(
        self,
        *,
        company_slug: str,
        session: requests.Session,
        geoblast: bool = True,
        depth: int | None = None,
        sleep_seconds: float = 0.0,
    ) -> tuple[LinkedInCompanyInfo, list[LinkedInEmployee]]: ...


class SeleniumLinkedInSessionProvider:
    """Obtain an authenticated LinkedIn requests session through Selenium."""

    def open_login_browser(self):
        """Open a Selenium-controlled browser on the LinkedIn login page."""
        try:
            from selenium import webdriver
            from selenium.common.exceptions import WebDriverException
            from selenium.webdriver.chrome.options import Options as ChromeOptions
        except Exception as exc:  # pragma: no cover - depends on runtime extras
            raise RuntimeError(
                "Selenium is not available in this runtime. Rebuild the ADscan runtime "
                "with the LinkedIn browser dependencies enabled."
            ) from exc

        browser_errors: list[str] = []

        try:
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            driver.get("https://www.linkedin.com/login")
            return driver
        except WebDriverException as exc:
            browser_errors.append(f"Chrome: {exc}")

        try:
            driver = webdriver.Firefox()
            driver.get("https://www.linkedin.com/login")
            return driver
        except Exception as exc:  # pragma: no cover - optional fallback
            browser_errors.append(f"Firefox: {exc}")

        raise RuntimeError(
            "Could not launch a Selenium browser for LinkedIn login. "
            f"Errors: {' | '.join(browser_errors)}"
        )

    def build_authenticated_session(self, driver) -> requests.Session:
        """Extract cookies from Selenium and build an authenticated requests session."""
        selenium_cookies = driver.get_cookies()
        driver.quit()

        session = requests.Session()
        for cookie in selenium_cookies:
            session.cookies.set(cookie["name"], cookie["value"])

        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 14; ADscan) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0 Mobile Safari/537.36"
                ),
                "X-RestLi-Protocol-Version": "2.0.0",
                "X-Li-Track": '{"clientVersion":"1.13.1665"}',
            }
        )
        jsession = session.cookies.get("JSESSIONID")
        if not jsession:
            raise RuntimeError(
                "LinkedIn login did not produce a JSESSIONID cookie. "
                "Make sure you completed the login in the browser before continuing."
            )
        session.headers.update({"Csrf-Token": jsession.replace('"', "")})
        return session

    def login_and_build_session(
        self,
        *,
        wait_for_user_ready: Callable[[], bool],
    ) -> requests.Session:
        """Open browser login flow and return an authenticated requests session."""
        driver = self.open_login_browser()
        if not wait_for_user_ready():
            driver.quit()
            raise RuntimeError("LinkedIn employee collection was cancelled before login completed.")
        return self.build_authenticated_session(driver)


class CachedLinkedInSessionProvider:
    """Persist and restore LinkedIn sessions from workspace cookies."""

    def __init__(self, cache_path: str | Path) -> None:
        self.cache_path = Path(cache_path)

    def load_session(self) -> requests.Session | None:
        """Load a cached LinkedIn requests session from disk."""
        if not self.cache_path.exists() or not self.cache_path.is_file():
            _emit_debug(
                f"[linkedin] no cached session present at "
                f"{mark_sensitive(str(self.cache_path), 'path')}"
            )
            return None
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            _emit_debug(
                f"[linkedin] cached session file at "
                f"{mark_sensitive(str(self.cache_path), 'path')} could not be parsed"
            )
            return None
        cookies = payload.get("cookies")
        if not isinstance(cookies, list) or not cookies:
            _emit_debug(
                f"[linkedin] cached session at "
                f"{mark_sensitive(str(self.cache_path), 'path')} does not contain usable cookies"
            )
            return None
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 14; ADscan) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0 Mobile Safari/537.36"
                ),
                "X-RestLi-Protocol-Version": "2.0.0",
                "X-Li-Track": '{"clientVersion":"1.13.1665"}',
            }
        )
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get("name") or "")
            value = str(cookie.get("value") or "")
            domain = str(cookie.get("domain") or "")
            path = str(cookie.get("path") or "/")
            if name and value:
                cookie_kwargs = {"path": path}
                if domain:
                    cookie_kwargs["domain"] = domain
                session.cookies.set(name, value, **cookie_kwargs)
        jsession = session.cookies.get("JSESSIONID")
        if jsession:
            session.headers.update({"Csrf-Token": jsession.replace('"', "")})
        _emit_debug(
            "[linkedin] loaded cached session from "
            f"{mark_sensitive(str(self.cache_path), 'path')} with "
            f"{len(list(session.cookies))} cookies"
        )
        return session

    def save_session(self, session: requests.Session) -> None:
        """Persist a LinkedIn requests session to disk for future reuse."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        cookies_payload = []
        for cookie in session.cookies:
            cookies_payload.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                }
            )
        self.cache_path.write_text(
            json.dumps({"cookies": cookies_payload}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        _emit_debug(
            "[linkedin] saved cached session to "
            f"{mark_sensitive(str(self.cache_path), 'path')} with "
            f"{len(cookies_payload)} cookies"
        )

    def clear(self) -> None:
        """Remove a stale cached LinkedIn session file."""
        try:
            self.cache_path.unlink(missing_ok=True)
            _emit_debug(
                f"[linkedin] cleared cached session at "
                f"{mark_sensitive(str(self.cache_path), 'path')}"
            )
        except Exception:
            _emit_debug(
                f"[linkedin] failed to clear cached session at "
                f"{mark_sensitive(str(self.cache_path), 'path')}"
            )
            pass


class VoyagerLinkedInEmployeeCollector:
    """Collect employee names through LinkedIn Voyager endpoints."""

    def _extract_text_field(self, value: object) -> str:
        """Extract a safe text value from LinkedIn mixed-shape fields."""
        if isinstance(value, dict):
            nested = value.get("text")
            return str(nested or "").strip()
        if isinstance(value, str):
            return value.strip()
        return ""

    def validate_company_slug_public(self, company_slug: str) -> bool | None:
        """Best-effort validation of a LinkedIn company slug without authentication.

        Returns:
            True: slug appears valid.
            False: slug appears invalid.
            None: could not determine conclusively.
        """
        slug = str(company_slug or "").strip().strip("/")
        if not slug:
            return False
        try:
            response = requests.get(
                f"https://www.linkedin.com/company/{slug}/",
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
                timeout=15,
            )
        except Exception:
            return None

        if response.status_code == 404:
            return False
        if response.status_code == 200:
            return True
        return None

    def get_company_info(
        self,
        *,
        company_slug: str,
        session: requests.Session,
    ) -> LinkedInCompanyInfo:
        """Resolve company metadata from the LinkedIn company slug."""
        escaped_name = urllib.parse.quote_plus(company_slug)
        response = session.get(
            "https://www.linkedin.com/voyager/api/organization/companies"
            f"?q=universalName&universalName={escaped_name}"
        )
        if response.status_code in {401, 403, 999} or "/login" in str(response.url):
            raise LinkedInSessionInvalidError(
                "The current LinkedIn session is not authenticated anymore."
            )
        if response.status_code == 404:
            raise RuntimeError(
                "LinkedIn could not find that company slug. Check the organization URL slug and try again."
            )
        if response.status_code != 200:
            raise RuntimeError(
                f"LinkedIn company lookup failed with HTTP {response.status_code}."
            )
        if "mwlite" in response.text:
            raise RuntimeError(
                "LinkedIn returned the unsupported 'lite' experience for this session. "
                "Try again from a different exit region or browser profile."
            )

        try:
            response_json = json.loads(response.text)
            company = response_json["elements"][0]
        except Exception as exc:
            raise RuntimeError("Could not parse LinkedIn company information.") from exc

        _emit_debug(
            "[linkedin] company resolved slug="
            f"{mark_sensitive(company_slug, 'company')} id="
            f"{mark_sensitive(str(company['trackingInfo']['objectUrn'].split(':')[-1]), 'id')} "
            f"staff_count={company.get('staffCount')}"
        )
        return LinkedInCompanyInfo(
            company_id=str(company["trackingInfo"]["objectUrn"].split(":")[-1]),
            staff_count=int(company["staffCount"]),
            name=str(company.get("name") or company_slug),
            website=str(company.get("companyPageUrl") or ""),
        )

    def collect_employees(
        self,
        *,
        company_slug: str,
        session: requests.Session,
        geoblast: bool = True,
        depth: int | None = None,
        sleep_seconds: float = 0.0,
    ) -> tuple[LinkedInCompanyInfo, list[LinkedInEmployee]]:
        """Collect employee names for a LinkedIn company slug."""
        company_info = self.get_company_info(company_slug=company_slug, session=session)
        max_loops = depth or int((company_info.staff_count / 50) + 1)

        outer_regions: list[str | None]
        if geoblast and company_info.staff_count > 1000:
            outer_regions = list(GEO_REGIONS.values())
        else:
            outer_regions = [None]

        employees: list[LinkedInEmployee] = []
        seen: set[tuple[str, str]] = set()
        pages_visited = 0
        malformed_skipped = 0

        for region in outer_regions:
            for page in range(max_loops):
                pages_visited += 1
                result = self._get_results(
                    session=session,
                    company_id=company_info.company_id,
                    page=page,
                    region=region,
                )
                if result.status_code != 200:
                    raise RuntimeError(
                        f"LinkedIn employee search failed with HTTP {result.status_code}."
                    )
                if "UPSELL_LIMIT" in result.text:
                    return company_info, employees

                found_employees, skipped_in_page = self._find_employees(result.text)
                malformed_skipped += skipped_in_page
                if not found_employees:
                    break

                added_this_page = 0
                for employee in found_employees:
                    key = (employee.full_name.strip(), employee.occupation.strip())
                    if key in seen:
                        continue
                    seen.add(key)
                    employees.append(employee)
                    added_this_page += 1

                if added_this_page == 0:
                    break
                time.sleep(max(0.0, sleep_seconds))

        _emit_debug(
            "[linkedin] collected employees slug="
            f"{mark_sensitive(company_slug, 'company')} "
            f"pages={pages_visited} raw_unique={len(employees)} "
            f"malformed_skipped={malformed_skipped} geoblast={geoblast}"
        )
        return company_info, employees

    def _get_results(
        self,
        *,
        session: requests.Session,
        company_id: str,
        page: int,
        region: str | None,
    ) -> requests.Response:
        """Query the LinkedIn people search API for one page of employees."""
        url = (
            "https://www.linkedin.com/voyager/api/graphql?variables=("
            f"start:{page * 50},"
            "query:("
            "flagshipSearchIntent:SEARCH_SRP,"
            f"queryParameters:List((key:currentCompany,value:List({company_id})),"
            f"{f'(key:geoUrn,value:List({region})),' if region else ''}"
            "(key:resultType,value:List(PEOPLE))),"
            "includeFiltersInResponse:false),count:50)"
            "&queryId=voyagerSearchDashClusters.66adc6056cf4138949ca5dcb31bb1749"
        )
        return session.get(url)

    def _find_employees(self, result_text: str) -> tuple[list[LinkedInEmployee], int]:
        """Parse one LinkedIn search response into a list of employee-like records."""
        try:
            result_json = json.loads(result_text)
        except Exception as exc:
            raise RuntimeError("Could not decode LinkedIn employee search JSON.") from exc

        data = result_json.get("data", {})
        search_clusters = data.get("searchDashClustersByAll", {})
        elements = search_clusters.get("elements", [])
        paging = search_clusters.get("paging", {})
        total = paging.get("total", 0)
        if total == 0:
            return [], 0

        employees: list[LinkedInEmployee] = []
        malformed_skipped = 0
        for element in elements:
            for item_body in element.get("items", []):
                entity = item_body.get("item", {}).get("entityResult", {})
                if not entity:
                    continue
                full_name = self._extract_text_field(entity.get("title"))
                if not full_name:
                    malformed_skipped += 1
                    continue
                if full_name.startswith("Dr "):
                    full_name = full_name[3:].strip()
                occupation = self._extract_text_field(entity.get("primarySubtitle"))
                employees.append(
                    LinkedInEmployee(full_name=full_name, occupation=occupation)
                )
        return employees, malformed_skipped


class LinkedInUsernameDiscoveryService:
    """Facade coordinating LinkedIn session acquisition and employee collection."""

    def __init__(
        self,
        *,
        session_provider: LinkedInSessionProvider | None = None,
        employee_collector: LinkedInEmployeeCollector | None = None,
        cache_provider: CachedLinkedInSessionProvider | None = None,
    ) -> None:
        self.session_provider = session_provider or SeleniumLinkedInSessionProvider()
        self.employee_collector = employee_collector or VoyagerLinkedInEmployeeCollector()
        self.cache_provider = cache_provider

    def login_and_collect(
        self,
        *,
        company_slug: str,
        wait_for_user_ready: Callable[[], bool],
        geoblast: bool = True,
        depth: int | None = None,
        sleep_seconds: float = 0.0,
    ) -> tuple[LinkedInCompanyInfo, list[LinkedInEmployee]]:
        """Reuse a cached session when possible, otherwise fall back to interactive login."""
        cached_session = self.cache_provider.load_session() if self.cache_provider else None
        if cached_session is not None:
            try:
                _emit_debug(
                    "[linkedin] trying cached LinkedIn session for slug="
                    f"{mark_sensitive(company_slug, 'company')}"
                )
                return self.employee_collector.collect_employees(
                    company_slug=company_slug,
                    session=cached_session,
                    geoblast=geoblast,
                    depth=depth,
                    sleep_seconds=sleep_seconds,
                )
            except LinkedInSessionInvalidError:
                _emit_debug(
                    "[linkedin] cached LinkedIn session expired for slug="
                    f"{mark_sensitive(company_slug, 'company')}; "
                    "falling back to interactive login"
                )
                if self.cache_provider:
                    self.cache_provider.clear()

        _emit_debug(
            "[linkedin] starting interactive LinkedIn login for slug="
            f"{mark_sensitive(company_slug, 'company')}"
        )
        session = self.session_provider.login_and_build_session(
            wait_for_user_ready=wait_for_user_ready
        )
        if self.cache_provider:
            self.cache_provider.save_session(session)
        return self.employee_collector.collect_employees(
            company_slug=company_slug,
            session=session,
            geoblast=geoblast,
            depth=depth,
            sleep_seconds=sleep_seconds,
        )

    def collect_with_existing_session(
        self,
        *,
        options: LinkedInCollectionOptions,
        session: requests.Session,
    ) -> tuple[LinkedInCompanyInfo, list[LinkedInEmployee]]:
        """Collect employees from an already-authenticated LinkedIn session."""
        return self.employee_collector.collect_employees(
            company_slug=options.company_slug,
            session=session,
            geoblast=options.geoblast,
            depth=options.depth,
            sleep_seconds=options.sleep_seconds,
        )

    def validate_company_slug_public(self, company_slug: str) -> bool | None:
        """Validate a LinkedIn company slug via the public company page when supported."""
        validator = getattr(self.employee_collector, "validate_company_slug_public", None)
        if callable(validator):
            return validator(company_slug)
        return None


__all__ = [
    "CachedLinkedInSessionProvider",
    "LinkedInCollectionOptions",
    "LinkedInCompanyInfo",
    "LinkedInEmployee",
    "LinkedInEmployeeCollector",
    "LinkedInSessionInvalidError",
    "LinkedInSessionProvider",
    "LinkedInUsernameDiscoveryService",
    "SeleniumLinkedInSessionProvider",
    "VoyagerLinkedInEmployeeCollector",
]
