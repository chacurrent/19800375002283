import base64
import html
import ipaddress
import os
import time
from urllib.parse import urlparse, urlunparse
import requests

VT_API_KEY = os.getenv(
    "VT_API_KEY",
    "2f8ed280bfc86fa50f1d215681094a86396b96a9123a728116d1325baf2a023d",
)
VT_BASE_URL = "https://www.virustotal.com/api/v3"

OFFICIAL_DOMAINS = [
    "naver.com", "kakao.com", "daum.net", "google.com", "youtube.com",
    "apple.com", "microsoft.com", "toss.im", "kbstar.com", "shinhan.com",
    "wooribank.com", "hanabank.com", "nhbank.com", "coupang.com", "gov.kr",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "han.gl", "me2.do", "vo.la", "url.kr", "cutt.ly", "rb.gy",
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "banking", "wallet", "auth",
}

RESERVED_TEST_TLDS = {"test", "invalid", "localhost", "example"}

CATEGORY_KO_MAP = {
    "search engines": "검색·포털",
    "portals": "검색·포털",
    "information technology": "IT·웹 서비스",
    "business": "비즈니스·기업",
    "education": "교육·기관",
    "government": "공공·정부기관",
    "finance": "금융·은행",
    "shopping": "쇼핑·커머스",
    "social networking": "SNS·커뮤니티",
    "news": "뉴스·미디어",
    "entertainment": "엔터테인먼트",
    "reference": "사전·정보자료",
    "health": "의료·건강",
    "travel": "여행·교통",
}

MALICIOUS_CATEGORY_KEYWORDS = (
    "phishing", "malicious", "malware", "compromised",
    "botnet", "scam", "fraud", "ransomware", "trojan", "spyware",
)

SUSPICIOUS_CATEGORY_KEYWORDS = (
    "spam", "suspicious", "untrusted", "not recommended", "adware", "hack",
    "elevated exposure", "high risk", "moderate risk", "caution", "warning", "greyware",
)

UNRATED_CATEGORY_KEYWORDS = (
    "unrated", "unknown", "uncategorized", "none", "parked",
    "newly registered", "newly observed", "low risk",
)


def normalize_and_validate_url(raw_url: str) -> tuple[bool, str]:
    """앞뒤 공백·제어문자를 제거하고 검사 가능한 정상 웹 URL 형식인지 검증합니다."""
    if not isinstance(raw_url, str):
        return False, "유효하지 않은 입력 형식입니다."

    cleaned = raw_url.replace("\u200b", "").replace("\ufeff", "").strip()
    if not cleaned:
        return False, "링크 주소(URL)를 입력해주세요."
    if len(cleaned) > 2000:
        return False, "링크 주소가 너무 깁니다. (최대 2,000자)"
    if any(ch in cleaned for ch in (" ", "\n", "\r", "\t")):
        return False, "링크 주소에 공백이나 줄바꿈이 포함되어 있습니다. 다시 확인해주세요."

    lowered = cleaned.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "file:", "ftp:", "vbscript:")):
        return False, "웹사이트 주소(http:// 또는 https://)만 검사할 수 있습니다."

    if "://" in cleaned and not lowered.startswith(("http://", "https://")):
        return False, "http:// 또는 https:// 로 시작하는 웹 주소만 검사할 수 있습니다."

    if not lowered.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
        _ = parsed.port
    except ValueError:
        return False, "올바른 링크 또는 포트 번호 형식이 아닙니다. (예: https://www.naver.com)"

    raw_host = (parsed.hostname or "").strip().lower()
    if (
        not raw_host
        or "." not in raw_host
        or ".." in raw_host
        or raw_host.startswith(".")
        or raw_host.endswith(".")
        or raw_host == "localhost"
    ):
        return False, "올바른 도메인 형식이 아닙니다. (예: https://www.naver.com)"

    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(raw_host)
        is_ip = True
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_multicast:
            return False, "내부망(로컬) IP 주소는 외부 보안 검사를 실행할 수 없습니다."
    except ValueError:
        is_ip = False

    if not is_ip:
        try:
            ascii_host = raw_host.encode("idna").decode("ascii")
        except UnicodeError:
            return False, "해석할 수 없는 도메인 문자(IDN)가 포함되어 있습니다."

        labels = ascii_host.split(".")
        if any(not lbl or len(lbl) > 63 or lbl.startswith("-") or lbl.endswith("-") for lbl in labels):
            return False, "올바른 도메인 형식이 아닙니다. (예: https://www.naver.com)"
        tld = labels[-1]
        if len(tld) < 2 or tld.isdigit():
            return False, "올바른 도메인 확장자(.com, .kr 등)를 포함한 주소를 입력해주세요."
        if tld in RESERVED_TEST_TLDS:
            return False, f"예약된 테스트용 도메인(.{tld})은 실제 인터넷에 존재하지 않아 검사할 수 없습니다."

    normalized_netloc = parsed.netloc.lower() if not parsed.username else parsed.netloc
    normalized_url = urlunparse(
        (
            parsed.scheme.lower(),
            normalized_netloc,
            parsed.path or "",
            parsed.params or "",
            parsed.query or "",
            "",
        )
    )
    return True, normalized_url


def _normalize_homoglyphs(text: str) -> str:
    return (
        text.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("rn", "m")
        .replace("vv", "w")
    )


def _is_lookalike_domain(hostname: str) -> str | None:
    parts = hostname.lower().split(".")
    reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()
    norm_reg = _normalize_homoglyphs(reg_domain)

    for official in OFFICIAL_DOMAINS:
        if reg_domain == official:
            continue
        if norm_reg == official:
            return official
        if len(reg_domain) == len(official):
            if sum(1 for a, b in zip(reg_domain, official) if a != b) == 1:
                return official
            if len(official) >= 6 and sum(1 for a, b in zip(norm_reg, official) if a != b) <= 1:
                return official
        brand = official.split(".")[0]
        if len(brand) >= 4 and (f"{brand}-" in reg_domain or f"-{brand}" in reg_domain):
            return official
    return None


def analyze_url_technically(url: str) -> dict:
    """보안 연결(HTTPS)과 도메인 위장·사칭 여부를 분석하고 체력바(안전도 %)를 계산합니다."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    parts = hostname.split(".")
    reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    final_url = url
    redirect_hops = 0
    conn_risk = 0
    struct_risk = 0
    reason_tags = []

    # 1) 보안 연결(HTTPS) 및 단축 URL 추적
    is_https = parsed.scheme == "https"
    if not is_https:
        conn_risk += 1
        reason_tags.append("비암호화(HTTP) 연결")

    is_shortener = hostname in SHORTENER_DOMAINS
    ssl_issue = False
    if is_shortener:
        conn_risk += 1
        reason_tags.append("단축 URL 우회")
        try:
            with requests.get(url, timeout=4, allow_redirects=True, stream=True) as resp:
                ok_dest, clean_dest = normalize_and_validate_url(resp.url)
                if ok_dest:
                    final_url = clean_dest
                redirect_hops = len(resp.history)
        except requests.exceptions.SSLError:
            ssl_issue = True
            conn_risk += 2
            reason_tags.append("SSL 인증서 오류")
        except requests.exceptions.TooManyRedirects:
            conn_risk += 2
        except requests.exceptions.RequestException:
            pass

    downgraded_http = is_https and urlparse(final_url).scheme == "http"
    if downgraded_http:
        conn_risk += 2
        reason_tags.append("HTTPS→HTTP 전환")

    if ssl_issue:
        conn_main = "인증서 오류"
        conn_desc = "보안 인증서가 손상되어 통신 가로채기 위험이 있습니다. (SSL 검증 실패 · +2점)"
        conn_hp, conn_level = 15, "danger"
    elif downgraded_http:
        conn_main = "암호화 해제 전환"
        conn_desc = f"접속 도중 보안 연결(HTTPS)이 풀려 일반 HTTP로 연결됩니다. (경유 {redirect_hops}회 · +2점)"
        conn_hp, conn_level = 20, "danger"
    elif is_https and not is_shortener:
        conn_main = "HTTPS 암호화 적용"
        conn_desc = "통신 구간이 암호화되어 비밀번호나 개인정보가 안전하게 보호됩니다."
        conn_hp, conn_level = 100, "safe"
    elif is_https and is_shortener:
        conn_main = "단축 URL 우회 연결"
        conn_desc = f"짧은 주소({hostname}) 뒤에 실제 목적지를 숨기고 있어 도착 주소를 확인하세요. (+1점)"
        conn_hp, conn_level = 55, "caution"
    else:
        conn_main = "암호화 미적용 (HTTP)"
        conn_desc = "데이터가 암호화 없이 전송되므로 로그인·개인정보 입력을 피하세요. (HTTP 평문 · +1점)"
        conn_hp, conn_level = 50, "caution"

    # 2) 주소 위장·사칭 점검
    is_public_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_public_ip = True
    except ValueError:
        is_public_ip = False

    lookalike = _is_lookalike_domain(hostname)
    has_at_trick = bool(parsed.username)
    has_punycode = any(lbl.startswith("xn--") for lbl in parts)
    try:
        port_val = parsed.port
    except ValueError:
        port_val = None
    non_std_port = port_val is not None and port_val not in (80, 443)
    deep_subdomain = (not is_public_ip) and (len(parts) >= 4) and (reg_domain not in OFFICIAL_DOMAINS)
    has_phish_kw = (
        (not is_public_ip)
        and (reg_domain not in OFFICIAL_DOMAINS)
        and any(kw in hostname for kw in PHISHING_KEYWORDS)
    )

    risk_flags = []
    if has_at_trick:
        struct_risk += 3
        risk_flags.append("@ 우회 기호")
        reason_tags.append("@ 주소 우회 트릭")
    if is_public_ip:
        struct_risk += 3
        risk_flags.append("숫자 IP 접속")
        reason_tags.append("숫자 IP 직접 접속")
    if lookalike:
        struct_risk += 4
        risk_flags.append(f"{lookalike} 유사 사칭")
        reason_tags.append(f"공식 사이트({lookalike}) 사칭 의심")
    if has_punycode:
        struct_risk += 2
        risk_flags.append("퓨니코드(xn--)")
        reason_tags.append("퓨니코드 변환 도메인")
    if non_std_port:
        struct_risk += 1
        risk_flags.append(f"비표준 포트(:{port_val})")
    if deep_subdomain:
        struct_risk += 1
        risk_flags.append(f"{len(parts)}단계 하위 도메인")
    if has_phish_kw:
        struct_risk += 1
        risk_flags.append("계정·인증 키워드")

    if has_at_trick or is_public_ip or lookalike:
        struct_main = "사칭·우회 의심"
        if lookalike:
            struct_desc = f"공식 사이트({lookalike})와 철자가 비슷한 가짜 사칭 의심 주소입니다. (+{struct_risk}점)"
        elif has_at_trick:
            struct_desc = f"'@' 기호를 넣어 정상 사이트인 것처럼 앞부분을 속인 피싱 주소입니다. (+{struct_risk}점)"
        else:
            struct_desc = f"도메인 이름 대신 숫자 IP로 직접 연결하는 수상한 주소입니다. (+{struct_risk}점)"
        struct_hp, struct_level = 15, "danger"
    elif risk_flags:
        struct_main = "특수 주소 구조"
        struct_desc = f"일반 사이트와 다른 특수 구조({', '.join(risk_flags)})가 감지되었습니다. (+{struct_risk}점)"
        struct_hp, struct_level = 55, "caution"
    else:
        struct_main = "정상 도메인 구조"
        struct_desc = f"유명 사이트 철자를 바꾼 사칭이나 우회 흔적이 없습니다. (도메인: {reg_domain})"
        struct_hp, struct_level = 100, "safe"

    return {
        "final_url": final_url,
        "extra_risk": conn_risk + struct_risk,
        "reason_tags": reason_tags,
        "conn_main": conn_main,
        "conn_desc": conn_desc,
        "conn_hp": conn_hp,
        "conn_level": conn_level,
        "struct_main": struct_main,
        "struct_desc": struct_desc,
        "struct_hp": struct_hp,
        "struct_level": struct_level,
    }


def calculate_risk_score(malicious: int, suspicious: int, harmless: int, extra_risk: int) -> tuple[int, int]:
    if malicious >= 5:
        base = 10
    elif malicious >= 3:
        base = 9
    elif malicious == 2:
        base = 8
    elif malicious == 1:
        base = 7
    elif suspicious >= 3:
        base = 6
    elif suspicious == 2:
        base = 5
    elif suspicious == 1:
        base = 4
    elif harmless >= 50:
        base = 1
    elif harmless >= 10:
        base = 2
    else:
        base = 3

    final_score = min(10, max(1, base + extra_risk))
    return final_score, base


def _encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def _extract_engine_details(results_map: dict) -> list[str]:
    if not isinstance(results_map, dict):
        return []
    flagged = []
    for engine_name, info in results_map.items():
        if not isinstance(info, dict):
            continue
        if info.get("category") in ("malicious", "suspicious"):
            flagged.append(str(engine_name))
    return flagged


def _summarize_site_profile(attrs: dict, malicious: int, suspicious: int) -> tuple[str, str, int, str]:
    """사이트 성격·평판을 분석해 (핵심상태, 1줄설명, 안전도HP, 등급)을 반환합니다."""
    if not isinstance(attrs, dict):
        attrs = {}
    categories = attrs.get("categories") if isinstance(attrs.get("categories"), dict) else {}
    reputation = int(attrs.get("reputation") or 0)
    raw_title = str(attrs.get("title") or "").strip()

    raw_cats = [str(v).strip() for v in categories.values() if v]
    lower_joined = " ".join(raw_cats).lower()

    has_mal_cat = any(k in lower_joined for k in MALICIOUS_CATEGORY_KEYWORDS)
    has_sus_cat = any(k in lower_joined for k in SUSPICIOUS_CATEGORY_KEYWORDS)

    valid_cats = []
    ko_label = ""
    for cat_val in raw_cats:
        c_low = cat_val.lower()
        if any(k in c_low for k in MALICIOUS_CATEGORY_KEYWORDS + SUSPICIOUS_CATEGORY_KEYWORDS + UNRATED_CATEGORY_KEYWORDS):
            continue
        valid_cats.append(cat_val)
        if not ko_label:
            for eng_key, ko_val in CATEGORY_KO_MAP.items():
                if eng_key in c_low:
                    ko_label = ko_val
                    break

    if malicious > 0 or has_mal_cat:
        return (
            "유해·피싱 사이트 분류",
            f"보안 DB에 피싱·유해 사이트 유형으로 등록되어 접속을 피해야 합니다. (평판 {reputation:+d})",
            15,
            "danger",
        )
    if has_sus_cat:
        return (
            "위험 노출 · 주의 분류",
            f"보안 DB에서 위험 노출(Suspicious/Exposure) 등급으로 분류된 사이트입니다. (평판 {reputation:+d})",
            45,
            "caution",
        )
    if valid_cats:
        display_cat = ko_label if ko_label else valid_cats[0][:18]
        title_note = f" · 제목: {raw_title[:14]}" if raw_title else ""
        return (
            f"정식 등록 ({display_cat})",
            f"보안 DB에 '{display_cat}' 정상 서비스로 정식 등록된 사이트입니다.{title_note}",
            100,
            "safe",
        )
    if suspicious > 0:
        return (
            "미분류 · 의심 사이트",
            f"정식 서비스로 등록되지 않았고 일부 보안 기관이 의심으로 표시했습니다. (평판 {reputation:+d})",
            50,
            "caution",
        )
    return (
        "미분류 (신규·개인)",
        f"보안 DB에 용도가 등록되지 않은 낯선 사이트이므로 출처를 확인하세요. (평판 {reputation:+d})",
        60,
        "caution",
    )


def inspect_url(raw_url: str) -> dict:
    """요구사항 4: 외부 API와 기술 점검을 결합해 4개 핵심 지표와 체력바(안전도) 데이터를 반환합니다."""
    if not VT_API_KEY or not VT_API_KEY.strip():
        return {"success": False, "error": "VirusTotal API 키가 설정되지 않았습니다."}

    is_valid, valid_or_err = normalize_and_validate_url(raw_url)
    if not is_valid:
        return {"success": False, "error": valid_or_err}

    url = valid_or_err
    tech_check = analyze_url_technically(url)
    target_url = tech_check["final_url"]

    headers = {
        "x-apikey": VT_API_KEY.strip(),
        "accept": "application/json",
    }
    url_id = _encode_url_id(target_url)

    try:
        res = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=10)
        attrs = {}

        if res.status_code == 200:
            payload = res.json()
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results_map = attrs.get("last_analysis_results", {})
        elif res.status_code == 404:
            submit_res = requests.post(
                f"{VT_BASE_URL}/urls",
                headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                data={"url": target_url},
                timeout=10,
            )
            if submit_res.status_code == 400:
                return {
                    "success": False,
                    "error": "실제 인터넷에 존재하지 않거나 검사할 수 없는 주소입니다. 올바른 주소를 입력해주세요.",
                }
            if submit_res.status_code == 429:
                return {"success": False, "error": "짧은 시간에 너무 많이 검사했습니다. 1분 뒤 다시 시도해주세요."}
            if submit_res.status_code != 200:
                return {"success": False, "error": f"검사 요청에 실패했습니다. (오류 코드: {submit_res.status_code})"}

            analysis_id = submit_res.json().get("data", {}).get("id")
            if not analysis_id:
                return {"success": False, "error": "분석 작업 ID를 받지 못했습니다. 다시 시도해주세요."}

            stats = None
            results_map = {}
            for _ in range(6):
                time.sleep(2.5)
                try:
                    poll = requests.get(
                        f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers, timeout=10
                    )
                    if poll.status_code == 200:
                        attr = poll.json().get("data", {}).get("attributes", {})
                        if attr.get("status") == "completed":
                            stats = attr.get("stats", {})
                            results_map = attr.get("results", {})
                            break
                except requests.exceptions.RequestException:
                    continue

            if stats is None:
                return {
                    "success": False,
                    "error": "처음 등록된 주소라 보안 서버에서 분석 중입니다. 10초 뒤 다시 눌러주세요.",
                }

            try:
                follow_res = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=6)
                if follow_res.status_code == 200:
                    attrs = follow_res.json().get("data", {}).get("attributes", {})
            except (requests.exceptions.RequestException, ValueError):
                pass
        elif res.status_code in (401, 403):
            return {"success": False, "error": "API 키가 유효하지 않거나 접근 권한이 없습니다."}
        elif res.status_code == 429:
            return {"success": False, "error": "짧은 시간에 너무 많이 검사했습니다. 1분 뒤 다시 시도해주세요."}
        elif res.status_code >= 500:
            return {"success": False, "error": "VirusTotal 서버가 일시적으로 불안정합니다. 잠시 후 다시 시도해주세요."}
        else:
            return {"success": False, "error": f"외부 보안 서버 오류가 발생했습니다. (코드: {res.status_code})"}

        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total_engines = malicious + suspicious + harmless + undetected

        if total_engines == 0:
            return {
                "success": False,
                "error": "보안 기관의 초기 분석 결과가 아직 집계되지 않았습니다. 잠시 후 다시 시도해주세요.",
            }

        flagged_engines = _extract_engine_details(results_map)
        score, base_score = calculate_risk_score(
            malicious, suspicious, harmless, tech_check["extra_risk"]
        )

        # 1. 보안 기관 검증 게이지
        engine_main = f"안전 {harmless}곳 · 위험 {malicious + suspicious}곳"
        if flagged_engines:
            vendor_brief = (
                flagged_engines[0]
                if len(flagged_engines) == 1
                else f"{flagged_engines[0]} 외 {len(flagged_engines) - 1}곳"
            )
        else:
            vendor_brief = ""

        if malicious > 0:
            engine_desc = f"보안 기관 {malicious}곳에서 악성·피싱으로 직접 차단 중입니다. ({vendor_brief})"
            engine_hp = 10 if malicious >= 3 else 20
            engine_level = "danger"
        elif suspicious > 0:
            engine_desc = f"보안 기관 {suspicious}곳에서 의심 징후를 포착했습니다. ({vendor_brief})"
            engine_hp = 50 if suspicious >= 2 else 65
            engine_level = "caution"
        else:
            engine_desc = f"전 세계 보안 기관 {total_engines}곳 중 악성·의심 탐지가 0건입니다."
            engine_hp = 100 if harmless >= 50 else (90 if harmless >= 10 else 80)
            engine_level = "safe"

        # 2. 사이트 성격 · 평판 게이지
        cat_main, cat_desc, cat_hp, cat_level = _summarize_site_profile(attrs, malicious, suspicious)

        # 상단 종합 판정
        reasons = []
        if malicious > 0:
            reasons.append(f"보안 기관 {malicious}곳 악성 탐지")
        elif suspicious > 0:
            reasons.append(f"보안 기관 {suspicious}곳 의심 신호")
        reasons.extend(tech_check["reason_tags"])
        reason_summary = " 및 ".join(reasons[:2])

        score_formula = (
            f"기본 {base_score}점 + 구조·연결 가산 {tech_check['extra_risk']}점 = {score}/10점"
        )
        if score >= 7:
            verdict_title = "위험한 링크입니다 (접속 금지)"
            verdict_desc = (
                f"{reason_summary}이 확인되어 개인정보 유출·악성코드 감염 위험이 큽니다."
                if reason_summary
                else "악성·피싱 위험이 감지되어 접속을 금지합니다."
            )
        elif score >= 4:
            verdict_title = "주의가 필요한 링크입니다"
            verdict_desc = (
                f"{reason_summary}이 확인되었습니다. 보낸 사람을 확인한 뒤 접속하세요."
                if reason_summary
                else "출처가 불분명한 링크입니다. 발신자를 확인한 뒤 접속하세요."
            )
        else:
            verdict_title = "안전한 링크입니다"
            verdict_desc = (
                f"보안 기관 {harmless}곳 안전 확인 및 HTTPS 암호화·정상 도메인 구조를 갖추고 있습니다."
            )

        detail_data = {
            "verdict_title": verdict_title,
            "verdict_desc": verdict_desc,
            "score_formula": score_formula,
            "engine_main": engine_main,
            "engine_desc": engine_desc,
            "engine_hp": engine_hp,
            "engine_level": engine_level,
            "cat_main": cat_main,
            "cat_desc": cat_desc,
            "cat_hp": cat_hp,
            "cat_level": cat_level,
            "conn_main": tech_check["conn_main"],
            "conn_desc": tech_check["conn_desc"],
            "conn_hp": tech_check["conn_hp"],
            "conn_level": tech_check["conn_level"],
            "struct_main": tech_check["struct_main"],
            "struct_desc": tech_check["struct_desc"],
            "struct_hp": tech_check["struct_hp"],
            "struct_level": tech_check["struct_level"],
            "harmless": harmless,
            "malicious": malicious,
            "suspicious": suspicious,
        }

        return {
            "success": True,
            "input_url": url,
            "final_url": target_url,
            "risk_score": score,
            "verdict_title": verdict_title,
            "verdict_desc": verdict_desc,
            "score_formula": score_formula,
            "engine_summary": engine_main,
            "detail_data": detail_data,
        }

    except requests.exceptions.Timeout:
        return {"success": False, "error": "응답 시간이 초과되었습니다. 인터넷 연결 상태를 확인해주세요."}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "인터넷에 연결할 수 없습니다. 네트워크 상태를 확인해주세요."}
    except (ValueError, KeyError, TypeError):
        return {"success": False, "error": "보안 서버 응답 형식을 해석하는 중 오류가 발생했습니다."}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"네트워크 요청 중 오류가 발생했습니다: {e}"}


def escape_text(val: str) -> str:
    return html.escape(str(val or ""))