import base64
import ipaddress
import os
import time
from urllib.parse import urlparse
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
    "is.gd", "buff.ly", "han.gl", "me2.do", "vo.la", "url.kr",
}


def normalize_and_validate_url(raw_url: str) -> tuple[bool, str]:
    """앞뒤 공백·제어문자를 제거하고 외부 검사 가능한 정상 URL 형식인지 검증합니다."""
    if not isinstance(raw_url, str):
        return False, "유효하지 않은 입력 형식입니다."

    url = raw_url.strip()
    if not url:
        return False, "링크 주소(URL)를 입력해주세요."
    if len(url) > 2000:
        return False, "링크 주소가 너무 깁니다. (최대 2,000자)"
    if any(ch in url for ch in (" ", "\n", "\r", "\t")):
        return False, "링크 주소에 공백이나 줄바꿈이 포함되어 있습니다. 다시 확인해주세요."

    lowered = url.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "file:")):
        return False, "웹사이트 주소(http:// 또는 https://)만 검사할 수 있습니다."

    if "://" in url and not lowered.startswith(("http://", "https://")):
        return False, "http:// 또는 https:// 로 시작하는 웹 주소만 검사할 수 있습니다."

    if not lowered.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "올바른 링크 형식이 아닙니다. (예: https://www.naver.com)"

    hostname = (parsed.hostname or "").lower()
    if (
        not hostname
        or "." not in hostname
        or ".." in hostname
        or hostname.startswith(".")
        or hostname.endswith(".")
        or hostname == "localhost"
    ):
        return False, "올바른 도메인 형식이 아닙니다. (예: https://www.naver.com)"

    # IP 주소 여부 및 내부망/사설 IP 차단
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return False, "내부망(로컬) IP 주소는 외부 보안 검사를 실행할 수 없습니다."
    except ValueError:
        is_ip = False

    # 일반 도메인인 경우 레이블 및 최상위 도메인(TLD) 형식 검증
    if not is_ip:
        labels = hostname.split(".")
        if any(not lbl or lbl.startswith("-") or lbl.endswith("-") for lbl in labels):
            return False, "올바른 도메인 형식이 아닙니다. (예: https://www.naver.com)"
        tld = labels[-1]
        if len(tld) < 2 or tld.isdigit():
            return False, "올바른 도메인 확장자(.com, .kr 등)를 포함한 주소를 입력해주세요."

    return True, url


def _is_lookalike_domain(hostname: str) -> str | None:
    """주요 공식 사이트와 1글자만 다른 사칭 의심 도메인인지 확인합니다."""
    parts = hostname.lower().split(".")
    reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()

    for official in OFFICIAL_DOMAINS:
        if reg_domain == official or len(reg_domain) != len(official):
            continue
        diff_count = sum(1 for a, b in zip(reg_domain, official) if a != b)
        if diff_count == 1:
            return official
    return None


def check_basic_url_safety(url: str) -> dict:
    """외부 API와 별개로 작동하는 3가지 기본 주소 안전 점검입니다."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    final_url = url
    extra_risk = 0
    notes = []

    if parsed.scheme == "https":
        https_short = "적용됨 (안전 연결)"
    else:
        https_short = "미적용 (일반 HTTP)"
        extra_risk += 1
        notes.append("보안 연결(HTTPS)이 없는 일반 주소입니다.")

    if hostname in SHORTENER_DOMAINS:
        extra_risk += 1
        try:
            with requests.get(url, timeout=4, allow_redirects=True, stream=True) as resp:
                final_url = resp.url
            notes.append(f"단축 주소가 사용되었습니다. (실제 연결 주소: {final_url})")
        except requests.exceptions.TooManyRedirects:
            extra_risk += 2
            notes.append("비정상적인 반복 리다이렉트(우회 연결)가 감지되었습니다.")
        except requests.exceptions.RequestException:
            notes.append("단축 주소(bit.ly 등)를 사용해 원래 주소를 가리고 있습니다.")

    lookalike = _is_lookalike_domain(hostname)
    is_public_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_public_ip = True
    except ValueError:
        is_public_ip = False

    if is_public_ip:
        extra_risk += 3
        address_short = "주의 (숫자 IP 접속)"
        notes.append("정상적인 사이트 이름 대신 숫자 IP 주소를 직접 사용하고 있습니다.")
    elif lookalike:
        extra_risk += 4
        address_short = f"사칭 의심 ({lookalike})"
        notes.append(f"공식 사이트({lookalike})와 철자가 비슷한 사칭 의심 주소입니다.")
    else:
        address_short = "정상 주소 형식"

    return {
        "final_url": final_url,
        "https_short": https_short,
        "address_short": address_short,
        "notes": notes,
        "extra_risk": extra_risk,
    }


def calculate_risk_score(malicious: int, suspicious: int, harmless: int, extra_risk: int) -> int:
    """보안 기관 탐지 결과와 기본 점검 점수를 합산해 1~10점 위험도를 계산합니다."""
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

    return min(10, max(1, base + extra_risk))


def _encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def inspect_url(raw_url: str) -> dict:
    """요구사항 4: 외부 API를 통해 실시간으로 링크 위험도를 분석합니다."""
    if not VT_API_KEY or not VT_API_KEY.strip():
        return {"success": False, "error": "VirusTotal API 키가 설정되지 않았습니다."}

    is_valid, valid_or_err = normalize_and_validate_url(raw_url)
    if not is_valid:
        return {"success": False, "error": valid_or_err}

    url = valid_or_err
    basic_check = check_basic_url_safety(url)
    target_url = basic_check["final_url"]

    headers = {
        "x-apikey": VT_API_KEY.strip(),
        "accept": "application/json",
    }
    url_id = _encode_url_id(target_url)

    try:
        res = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=10)

        if res.status_code == 200:
            payload = res.json()
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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
                    "error": "실제 인터넷에 존재하지 않거나 검사할 수 없는 주소(.test 등)입니다. 올바른 주소를 입력해주세요.",
                }
            if submit_res.status_code == 429:
                return {"success": False, "error": "짧은 시간에 너무 많이 검사했습니다. 1분 뒤 다시 시도해주세요."}
            if submit_res.status_code != 200:
                return {"success": False, "error": f"검사 요청에 실패했습니다. (오류 코드: {submit_res.status_code})"}

            analysis_id = submit_res.json().get("data", {}).get("id")
            if not analysis_id:
                return {"success": False, "error": "분석 작업 ID를 받지 못했습니다. 다시 시도해주세요."}

            stats = None
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
                            break
                except requests.exceptions.RequestException:
                    continue

            if stats is None:
                return {
                    "success": False,
                    "error": "처음 등록된 주소라 보안 서버에서 분석 중입니다. 10초 뒤 다시 눌러주세요.",
                }
        elif res.status_code in (401, 403):
            return {"success": False, "error": "API 키가 유효하지 않거나 접근 권한이 없습니다."}
        elif res.status_code == 429:
            return {"success": False, "error": "짧은 시간에 너무 많이 검사했습니다. 1분 뒤 다시 시도해주세요."}
        elif res.status_code >= 500:
            return {"success": False, "error": "VirusTotal 서버가 일시적으로 불안정합니다. 잠시 후 다시 시도해주세요."}
        else:
            return {"success": False, "error": f"외부 보안 서버 오류가 발생했습니다. (코드: {res.status_code})"}

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))

        score = calculate_risk_score(malicious, suspicious, harmless, basic_check["extra_risk"])

        if score >= 7:
            verdict_title = "위험한 링크입니다 (접속 금지)"
            verdict_desc = f"글로벌 보안 기관 {malicious + suspicious}곳에서 악성 또는 피싱 위험을 탐지했습니다."
        elif score >= 4:
            verdict_title = "주의가 필요한 링크입니다"
            verdict_desc = "일부 주의 징후가 확인되었습니다. 보낸 사람과 주소를 다시 확인한 뒤 접속하세요."
        else:
            verdict_title = "안전한 링크입니다"
            verdict_desc = f"글로벌 보안 기관 {harmless}곳에서 안전으로 확인되었으며 특이 위험이 없습니다."

        engine_summary = f"안전 {harmless}곳 · 위험 {malicious + suspicious}곳"
        detail_data = {
            "verdict_title": verdict_title,
            "verdict_desc": verdict_desc,
            "https_short": basic_check["https_short"],
            "address_short": basic_check["address_short"],
            "notes": basic_check["notes"],
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
            "engine_summary": engine_summary,
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