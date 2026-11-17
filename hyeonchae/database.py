import json
import os
import sqlite3
import tempfile
from datetime import datetime


def _resolve_db_path() -> str:
    """실행 위치와 권한을 확인해 쓰기 가능한 SQLite DB 경로를 반환합니다."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    primary_path = os.path.join(base_dir, "safelink.db")
    try:
        os.makedirs(base_dir, exist_ok=True)
        with open(primary_path, "a", encoding="utf-8"):
            pass
        return primary_path
    except OSError:
        return os.path.join(tempfile.gettempdir(), "safelink.db")


DB_NAME = _resolve_db_path()


def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def init_db():
    """프로그램 시작 시 links 테이블을 생성하고 기존 DB 스키마와 자동 호환시킵니다."""
    try:
        with get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    final_url TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    api_risk TEXT NOT NULL,
                    user_risk TEXT NOT NULL,
                    engine_summary TEXT NOT NULL,
                    detail_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
            """)
            existing_cols = {
                row["name"] for row in conn.execute("PRAGMA table_info(links)").fetchall()
            }
            if "final_url" not in existing_cols:
                conn.execute("ALTER TABLE links ADD COLUMN final_url TEXT NOT NULL DEFAULT ''")
            if "detail_json" not in existing_cols:
                conn.execute("ALTER TABLE links ADD COLUMN detail_json TEXT NOT NULL DEFAULT '{}'")
            conn.commit()
    except sqlite3.Error as e:
        raise RuntimeError(f"데이터베이스 초기화 중 오류가 발생했습니다: {e}")


def add_direct_link(url: str, source: str) -> bool:
    """직접 링크 등록 (체감 위험도='입력 없음', 검사 상태='대기 중')"""
    clean_url = str(url or "").strip()[:2000]
    clean_source = str(source or "").strip()[:50]
    if not clean_url or not clean_source:
        return False

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO links (url, final_url, source, status, api_risk, user_risk, engine_summary, detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_url, clean_url, clean_source, "대기 중", "미검사", "입력 없음", "검사 대기 중", "{}", now),
            )
            conn.commit()
        return True
    except sqlite3.Error:
        return False


def save_api_result(
    url: str,
    final_url: str,
    source: str,
    api_risk_score: int,
    engine_summary: str,
    detail_data: dict,
) -> bool:
    """외부 API 검사 결과 저장 (초기 체감 위험도='입력 없음')"""
    clean_url = str(url or "").strip()[:2000]
    if not clean_url:
        return False

    raw_src = str(source or "").strip()
    clean_source = (raw_src if raw_src else "직접 검사")[:50]
    try:
        safe_score = max(1, min(10, int(api_risk_score)))
    except (TypeError, ValueError):
        safe_score = 5

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        detail_str = json.dumps(detail_data if isinstance(detail_data, dict) else {}, ensure_ascii=False)
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO links (url, final_url, source, status, api_risk, user_risk, engine_summary, detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_url,
                    (str(final_url or "").strip() or clean_url)[:2000],
                    clean_source,
                    "검사 완료",
                    str(safe_score),
                    "입력 없음",
                    str(engine_summary or "-"),
                    detail_str,
                    now,
                ),
            )
            conn.commit()
        return True
    except (sqlite3.Error, TypeError, ValueError):
        return False


def update_scan_result_by_id(
    link_id: int,
    final_url: str,
    api_risk_score: int,
    engine_summary: str,
    detail_data: dict,
) -> bool:
    """대기 중이던 링크를 검사 완료 상태로 갱신합니다."""
    try:
        target_id = int(link_id)
        safe_score = max(1, min(10, int(api_risk_score)))
        detail_str = json.dumps(detail_data if isinstance(detail_data, dict) else {}, ensure_ascii=False)
        with get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE links
                SET final_url = ?, status = ?, api_risk = ?, engine_summary = ?, detail_json = ?
                WHERE id = ?
                """,
                (
                    str(final_url or "")[:2000],
                    "검사 완료",
                    str(safe_score),
                    str(engine_summary or "-"),
                    detail_str,
                    target_id,
                ),
            )
            conn.commit()
            return cursor.rowcount > 0
    except (sqlite3.Error, TypeError, ValueError):
        return False


def get_all_links() -> list[dict]:
    """저장된 전체 기록을 최신순으로 조회합니다."""
    try:
        with get_connection() as conn:
            cursor = conn.execute("SELECT * FROM links ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error:
        return []


def search_links(keyword: str) -> list[dict]:
    """URL 또는 출처 필드로 검색합니다. (빈칸 입력 시 전체 반환)"""
    clean_keyword = str(keyword or "").strip()
    if not clean_keyword:
        return get_all_links()

    escaped = (
        clean_keyword.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    pattern = f"%{escaped}%"

    try:
        with get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM links
                WHERE url LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\'
                ORDER BY id DESC
                """,
                (pattern, pattern),
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error:
        return []


def find_existing_url(url: str) -> dict | None:
    """동일 URL이 이미 저장되어 있는지 조회합니다."""
    clean_url = str(url or "").strip()
    if not clean_url:
        return None
    try:
        with get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM links WHERE url = ? ORDER BY id DESC LIMIT 1",
                (clean_url,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error:
        return None


def update_user_risk(link_id: int, risk_score: int) -> bool:
    """선택한 링크의 체감 위험도를 1~10점으로 변경합니다."""
    try:
        target_id = int(link_id)
        safe_score = max(1, min(10, int(risk_score)))
        with get_connection() as conn:
            cursor = conn.execute(
                "UPDATE links SET user_risk = ? WHERE id = ?",
                (str(safe_score), target_id),
            )
            conn.commit()
            return cursor.rowcount > 0
    except (sqlite3.Error, TypeError, ValueError):
        return False


def delete_link(link_id: int) -> bool:
    """선택한 기록을 삭제합니다."""
    try:
        target_id = int(link_id)
        with get_connection() as conn:
            cursor = conn.execute("DELETE FROM links WHERE id = ?", (target_id,))
            conn.commit()
            return cursor.rowcount > 0
    except (sqlite3.Error, TypeError, ValueError):
        return False