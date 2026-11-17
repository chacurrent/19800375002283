import json
import altair as alt
import pandas as pd
import streamlit as st
import api
import database as db

st.set_page_config(
    page_title="안전링크 (SafeLink)",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
<style>
.block-container {
    padding-top: 2.8rem !important;
    padding-bottom: 1.6rem !important;
    max-width: 1260px;
}
[data-testid="stVerticalBlock"] {
    gap: 1.15rem;
}
h3 {
    margin-top: 0 !important;
    margin-bottom: 0.25rem !important;
    font-size: 1.35rem !important;
}
.kpi-box {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(250, 250, 250, 0.12);
    border-radius: 10px;
    padding: 14px 16px;
    min-height: 80px;
    margin-top: 4px;
    margin-bottom: 4px;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
.kpi-label {
    font-size: 0.82rem;
    opacity: 0.78;
    margin-bottom: 5px;
    white-space: nowrap;
}
.kpi-value {
    font-size: 1.15rem;
    font-weight: 700;
    line-height: 1.25;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.unified-panel {
    background: rgba(255, 255, 255, 0.025);
    border: 1px solid rgba(250, 250, 250, 0.13);
    border-radius: 12px;
    padding: 4px 20px;
    margin-top: 4px;
    margin-bottom: 4px;
}
.hp-row {
    padding: 13px 0;
    border-bottom: 1px solid rgba(250, 250, 250, 0.09);
}
.hp-row:last-child {
    border-bottom: none;
}
.hp-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 7px;
    flex-wrap: wrap;
}
.hp-title-group {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}
.hp-title {
    font-size: 0.96rem;
    font-weight: 700;
}
.hp-badge {
    font-size: 0.76rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 999px;
    letter-spacing: 0.01em;
}
.hp-main-val {
    font-size: 0.9rem;
    font-weight: 600;
    opacity: 0.92;
}
.hp-percent {
    font-size: 0.84rem;
    font-weight: 700;
    white-space: nowrap;
}
.hp-track {
    width: 100%;
    height: 12px;
    background: rgba(255, 255, 255, 0.09);
    border-radius: 999px;
    overflow: hidden;
    position: relative;
    margin-bottom: 6px;
    box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.35);
}
.hp-fill {
    height: 100%;
    border-radius: 999px;
    transition: width 0.35s ease;
}
.hp-desc {
    font-size: 0.83rem;
    opacity: 0.82;
    line-height: 1.4;
    word-break: keep-all;
}
.verdict-card {
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 8px;
    border: 1px solid rgba(250, 250, 250, 0.14);
    word-break: keep-all;
    overflow-wrap: anywhere;
}
.verdict-safe {
    background: rgba(34, 197, 94, 0.12);
    border-left: 5px solid #22c55e;
}
.verdict-caution {
    background: rgba(234, 179, 8, 0.12);
    border-left: 5px solid #eab308;
}
.verdict-danger {
    background: rgba(239, 68, 68, 0.14);
    border-left: 5px solid #ef4444;
}
.info-pill {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    background: rgba(255, 255, 255, 0.07);
    font-size: 0.86rem;
    margin-right: 6px;
    white-space: nowrap;
}
.desc-inline {
    font-size: 0.85rem;
    opacity: 0.88;
    word-break: keep-all;
    line-height: 1.45;
}
</style>
""",
    unsafe_allow_html=True,
)

try:
    db.init_db()
except RuntimeError as err:
    st.error(str(err))
    st.stop()

if "toast_msg" in st.session_state:
    kind, msg = st.session_state.pop("toast_msg")
    st.toast(msg, icon="✅" if kind == "success" else "🗑️")


def safe_load_json(raw_str: str) -> dict:
    try:
        data = json.loads(raw_str or "{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def get_status_badge(status: str, api_risk: str) -> str:
    if status == "대기 중" or not str(api_risk).isdigit():
        return "⏳ 대기 중"
    score = int(api_risk)
    if score >= 7:
        return f"🔴 위험 ({score}/10)"
    if score >= 4:
        return f"🟡 주의 ({score}/10)"
    return f"🟢 안전 ({score}/10)"


def get_comparison_text(api_risk: str, user_risk: str) -> str:
    if not str(api_risk).isdigit() or not str(user_risk).isdigit():
        return "비교 대기"
    diff = int(api_risk) - int(user_risk)
    if diff >= 3:
        return "⚠️ 실제 위험 높음"
    if diff <= -3:
        return "💡 우려보다 안전"
    return "✅ 판단 일치"


def render_kpi_card(col, label: str, value: str, accent_color: str = "#60a5fa"):
    safe_val = api.escape_text(value)
    html_block = (
        f'<div class="kpi-box" style="border-top: 3px solid {accent_color};">'
        f'<div class="kpi-label">{label}</div>'
        f'<div class="kpi-value" title="{safe_val}">{safe_val}</div>'
        f"</div>"
    )
    col.markdown(html_block, unsafe_allow_html=True)


def render_unified_health_panel(items: list[dict]):
    """4개 진단 항목을 하나의 통합 패널 안에 체력바(안전도 게이지) 형태로 렌더링합니다."""
    level_styles = {
        "safe": {
            "label": "안전",
            "color": "#22c55e",
            "bg": "rgba(34, 197, 94, 0.16)",
            "grad": "linear-gradient(90deg, #16a34a, #22c55e)",
        },
        "caution": {
            "label": "주의",
            "color": "#eab308",
            "bg": "rgba(234, 179, 8, 0.18)",
            "grad": "linear-gradient(90deg, #ca8a04, #eab308)",
        },
        "danger": {
            "label": "위험",
            "color": "#ef4444",
            "bg": "rgba(239, 68, 68, 0.18)",
            "grad": "linear-gradient(90deg, #dc2626, #ef4444)",
        },
    }

    parts = ['<div class="unified-panel">']
    for item in items:
        lv = level_styles.get(item.get("level", "caution"), level_styles["caution"])
        hp = max(6, min(100, int(item.get("hp", 50))))
        parts.append(
            '<div class="hp-row">'
            '<div class="hp-header">'
            '<div class="hp-title-group">'
            f'<span class="hp-title">{api.escape_text(item["title"])}</span>'
            f'<span class="hp-badge" style="color:{lv["color"]}; background:{lv["bg"]}; border:1px solid {lv["color"]}44;">{lv["label"]}</span>'
            f'<span class="hp-main-val">{api.escape_text(item["main"])}</span>'
            "</div>"
            f'<span class="hp-percent" style="color:{lv["color"]};">안전도 {hp}%</span>'
            "</div>"
            '<div class="hp-track">'
            f'<div class="hp-fill" style="width:{hp}%; background:{lv["grad"]};"></div>'
            "</div>"
            f'<div class="hp-desc">{api.escape_text(item["desc"])}</div>'
            "</div>"
        )
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


all_records = db.get_all_links()
total_cnt = len(all_records)
safe_cnt = sum(1 for r in all_records if str(r["api_risk"]).isdigit() and int(r["api_risk"]) <= 3)
caution_cnt = sum(1 for r in all_records if str(r["api_risk"]).isdigit() and 4 <= int(r["api_risk"]) <= 6)
danger_cnt = sum(1 for r in all_records if str(r["api_risk"]).isdigit() and int(r["api_risk"]) >= 7)
wait_cnt = sum(1 for r in all_records if r["status"] == "대기 중")

# ==============================================================================
# 왼쪽 사이드바
# ==============================================================================
with st.sidebar:
    st.markdown("## 🛡️ 안전링크")
    st.caption("악성 링크 검사 · 위험도 기록 관리")
    st.divider()

    menu = st.radio(
        "메뉴 이동",
        [
            "🔍 실시간 링크 검사",
            "➕ 직접 링크 등록",
            "📋 내 기록 조회 · 검색",
            "📊 위험도 통계 · 요약",
        ],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown(
        "**위험도 기준 (1~10점)**\n"
        "- 🟢 **1~3점**: 안전 (안심 접속)\n"
        "- 🟡 **4~6점**: 주의 (출처 확인)\n"
        "- 🔴 **7~10점**: 위험 (접속 금지)"
    )

# ==============================================================================
# 메뉴 1: 실시간 링크 검사
# ==============================================================================
if menu == "🔍 실시간 링크 검사":
    st.markdown("### 🔍 실시간 링크 안전 검사")
    st.caption("의심스러운 URL을 입력하면 보안 기관 데이터와 주소 안전성을 분석해 1~10점 위험도와 항목별 안전도 게이지를 보여줍니다.")

    with st.form("api_scan_form"):
        c1, c2, c3 = st.columns([2.5, 1.3, 0.9])
        input_url = c1.text_input("링크 주소 (URL) *", placeholder="예: https://www.naver.com")
        input_source = c2.text_input("링크 출처 (선택)", placeholder="예: 이메일, 문자, 카톡")
        c3.markdown("<div style='height:27px;'></div>", unsafe_allow_html=True)
        scan_btn = c3.form_submit_button("🔍 안전 검사", type="primary", use_container_width=True)

    if scan_btn:
        clean_url = input_url.strip()
        clean_src = input_source.strip()
        if not clean_url:
            st.warning("검사할 링크 주소(URL)를 입력해주세요.")
        elif any(ch in clean_src for ch in ("\n", "\r", "\t")):
            st.warning("링크 출처에 줄바꿈 문자를 포함할 수 없습니다.")
        elif len(clean_src) > 50:
            st.warning("링크 출처는 50자 이내로 입력해주세요.")
        else:
            is_valid, normalized = api.normalize_and_validate_url(clean_url)
            if is_valid:
                existing = db.find_existing_url(normalized) or db.find_existing_url(clean_url)
                if existing:
                    st.info(
                        f"이미 기록에 저장된 주소입니다 — 출처: **{existing['source']}** · "
                        f"기존 판정: **{get_status_badge(existing['status'], existing['api_risk'])}**"
                    )

            with st.spinner("보안 기관 데이터와 주소 안전성을 분석하고 있습니다..."):
                result = api.inspect_url(clean_url)

            if result["success"]:
                st.session_state["scan_result"] = {
                    **result,
                    "source": clean_src if clean_src else "직접 검사",
                }
            else:
                st.session_state.pop("scan_result", None)
                st.error(result["error"])

    if "scan_result" in st.session_state:
        res = st.session_state["scan_result"]
        score = res["risk_score"]
        detail = res["detail_data"]

        if score >= 7:
            card_cls, badge_icon = "verdict-danger", "🔴"
        elif score >= 4:
            card_cls, badge_icon = "verdict-caution", "🟡"
        else:
            card_cls, badge_icon = "verdict-safe", "🟢"

        st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)

        top_col, save_col = st.columns([4.2, 0.9])
        with top_col:
            formula_line = detail.get("score_formula") or res.get("score_formula", "")
            formula_html = f" &nbsp;|&nbsp; <span>{api.escape_text(formula_line)}</span>" if formula_line else ""
            verdict_html = (
                f'<div class="verdict-card {card_cls}">'
                f'<div style="font-size:1.15rem; font-weight:700; margin-bottom:4px;">'
                f"{badge_icon} {api.escape_text(res['verdict_title'])} &nbsp;·&nbsp; 위험도 {score} / 10점"
                f"</div>"
                f'<div style="font-size:0.93rem; margin-bottom:6px;">{api.escape_text(res["verdict_desc"])}</div>'
                f'<div style="font-size:0.81rem; opacity:0.82;">'
                f"검사 주소: <code>{api.escape_text(res['final_url'])}</code> &nbsp;|&nbsp; "
                f"출처: <b>{api.escape_text(res['source'])}</b>{formula_html}"
                f"</div></div>"
            )
            st.markdown(verdict_html, unsafe_allow_html=True)
        with save_col:
            st.markdown("<div style='height:31px;'></div>", unsafe_allow_html=True)
            if st.button("💾 내 기록 저장", type="primary", use_container_width=True):
                if db.save_api_result(
                    url=res["input_url"],
                    final_url=res["final_url"],
                    source=res["source"],
                    api_risk_score=score,
                    engine_summary=res["engine_summary"],
                    detail_data=detail,
                ):
                    st.session_state.pop("scan_result", None)
                    st.session_state["toast_msg"] = (
                        "success",
                        "내 기록에 저장되었습니다. (초기 체감 위험도: 입력 없음)",
                    )
                    st.rerun()
                else:
                    st.error("데이터베이스 저장 중 오류가 발생했습니다.")

        render_unified_health_panel(
            [
                {
                    "title": "1. 보안 기관 검증",
                    "main": detail.get("engine_main", res["engine_summary"]),
                    "desc": detail.get("engine_desc", ""),
                    "hp": detail.get("engine_hp", 80),
                    "level": detail.get("engine_level", "safe"),
                },
                {
                    "title": "2. 사이트 성격 · 평판",
                    "main": detail.get("cat_main", "미분류 (신규·개인)"),
                    "desc": detail.get("cat_desc", ""),
                    "hp": detail.get("cat_hp", 60),
                    "level": detail.get("cat_level", "caution"),
                },
                {
                    "title": "3. 보안 연결 · 암호화",
                    "main": detail.get("conn_main", "-"),
                    "desc": detail.get("conn_desc", ""),
                    "hp": detail.get("conn_hp", 50),
                    "level": detail.get("conn_level", "caution"),
                },
                {
                    "title": "4. 도메인 · 사칭 점검",
                    "main": detail.get("struct_main", "-"),
                    "desc": detail.get("struct_desc", ""),
                    "hp": detail.get("struct_hp", 100),
                    "level": detail.get("struct_level", "safe"),
                },
            ]
        )

# ==============================================================================
# 메뉴 2: 직접 링크 등록
# ==============================================================================
elif menu == "➕ 직접 링크 등록":
    st.markdown("### ➕ 검사 대기 링크 직접 등록")
    st.caption("나중에 검사할 링크와 출처를 먼저 등록합니다. 초기 체감 위험도는 '입력 없음', 상태는 '대기 중'으로 저장됩니다.")

    with st.form("direct_register_form", clear_on_submit=True):
        c1, c2, c3 = st.columns([2.5, 1.3, 0.9])
        reg_url = c1.text_input("등록할 링크 주소 (URL) *", placeholder="예: https://example.com")
        reg_source = c2.text_input("링크 출처 *", placeholder="예: 택배 문자, 모르는 메일")
        c3.markdown("<div style='height:27px;'></div>", unsafe_allow_html=True)
        reg_btn = c3.form_submit_button("📝 대기 등록", type="primary", use_container_width=True)

    if reg_btn:
        clean_url = reg_url.strip()
        clean_src = reg_source.strip()
        if not clean_url:
            st.warning("등록할 링크 주소(URL)를 입력해주세요.")
        elif not clean_src:
            st.warning("링크 출처를 입력해주세요.")
        elif any(ch in clean_src for ch in ("\n", "\r", "\t")):
            st.warning("링크 출처에 줄바꿈 문자를 포함할 수 없습니다.")
        elif len(clean_src) > 50:
            st.warning("링크 출처는 50자 이내로 입력해주세요.")
        else:
            is_valid, valid_or_err = api.normalize_and_validate_url(clean_url)
            if not is_valid:
                st.warning(valid_or_err)
            else:
                existing = db.find_existing_url(valid_or_err)
                if existing:
                    st.info(
                        f"이미 동일한 주소가 등록되어 있습니다. (기존 출처: {existing['source']} · 상태: {existing['status']})"
                    )
                if db.add_direct_link(valid_or_err, clean_src):
                    st.session_state["toast_msg"] = (
                        "success",
                        "대기 목록에 등록되었습니다. (체감 위험도: 입력 없음)",
                    )
                    st.rerun()
                else:
                    st.error("데이터베이스 등록 중 오류가 발생했습니다.")

    wait_records = [r for r in all_records if r["status"] == "대기 중"]
    if wait_records:
        st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)
        st.markdown(f"**현재 검사 대기 중인 링크 ({len(wait_records)}건)**")
        wait_df = pd.DataFrame(
            [
                {
                    "순번": f"No. {i}",
                    "링크 주소 (URL)": r["url"],
                    "출처": r["source"],
                    "상태": r["status"],
                    "체감 위험도": r["user_risk"],
                    "등록일시": r["created_at"],
                }
                for i, r in enumerate(wait_records, start=1)
            ]
        )
        st.dataframe(
            wait_df,
            use_container_width=True,
            hide_index=True,
            height=220,
            column_config={
                "순번": st.column_config.TextColumn(width="small"),
                "링크 주소 (URL)": st.column_config.TextColumn(width="large"),
                "출처": st.column_config.TextColumn(width="small"),
                "상태": st.column_config.TextColumn(width="small"),
                "체감 위험도": st.column_config.TextColumn(width="small"),
                "등록일시": st.column_config.TextColumn(width="small"),
            },
        )

# ==============================================================================
# 메뉴 3: 내 기록 조회 · 검색 · 빠른 관리
# ==============================================================================
elif menu == "📋 내 기록 조회 · 검색":
    st.markdown("### 📋 내 기록 조회 및 검색")

    if total_cnt == 0:
        st.info("저장된 검사 기록이 없습니다.")
    else:
        with st.form("search_form"):
            s1, s2, s3 = st.columns([3.8, 1.4, 0.8])
            keyword = s1.text_input(
                "검색어",
                placeholder="URL 또는 출처로 검색 (빈칸 검색 시 전체 목록 표시)",
                label_visibility="collapsed",
            )
            status_filter = s2.selectbox(
                "필터",
                ["전체 보기", "🟢 안전 (1~3점)", "🟡 주의 (4~6점)", "🔴 위험 (7~10점)", "⏳ 대기 중"],
                label_visibility="collapsed",
            )
            s3.form_submit_button("🔍 검색", use_container_width=True)

        records = db.search_links(keyword)

        if status_filter == "🟢 안전 (1~3점)":
            records = [r for r in records if str(r["api_risk"]).isdigit() and int(r["api_risk"]) <= 3]
        elif status_filter == "🟡 주의 (4~6점)":
            records = [r for r in records if str(r["api_risk"]).isdigit() and 4 <= int(r["api_risk"]) <= 6]
        elif status_filter == "🔴 위험 (7~10점)":
            records = [r for r in records if str(r["api_risk"]).isdigit() and int(r["api_risk"]) >= 7]
        elif status_filter == "⏳ 대기 중":
            records = [r for r in records if r["status"] == "대기 중"]

        if len(records) == 0:
            if keyword.strip():
                st.warning(f"'{keyword.strip()}'에 대한 검색 결과가 없습니다.")
            else:
                st.info("선택한 조건에 해당하는 기록이 없습니다.")
        else:
            st.markdown("<div style='height:2px;'></div>", unsafe_allow_html=True)

            table_rows = [
                {
                    "순번": f"No. {i}",
                    "판정 결과": get_status_badge(r["status"], r["api_risk"]),
                    "링크 주소 (URL)": r["url"],
                    "출처": r["source"],
                    "API 위험도": f"{r['api_risk']}/10점" if str(r["api_risk"]).isdigit() else "미검사",
                    "체감 위험도": f"{r['user_risk']}/10점" if str(r["user_risk"]).isdigit() else "입력 없음",
                    "비교 분석": get_comparison_text(r["api_risk"], r["user_risk"]),
                    "등록일시": r["created_at"][5:] if len(r["created_at"]) >= 16 else r["created_at"],
                }
                for i, r in enumerate(records, start=1)
            ]
            st.dataframe(
                pd.DataFrame(table_rows),
                use_container_width=True,
                hide_index=True,
                height=210,
                column_config={
                    "순번": st.column_config.TextColumn(width="small"),
                    "판정 결과": st.column_config.TextColumn(width="small"),
                    "링크 주소 (URL)": st.column_config.TextColumn(width="medium"),
                    "출처": st.column_config.TextColumn(width="small"),
                    "API 위험도": st.column_config.TextColumn(width="small"),
                    "체감 위험도": st.column_config.TextColumn(width="small"),
                    "비교 분석": st.column_config.TextColumn(width="small"),
                    "등록일시": st.column_config.TextColumn(width="small"),
                },
            )

            st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)

            with st.container(border=True):
                option_map = {
                    f"No. {i}  |  {r['url']}  ({r['source']})": (i, r)
                    for i, r in enumerate(records, start=1)
                }
                sel_col, info_col = st.columns([1.85, 3.15])
                selected_label = sel_col.selectbox(
                    "관리할 기록 선택",
                    list(option_map.keys()),
                    label_visibility="collapsed",
                )
                sel_no, target = option_map[selected_label]
                detail = safe_load_json(target.get("detail_json", "{}"))

                api_str = f"{target['api_risk']}/10점" if str(target["api_risk"]).isdigit() else "미검사"
                user_str = f"{target['user_risk']}/10점" if str(target["user_risk"]).isdigit() else "입력 없음"
                verdict_info = detail.get("verdict_desc") or target["engine_summary"]
                tech_brief = detail.get("score_formula") or ""

                info_html = (
                    '<div style="display:flex; align-items:center; flex-wrap:wrap; gap:6px; padding-top:2px;">'
                    f'<span class="info-pill">API: <b>{api_str}</b></span>'
                    f'<span class="info-pill">체감: <b>{user_str}</b></span>'
                    f'<span class="desc-inline">{api.escape_text(verdict_info)}</span>'
                    "</div>"
                )
                info_col.markdown(info_html, unsafe_allow_html=True)
                if tech_brief:
                    st.caption(f"산출 근거: {tech_brief}")

                st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)

                c_slider, c_save, c_scan, c_del = st.columns([3.0, 1.0, 1.0, 0.8])
                default_val = int(target["user_risk"]) if str(target["user_risk"]).isdigit() else 5
                new_score = c_slider.slider(
                    "내 체감 위험도 변경 (1~10점)",
                    min_value=1,
                    max_value=10,
                    value=default_val,
                    key=f"slider_{target['id']}",
                )

                c_save.markdown("<div style='height:25px;'></div>", unsafe_allow_html=True)
                if c_save.button("위험도 저장", key=f"save_{target['id']}", use_container_width=True):
                    if db.update_user_risk(target["id"], new_score):
                        st.session_state["toast_msg"] = (
                            "success",
                            f"No. {sel_no} 체감 위험도가 {new_score}점으로 저장되었습니다.",
                        )
                    else:
                        st.session_state["toast_msg"] = ("delete", "이미 삭제된 기록입니다.")
                    st.rerun()

                c_scan.markdown("<div style='height:25px;'></div>", unsafe_allow_html=True)
                if target["status"] == "대기 중":
                    if c_scan.button("🔍 지금 검사", key=f"scan_{target['id']}", type="primary", use_container_width=True):
                        with st.spinner("안전 여부를 분석하고 있습니다..."):
                            scan_res = api.inspect_url(target["url"])
                        if scan_res["success"]:
                            db.update_scan_result_by_id(
                                link_id=target["id"],
                                final_url=scan_res["final_url"],
                                api_risk_score=scan_res["risk_score"],
                                engine_summary=scan_res["engine_summary"],
                                detail_data=scan_res["detail_data"],
                            )
                            st.session_state["toast_msg"] = (
                                "success",
                                f"No. {sel_no} 검사 완료! ({scan_res['risk_score']}점)",
                            )
                            st.rerun()
                        else:
                            st.error(scan_res["error"])

                c_del.markdown("<div style='height:25px;'></div>", unsafe_allow_html=True)
                if c_del.button("🗑️ 삭제", key=f"del_{target['id']}", use_container_width=True):
                    if db.delete_link(target["id"]):
                        st.session_state["toast_msg"] = (
                            "delete",
                            f"No. {sel_no} 기록이 삭제되었습니다.",
                        )
                    else:
                        st.session_state["toast_msg"] = ("delete", "이미 삭제된 기록입니다.")
                    st.rerun()

# ==============================================================================
# 메뉴 4: 위험도 통계 · 요약
# ==============================================================================
elif menu == "📊 위험도 통계 · 요약":
    st.markdown("### 📊 내 링크 안전 현황 통계 및 요약")

    if total_cnt == 0:
        st.info("통계를 표시할 기록이 아직 없습니다. 먼저 링크를 검사하거나 등록해보세요.")
    else:
        k1, k2, k3, k4, k5 = st.columns(5)
        render_kpi_card(k1, "전체 관리 링크", f"{total_cnt}건", "#60a5fa")
        render_kpi_card(k2, "🟢 안전 (1~3점)", f"{safe_cnt}건", "#22c55e")
        render_kpi_card(k3, "🟡 주의 (4~6점)", f"{caution_cnt}건", "#eab308")
        render_kpi_card(k4, "🔴 위험 (7~10점)", f"{danger_cnt}건", "#ef4444")
        render_kpi_card(k5, "⏳ 검사 대기 중", f"{wait_cnt}건", "#94a3b8")

        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

        col_left, col_right = st.columns([1.3, 1])

        with col_left:
            with st.container(border=True):
                st.markdown("**위험 등급별 분포**")
                categories = ["안전 (1~3점)", "주의 (4~6점)", "위험 (7~10점)", "대기 중"]
                chart_df = pd.DataFrame(
                    {
                        "등급": categories,
                        "건수": [safe_cnt, caution_cnt, danger_cnt, wait_cnt],
                        "색상": ["#22c55e", "#eab308", "#ef4444", "#94a3b8"],
                    }
                )

                bars = (
                    alt.Chart(chart_df)
                    .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6, size=44)
                    .encode(
                        x=alt.X(
                            "등급:N",
                            sort=categories,
                            axis=alt.Axis(labelAngle=0, title=None, labelFontSize=12),
                        ),
                        y=alt.Y(
                            "건수:Q",
                            scale=alt.Scale(domain=[0, max(chart_df["건수"].max() + 1, 2)]),
                            axis=alt.Axis(title=None, tickMinStep=1, format="d"),
                        ),
                        color=alt.Color("색상:N", scale=None),
                    )
                )

                labels = (
                    alt.Chart(chart_df)
                    .mark_text(dy=-9, fontSize=12, fontWeight="bold", color="#e5e7eb")
                    .encode(
                        x=alt.X("등급:N", sort=categories),
                        y=alt.Y("건수:Q"),
                        text=alt.Text("건수:Q", format="d"),
                    )
                )

                st.altair_chart((bars + labels).properties(height=230), use_container_width=True)

        with col_right:
            with st.container(border=True):
                st.markdown("**유입 출처별 현황**")
                source_counts = {}
                for r in all_records:
                    src = r["source"]
                    source_counts[src] = source_counts.get(src, 0) + 1
                src_df = pd.DataFrame(
                    [{"출처": k, "등록 건수": f"{v}건"} for k, v in source_counts.items()]
                )
                st.dataframe(src_df, use_container_width=True, hide_index=True, height=230)