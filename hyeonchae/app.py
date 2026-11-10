import streamlit as st
from database import (create_table, add_book, get_all_books, update_rating, toggle_finished, search_books, delete_book)
from api import search_external_books
create_table()

def print_books(rows):
    if len(rows) == 0:
        st.info("동록된채겅ㅄ다")
        return

    st.write(f"총 {len(rows)}권")
    st.write("---")
    # st.dataframe(rows)  

    for row in rows:
        book_id = row[0]
        title = row[1]
        author = row[2]
        rating = row[3]
        finished = row[4]

        if finished == 1 : status = "완료"
        else : status = "읽는 중"

        if rating == 0 : rating_text = "평점 없음"
        else : rating_text = f"{rating}점"

        st.write(f"{book_id}. [{status}] {title} / {author} / {rating_text}")

        col1, col2, col3, col4 = st.columns([2, 1.5, 2, 1])

        # 독서 상태 변경
        with col1:
            toggle_label = "읽는 중으로 변경" if finished == 1 else "완독 처리"
            if st.button(toggle_label, key = f"toggle_{book_id}"):
                toggle_finished(book_id)
                st.toast(f"'{title}' 상태가 변경되었습니다.")
                st.rerun()
        # 평점
        with col2:
            current_rate = rating if 1 <= rating <= 5 else 1
            new_rating = st.selectbox("평점", options=[1, 2, 3, 4, 5], index = current_rate - 1, key = f"rate_sel_{book_id}", label_visibility = "collapsed")
        # 평점 수정 버튼
        with col3:
            if st.button("평점 저장", key = f"rate_btn_{book_id}"):
                update_rating(book_id, new_rating)
                st.toast(f"'{title}'의 평점이 수정되었습니다.")
                st.rerun()
        # 삭제 버튼
        with col4:
            if st.button("삭제", key = f"del_{book_id}"):
                delete_book(book_id)
                st.toast(f"'{title}' 도서가 삭제되었습니다.")        
                st.rerun()

def print_search_results(results):
    if len(results) == 0:
        st.warning("검색결과가없습니다")
        return
    st.subheader("\n=========외부도서검색결과==========")
    for index, book in enumerate(results, start=1):
        st.success(f"{index}. " f"{book['title']} / " f"{book['author']}")
        col_info, col_save = st.columns([4, 1])
        with col_info:
            st.markdown(f"{index}. " f"{book['title']} / " f"{book['author']}")
        with col_save:
            if st.button("내 서재에 저장", key = f"save_ext_{index}",use_container_width = True):
                try:
                    add_book(book['title'], book['author'])
                    st.toast(f"'{title}'이(가)내 서재에 저장되었습니다.")
                except Exception as e:
                    st.error(f"저장 실패 : {e}")
        st.divider()




        
st.set_page_config(page_title="독서 기록 관리 시스템", page_icon="💩")


st.sidebar.title("독서 기록 관리")
st.sidebar.write("나만의 독서 기록을 관리 해보세요.")

menu = st.sidebar.radio("메뉴 선택", ["내 서재 (목록/관리)", "직접 도서 등록", "외부 도서 등록"])



if menu == "내 서재 (목록/관리)":
    st.header("내 서재")
    st.write("저장된 도서를 조회하고 독서 상태, 평점 수정 및 삭제를 관리할 수 있습니다.")

    keyword = st.text_input("내 서재 검색(책 제목)", placeholder = "검색어 입력")

    if keyword.strip():
        rows = search_books(keyword.strip())
    else:
        rows = get_all_books()
    
    print_books(rows)



elif menu == "직접 도서 등록":
    st.header("직접 도서 등록")
    st.write("소장하고 있거나 읽은 책의 정보를 직접 등록하세요.")

    with st.form("add_book_form", clear_on_submit = True):
        title = st.text_input("책 제목 *", placeholder = "도서명을 입력하세요.")
        author = st.text_input("저자 *", placeholder = "저자명을 입력하세요.")
        submitted = st.form_submit_button("내 서재에 등록", use_container_width = True)

        if submitted:
            if not title.strip() or not author.strip():
                st.warning("책 제목과 저자를 모두 입력해주세요.")
            
            else:
                add_book(title.strip(), author.strip())
                st.success("내 서재에 등록되었습니다.")



elif menu == "외부 도서 등록":
    st.header("외부 도서 검색 및 등록")
    st.write("외부 도서 API를 통해 책 정보를 검색하고 서재에 저장할 수 있습니다.")

    search_col, btn_col = st.columns([4, 1])
    with search_col:
        keyword = st.text_input("검색할 책 제목", placeholder = "예 : 어린왕자", label_visibility = "collapsed")

    with btn_col:
        search_clicked = st.button("도서 검색", use_container_width = True)

    if search_clicked:
        if not keyword.strip():
            st.warning("검색어를 입력해주세요.")
        else:
            try:
                results = search_external_books(keyword.strip())
                st.session_state["search_results"] = results
            except Exception as e:
                st.error(f"검색 중 오류가 발생했습니다. {e}")
                st.session_state["search_results"] = []

    if "search_results" in st.session_state:
        results = st.session_state["search_results"]
        print_search_results(results)








    