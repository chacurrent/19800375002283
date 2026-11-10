from database import (create_table, add_book, get_all_books, update_rating, toggle_finished, search_books, delete_book)
from api import search_external_books



def show_menu():
    print("\n===== 독서 기록 관리 v4 =====")
    print("1. 책 등록")
    print("2. 책 목록 보기")
    print("3. 평점 입력")
    print("4. 독서 상태 변경")
    print("5. 책 삭제")
    print("6. 제목 검색")
    print("7. 외부도서검색")
    print("8. 검색한책을내서재에저장")
    print("0. 종료")
    print("=============================")

def input_number(message):
    try:
        return int(input(message))

    except ValueError:
        print("숫자를 입력하세요.")
        return None


def print_books(rows):
    if len(rows) == 0:
        print("동록된채겅ㅄ다")
        return

    print("\n============================ㄷㅅ ㅁㄹ============================")
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

        print(f"{book_id}. [{status}] {title} / {author} / {rating_text}")



def print_search_results(results):
    if len(results) == 0:
        print("검색결과가없습니다")
        return
    print("\n=========외부도서검색결과==========")
    for index, book in enumerate(results, start=1):
        print(
            f"{index}. "
            f"{book['title']} / "
            f"{book['author']}"
        )




def main():

    create_table()
    results = []

    while True:

        show_menu()

        menu = input("메뉴 선택: ").strip()

        if menu == "1":
            title = input("책 제목: ").strip()
            author = input("저자: ").strip()
            if title == "" or author == "":
                print("책 제목과 저자를 모두 입력하세요.")
                continue

            add_book(title, author)
            print("책이 등록되었습니다.")

        elif menu == "2":
            rows = get_all_books()
            print_books(rows)

        elif menu == "3":
            rows = get_all_books()
            print_books(rows)

            if len(rows) == 0:
                continue

            book_id = input_number("평점을 수정할 책 ID: ")
            if book_id is None:
                continue

            rating = input_number("평점 입력 (1~5): ")

            if rating is None:
                continue

            if rating < 1 or rating > 5:
                print("평점은 1~5 사이로 입력하세요.")
                continue

            changed = update_rating(book_id, rating)

            if changed == 0:
                print("해당 ID의 책이 없습니다.")
            else:
                print("평점이 수정되었습니다.")

        elif menu == "4":
            rows = get_all_books()
            print_books(rows)
            if len(rows) == 0:
                continue

            book_id = input_number("상태를 변경할 책 ID: ")
            if book_id is None:
                continue

            if toggle_finished(book_id):
                print("독서 상태가 변경되었습니다.")
            else:
                print("해당 ID의 책이 없습니다.")

        elif menu == "5":
            rows = get_all_books()
            print_books(rows)
            if len(rows) == 0:
                continue

            book_id = input_number("삭제할 책 ID: ")
            if book_id is None:
                continue

            changed = delete_book(book_id)
            if changed == 0:
                print("해당 ID의 책이 없습니다.")
            else:
                print("책이 삭제되었습니다.")

        elif menu == "6":
            keyword = input("검색할 책 제목: ").strip()
            rows = search_books(keyword)
            print_books(rows)


        elif menu == "7":
            keyword = input("외부에서검색할책제목 : ").strip()
            results = search_external_books(keyword)
            print_search_results(results)
            


        elif menu == "8":
            if len(results) == 0:
                print("먼저외부도서검색을실행하세요")
                continue
            print_search_results(results)
            number = input_number("저장할책번호 : ")
            if number is None:
                continue
            if number < 1 or number > len(results):
                print("올바른책번호를선택하세요")
                continue

            selected_book = results[number - 1]
            add_book(selected_book['title'], selected_book['author'])
            print(f"'{selected_book['title']}'이(가)내서재에저장되었습니다.")



        elif menu == "0":
            print("프로그램을 종료합니다.")
            break
        else:
            print("올바른 메뉴를 선택하세요.")

        

if __name__ == "__main__":
    main()