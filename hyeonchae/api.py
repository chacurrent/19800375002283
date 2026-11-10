import requests





API_URL = "https://openlibrary.org/search.json"

def search_external_books(keyword):
    if keyword.strip() == "":
        return []
    
    params = {
        'q' : keyword,
        'limit' : 5
    }

    
    try:
        response = requests.get(API_URL, params = params, timeout = 5)
        data = response.json()
    except requests.RequestException:
        print("네트워크오류발생네트워크오류발생")
    except ValueError:
        print("응답데이터처리할수없습니다")
        return []
    results = []


    for item in data.get('docs', []):
        title = item.get("title", "무제")
        author_list = item.get("author_name", [])
        if len(author_list) > 0:
            author = author_list[0]
        else:
            author = "저자정보없음"

        book = {
            "title" : title,
            "author" : author
        }
        results.append(book)
    return results