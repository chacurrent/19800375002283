import sqlite3
DB_NAME = "Books.db"





def connect_db():
    return sqlite3.connect(DB_NAME)



def create_table():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS books(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    rating INTEGER DEFAULT 0,
    finished INTEGER DEFAULT 0)""")

    conn.commit()
    conn.close()



def add_book(title, author):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""INSERT INTO BOOKS (title, author) VALUES (?, ?)""", (title, author))

    conn.commit()
    conn.close()



def get_all_books():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""SELECT id, title, author, rating, finished FROM books ORDER BY id""")

    rows = cursor.fetchall()
    conn.close()
    return rows



def update_rating(book_id, rating):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""UPDATE books SET rating = ? WHERE id = ?""", (rating, book_id))

    conn.commit()
    changed = cursor.rowcount
    conn.close()

    return changed



def toggle_finished(book_id):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""SELECT finished FROM books WHERE id = ?""", (book_id,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return False
    current_status = row[0]
    if current_status == 0:
        new_status = 1
    else:
        new_status = 0

    cursor.execute("""UPDATE books SET finished = ? WHERE id = ?""", (new_status, book_id))

    conn.commit()
    conn.close()
    return True



def delete_book(book_id):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""DELETE FROM books WHERE id = ?""", (book_id,))

    conn.commit()
    changed = cursor.rowcount
    conn.close()
    return changed



def search_books(keyword):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""SELECT id, title, author, rating, finished FROM books WHERE title Like ? ORDER BY id""", (f"%{keyword}%",))
    # %{ }% : 앞뒤로 다른 글자가 있을 수도 있다(상관없다).

    rows = cursor.fetchall()
    conn.close()
    return rows



if __name__ == "__main__":
    # create_table()
    # add_book('어린왕자', '생택쥐페리')
    # add_book('데미안', '헤르만해세')
    # print(get_all_books())

    # print(update_rating(1, 4))
    # print(get_all_books())

    # toggle_finished(1)
    # print(get_all_books())

    pass