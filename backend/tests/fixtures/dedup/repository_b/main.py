from flask import request


# equivalent vulnerability to repository_a/views.py, different names,
# different file, different lines, different construction style


def find_record():
    sql = "SELECT * FROM records WHERE owner = " + request.args.get("owner_id")
    db.execute(sql)