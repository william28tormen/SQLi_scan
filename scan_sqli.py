import copy
from urllib import parse
import requests
import sys

def request(url):
    headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36"}
    try:
        response = requests.get(url, headers=headers)
        html = response.text
        return  html
    except:
        pass

def is_vulnerable(html):
    errors = [
        "mysql_fetch_array()",
        "You have an error in your SQL syntax",
        "Warning: mysql_connect()",
        "Warning: mysqli_connect()",
        "Uncaught Error: Call to undefined function mysql_connect()",
        "SQLSTATE[HY000] [2002]",
        "Access denied for user",
        "SQL syntax; check the manual",
        "SQL Error:",
        "PDOException: SQLSTATE[HY000]",
        "ORA-00933: SQL command not properly ended",
        "ORA-01756: quoted string not properly terminated",
        "ORA-12541: TNS:no listener",
        "ORA-12154: TNS:could not resolve the connect identifier specified",
        "SQL Server does not exist or access denied",
        "SQL Server Network Interfaces: Error Locating Server/Instance Specified",
        "A network-related or instance-specific error occurred while establishing a connection to SQL Server",
        "Login failed for user",
        "The server was not found or was not accessible",
        "An error has occurred while establishing a connection to the server",
        "Cannot connect to the database",
        "Database connection failed",
        "Unable to connect to the database",
        "Error establishing a database connection",
        "Lost connection to MySQL server during query",
        "MySQL server has gone away",
        "Too many connections",
        "Disk full",
        "Table 'xyz' doesn't exist",
        "Unknown column 'xyz' in 'field list'",
        "The table is full",
        "Can't connect to local MySQL server through socket"
    ]

    for error in errors:
        if error in html:
            return True

if __name__ == "__main__":
    url = sys.argv[1]

    print("SQLi Scan - n0body v2.0.3")
    print("----------------------------------------------------------------------------------------")

    url_parsed = parse.urlsplit(url)
    params = parse.parse_qs(url_parsed.query)
    for param in params.keys():
        query = copy.deepcopy(params)
        for c in "'\"":
            query[param][0] = c
            new_params = parse.urlencode(query, doseq=True)
            url_final = url_parsed._replace(query=new_params)
            url_final = url_final.geturl()
            html = request(url_final)
            if html:
                if is_vulnerable(html):

                    print("-----> VULNERABLE ## {} ##".format(param))
                    quit()

print("-----> NOT VULNERABLE!")