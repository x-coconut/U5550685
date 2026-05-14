import os
import re
import sys
import time
import sqlite3
import argparse
import urllib.parse
from datetime import datetime
from rich import print 
from rich import box       
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
from playwright.sync_api import sync_playwright

# set up args
parser = argparse.ArgumentParser(description="A wrapper for the fine-tuned LLM to redact the HTTP requests and send them to test for automatic payload execution")
parser.add_argument("--auto", action="store_true", help="run without prompting you for consent for each action")
parser.add_argument("--no-redaction", action="store_true", help="run without redacting the HTTP request before passign it to the LLM")
parser.add_argument("--no-test", action="store_true", help="run without sending the request to the site to automatically check if the payload executed")
parser.add_argument("--proxy", action="store_true", help="proxy traffic on port 8080")
parser.add_argument("--http", action="store_true", help="forces HTTP rather than HTTPS")
parser.add_argument("--url", type=str, help="specify the URL to visit to trigger the payload if this differs from the page the payload is sent to")
args = parser.parse_args()

if len(sys.argv) == 1:
    print("Run with --help to see more options")
AUTO_MODE = args.auto
NO_REDACTION = args.no_redaction
NO_TEST = args.no_test
PROXY = args.proxy
HTTP = args.http

# for logging
conn = sqlite3.connect("log.sqlite")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        message TEXT
    )
""")
conn.commit()

def log(level, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
        (timestamp, level, message)
    )
    conn.commit()

log("INFO", f"Script started with args: {vars(args)}")

INPUT_FILE = "input_request.txt"
REDACTED_FILE = "redacted_request.txt"
GENERATED_FILE = "generated_request.txt"
OUTPUT_FILE = "output_request.txt"

# build regex to find domain names
KNOWN_TLDS = [
    "com", "org", "net", "gov", "edu", "int", "mil", "info", "biz", "name", "pro", "xyz", "top",
    "io", "ai", "app", "dev", "tech", "cloud", "digital", "site", "online", "space", "shop", "studio",
    "uk", "co.uk", "us", "ca", "de", "fr", "jp", "cn", "in", "au", "nz", "ru", "br", "es", "it", "se", "nl",
    "local", "internal", "test", "example", "localhost",
    "me", "tv", "io", "ai", "app", "dev", "tech", "cloud"
]
TLD_PATTERN = "|".join([re.escape(tld) for tld in KNOWN_TLDS])
DOMAIN_REGEX = re.compile(
    rf"\b([a-zA-Z0-9-]+\.)+({TLD_PATTERN})\b",
    re.IGNORECASE
)

# build regex to find auth info 
SESSION_KEYS = [
    "phpsessid", "jsessionid", "sessionid", "sessid",
    "asp.net_sessionid", "sid", "connect.sid", "session",
    "token", "auth", "jwt", "access_token", "refresh_token",
    "api_key", "apikey", "secret", "auth_token", "bearer",
    "cfduid", "laravel_session", "wp_logged_in", "wp_session",
    "django_sessionid", "symfony", "express.sid", "zend_sessionid",
    "rails_session", "csrf_token",
    "x-api-key", "x-auth-token", "authorization", "x-access-token",
    "session_token", "id_token",
    "user_session", "login_token", "jwt_token", "cookie_token",
    "refreshToken", "accessToken", "authToken"
]
SESSION_KEY_PATTERN = "|".join([re.escape(k) for k in SESSION_KEYS])
SESSION_REGEX = re.compile(
    rf"(?i)\b({SESSION_KEY_PATTERN})=([^\s;]+)"
)
JWT_REGEX = re.compile(
    r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
)
GENERIC_TOKEN_REGEX = re.compile(
    r"\b[a-f0-9]{32,}\b", re.IGNORECASE
)

# menu for users to selct whether they are doing XSS or SQLi
def exploit_type_menu():
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]Select Attack Type[/bold cyan]\n\n"
        "[1] XSS (Cross-Site Scripting)\n"
        "[2] SQLi (SQL Injection)\n"
        "[3] Quit",
        border_style="cyan",
        box=box.ROUNDED
    ))

    while True:
        choice = Prompt.ask("[bold cyan]Enter choice[/bold cyan]").strip()

        if choice == "1":
            return "xss"
        elif choice == "2":
            return "sqli"
        elif choice == "3":
            exit()

# redact auth info from the requests
def redact_auth(text, replace_value):

    # redact session keys 
    text = SESSION_REGEX.sub(
        lambda m: f"{m.group(1)}={replace_value(m.group(2))}",
        text
    )

    # redact JWTs
    text = JWT_REGEX.sub(
        lambda m: replace_value(m.group(0)),
        text
    )

    # redact bearer token
    text = re.sub(
        r"(?i)(bearer\s+)([a-zA-Z0-9\-\._~\+/]+=*)",
        lambda m: m.group(1) + replace_value(m.group(2)),
        text
    )

    # redact anything else that may look like an auth token
    text = GENERIC_TOKEN_REGEX.sub(
        lambda m: replace_value(m.group(0)),
        text
    )

    return text

# redact the HTTP requests
def redact_text(text: str):
    mapping = {}
    counter = 1

    def replace_value(value: str):
        nonlocal counter
        if value not in mapping:
            mapping[value] = f"[REDACTED {counter}]"
            counter += 1
        return mapping[value]

    # redact auth tokens
    text = redact_auth(text, replace_value)

    # redact IPs
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", lambda m: replace_value(m.group(0)), text)

    # redact domains
    text = DOMAIN_REGEX.sub(lambda m: replace_value(m.group(0)), text)

    return text, mapping

# un-redact the payloads
def restore_text(text: str, mapping: dict):
    reverse_map = {v: k for k, v in mapping.items()}
    for redacted, original in reverse_map.items():
        text = text.replace(redacted, original)
    return text

# prints redactions to the terminal in red
def highlight_redactions(text):
    return re.sub(r"\[REDACTED.*?\]", "[bold red]\\g<0>[/bold red]", text)

# parse HTTP requests to build them with playwright
def parse_raw_request(raw):
    lines = raw.strip().split("\n")
    
    method, path, _ = lines[0].split()
    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        line = line.strip()

        if line == "":
            is_body = True
            continue

        if is_body:
            body += line
        else:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    host = headers.get("Host")
    if HTTP:
        url = f"http://{host}{path}"
    else:
        url = f"https://{host}{path}"

    return method, url, headers, body

# extract cookie header to set cookies in playwright
def extract_cookies(headers, domain):
    cookies = []
    if "Cookie" not in headers:
        return cookies

    for pair in headers["Cookie"].split(";"):
        name, value = pair.strip().split("=", 1)
        cookies.append({
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/"
        })
    return cookies

# build request that playwright will actually send
def playwright_request_preview(filepath):
    with open(filepath, "r") as f:
        raw_request = f.read()

    method, url, headers, body = parse_raw_request(raw_request)
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname
    
    captured = {"text": None}

    with sync_playwright() as p:
        if PROXY:
            browser = p.chromium.launch(headless=True,proxy={"server": "http://127.0.0.1:8080"})
        else:
            browser = p.chromium.launch(headless=True)

        context = browser.new_context(ignore_https_errors=True)

        cookies = extract_cookies(headers, domain)
        if cookies:
            context.add_cookies(cookies)

        page = context.new_page()

        def handle_route(route):
            req = route.request

            if req.url == url:
                req_preview = f"{method} {url}\n\n"

                for k, v in headers.items():
                    if k.lower() != "cookie":
                        req_preview += f"{k}: {v}\n"

                cookies_now = context.cookies()
                if cookies_now:
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies_now])
                    req_preview += f"\nCookies:\n{cookie_str}\n"
                else:
                    req_preview += "\nCookies: NONE\n"

                if method != "GET" and body:
                    req_preview += f"\nBody:\n{body}"

                captured["text"] = req_preview

                route.abort()
            else:
                route.continue_()

        page.route("**/*", handle_route)

        try:
            page.goto(url)
        except:
            pass
        browser.close()
        
    return captured["text"]

# send final request and check if payload executed
def check_for_successful_exploitation(filepath, exploit_type, check_url_override=None):
    with open(filepath, "r") as f:
        raw_request = f.read()

    method, url, headers, body = parse_raw_request(raw_request)
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname

    if check_url_override:
        url_to_visit = check_url_override
    else:
        url_to_visit = url

    xss_pattern = re.compile(r"XSS_test_\d+")
    sqli_pattern = re.compile(r"SQLi_test_\d+")

    console = Console()

    with sync_playwright() as p:
        if PROXY:
            browser = p.chromium.launch(headless=True,proxy={"server": "http://127.0.0.1:8080"})
        else:
            browser = p.chromium.launch(headless=True)

        context = browser.new_context(ignore_https_errors=True)

        cookies = extract_cookies(headers, domain)
        if cookies:
            context.add_cookies(cookies)

        page = context.new_page()

        def handle_route(route):
            req = route.request

            if req.url == url:
                route.continue_(
                    method=method,
                    headers={k: v for k, v in headers.items() if k.lower() != "cookie"},
                    post_data=body if method != "GET" else None
                )
            else:
                route.continue_()

        page.route("**/*", handle_route)

        try:
            start_time = time.time()
            page.goto(url_to_visit, timeout=5000)
            load_time = time.time() - start_time
        except Exception:
            console.print(f"\nFailed to load page: {url_to_visit}", style="bold red")
            log("ERROR", f"Failed to load page: {url_to_visit}")
            browser.close()
            return False

        if url_to_visit != url:
            page.goto(url_to_visit)

        # check if XSS payload executed
        if exploit_type == "xss":

            xss_pattern = re.compile(r"XSS_test_\d+")
            found = {"value": None}

            def on_console(msg):
                text = msg.text
                match = xss_pattern.search(text)
                if match:
                    found["value"] = match.group(0)

            page.on("console", on_console)

            try:
                page.goto(url_to_visit, timeout=5000)
            except:
                pass

            page.wait_for_timeout(3000)
            if found["value"]:
                console.print(f"\nXSS Successful: Console output - {found['value']}", style="bold green")
                log("INFO", f"XSS Successful: Console output - {found['value']}")
                browser.close()
                return True

            console.print("\nXSS not detected automatically", style="bold red")
            log("INFO", "XSS not detected automatically")
            browser.close()
            return False

        # check if SQLi payload executed
        elif exploit_type == "sqli":

            try:
                content = page.content()
                match = sqli_pattern.search(content)
                if match:
                    console.print(f"\nSQLi Successful: Response Contained {match.group()}", style="bold green")
                    log("INFO", f"SQLi Successful: Response Contained {match.group()}")
                    browser.close()
                    return True
            except:
                pass

            if load_time >= 2 and load_time <=3:
                console.print(f"\nSQLi Possible: Response took {load_time:.2f}s to load", style="bold yellow")
                log("INFO", f"SQLi Possible: Response took {load_time:.2f}s to load")
                browser.close()
                return True

            console.print("\nSQLi not detected automatically", style="bold red")
            log("INFO", "SQLi not detected automatically")
            browser.close()
            return False

# prompt a user to continue or quit (ensures user consents to all actions - HitL)
def prompt_before_continue():
    if AUTO_MODE:
        return
    while True:
        entered = Prompt.ask("[bold cyan]Enter 'c' to continue or 'q' to quit[/bold cyan]").lower()
        if entered == "q":
            exit()
        if entered == "c":
            return

def main():
    console = Console()
    exploit_found = False
    
    exploit_type = exploit_type_menu()
    
    if not AUTO_MODE and not NO_REDACTION:
        print(f"\nPlease save the request you want to redact into ./{INPUT_FILE}\n({os.path.join(os.getcwd(), INPUT_FILE)})")
        prompt_before_continue()
        
    while not exploit_found:
        
        # get user's inputted request
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            original_request = f.read()

        # redact input request
        if NO_REDACTION:
            redacted_request = original_request
            mapping = {}
        else:
            redacted_request, mapping = redact_text(original_request)

        # save the redacted request - so the user can make any final changes/redactions - HitL
        with open(REDACTED_FILE, "w", encoding="utf-8") as f:
            f.write(redacted_request)
            
        if not AUTO_MODE and not NO_REDACTION:
            print("\nThe redacted request is:\n")
            console.print(Panel.fit(f"[italic]{highlight_redactions(redacted_request)}[/italic]", title="Redacted Request", border_style="green", box=box.HORIZONTALS, padding=0))
            print(f"\nPlease make any further redactions/modifications to ./{REDACTED_FILE}\n({os.path.join(os.getcwd(), REDACTED_FILE)})")
            prompt_before_continue()

        # Read redacted request from file (in case user did change anything)
        with open(REDACTED_FILE, "r", encoding="utf-8") as f:
            redacted_request = f.read()
            
        log("INFO", f"Request sent to AI:\n{redacted_request}")
        
        # IF ADDING THE LOGIC TO RUN THE AI MODEL IN THIS FILE, IT GOES HERE
        #######################################################################
        console.print(Panel.fit(f"[bold red]Upload ./{REDACTED_FILE} to your Google Drive.\nSet the 'exploit_type' variable in cell 4 of 'generate_new_request.ipynb to the relevant value ('xss' or 'sqli').\nThen, run the 'generate_new_request.ipynb' file with Google Colab.\nSave the 'generated_request.txt' file from your Google drive to ./{GENERATED_FILE}.[/bold red]", title="NOTICE", border_style="red", box=box.HORIZONTALS, padding=0))
        while True:
            entered = Prompt.ask("[bold cyan]Enter 'c' to continue or 'q' to quit[/bold cyan]").lower()
            if entered == "q":
                exit()
            if entered == "c":
                break
        #######################################################################
        
        # read the HTTP request generated by AI    
        with open(GENERATED_FILE, "r", encoding="utf-8") as f:
            generated_redacted = f.read()
            
        log("INFO", f"AI generated request:\n{generated_redacted}")

        # unredact the request 
        if NO_REDACTION:
            unredacted_generated_request = generated_redacted
        else:
            unredacted_generated_request = restore_text(generated_redacted, mapping)

        # save the unredacted output request - so the user can access it or make changes before it is sent automatically - HitL
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(unredacted_generated_request)
            
        print("\nThe final generated request is:\n")
        console.print(Panel.fit(f"[italic]{unredacted_generated_request}[/italic]", title="Generated Request", border_style="green", box=box.HORIZONTALS, padding=0))
        if not AUTO_MODE and not NO_REDACTION:
            print(f"\nThis has been saved to ./{OUTPUT_FILE}\n({os.path.join(os.getcwd(), OUTPUT_FILE)})\nIf you made any additional redactions, ensure to modify this file and add any necessary information back\nEnsure that any authentication tokens are for current valid sessions")

        if NO_TEST:
            return
        prompt_before_continue()

        while True:
            if AUTO_MODE:
                send = "y"
            else:
                send = Prompt.ask(f"\n[bold cyan]Send request and check for {exploit_type.upper()}? (y/n)[/bold cyan]").lower()
            if send == "y":
                break
            elif send == "n":
                return

        check_url = args.url

        if not AUTO_MODE:
            print("\nThe request that will be sent with Playwright is:")
        playwright_request = playwright_request_preview(OUTPUT_FILE)
        log("INFO", f"Request sent with Playwright:\n{playwright_request}")

        if not AUTO_MODE:
            console.print(Panel.fit(f"[italic]{playwright_request}[/italic]", title="Playwright Request", border_style="green", box=box.HORIZONTALS, padding=0))

        prompt_before_continue()

        # send the generated request and automatically check for payload execution
        exploit_found = check_for_successful_exploitation(OUTPUT_FILE, exploit_type, check_url)
        if not exploit_found:
            while True:
                entered = Prompt.ask("\n[bold cyan]Generate a new exploit based on this attempted exploit? (y/n)[/bold cyan]").lower()
                if entered == "n":
                    exit()
                if entered == "y":
                    # write output request to input file
                    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                        old_request = f.read()
                    with open(INPUT_FILE, "w", encoding="utf-8") as f:
                        f.write(old_request)
                    break

if __name__ == "__main__":
    main()