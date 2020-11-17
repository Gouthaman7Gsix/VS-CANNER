import requests
from urllib.parse import urlparse, urljoin
import platform
import re
from bs4 import BeautifulSoup
import sys,os
from time import sleep as timeout                                   #seting the time exp
from termcolor import colored                    #coloring the figlet text
from pyfiglet import figlet_format                        #for echo


def typewriter(message):
    for char in message:
        sys.stdout.write(char)
        sys.stdout.flush()
        timeout(0.1)


def restart_program() :                                               #defining restart
    python = sys.executable                                         #making excecutable
    os.execl(python, python, *sys.argv)                            #calling the path of exc file
    os.system('clear')

def sub_scanner():
    domain = input("Input target domain :")
    file = open("Subdomain.txt")
    DNS = file.read()
    subs = DNS.splitlines()

    for sub in subs:
        if sub !=True:
            Link = f'http://{sub}.{domain}'
            try :
                requests.get(Link)
            except requests.ConnectionError:
                pass
            finally:
                print("Your target subdomain :-  ",Link)
        else: break


class PyCrawler(object):
    def __init__(self, starting_url):
        self.starting_url = starting_url
        self.visited = set()

    def get_html(self, url):
        try:
            html = requests.get(url)
        except Exception as e:
            print(e)
            return ""
        return html.content.decode('latin-1')

    def get_links(self, url):
        html = self.get_html(url)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        links = re.findall('''<a\s+(?:[^>]*?\s+)?href="([^"]*)"''', html)
        for i, link in enumerate(links):
            if not urlparse(link).netloc:
                link_with_base = base + link
                links[i] = link_with_base

        return set(filter(lambda x: 'mailto' not in x, links))

    def extract_info(self, url):
        html = self.get_html(url)
        return None

    def crawl(self, url):
        for link in self.get_links(url):
            if link in self.visited:
                continue
            print(link)
            self.visited.add(link)
            info = self.extract_info(link)
            self.crawl(link)

    def start(self):
        self.crawl(self.starting_url)


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):

    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    print(target_url)
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)


def scan_xss(url):
     # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        try:
            content = submit_form(form_details, url, js_script).content.decode()
        except:
            pass
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            print(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable


def scan_html(url):
     # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<title>Search Results for ‘</title>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        try:
            content = submit_form(form_details, url, js_script).content.decode()
        except:
            pass
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            print(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable


def is_vulnerable(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to preceed for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # any input form that is hidden or has some value,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break


message='''\n\n\nTo use this Tool you requires a minimum basic knowldege in web and web based attacks\nso please co-operate with us...\n\n'''


typewriter(message)


def clear():
    a = platform.system()
    if a == 'Windows':
        print(os.system('cls'))
    elif a == 'Linux':
        print(os.system('clear'))
    elif a == 'Darwin':
        print(os.system('clear'))


while True:

    print(colored(figlet_format("VS-Canner"), color="cyan"))
    print("[1].Sub-domain_Scanner\n[2].Web-Crawler \n[3].XSS_Scanner\n[4].HTML_Injection_Scanner\n[5].SQL_Injection_Scanner\n[6].Local-Fie-Inclusion-Scanner\n[7].[00] Back\nEnter your choice:")
    choice=input()


    if choice=="1":
        clear()
        print(colored(figlet_format("SUB-SCANNER"), color="blue"))
        sub_scanner()

    elif choice=="2":
        clear()
        print(colored(figlet_format("Web-Crawler"), color="blue"))


        if __name__ == "__main__":
            url =input("Enter the url (Example http://www.google.com) :")
            crawler = PyCrawler(url)
            crawler.start()


    elif choice=="3":
        clear()
        print(colored(figlet_format("XSS-SCANNER"), color="yellow"))


        if __name__ == "__main__":
            url = input("Enter the Url (Example http://www.google.com) :")
            try:
                print(scan_xss(url))
            except:
                print("No xss vulnerabilities are found")


    elif choice=="4":
        clear()
        print(colored(figlet_format("HTML-SCANNER"), color="green"))



        if __name__ == "__main__":
            url = input("Enter the Url (Example http://www.google.com) :")
            try:
                print(scan_xss(url))
            except:
                print("No xss vulnerabilities are found")


    elif choice=="5":
        clear()
        print(colored(figlet_format("SQL-SCANNER"), color="green"))
        # initialize an HTTP session & set the browser
        s = requests.Session()
        s.headers[
            "User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
        try:
            if __name__ == "__main__":


                url=input("Enter a url (Example http://testphp.vulnweb.com/artists.php?artist=1) :")
                scan_sql_injection(url)
        except requests.exceptions.ConnectionError :
            print("<urllib3.connection.HTTPConnection object at 0x000001F0BD270940>: Failed to establish a new connection: [WinError 10060] A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond")


    elif choice=="6":
        clear()
        print(colored(figlet_format("LFI-Scanner"), color="white"))
        url =input("Enter the URL (Example http://www.google.com) :")
        payload="../"
        file_name="etc/passwd"
        string="root"
        error="include(../etc/passwd)"
        cookies={'security':'low','PHPSESSID':'inm9r4n0ro9mro55as3h1ljb4c'}
        print(url+payload+file_name)
        req=requests.get(url+payload+file_name,cookies=cookies)
        if error in req.text:
            print("The url is vulnerable to LFI")
        else:
            print("The url is not vulnerable to LFI")
        for i in range(1,7):
            data =payload*i+file_name
            req =requests.get(url+data,cookies=cookies)
            if req.status_code == 200 and  string in req.text:
                print(url+data)
                print(req.text)
                break
            else:
                continue
    elif choice>="7":
        print("Enter a Valid option:")

    elif choice == '00' or '0':
        restart_program()
    else:
        timeout(3)
        restart_program()