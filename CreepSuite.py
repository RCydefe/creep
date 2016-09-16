#!/usr/local/bin/python3
import time,sys
import re,os,subprocess
import mmap
from bs4 import BeautifulSoup
from argparse import ArgumentParser
from requests import get
import logging

# TODO: implement this
from swf.movie import SWF
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3 import disable_warnings

disable_warnings(InsecureRequestWarning)
from traceback import print_exc

flare_path = os.path.join(os.getcwd(), "flare", "flare.exe")
# Make a log file
rootLogger = logging.basicConfig(filename='creep.log',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
rootLogger = logging.getLogger('forwarder_client')

# Make a streamhandler to log to console too
consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
consoleHandler.setLevel(logging.DEBUG)
rootLogger.addHandler(consoleHandler)

# Constants
USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0'
newdir = os.path.join(os.getcwd(), "swfs")
def correct_url(url):
    if not url.startswith("http"):
        url = "http://{0}".format(url)
    return url
def get_matching_files(url_list, pattern, extension, out_dir=newdir, auto_scan_start=True):
    # TODO clean this up
    headers = {
            'User-Agent': USER_AGENT,
            }
    out_dir=newdir.replace('swf', extension)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    for url in url_list:
        url = correct_url(url)
        if url.lower().endswith('.{0}'.format(extension)):
            with open(os.path.join(out_dir, "{1}_{0}.{2}".format(0, extension, extension)), 'wb') as f:
                r = get(url, headers=headers, verify=False)
                for block in r.iter_content(1024):
                    if not block:
                        break
                    f.write(block)

        else:
            print('now searching {0} for {1} files'.format(url, extension))

            # TODO: Add proxy handling
            r = get(url, headers=headers, verify=False)
            if r.status_code >= 200 and r.status_code <300:
                find_word = re.findall(pattern, r.text)
                if len(find_word) == 0:
                    print ('No files were found please try another page')
                    return 0

                print('Found {0} possible {1} files.'.format(len(find_word), extension))

                if auto_scan_start:

                    if not os.path.isdir(out_dir):
                        os.mkdir(out_dir, 777)
                        print('Created new directory {0}.'.format(out_dir))
                    print('Using \'{0}\' to put downloaded {1} files'.format(out_dir, extension))
                    print ('Running script.. ')

                    # Use BeautifulSoup to clean up the page
                    soup = BeautifulSoup(r.text, 'html.parser')
                    soup.prettify()

                    _links = []
                    for anchor in soup.findAll('a'):
                        link = anchor.get('href')
                        if link:
                            if not link.startswith('http'):
                                link = '{0}{1}'.format(url, anchor.get('href'))
                            if link.endswith(extension):
                                print (link)
                                _links.append(link)
                    for anchor in soup.findAll('img'):
                        link = anchor.get('src')
                        if link:
                            if not link.startswith('http'):
                                link = '{0}{1}'.format(url, anchor.get('src'))
                            if link.endswith(extension):
                                print (link)
                                _links.append(link)
                    cntr = 0
                    for link in _links:
                        with open(os.path.join(out_dir, "{1}_{0}.{2}".format(cntr, extension, extension)), 'wb') as f:
                            r = get(link, headers=headers, verify=False)
                            for block in r.iter_content(1024):
                                if not block:
                                    break
                                f.write(block)
                        cntr+=1
                    return cntr
def convert_swf(file_path, flare=False, flare_path=os.path.join(os.getcwd(), 'flare', 'flare.exe')):
    if file_path.endswith(".swf"):
        print( file_path)
        out_name = file_path.replace('.swf','.out')
        if flare:

            subprocess.call([flare_path,file_path])
            return file_path.replace('.swf','.flr')
        else:
            try:
                with open(file_path, 'rb') as f:
                    swf = SWF(f)
                    with open(out_name, 'wb') as out:
                        out.write(bytes(str(swf), 'UTF-8'))
                return out_name
            except:
                print(print_exc())
                return None

def do_xss(url_list, auto_scan_start=True, auto_convert=True):
    comp = r'\b.swf\b'
    get_matching_files(url_list, comp, 'swf', auto_scan_start=auto_scan_start, )


    if auto_convert:
        for file in os.listdir(newdir):
            if file.endswith(".swf"):
                processed_file = convert_swf(os.path.join(newdir,file), True, )
                run_signatures(processed_file)
                # print( file)
                # try:
                #     with open(os.path.join(newdir,file), 'rb') as f:
                #         swf = SWF(f)
                #         with open(os.path.join(newdir,file.replace('.swf','out')), 'wb') as out:
                #             out.write(str(swf))
                # except:
                #     print(print_exc())
                # # TODO: implement flare option
                # #             subprocess.call([flare_path,os.path.join(newdir,file)])

    # print('\nConversion complete')
    # time.sleep(1)
    # print('\nScanning files now')
    # time.sleep(1)
    # for file in os.listdir(newdir):
    #     #if file.endswith('.flr'):
    #     if file.endswith('.flr') or file.endswith('.out'):
    #         with open('%s/%s' %(newdir, file), 'r+') as z:
    #             data = mmap.mmap(z.fileno(), 0, access=mmap.ACCESS_READ)
    #             #start of signatures. More signatures are coming.
    #             ab = re.search(b'[\s]on \(release\) {\n[\s]geturl \(_root.clickTAG, "_self"\);\n[\s]}', data)
    #             aa = re.search(b'[\s]\(_root\.urltoload !=null\) {\n[\s]+GetURL \(_root\.urltoload\)\;+\n([ \t]+}|[}\t])', data)
    #             ac = re.search(b'[\s]navigateToURL\(new URLRequest\(cmd\),"_self"\);',data)
    #             ad = re.search(b'[\s]navigateToURL\(new URLRequest\(cmd\),"_blank"\);', data)
    #             ae = re.search(b'[\s]*var loader:URLLoader = new URLLoader\(new URLRequest\(cmd\)\);\n[\s]*loader\.addEventListener\(Event\.COMPLETE,get_complete\);\n[\s]*loader\.addEventListener\(SecurityErrorEvent\.SECURITY_ERROR,get_sec_error\);', data)
    #             af = re.search(b'[\s]flash\.external\.ExternalInterface\.call\("eval", cmd\);', data)
    #             ag = re.search(b'[\s]target="_blank"', data)
    #             if ab:
    #                 print ('Possible vulnerability found in %s'%file)
    #             if aa:
    #                 print ('Possible vulnerability found in %s'%file)
    #             if ac:
    #                 print ('Possible vulnerability found in %s'%file)
    #             if ad:
    #                 print ('Possible vulnerability found in %s'%file)
    #             if ae:
    #                 print ('Possible vulnerability found in %s'%file)
    #             if af:
    #                 print ('Possible vulnerability found in %s'%file)
    #             if ag:
    #                 print ('Possible vulnerability found in %s'%file, 'Target="_blank" may be unfiltered')
def run_signatures(file):
    print('Running signatures...')
    with open(file, 'r+') as z:
        data = z.read()
        sigs = {
            'ab': {'pattern': r'on \(release\) {\ngeturl \(_root.clickTAG, "_self"\);\n}', 'message':'Possible vulnerability'},
            'aa': {'pattern': r'\(_root\.urltoload !=null\) {\n+GetURL \(_root\.urltoload\)\;+\n([ \t]+}|[}\t])', 'message':'Possible vulnerability'},
            'ac': {'pattern': r'navigateToURL\(new URLRequest\(cmd\),"_self"\);', 'message':'Possible vulnerability'},
            'ad': {'pattern': r'navigateToURL\(new URLRequest\(cmd\),"_blank"\);', 'message':'Possible vulnerability'},
            # TODO: fix ae, it's buggy
            #'ae': {'pattern': r'*var loader:URLLoader = new URLLoader\(new URLRequest\(cmd\)\);\n*loader\.addEventListener\(Event\.COMPLETE,get_complete\);\n*loader\.addEventListener\(SecurityErrorEvent\.SECURITY_ERROR,get_sec_error\);', 'message':'Possible vulnerability'},
            'af': {'pattern': r'flash\.external\.ExternalInterface\.call\("eval", cmd\);', 'message':'Possible vulnerability'},
            'ag':  {'pattern': r'target="_blank"', 'message':'Target="_blank" may be unfiltered'},
            'ah':  {'pattern': r'_root\.createTextField\("tf",0,100,100,640,480\);\n_root\.tf\.html = true;\n_root\.tf\.htmlText = "Hello, " \+ _root\.username \+ "!";', 'message':'test succeeded.'},
        }
        for k, v in sigs.items():
            res = re.findall(v['pattern'],data)
            if res:
                print (v['message'])

def do_static_xss(file_list):
    print('Running static check on swf file(s): {0}'.format(file_list))
    for f in file_list:
        if os.path.isdir(f):
            for file in os.listdir(f):
                out = convert_swf(os.path.join(f, file))
                if out:
                   run_signatures(out)
        elif os.path.isfile(f):
            out = convert_swf(f)
            print(out)
            if out:
               run_signatures(out)
        else:
            print('Thats not a file.')

def do_file(url_list, file_type, auto_scan_start=True):
    print ('File Creep at your service')
    for _f in file_type:
        comp = r'\b.%s\b'%_f
        get_matching_files(url_list, comp, _f, auto_scan_start=auto_scan_start)

def main():
    parser = ArgumentParser(description="", epilog="Welcome to Creep Suite Version 1.1")
    parser.add_argument("-t, --tools", dest="tools", action="store", help="Comma-separated list of tools to run. Options: xss, file, static_xss.")
    parser.add_argument("-u, --url", dest="url", action="store", nargs="?", default=None, help="Comma-separated list of urls to try.")
    parser.add_argument("-f, --file_extension", dest="file_extension", action="store", default=None, nargs="?")
    parser.add_argument("-s, --static_files", dest="static_files", action="store", default=None, nargs="?", help="list of static swf files to scan for evil.")
    args = parser.parse_args()

    if args.tools:
        tool_array = args.tools.split(',')
        if "static_xss" in tool_array:
            if not args.static_files:
                rootLogger.error("Need a url to run xss.")
                sys.exit(0)
            static_files = args.static_files.split(',')

            do_static_xss(static_files, )
        if args.url:
            urls = args.url.split(',')

            if "xss" in tool_array:

                if not args.url:
                    rootLogger.error("Need a url to run xss.")
                    sys.exit(0)

                do_xss(urls, )


            if "file" in tool_array:
                if not args.file_extension:
                    rootLogger.error("Need a file extension to search for.")
                    sys.exit(0)
                file_extensions = args.file_extension.split(',')
                do_file(urls, file_extensions)


if __name__ == "__main__":
    main()
