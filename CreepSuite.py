#!/usr/local/bin/python3

import urllib,time,sys,pycurl,codecs,re,os,subprocess,wget,mmap
from urllib.request import Request, urlopen, URLError
from bs4 import BeautifulSoup
# Constants
user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0'
mainTitle ='''Welcome to Creep Suite Version 1.1'''

title = '''Now in the XSS Creep menu'''

# Main Code
print (mainTitle)
input_selection = input('''
The Following tools are available
1.XSS Creep
2.File Creep

Please enter the number of the tool you wish to use: ''')
if input_selection == '1':
    # Main Code
    print (title)

    input_url = input('Please enter the webpage you wish to be scanned: ')

    short_url = full_url = ''
    if 'http://' in input_url: # will not handle https
        short_url = input_url[7:]
        full_url = input_url
    else:
        short_url = input_url
        full_url = 'http://{0}'.format(short_url)

    print('now searching {0} for javascript files'.format(short_url))

    with open('out.txt', 'wb') as f:
        c = pycurl.Curl()
        c.setopt(pycurl.USERAGENT, user_agent)
        c.setopt(pycurl.FOLLOWLOCATION, True)
        c.setopt(pycurl.MAXREDIRS, 5)

        c.setopt(pycurl.URL, short_url)
        c.setopt(pycurl.WRITEDATA, f)
        c.perform()
        c.close()

    comp = r'\b.swf\b'
    f = codecs.open('out.txt', 'r',encoding='utf-8', errors='ignore').read()
    find_word = re.findall(comp, f)

    if len(find_word) == 0:
        print ('No files were found please try another page')
        sys.exit()

    print('Found {0} possible .swf files.'.format(len(find_word))) # Incorrect... found swf
                                                          # this many times
    scan_start = input('would you like to download them? y or n?: ')

    if scan_start is 'y':

        cwd = os.getcwd()
        newdir = '{0}/swfs/'.format(cwd)

        print('The current Working directory is {0}.'.format(cwd))
        if not os.path.isdir(newdir):
            os.mkdir(newdir, 495);
            print('Created new directory {0}.'.format(newdir))
        print('Using \'{0}\' to put downloaded .swf files'.format(newdir))
        subprocess.call(["sudo","chmod","777","%s"%newdir])
        print ('Running script.. ')
        headers = {'User-Agent': user_agent}

        req = urllib.request.Request(full_url, headers = headers)
        page_data = urllib.request.urlopen(req).read()

        # File extension to be looked for.
        extension = '.swf'

        # Use BeautifulSoup to clean up the page
        soup = BeautifulSoup(page_data, 'html.parser')
        soup.prettify()

        # Find all the links on the page that end in .swf
        with open('swffiles.txt','w') as link_file:
            for anchor in soup.findAll('a', href=True):
                link = '{0}{1}'.format(short_url, anchor['href'])
                if link.endswith(extension):
                    link_file.write('{0}\n'.format(link))

        # Read what is saved in swffiles.txt and output it to the user
        # This is done to create persistent data
        with open('swffiles.txt', 'r') as newfile:
            for line in newfile:
                print('{0}\n'.format(line))

        # Read through the lines in the text file and download the swf files.
        # Handle exceptions and print exceptions to the console
        with open('swffiles.txt', 'r') as urls:
            for url in urls:
                if url:
                    url = url[:-1] # Get rid of newline
                    print('Downloading {0}...'.format(url))
                    wget.download('http://{0}'.format(url), newdir)

        print('\nDownloads completed')
        subprocess.call(["sudo","chmod","-R","777","%s"%newdir])
        convert = input('would you like to convert the downloaded files ? y or n?: ')
        if convert == 'y':
            for file in os.listdir(newdir):
                if file.endswith(".swf"):
                    subprocess.call(["sudo","./flare","%s/%s"%(newdir,file)])
        subprocess.call(["sudo","chmod","-R","777","%s"%newdir])

        print('\nConversion complete')
        time.sleep(1)
        print('\nScanning files now')
        time.sleep(1)
        subprocess.call(["sudo","chmod","-R","777","%s"%newdir])
        for file in os.listdir(newdir):
          if file.endswith('.flr'):
            with open('%s/%s' %(newdir, file), 'r+') as z:
                data = mmap.mmap(z.fileno(), 0, access=mmap.ACCESS_READ)
                #start of signatures. More signatures are coming.
                ab = re.search(b'[\s]on \(release\) {\n[\s]geturl \(_root.clickTAG, "_self"\);\n[\s]}', data)
                aa = re.search(b'[\s]\(_root\.urltoload !=null\) {\n[\s]+GetURL \(_root\.urltoload\)\;+\n([ \t]+}|[}\t])', data)
                ac = re.search(b'[\s]navigateToURL\(new URLRequest\(cmd\),"_self"\);',data)
                ad = re.search(b'[\s]navigateToURL\(new URLRequest\(cmd\),"_blank"\);', data)
                ae = re.search(b'[\s]*var loader:URLLoader = new URLLoader\(new URLRequest\(cmd\)\);\n[\s]*loader\.addEventListener\(Event\.COMPLETE,get_complete\);\n[\s]*loader\.addEventListener\(SecurityErrorEvent\.SECURITY_ERROR,get_sec_error\);', data)
                af = re.search(b'[\s]flash\.external\.ExternalInterface\.call\("eval", cmd\);', data)
                ag = re.search(b'[\s]target="_blank"', data)
                if ab:
                    print ('Possible vulnerability found in %s'%file)
                if aa:
                    print ('Possible vulnerability found in %s'%file)
                if ac:
                    print ('Possible vulnerability found in %s'%file)
                if ad:
                    print ('Possible vulnerability found in %s'%file)
                if ae:
                    print ('Possible vulnerability found in %s'%file)
                if af:
                    print ('Possible vulnerability found in %s'%file)
                if ag:
                    print ('Possible vulnerability found in %s'%file 'Target="_blank" may be unfiltered')
elif input_selection == '2':
    print ('File Creep at your service')

    input_url = input('Please enter the target webpage: ')
    file_type = input('Please enter the file type you wish to download with out the period (Example txt, pdf, jpg) :')
    short_url = full_url = ''
    if 'http://' in input_url: # will not handle https
        short_url = input_url[7:]
        full_url = input_url
    else:
        short_url = input_url
        full_url = 'http://{0}'.format(short_url)

    print('now searching {0} for %s files'.format(short_url)%file_type)

    with open('out.txt', 'wb') as f:
        c = pycurl.Curl()
        c.setopt(pycurl.USERAGENT, user_agent)
        c.setopt(pycurl.FOLLOWLOCATION, True)
        c.setopt(pycurl.MAXREDIRS, 5)

        c.setopt(pycurl.URL, short_url)
        c.setopt(pycurl.WRITEDATA, f)
        c.perform()
        c.close()

    comp = r'\b.%s\b'%file_type
    f = codecs.open('out.txt', 'r',encoding='utf-8', errors='ignore').read()
    find_word = re.findall(comp, f)

    if len(find_word) == 0:
        print ('No files were found please try another page')
        sys.exit()

    print('Found {0} possible %s files.'.format(len(find_word))%file_type) # Incorrect... found swf
                                                          # this many times
    scan_start = input('would you like to download them? y or n?: ')

    if scan_start is 'y':

        cwd = os.getcwd()
        newdir = '{0}/%s/'.format(cwd)%file_type

        print('The current Working directory is {0}.'.format(cwd))
        if not os.path.isdir(newdir):
            os.mkdir(newdir, 495);
            print('Created new directory {0}.'.format(newdir))
        print('Using \'{0}\' to put downloaded .%s files'.format(newdir)%file_type)
        subprocess.call(["sudo","chmod","777","%s"%newdir])
        print ('Running script.. ')
        headers = {'User-Agent': user_agent}

        req = urllib.request.Request(full_url, headers = headers)
        page_data = urllib.request.urlopen(req).read()

        # File extension to be looked for.
        extension = '%s'%file_type

        # Use BeautifulSoup to clean up the page
        soup = BeautifulSoup(page_data, 'html.parser')
        soup.prettify()

        # Find all the links on the page that end in .swf
        with open('%s.txt'%file_type,'w') as link_file:
            for anchor in soup.findAll('a', href=True):
                link = '{1}'.format(short_url, anchor['href'])
                if link.endswith(extension):
                    link_file.write('{0}\n'.format(link))

        # Read what is saved in swffiles.txt and output it to the user
        # This is done to create persistent data
        with open('%s.txt'%file_type, 'r') as newfile:
            for line in newfile:
                print('{0}\n'.format(line))

        # Read through the lines in the text file and download the swf files.
        # Handle exceptions and print exceptions to the console
        with open('%s.txt'%file_type, 'r') as urls:
            for url in urls:
                if url:
                    url = url[:-1] # Get rid of newline
                    print('Downloading {0}...'.format(url))
                    wget.download('{0}'.format(url), newdir)

        print('\nDownloads completed')
