#!/usr/bin/env python3

# Copyright (C) 2021 Karim Kanso
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Name: Simple Spider.
##
## Description: Designed for lightweight spidering of small sites to
## gain initial visibility.
##
## TODO:
## * save output as json
## * allow for mutators to be dependent upon processing another page
## ** e.g. only apply mutators if parent has been requested and is not an index

import urllib.request
from urllib.error import URLError
from urllib.parse import urlsplit, urljoin, urldefrag, SplitResult, quote
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import ssl
from bs4 import BeautifulSoup
import magic
import re
import socket
import http.client
import http.cookies
import argparse
import posixpath
import logging
from colorama import Fore, Style
import inspect
import sys
import traceback
import time
import signal
import errno
import random
import itertools

inscope_urls = {}
outscope_urls = {}
exclude_urls = {}
base_url = None

default_headers = {
    'User-Agent': 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
}

def create_connection(h, *a, **kw):
    global args
    return socket.create_connection(args.target, *a, **kw)

def PatchHTTPConnection(cls):
    def httpconn(host, cls=cls, **kw):
        global args
        h = cls(host, **kw)
        if args.target:
            h._create_connection = create_connection
        return h
    return httpconn

class SpiderHTTPHandler(urllib.request.AbstractHTTPHandler):
    def __init__(self, debuglevel=0):
        urllib.request.AbstractHTTPHandler.__init__(self, debuglevel)

    def https_open(self, req):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        ctx.set_alpn_protocols(['http/1.1'])

        return self.do_open(
            PatchHTTPConnection(http.client.HTTPSConnection),
            req,
            context=ctx
        )

    def http_open(self, req):
        return self.do_open(
            PatchHTTPConnection(http.client.HTTPConnection),
            req
        )

    http_request = urllib.request.AbstractHTTPHandler.do_request_
    https_request = urllib.request.AbstractHTTPHandler.do_request_

opener = urllib.request.OpenerDirector()
opener.add_handler(SpiderHTTPHandler())

recurse_types = [
    'text/html',
    'application/xhtml+xml'
]

# some common file types are not correctly detected by libmagic, so
# these are manual hacks to avoid spamming output with mismatches.
# key is server reported, and value is detected content type
libmagic_override = {
    'application/javascript': [
        'text/plain', # nominal case
        'text/html'   # rare cases libmagic will detect as html
    ],
    'text/css': ['text/plain'],
    'application/xml': ['text/html'],
    '': ['application/x-empty']
}

class Result:
    def __init__(
            self,
            url,
            status_code,
            length,
            content_type,
            detected_content_type
    ):
        self.url                   = url
        self.status_code           = status_code
        self.content_length        = length
        self.content_type          = (content_type or '').lower().split(';')[0]
        self.detected_content_type = detected_content_type.split(';')[0]
        self.linked_resources      = []
        self.custom_error          = None
        self.tags                  = set()

        if type(self.content_length) == str:
            self.content_length = int(self.content_length)

        if (detected_cts := libmagic_override.get(self.content_type, [])):
            if self.detected_content_type in detected_cts:
                self.detected_content_type = self.content_type

    def add_resource(self, tag, link, **kw):
        url = urldefrag(link).url
        if not url:
            return
        self.linked_resources.append(
            dict(
                {
                    'tag': tag,
                    'link': url,
                },
                **kw
            )
        )

    def set_ignore(self, ok):
        self.ignore = bool(ok)


    def get_resources(self, tag):
        return filter(lambda x: x['tag'] == tag, self.linked_resources)

    def __str__(self):
        return f'{self.status_code:03d} {self.detected_content_type} {self.url}'

class FormRegistry:
    def __init__(self):
        self.form = set()

    def add_form(self, method, params):
        if method:
            self.form.add((method,*params))

class RequestTrack(FormRegistry):
    def __init__(
            self,
            depth,
            guess=False,
            func_is_ok=None,
            tags=set(),
            callback=None
    ):
        FormRegistry.__init__(self)
        self.depth         = depth
        self.guess         = guess
        self.response      = None
        self.function_ok   = func_is_ok
        self.tries_left    = 5
        self.last_error    = None
        self.func_callback = callback
        self.tags          = tags # tracks mutators
        self.resp_tags     = set() # addendum to response.tags

    def set_response(self, response):
        if self.response:
            raise Exception('Request already completed')
        self.response = response

    def is_done(self):
        return bool(self.response)

    def is_interesting(self):
        if self.is_done():
            if self.function_ok:
                return self.function_ok(self.response)
            if not self.guess and not args.filter_all_pages:
                return True
            if type(self.response.ignore) == bool:
                return not self.response.ignore
            else:
                return self.response.status_code < 400
        else:
            return not self.guess and self.is_pending()

    def is_pending(self):
        return self.depth < 0

    def set_error(self, err):
        self.tries_left = max(self.tries_left - 1, 0)
        self.last_error = err

    def callback(self):
        if self.func_callback:
            return self.func_callback(self)
        return None

    def get_response_tags(self):
        if self.is_done():
            return self.resp_tags | self.response.tags
        else:
            return self.resp_tags

    def add_response_tag(self, tag):
        self.resp_tags.add(tag)

    def is_media(self):
        if self.is_done():
            macro_content_type = self.response.detected_content_type or ''
            macro_content_type = macro_content_type.split('/', 1)[0]
            return macro_content_type in ['image', 'audio', 'video']

class SpiderException(Exception):
    pass

class OutOfScope(SpiderException):
    def __init__(self):
        SpiderException.__init__(self, 'out of scope')

index_title = re.compile(
    '^((Index|Directory contents) of /.*)|(Directory Listing -.*)'
)
apache_link = re.compile('^\\?C=[SDMN];O=[AD]$')
def is_index(soup):
    if (title := soup.find('title')) and (title := title.string):
        if index_title.match(title):
            return True
    # IIS directory listing module
    return soup.find('a', {'href': True}, string='[To Parent Directory]')

def _load_url(url, timeout=30):
    global opener, args, default_headers, recurse_types, abort
    if abort:
        raise Exception('user aborted')
    if not check_url_scope(url):
        raise OutOfScope()
    if type(url) == SplitResult:
        url = url.geturl()
    logging.debug(f'requesting {url}')
    req = urllib.request.Request(
        url,
        headers=dict(default_headers, **dict(args.headers)),
        method='GET'
    )
    with opener.open(req, timeout=timeout) as resp:
        chunk1 = resp.read(1024)
        with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
            res = Result(
                url,
                resp.status,
                resp.getheader('Content-Length'),
                resp.getheader('Content-Type'),
                m.id_buffer(chunk1)
            )

        if args.filter_status:
            res.set_ignore(
                any([ s == resp.status for s in args.filter_status ])
            )

        if not res.ignore and args.filter_regex:
            res.set_ignore(args.filter_regex.search(chunk1))

        if (redir := resp.getheader('Location')):
            res.add_resource('redirect', redir)

        if (cookies := resp.info().get_all('Set-Cookie')):
            res.tags.add('cookie')
            for cookie in cookies:
                logging.info(f'found cookie {cookie} on {url}')
                for c in (sc := http.cookies.SimpleCookie(cookie)):
                    if sc[c]['path']:
                        res.add_resource('cookie', sc[c]['path'])

        if res.detected_content_type == 'application/javascript':
            content = chunk1 + resp.read()
            for mapping in re.finditer(
                    b'(?m:^//[#@] sourceMappingURL=(.*)$)',
                    content
            ):
                if (
                        not mapping[1].startswith(b'data:') and
                        not mapping[1].startswith(b'blob:')
                ):
                    res.tags.add('sourcemap')
                    res.add_resource('map', mapping[1].decode('utf8'))
                else:
                    res.tags.add('sourcemap-embedded')
            return res

        # if detected content type is not valid for recursion, bomb
        # out as its likely that the html parser will fail. n.b. this
        # covers case of empty body.
        if res.detected_content_type not in recurse_types:
            if (
                    not res.content_type or
                    res.detected_content_type.split('/')[0] != 'text' or
                    res.content_type not in recurse_types
            ):
                return res

        # for now, ignore reported content type
        # if res.content_type:
        #     if res.content_type not in recurse_types:
        #         return res

        content = chunk1 + resp.read()
        logging.debug(f'recurse condition for {url} with {res.content_type}')
        soup = BeautifulSoup(content, "html5lib")

        if not res.content_length:
            if (
                type(res.content_length) == int and
                res.content_length != len(content)
            ):
                res.tags.add('bad-length')
                logging.warning(
                    f'inconsistent content-length detected for {url},'
                    f' header reports size as {res.content_length} '
                    f'but actual size received is {len(content)}'
                )
            res.content_length = len(content)

        if is_index(soup):
            res.tags.add('index')

        for link in soup.find_all('a'):
            if 'index' in res.tags and apache_link.match(link.get('href')):
                continue
            res.add_resource('a', link.get('href'))

        for elem in soup.find_all(src=True):
            res.add_resource(elem.name, elem.get('src'))

        for form in soup.find_all('form'):
            params={}
            for inp in form.find_all('input', {'name': True}):
                params[inp.get('name')] = inp.get('type')
            for inp in form.find_all(
                    re.compile('button|select|textarea|object'),
                    {'name': True}
            ):
                params[inp.get('name')] = inp.name

            res.add_resource(
                'form',
                form.get('action') or url_dequery(url),
                method=(form.get('method') or 'get').lower(),
                params=params
            )

        for link in soup.find_all('link'):
            res.add_resource('link', link.get('href'))

        return res

def load_url(*arg, **kw):
    try:
        return _load_url(*arg, **kw)
    except Exception as e:
        raise SpiderException(*arg, **kw)

def url_normalise(url, base=None):
    if type(url) == str:
        url = urlsplit(url)
    if not url.path:
        p = '/' if url.netloc else ''
    else:
        p = posixpath.normpath(url.path)
        if url.path[-1:] == '/' and  p[-1] != '/':
            p += '/'
    url = SplitResult(
        url.scheme.lower(),
        url.netloc.lower(),
        p,
        url.query,
        ''
    )
    if base:
        return urlsplit(
            urljoin(url_normalise(base).geturl(), url.geturl())
        )
    return url

def url_to_dir(url):
    url = url_normalise(url)
    f = posixpath.basename(url.path)
    p = posixpath.dirname(url.path) if url.path[-1:] != '/' else url.path
    return (
        SplitResult(
            url.scheme,
            url.netloc.lower(),
            p if p[-1:] == '/' else p + '/',
            '',
            ''
        ),
        SplitResult(
            '',
            '',
            f,
            url.query,
            ''
        )
    )

def url_to_dirs(url):
    url = url_to_dir(url)[0]
    subpaths = []
    i = 0
    while (i := url.path.find('/', i)) >= 0:
        i += 1
        subpaths.append(url.path[:i])
    return {
        SplitResult(
            url.scheme,
            url.netloc,
            p,
            '',
            ''
        ) for p in subpaths
    }

def url_dequery(url):
    url = url_normalise(url)
    return SplitResult(
        url.scheme,
        url.netloc,
        url.path,
        '',
        ''
    ).geturl()

def is_url_prefix(base, url, same_ok=False):
    base = url_normalise(base)
    url = url_normalise(url)
    if not base.scheme == url.scheme:
        return False
    if not base.netloc == url.netloc:
        return False
    return url.path.startswith(base.path) and (
        same_ok or
        url.path != base.path or
        bool(url.query)
    )

def random_str(l):
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=l))

def url_random(base, tag):
    dir_url, file_url = url_to_dir(base)
    return url_normalise(f'{random_str(8)}-{tag}.html' , dir_url)

def check_url_scope(url, base=None):
    if not is_url_prefix(base or base_url, url, same_ok=True):
        return False
    for u in exclude_urls:
        if is_url_prefix(u, url, same_ok=True):
            return False
    return True


boring_path_segments = [
    'theme', 'thirdparty', 'third_party', 'third-party', 'vendor'
]
null_mut = ([],0,None,None)
extensions = [
    '~', '.save', '.sav', '.bak', '.tar.gz', '.gz', '.7z', '.cab',
    '.tgz', '.gzip', '.bzip2', '.inc', '.zip', '.rar', '.jar',
    '.java', '.class', '.properties', '.bak', '.bak1', '.bkp',
    '.back', '.backup', '.backup1', '.old', '.old1', '.$$$'
]
base_words = [
    'index', 'config', 'home', 'login', 'readme', 'README', 'robots'
]
base_extensions = [
    '.php', '.asp', '.html', '.txt', '.md', '', '/'
]
basic_wordlist = [
    a+b for a, b in itertools.product(base_words, base_extensions)
]

def deferred_normal_mutator_aux(track, parent_track, impl, mut):
    if track.is_interesting():
        parent_track.add_response_tag('acceptsall')
        dir_url, file_url = url_to_dir(parent_track.response.url)
        logging.info(
            f'base url {dir_url.geturl()} accepts all, skipping '
            f'mutator {mut}, consider using a filter or exclude path'
        )
        return []
    else:
        logging.debug(
            f'base url {parent_track.response.url} appears normal with request '
            f'{track.response.url}, continuing with mutator {mut}'
        )
        return impl()

def deferred_normal_mutator(parent_track, impl, mut):
    return lambda t, p=parent_track, i=impl, m=mut: \
        deferred_normal_mutator_aux(t, p, i, m)

def mut_subdirs(track):
    "enumerate parent directories"
    return (url_to_dirs(track.response.url), track.depth - 1, None, None)

def mut_relatedfiles(track):
    "add exts. to files looking for backups"
    dir_url, file_url = url_to_dir(track.response.url)
    if not file_url.path:
        return null_mut
    if 'index' in track.get_response_tags():
        raise Exception('internal error: bad index detection')
    if (parent := inscope_urls.get(dir_url.geturl())):
        if 'index' in parent.get_response_tags():
            return null_mut
    if track.is_media():
        logging.debug(
            f'skipping relatedfiles mutator on media file {track.response.url}'
        )
        return null_mut
    for bps in boring_path_segments:
        if bps in track.response.url.lower():
            logging.debug(
                f'skipping relatedfiles mutator on {track.response.url}'
            )
            return null_mut
    return (
        [ url_random(dir_url, 'relatedfiles') ]
        , track.depth
        # avoid redirect loop as depth is non-decrementing
        , lambda req: req.status_code >= 200 and req.status_code < 300
        , deferred_normal_mutator(
            impl=lambda dir_url=dir_url, file_url=file_url.path: (
                [ url_normalise(f'%23{file_url}%23', dir_url) ] +
                [ url_normalise(file_url + e, dir_url) for e in extensions ]
            ),
            parent_track=track,
            mut='relatedfiles'
       )
    )

def mut_commonfiles(track):
    "use wordlist in each directory"
    if 'index' in track.get_response_tags():
        return null_mut
    dir_url, file_url = url_to_dir(track.response.url)
    if file_url.path:
        return null_mut
    if (
            (parent := inscope_urls.get(dir_url.geturl())) and
            'index' in parent.get_response_tags()
    ):
        return null_mut
    if 'commonfiles' in args.mutator_wordlist:
        words = args.mutator_wordlist['commonfiles']
    else:
        logging.info('commonfiles mutator enabled without wordlist')
        words = basic_wordlist
    for bps in boring_path_segments:
        if bps in track.response.url.lower():
            logging.debug(
                f'skipping commonfiles mutator on {track.response.url}'
            )
            return null_mut
    return (
        [ url_random(dir_url, 'commonfiles') ],
        track.depth - 1,
        lambda req: req.status_code >= 200 and req.status_code < 300,
        deferred_normal_mutator(
            impl=lambda dir_url=dir_url: [
                url_normalise(quote(f.lstrip('/').strip()), dir_url)
                for f in words
            ],
            parent_track=track,
            mut='commonfiles'
        )
    )


def deferred_mut_autoexclude(track, parent_track):
    global exclude_urls, inscope_urls
    if track.is_interesting():
        dir_url, file_url = url_to_dir(parent_track.response.url)
        # try to tag parent directory, otherwise tag originator url
        if (dir_url := dir_url.geturl()) in inscope_urls:
            inscope_urls[dir_url].add_response_tag('acceptsall')
        else:
            parent_track.add_response_tag('acceptsall')
        if dir_url not in exclude_urls:
            logging.warning(
                f'Autoexclude: {dir_url} accepts all, removing from scope. '
                f'Consider using a filter to tune detection.'
            )
            exclude_urls[dir_url] = True
    return []

def mut_autoexclude(track):
    "add acceptall urls to externals"
    dir_url, file_url = url_to_dir(track.response.url)
    return (
        [ url_random(dir_url, 'autoexclude') ]
        , track.depth
        , lambda req: req.status_code >= 200 and req.status_code < 300
        , lambda t, p=track: deferred_mut_autoexclude(t, p)
    )

all_mutators = [
    obj for name,obj in inspect.getmembers(sys.modules[__name__])
    if inspect.isfunction(obj) and name.startswith('mut_')
]

def mutator(x):
    for f in all_mutators:
        if x == f.__name__[4:]:
            return f
    else:
        raise Exception(f'Mutator {x} not found')

def mutator_file(x):
    try:
        mut, fn = x.split(':',1)
    except:
        raise Exception('Mutator wordlist should be: "mutator:/path/to/file"')
    for f in all_mutators:
        if mut == f.__name__[4:]:
            break
    else:
        raise Exception(f'Mutator {mut} not found')
    return (mut, list(
        filter(
            lambda x: x and not x.startswith('#'),
            map(
                lambda y: y.rstrip('\n\r'),
                open(fn,'r').readlines()
            )
        )
    ))


start_time = time.monotonic()
window_start_time = start_time
window_start_requests = 0
finished_requests = 0
abort = False

def main():
    global args, abort, inscope_urls, outscope_urls, exclude_urls, base_url

    def header(x):
        name, value = x.split(': ', 1)
        return (name, value)

    parser = argparse.ArgumentParser(
        description='Simple Spider.'
    )
    parser.add_argument(
        'url',
        metavar='BASE_URL',
        type=urllib.parse.urlsplit,
        help='Base url to start spidering from (limits scope).'
    )
    parser.add_argument(
        'start_paths',
        metavar='START_PATH',
        nargs='*',
        type=urllib.parse.urlsplit,
        help='Paths, relative from BASE_URL to start spidering from.'
    )
    parser.add_argument(
        '--exclude-path','-e',
        dest='exclude_paths',
        metavar='EXCL_PATH',
        type=urllib.parse.urlsplit,
        action='append',
        default=[],
        help='Paths, relative from BASE_URL to prune.'
    )
    parser.add_argument(
        '--target-ip','-t',
        metavar='IP',
        dest='target',
        type=lambda x: x.split(':', 1) if ':' in x  else (x, 80),
        help='Redirect connections to given "host:port" combo.'
    )
    parser.add_argument(
        '--depth', '-d',
        metavar='NUM',
        type=int,
        default=5,
        help='Maximum number of links to follow from base url. Default 5.'
    )
    parser.add_argument(
        '--header', '-H',
        dest='headers',
        action='append',
        default=[],
        type=header,
        help='"Header: value" pairs to add to requests.'
    )
    parser.add_argument(
        '--verbose','-v',
        dest='debug',
        action='count',
        default=0,
        help='Enable detailed logging, give twice for full debug.'
    )
    parser.add_argument(
        '--log-file',
        dest='logfile',
        help='File to log to, default stderr'
    )
    parser.add_argument(
        '--hide-external', '-he',
        dest='show_external',
        action='store_false',
        help='Do not list urls outside of base url.'
    )
    parser.add_argument(
        '--hide-media', '-hm',
        dest='hide_media',
        action='store_true',
        help='Do not list urls with media mime type (detected by libmagic).'
    )
    parser.add_argument(
        '--filter-regex', '-fr',
        metavar='REGEX',
        dest='filter_regex',
        type=lambda x: re.compile(x.encode('utf8')),
        help='Regex for error pages, if not set, fallback to -fc.'
    )
    parser.add_argument(
        '--filter-status', '-fc',
        metavar='CODE',
        dest='filter_status',
        nargs='*',
        default=[404],
        type=int,
        help=(
            'Status to filter (default: 404). no params: >=400 '
            '(or with -fr set does nothing).'
        )
    )
    parser.add_argument(
        '--filter-all-pages',
        dest='filter_all_pages',
        action='store_true',
        help='Apply filter to all pages (default: only guessed/fuzzed pages).'
    )
    parser.add_argument(
        '--mutators','-m',
        nargs='*',
        type=mutator,
        default=[
              mut_autoexclude
            , mut_subdirs
            , mut_relatedfiles
            , mut_commonfiles
        ],
        help='Fuzzers to apply, (default: {}). available: {}'.format(
            'subdirs, relatedfiles',
            ', '.join([
                f'{f.__name__[4:]} ({f.__doc__})' for f in all_mutators
            ])
        )
    )
    parser.add_argument(
        '--mutator-wordlist','-wl',
        dest='mutator_wordlist',
        metavar='MUT:FILE',
        type=mutator_file,
        action='append',
        default=[],
        help='Wordlist used by mutator: "mutator:filename".'
    )
    parser.add_argument(
        '--threads',
        metavar='NUM',
        type=int,
        default=10,
        help='Number of threads (default: 10).'
    )
    parser.add_argument(
        '--show-backlinks',
        dest='back_links',
        action='store_true',
        help='For links not guessed, show source page.'
    )

    args = parser.parse_args()
    args.mutator_wordlist = dict(args.mutator_wordlist)
    logging.basicConfig(
        filename=args.logfile,
        format='[%(levelname)s] %(message)s',
        level=(3 - min(args.debug,2)) * 10
    )

    if not args.url.scheme:
        raise Exception('Base URL requires scheme to be specified (http/https)')

    base_url, start_url = url_to_dir(args.url)
    start_url = {urljoin(base_url.geturl(), start_url.geturl())}

    print(f'[*] base url: {base_url.geturl()}')

    for path in args.exclude_paths:
        if is_url_prefix(base_url, (url := url_normalise(path, base_url))):
            exclude_urls[url.geturl()] = False
        else:
            logging.warning(f'out of scope exclude path {url.geturl()}')

    for path in args.start_paths:
        if check_url_scope((url := url_normalise(path, base_url))):
            start_url.add(url.geturl())
        else:
            logging.warning(f'out of scope start path {url.geturl()}')


    for m in args.mutators:
        logging.info(f'enabled mutator {m.__name__}')

    for url in start_url:
        print(f'[*] start url: {url}')
        inscope_urls[url] = RequestTrack(args.depth)

    def enqueue(
            executor,
            parent_url,
            url,
            depth,
            guess=False,
            check=None,
            method=None,
            params=None,
            tag_msg=None,
            tags=set(),
            callback=None,
            **kw
    ):
        if type(url) != str:
            url = url.geturl()
        waspending = False
        if (wasnotpresent := url not in inscope_urls):
            inscope_urls[url] = RequestTrack(
                depth,
                guess,
                check,
                tags,
                callback
            )
        elif (waspending := inscope_urls[url].is_pending()):
            inscope_urls[url].depth = depth
        inscope_urls[url].guess &= guess
        inscope_urls[url].check = check if inscope_urls[url].guess else None
        inscope_urls[url].add_form(method, params)
        inscope_urls[url].tags &= tags
        if not inscope_urls[url].is_pending() and (wasnotpresent or waspending):
            logging.debug(
                f'enqueing {url} from {parent_url} at depth {depth}'
                f'{" by " + tag_msg if tag_msg else ""}'
            )
            return { executor.submit(load_url, url) }
        elif inscope_urls[url].is_pending():
            logging.debug(f'max depth reached for {url} from {parent_url}')
        return set()

    def enqueue_all(urls, **kw):
        if (to_enqueue := [
                enqueue(url=u, **kw) for u in filter(check_url_scope, urls)
        ]):
            return set.union(*to_enqueue)
        return set()

    def process_result(result, executor):
        global finished_requests
        global window_start_time
        global window_start_requests
        global start_time
        finished_requests +=+ 1
        if (window_next_time := window_start_time + 60) <= time.monotonic():
            print(
                f'[*] completed {finished_requests} requests, avg req/s:'
                f'{int(finished_requests / (time.monotonic() - start_time)):4}'
                f' req/s:'
                f'{int((finished_requests - window_start_requests) / 60):4}'
            )
            window_start_time = window_next_time
            window_start_requests = finished_requests
        (track := inscope_urls[result.url]).set_response(result)
        if (pack := track.callback()) or type(pack) == set:
            del inscope_urls[result.url]
            return pack
        if track.is_interesting():
            logging.info(f'found url {result.url} {result.status_code}')
        futures = set()
        for r in result.linked_resources:
            link = url_normalise(
                r['link'],
                url_to_dir(result.url)[0]
            )
            r['link_normalised'] = (link_norm := link.geturl())
            if check_url_scope(link):
                futures |= enqueue(
                    executor,
                    result.url,
                    link,
                    track.depth - 1,
                    **r
                )
            elif link_norm != base_url.geturl():
                if link_norm not in outscope_urls:
                    outscope_urls[link_norm] = FormRegistry()
                if r.get('method'):
                    outscope_urls[link_norm].add_form(
                        r.get('method'),
                        r.get('params')
                    )
        if not track.is_interesting():
            return futures
        # iterate over mutators and add new urls to spider
        for mut in args.mutators:
            if mut.__name__ in track.tags:
                # break out of branches with just mutators
                continue
            urls, depth, check, hook = mut(track)
            base_args={
                'executor': executor,
                'parent_url': result.url,
                'depth': depth,
                'guess': True,
                'check': check,
                'tag_msg': f'mutator {mut.__name__}',
                'tags': {mut.__name__} | track.tags,
            }
            if hook:
                hook = lambda track, hook=hook, kw=base_args : enqueue_all(
                    urls=hook(track), **kw
                )
            futures |= enqueue_all(
                urls=urls,
                callback=hook,
                **base_args
            )
        return futures

    def sigint(*a):
        global abort
        abort = True
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        print('\n[!] ctrl-c received, waiting for connections to close')
    signal.signal(signal.SIGINT, sigint)

    def failed(executor, error, url):
        track = inscope_urls[url]
        logging.debug(f'Error while loading {failed_url}')
        for l in traceback.format_exception(
                type(track.last_error),
                track.last_error,
                track.last_error.__traceback__
        ):
            for m in l.rstrip('\n').split('\n'):
                logging.debug(m)
        if not track.tries_left or error not in ['timeout']:
            if error in ['outofscope']:
                if url not in outscope_urls:
                    if not track.guess:
                        outscope_urls[url] = track
                else:
                    outscope_urls[url].form |= track.form
                del inscope_urls[url]
            else:
                logging.warning(
                    f'{error} while fetching {url}, dropping request'
                )
            return set()
        logging.debug(f'retrying {url}')
        return { executor.submit(load_url, url) }

    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        waiting = { exe.submit(load_url, u) for u in inscope_urls }
        while waiting and not abort:
            done, waiting = wait(
                waiting,
                timeout=60,
                return_when=FIRST_COMPLETED
            )
            for future in done:
                try:
                    result = future.result()
                except SpiderException as e:
                    original_error = e.__context__
                    failed_url = e.args[0]
                    inscope_urls[failed_url].set_error(original_error)
                    # handle non-fatal errors
                    if type(original_error) == URLError:
                        if type(original_error.__context__) == OSError:
                            os_error = original_error.__context__
                            if os_error.errno == errno.ETIMEDOUT:
                                waiting |= failed(exe, 'timeout', failed_url)
                                continue
                    elif type(original_error) == http.client.InvalidURL:
                        waiting |= failed(exe, 'invalid-url', failed_url)
                        continue
                    elif type(original_error) == socket.timeout:
                        waiting |= failed(exe, 'timeout', failed_url)
                        continue
                    elif type(original_error) == OutOfScope:
                        waiting |= failed(exe, 'outofscope', failed_url)
                        continue
                    logging.critical(
                        'Quitting due to un-handled error while processing: '
                        f'{failed_url},  '
                        f'{type(original_error).__name__}: {original_error}'
                    )
                    logging.error(f'Error while loading {failed_url}')
                    for l in traceback.format_exception(
                            type(original_error),
                            original_error,
                            original_error.__traceback__
                    ):
                        for m in l.rstrip('\n').split('\n'):
                            logging.error(m)
                    abort = True
                    break
                except Exception as e:
                    logging.critical(
                        'Quitting due to un-handled error: '
                        f' {type(e).__name__}: {e}'
                    )
                    for l in traceback.format_exc().rstrip('\n').split('\n'):
                        logging.error(l)
                    abort = True
                    break
                else:
                    waiting |= process_result(result, exe)

    print('[*] URLs in scope:')
    ct_width = max(
        map(
            lambda x: len(x.response.content_type),
            filter(
                lambda x: not x.is_pending() and x.is_done(),
                inscope_urls.values()
            )
        ),
        default=0
    )
    format_annotation = lambda tag, text, colour: (
        f' {Style.BRIGHT}{colour}{tag}{Style.RESET_ALL}('
        f'{colour}{text}{Style.RESET_ALL})'
    )
    format_form = lambda *a: format_annotation(
        a[0], f'{Style.RESET_ALL}&{Fore.CYAN}'.join(a[1:]), Fore.CYAN
    )
    format_comment = lambda tag, text: format_annotation(tag, text, Fore.YELLOW)
    format_metadata = lambda a: format_annotation(
        'meta', f'{Style.RESET_ALL},{Fore.BLUE}'.join(a), Fore.BLUE
    )
    def show_backlinks(url):
        global inscope_urls, args
        if not args.back_links:
            return
        for j in inscope_urls:
            if  (
                    inscope_urls[j].is_pending() or
                    not inscope_urls[j].is_done()
            ):
                continue
            back_links = set()
            for link in inscope_urls[j].response.linked_resources:
                if link.get('link_normalised') == url:
                    back_links.add((
                        link["tag"],
                        j,
                        link.get('method'),
                        *link.get('params',[])
                    ))
            for bl in back_links:
                print(
                    f'    {Style.DIM}{bl[0]:<10}{bl[1]}'
                    f'{Style.RESET_ALL}',
                    end=''
                )
                if bl[0] == 'form':
                    print(format_form(*bl[2:]), end='')
                print()
    for k in sorted(inscope_urls):
        if not (track := inscope_urls[k]).is_interesting():
            continue
        if args.hide_media and track.is_media():
            continue
        resp = track.response
        sc = 0
        l = '?'
        ct = ''
        if not track.is_pending():
            sc = resp.status_code
            if (l := resp.content_length) == None:
                l = '???'
            ct = resp.content_type
        col = ''
        if sc >= 200:
            col = Fore.GREEN + Style.BRIGHT
        if sc >= 300:
            col = Fore.YELLOW + Style.BRIGHT
        if sc >= 400:
            col = Fore.RED + Style.BRIGHT
        if sc >= 500:
            col = Fore.BLUE + Style.BRIGHT
        if not sc:
            sc = '???'
        print(
            '  '
            f'[{col}{sc:0>3}{Style.RESET_ALL}] '
            f'[{l:·>8}] '
            f'[{ct:·<{ct_width}}] '
            f'{Fore.YELLOW}{"F" if track.guess else " "}{Style.RESET_ALL} '
            f'{k}', end=''
        )
        if not args.back_links:
            for f in track.form:
                print(format_form(*f), end='')
        if track.is_done():
            if resp.content_type != resp.detected_content_type:
                print(
                    format_comment('libmagic', resp.detected_content_type),
                    end=''
                )
            if (redirs := resp.get_resources('redirect')):
                for redir in redirs:
                    print(
                        format_comment('redirect', redir['link_normalised']),
                        end=''
                    )
            if (tags := track.get_response_tags()):
                print(format_metadata(tags), end='')
        print()
        if not track.guess:
            show_backlinks(k)

    if any(map(lambda x: x.is_pending(), inscope_urls.values())):
        logging.warning(
            'some urls were not fully spidered, try increasing depth'
            ' (--depth), if not shown they were guessed/fuzzed.')
        logging.debug('un-processed urls:')
        for u in filter(lambda x: inscope_urls[x].is_pending(), inscope_urls):
            logging.debug(f'  {u}')

    # cover items that error
    first = True
    for k in sorted(inscope_urls):
        if (
                (track := inscope_urls[k]).is_pending() or
                track.is_done() or
                track.guess
        ):
            continue
        if first:
            print('[*] URLs did not complete successfully:')
        first = False
        print(f'  {Fore.RED}{k}', end='')
        if track.last_error:
            print(f'    {Style.BRIGHT}{str(track.last_error).strip()}', end='')
        print(f'{Style.RESET_ALL}')
        show_backlinks(k)

    if args.show_external and outscope_urls:
        print('[*] URLs out of scope:')
        for k in sorted(set(outscope_urls).difference(inscope_urls)):
            auto = ''
            for u in exclude_urls:
                if is_url_prefix(u, k, same_ok=True):
                    if exclude_urls[u]:
                        auto = f'{Fore.YELLOW}A{Style.RESET_ALL}'
                        break
            print(f'  {auto: <1} {k}', end='')
            if outscope_urls[k].form:
                for f in outscope_urls[k].form:
                    print(format_form(*f), end='')
            print()
            show_backlinks(k)

if __name__ == '__main__':
    main()
