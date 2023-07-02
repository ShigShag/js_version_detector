import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from tabulate import tabulate
import argparse
import threading
import tldextract
import hashlib

non_html_extensions = ('.jpg', '.png', '.gif', '.pdf', '.doc', '.docx',
                       '.xls', '.xlsx', '.ppt', '.pptx', '.mp4', '.mp3', '.json', '.txt', '.css', '.ico')


def get_version_from_file_content(content):
    patterns = [
        (r"VERSION: '(\d+\.\d+\.\d+)'", 1),
        (r'(//|/\*|\*).*([0-9]+\.[0-9]+\.[0-9]+)', 2),  # n.n.n
        (r'(//|/\*).*v([0-9]+\.[0-9]+\.[0-9]+)', 2),  # vn.n.n
        (r'(//|/\*).\bversion\b.*?(\d+(?:\.\d+)*)', 2),  # version n.n.n
        (r'(//|/\*).*([0-9]+\.[0-9]+)', 2),  # n.n
    ]

    # Get the first 10% of the content
    slice_index = int(len(content) * 0.10)
    content_slice = content[:slice_index]

    for pattern, group in patterns:
        match = re.search(pattern, content_slice, re.IGNORECASE)
        if match:
            return match.group(group)  # Return the matched version number

    return None  # Return None if no match is found


def get_version_from_file_name(file_name):
    patterns = [
        (r'ver=([0-9.]+)', 1),  # ver=n or ver=n.n.n
        (r'ver=(\d+)$', 1),  # ver=n at the end of the string
        (r'ver=([^ ]+)', 1),  # ver=n at the end of the string
        (r'v=(\d+)$', 1),  # v=n at the end of the string
        (r'v=([^ ]+)', 1),  # v=n at the end of the string
        (r'v(\d+\.\d+\.\d+)', 1),  # v.n.n.n
        (r'(\d+\.\d+\.\d+)', 1)  # n.n.n
    ]

    for pattern, group in patterns:
        match = re.search(pattern, file_name, re.IGNORECASE)
        if match:
            return match.group(group)  # Return the matched version number

    return None  # Return None if no match is found


class Parse_Url:

    def __init__(self, url, recursion, verbose, proxy, user_agent, timeout) -> None:

        self.url = url

        parsed = urlparse(self.url)
        extract_result = tldextract.extract(parsed.netloc)
        self.root_domain = f"{extract_result.domain}.{extract_result.suffix}"

        # Already visited pages
        self.visited_pages = set()
        self.visited_pages_lock = threading.Lock()

        # Already parsed JavaScript libraries
        self.libraries = list()
        self.libraries_lock = threading.Lock()

        # For recursion to prevent duplicate findings
        self.seen_hashes = set()

        # Proxies
        self.proxies = {'https': proxy,
                        'http': proxy}

        # Headers
        self.headers = {
            'User-Agent': user_agent}

        # Timeout
        self.timeout = timeout

        if self._get_js_libraries(self.url, recursive_depth=recursion, verbose=verbose) is True:
            self._print_libraries()

    def _check_for_seen_hash(self, java_script_content):

        hash = hashlib.md5(java_script_content.encode()).hexdigest()
        hash_seen = False

        self.libraries_lock.acquire()
        try:
            hash_seen = hash in self.seen_hashes

            if not hash_seen:
                self.seen_hashes.add(hash)
        finally:
            self.libraries_lock.release()

        return hash_seen

    def _print_libraries(self):

        libraries_found = len(self.libraries)

        # Count the number of versions detected
        versions_detected = 0

        for library in self.libraries:
            if 'Not found' not in library[1]:
                versions_detected += 1

        # Print the summary line
        summary = f"Scanning results for {self.url}"
        summary_line = '-' * len(summary)
        print(f"\n{summary_line}\n{summary}\n{summary_line}")

        table = tabulate([["JavaScript files found:", libraries_found], [
                         "Versions detected:", versions_detected]], ["", ""], tablefmt="plain")
        print(table + "\n")

        # Print the table
        table = tabulate(self.libraries, headers=['File', 'Version', 'URL'])
        print(table)

    def _get_js_libraries(self, url, verbose=False, recursive_depth=0):

        if verbose:
            print("[!] Scanning " + url)

        try:
            response = requests.get(
                self.url, proxies=self.proxies, timeout=self.timeout, headers=self.headers)

        except Exception as error:
            print(error)
            return False

        # Find script Tags
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.findAll(lambda tag: tag.name == 'script' and (
            tag.get('type') in [None, 'text/javascript', 'application/javascript']))

        for tag in script_tags:

            src = tag.get('src')

            # Check if tag has 'src' attribute and points to a .js file
            if src and '.js' in src:

                library_url = urljoin(self.url, src)

                # Check if file name contains version pattern
                version_from_file_name = get_version_from_file_name(src)
                if version_from_file_name:
                    version = version_from_file_name
                else:

                    try:
                        js_file_response = requests.get(
                            library_url, proxies=self.proxies, timeout=self.timeout, headers=self.headers)
                    except requests.exceptions.RequestException:
                        version = None

                    js_file_content = js_file_response.text

                    # Check if java script content was already discovered
                    if self._check_for_seen_hash(js_file_content) is True:
                        continue

                    version = get_version_from_file_content(
                        js_file_content)

                if version is None:
                    version = 'Not found'

                new_entry = [urlparse(src).path.split(
                    '/')[-1], version, library_url]

            # If inline JavaScript
            else:

                inline_js_code = tag.text

                if inline_js_code is None:
                    continue

                version = get_version_from_file_content(inline_js_code)

                if version is None:
                    version = 'Not found - embedded'

                # Check if java script content was already discovered
                if self._check_for_seen_hash(inline_js_code) is True:
                    continue

                new_entry = [
                    f'Inline script at line {tag.sourceline}', version, url]

            # Check if entry already exists
            if new_entry not in self.libraries:
                self.libraries.append(new_entry)

                if verbose:
                    print(
                        f'[+] Detected {new_entry[0]} in version {new_entry[1]}')

        self.visited_pages_lock.acquire()
        try:
            self.visited_pages.add(url)
        finally:
            self.visited_pages_lock.release()

        if recursive_depth > 0:

            # Find all links on the page and recursively crawl them
            links = soup.find_all(href=True)
            for link in links:
                next_url = urljoin(url, link['href'])

                parsed = urlparse(next_url)
                extract_result = tldextract.extract(parsed.netloc)
                root_domain = f"{extract_result.domain}.{extract_result.suffix}"

                # Check if link endswith specific sign and if the second_level_domain remains the same
                if next_url.endswith(non_html_extensions) or root_domain != self.root_domain:
                    continue

                self.visited_pages_lock.acquire()
                try:
                    page_already_visited = next_url in self.visited_pages
                finally:
                    self.visited_pages_lock.release()

                if page_already_visited is False:
                    self._get_js_libraries(
                        next_url, verbose, recursive_depth - 1)

        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--url', '-u', help='URL of the website to analyze', required=True)
    parser.add_argument(
        '--recursion', '-r', help='Recursive level of links on the site', default=0, type=int
    )
    parser.add_argument(
        '--verbose', '-v', help='Displays realtime data / activities', action='store_true'
    )
    parser.add_argument(
        '--proxy', '-p', help='Enter a proxy address e.g. socks5h://localhost:9050 for TOR', default=None
    )
    parser.add_argument(
        '--user-agent', '-a', help='Custom user agent', default=None
    )
    parser.add_argument(
        '--timeout', '-t', help='Timeout in Seconds -> Default 10 seconds', default=10, type=int
    )
    args = parser.parse_args()

    url = args.url
    recursion_level = args.recursion
    verbose = args.verbose
    proxy = args.proxy
    user_agent = args.user_agent
    timeout = args.timeout

    Parse_Url(url, recursion_level, verbose, proxy, user_agent, timeout)


if __name__ == '__main__':
    main()
