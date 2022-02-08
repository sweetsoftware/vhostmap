#!/usr/bin/env python3

import os
import ipaddress
import argparse
import re
import ssl
import asyncio

import validators
import aiohttp
import dns.resolver
import dns.reversename
import dns.asyncresolver
import dns.exception
import requests
requests.packages.urllib3.disable_warnings()
import OpenSSL
from bs4 import BeautifulSoup


class Host():
    """ Hosts have a single IP address and a set of hostnames. """
    def __init__(self, address, hostnames=set()):
        """ Create Host and associate any hostnames. """
        self.address = address
        self.hostnames = set()
        for hostname in hostnames:
            self.hostnames.add(hostname)


    def add_hostname(self, hostname):
        """ Add a new hostname to the Host. """
        if hostname not in self.hostnames:
            self.hostnames.add(hostname)

    
    def get_hostnames(self):
        """ Get the list of hostnames running on this Host. """
        return self.hostnames


    def __str__(self):
        """ Print in the host file format. """
        return self.address + " " + " ".join(self.hostnames)


class HostMapper():
    """ Finds and links Hosts to IPs and hostnames. """

    def __init__(self, targets_file, recursion_depth=2, max_concurrency=50, verbose=False, debug=False, output_dir=None, 
        http_port_list="medium", extra_http_ports=None, use_ext_apis=False, connection_timeout=5):
        # Exit program after X passes (avoid infinite loop out of scope)
        self.recursion_depth = recursion_depth
        # Timeout for socket and HTTP connections
        self.connection_timeout = connection_timeout
        # Stores known IP addresses
        self.ips = set()
        # Stores known hostnames
        self.hostnames = set()
        # IPs added to scope during current pass
        self.new_ips = set()
        # Hostnames added to scope during current pass
        self.new_hostnames = set()
        # Max concurrent I/O tasks
        self.max_concurrency = max_concurrency
        # If True then print verbose/debug messages
        self.verbose = verbose
        self.debug = debug
        # Stores valid urls
        self.urls = set()
        # Use external APIs ?
        self.use_ext_apis = use_ext_apis
        # Database of Hosts. Key is IP (string), value is of type Host
        self.DB = {}
        # Ports to scan for HTTP(S) services
        HTTP_PORTS = {
            "small": [80, 443],
            "medium": [80, 443, 8080, 8443, 8000],
            "large": [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888],
            "xlarge": [80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128,
                3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008,
                8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500,
                8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 9999, 12443, 16080, 18091, 
                18092, 20720, 28017]
        }
        self.http_ports = set(HTTP_PORTS[http_port_list])
        # Any extra HTTP port passed as argument
        if extra_http_ports:
            extra_ports_list = set()
            for item in extra_http_ports.split(","):
                if "-" in item:
                    start, end = item.split("-")
                    extra_ports_list = extra_ports_list.union(range(int(start), int(end) + 1))
                else:
                    extra_ports_list.add(int(item))
            self.http_ports = self.http_ports.union(extra_ports_list)
        # Directory to store output
        self.output_dir = output_dir
        # File to write output to
        self.log_file = None
        if output_dir:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            self.log_file = open(os.path.join(self.output_dir, "log.txt"), 'w')
        # Load targets
        self.targets_file = targets_file
        self.load_target_list(self.targets_file)
        # Configure DNS resolver
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8']
        self.resolver.lifetime = self.connection_timeout


    def log(self, message, log_type='debug'):
        """ Print debug message. """
        if log_type == 'debug' and self.debug or \
            log_type == 'verbose' and self.verbose:
            message = "[" + log_type + "] " + str(message)
            print(message)
            if self.log_file:
                self.log_file.write(message + "\n")


    def result_log(self, result_type, asset, result):
        """ Print result in the form [Type] <assetname> <associated result>. """
        message = "[" + str(result_type) + "] " + str(asset) + " " + str(result)
        print(message)
        if self.log_file:
            self.log_file.write(message + "\n")


    def update_ip_scope(self, cidr, from_hostname=None):
        """ Adds IP(s) to scope if not already known. """
        try:
            cidr = ipaddress.ip_network(cidr, strict=False)
            for ip in cidr:
                ip_str = str(ip)
                if ip_str not in self.ips:
                    self.log("Adding IP {} to {}".format(ip_str, from_hostname), 'verbose')
                    self.ips.add(ip_str)
                    self.new_ips.add(ip_str)
                # If no host associated with IP, create one and associate hostname if any
                if ip_str not in self.DB:
                    self.DB[ip_str] = Host(ip_str)
                host = self.DB[ip_str]
                if from_hostname and from_hostname not in host.get_hostnames():
                    self.log("Adding hostname {} to {}".format(from_hostname, ip_str), 'verbose')
                    host.add_hostname(from_hostname)
            return True
        except ValueError:
            # Invalid IP
            return False 


    def update_hostname_scope(self, hostname, from_ip=None):
        """ Add hostname to scope if not already known. """
        if hostname.endswith("."):
            hostname = hostname[:-1]
        # Ignore wildcards
        if "*." in hostname:
            return
        if validators.domain(hostname):
            if hostname not in self.hostnames:
                self.log("Adding hostname {} to {}".format(hostname, from_ip), 'verbose')
                self.new_hostnames.add(hostname)
                self.hostnames.add(hostname)
            if from_ip:
                # It is an IP (else it's a hostname source)
                if from_ip in self.DB:
                    if hostname not in self.DB[from_ip].get_hostnames():
                        self.DB[from_ip].add_hostname(hostname) 
            return True
        else:
            # Invalid hostname
            return False


    def update_scope(self, asset, src=None):
        """ Add hostname or ip/range to scope. """
        if not asset:
            return False
        if self.update_hostname_scope(asset, src):
            return True
        elif self.update_ip_scope(asset, src):
            return True
        self.log("Could parse asset into scope: " + asset)
        return False
    

    def parse_hostname_from_url(self, url):
        """ Extract hostname from a URL. """
        url = url.replace('http:', '')
        url = url.replace('https:', '')
        if '//' in url:
            url = url.split('//')[1]
        if '/' in url or ':' in url:
            url = url.split('/')[0].split(':')[0]
        return url

    
    def load_target_list(self, filename):
        """ Reads file with one target per line and loads it into scope. """
        with open(filename, 'r') as hfile:
            for line in hfile.read().splitlines():
                if not line:
                    continue
                self.update_scope(line)


    async def dns_query(self, record_type, name):
        """ Perform async DNS query and return answers. """
        answers = []
        try:
            answers = await self.resolver.resolve(name, record_type)
        except dns.resolver.NoAnswer:
            self.log(record_type + " for " + name + " : NO ANSWER")
        except dns.resolver.NXDOMAIN:
            self.log(record_type, "for", name, " : NXDOMAIN")
        except dns.resolver.NoNameservers:
            self.log(record_type, "for", name, " : Server did not reply")
        except dns.exception.Timeout:
            self.log(record_type, "for", name, " : Timed out")
        finally:
            return answers


    async def resolve_host_ips(self, hostname):
        """ Get A and AAAA records for an hostname.
        Associate hostname with found IPs.""" 
        ip_addresses = set()
        for record_type in ['A', 'AAAA']:
            for answer in await self.dns_query(record_type, hostname):
                self.result_log(record_type, hostname, str(answer))
                ip_addresses.add(str(answer))
        for ip in ip_addresses :
            # Create new Host if does not exist
            self.update_scope(ip, hostname)


    async def reverse_dns_names(self, ip):
        """ Get PTR record for an IP. """
        ptrs = set()
        rev_dns = dns.reversename.from_address(ip)
        for answer in await self.dns_query("PTR", rev_dns):
            ptrs.add(str(answer))
        for ptr in ptrs:
            self.update_scope(ptr, ip)

    
    def parse_http_headers(self, headers, ip, url):
        """ Extract hosts from various HTTP headers. """
        if 'location' in headers:
            redirect_url = headers['location']
            if ip not in redirect_url:
                if "//" in redirect_url:
                    asset = self.parse_hostname_from_url(redirect_url)
                    self.result_log("LocationHeader", url, asset)
                    self.update_scope(asset, ip)
        if 'access-control-allow-origin' in headers:
            allow_origin = headers['access-control-allow-origin']
            if allow_origin not in ['*', 'null']:
                self.result_log("access-control-allow-origin", allow_origin)
                self.new_hostnames.add(allow_origin)
        if 'content-security-policy' in headers or 'csp' in headers:
            csp =  headers['content-security-policy'] if 'content-security-policy' in headers else headers['csp']
            csp = csp.replace(";", " ")
            for word in csp.split(" "):
                csp_asset = self.parse_hostname_from_url(word)
                self.update_scope(csp_asset, ip)


    def parse_javascript_redirects(self, html, ip, url):
        """ Find JavaScript redirects in HTML code and parse hostnames. """
        for parsed_url in re.findall(r'\.location[\s]*=[\s]*[\'\"](.+?)[\'\"]', html):
            if ip not in parsed_url:
                asset = self.parse_hostname_from_url(parsed_url)
                self.result_log("JavaScriptRedirect", url, asset)
                self.update_scope(asset, ip)
    

    async def query_rapiddns(self, asset, api):
        """ Query rapiddns API to find vhosts or subdomains. """
        if api not in ['vhosts', 'subdomains']:
            self.log("Invalid Rapiddns api " + api)
            return
        if api == 'vhosts':
            url = "https://rapiddns.io/sameip/%s#result" % asset
        else:
            url = "https://rapiddns.io/s/%s#result" % asset
        try:
            session = aiohttp.ClientSession()
            resp = await asyncio.wait_for(session.get(url), timeout=self.connection_timeout)
            html = await asyncio.wait_for(resp.text(), timeout=self.connection_timeout)
            soup = BeautifulSoup(html, 'html.parser')
            results_table = soup.table
            for item in results_table.find_all('tr')[1:]:
                result = item.td.string
                self.result_log("Rapiddns", asset, result)
                self.update_scope(result, asset)
        except asyncio.TimeoutError:
            self.log("Timeout when querying Rapiddns for " + asset)
        except Exception as exc:
            self.log("Error when querying Rapiddns " + url + " : " + str(exc))
        finally:
            await session.close()


    async def scan_port(self, ip, port):
        """ Checks if TCP port is open.
        Returns port number if connection succeeded.
        Returns None if connection timed out or port is closed.
        """
        try:
            connection = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(connection, timeout=self.connection_timeout)
            self.log("TCP Open : " + ip + ":" + str(port))
            writer.close()
            return port
        except OSError as exc:
            self.log("TCP Closed : " + ip + ":" + str(port))
            return None
        except asyncio.TimeoutError:
            self.log("TCP Timeout : " + ip + ":" + str(port))
            return None


    async def scan_http_services(self, ip):
        """ Grab info from HTTP services. """
        # Async scan TCP ports
        ports_to_scan = self.http_ports
        open_ports = set()
        tasks = []
        for port in ports_to_scan:
            tasks.append(self.scan_port(ip, port))
        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                open_ports.add(result)
        if not open_ports:
            return

        # Scan HTTP services on open ports
        hostnames = set()
        # Try to connect with HTTP
        for port in self.http_ports:
            if port not in open_ports:
                continue
            try:
                url = "http://" + ip + ":" + str(port)
                session = aiohttp.ClientSession()
                resp = await asyncio.wait_for(session.get(url, allow_redirects=False), timeout=self.connection_timeout)
                # May be HTTPS, skip
                if resp.status == 400:
                    continue
                self.result_log("HTTPService", ip, url)
                self.urls.add(url)
                open_ports.remove(port) # avoid requesting https since the service is http
                self.parse_http_headers(resp.headers, ip, url)
                html = await asyncio.wait_for(resp.text(), timeout=self.connection_timeout)
                self.parse_javascript_redirects(html, ip, url)
            except asyncio.TimeoutError:
                self.log("HTTP Timeout : " + url)
            except Exception as exc:
                self.log("Error when scanning HTTP service " + url + " : " + str(exc))
            finally:
                await session.close()
        # Try to connect with HTTPS
        for port in self.http_ports:
            if port not in open_ports:
                continue
            try:
                url = "https://" + ip + ":" + str(port)
                session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
                resp = await asyncio.wait_for(session.get(url, allow_redirects=False), timeout=self.connection_timeout)
                self.result_log("HTTPService", ip, url)
                self.urls.add(url)
                self.parse_http_headers(resp.headers, ip, url)
                html = await asyncio.wait_for(resp.text(), timeout=self.connection_timeout)
                self.parse_javascript_redirects(html, ip, url)
                # Extract hostnames from certificate
                try:
                    cert = ssl.get_server_certificate((ip, port))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    cert_hostname = x509.get_subject().CN
                    if cert_hostname:
                        hostnames.add(cert_hostname)
                        self.result_log("CertCN", url, cert_hostname)
                    alt_names = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if "subjectAltName" in str(ext.get_short_name()):
                            content = str(ext)
                            for alt_name in content.split(","):
                                alt_names.append(alt_name.strip()[4:])
                    for i in alt_names:
                        self.result_log("CertAltName", url, i)
                        hostnames.add(i)
                except Exception as exc:
                    self.log("Error parsing certificate for " + url + ": " + str(exc))
            except asyncio.TimeoutError:
                self.log("HTTP Timeout : " + url)
            except Exception as exc:
                self.log("Error when scanning HTTP service " + url + " : "  + str(exc))
            finally:
                await session.close()
        for hostname in hostnames:
            self.update_scope(hostname, ip)


    async def run(self):
        """ Main loop looking for new IPs and hostnames. """
        ips_to_process = set(self.ips)
        hostnames_to_process = set(self.hostnames)
        self.new_ips = set()
        self.new_hostnames = set()
        npass = 1
        
        while True:
            print("#" * 80)
            print("# PASS", npass)
            print("# IP to process:", len(ips_to_process))
            print("# Hostnames to process:", len(hostnames_to_process))
            print("#" * 80)
            tasks = []
            # Find new assets from hostnames
            for hostname in hostnames_to_process:
                tasks.append(self.resolve_host_ips(hostname))
                if self.use_ext_apis:
                    tasks.append(self.query_rapiddns(hostname, 'subdomains'))
            # Find new assets from IP address
            for ip in ips_to_process:
                tasks.append(self.reverse_dns_names(ip))
                tasks.append(self.scan_http_services(ip))
                if self.use_ext_apis:
                    tasks.append(self.query_rapiddns(ip, 'vhosts'))
            # Run tasks in chunks
            task_splits = int(len(tasks) / self.max_concurrency)
            if len(tasks) % self.max_concurrency != 0:
                task_splits += 1
            for i in range(task_splits):
                # Wait for this pass to complete
                if i == task_splits - 1:
                    todo = tasks [ i * self.max_concurrency:]
                else:
                    todo = tasks[ i * self.max_concurrency : i * self.max_concurrency + self.max_concurrency]
                self.log(f"Tasks Done : [{i}/{task_splits}]", 'verbose')
                await asyncio.gather(*todo)

            #Loop until no new IP / hostname found or max recursion
            if not self.new_ips and not self.new_hostnames or npass == self.recursion_depth:
                break
            npass += 1

            # Queue newfound assets to be processed during next pass
            ips_to_process = set(self.new_ips)
            hostnames_to_process = set(self.new_hostnames)

            # Reset the newfound assets lists
            self.new_ips = set()
            self.new_hostnames = set()


    def save_results(self):
        """ Output results to files. """
        print("\nRESULTS\n=========")
        for host in self.DB.values():
            print(host)
        if not self.output_dir:
            return False
        if self.log_file:
            self.log_file.close()
        with open(os.path.join(self.output_dir, "all-hostnames.txt"), "w") as f:
            f.write("\n".join(self.hostnames))
        with open(os.path.join(self.output_dir, "all-ips.txt"), "w") as f:
            f.write("\n".join(self.ips))
        with open(os.path.join(self.output_dir, "all-urls.txt"), "w") as f:
            f.write("\n".join(self.urls))
        with open(os.path.join(self.output_dir, "hosts.txt"), "w") as f:
            for host in self.DB.values():
                if host.get_hostnames():
                    f.write(str(host) + "\n")
        return True


async def main():
    parser = argparse.ArgumentParser(description='Enumerates targets to find related hostnames and IPs.')

    group1 = parser.add_argument_group('Main options')
    group1.add_argument('-t', '--targets-file', help="File with ips and dns names (one per line)", required=True)
    group1.add_argument('-o', '--output', help="Store output to this folder")
    group1.add_argument("--apis", action='store_true', help="Use external APIs")

    group2 = parser.add_argument_group('Extra options')
    group2.add_argument('-r', '--recursion-depth', type=int, help="Max recursion depth (default 2)", default=2)
    group2.add_argument('-c', '--max-concurrency', type=int, help="Max concurrent tasks (default 50)", default=50)
    group2.add_argument('-v', '--verbose', action='store_true', help="Print verbose output")
    group2.add_argument('-d', '--debug', action='store_true', help="Print debug output")
    group2.add_argument('-p', '--ports', choices=["small", "medium", "large", "xlarge"],
        help="Port list to use for HTTP service discovery (default medium)", default="medium")
    group2.add_argument("--extra-ports", help="Additional comma separated HTTP ports to scan")
    group2.add_argument("--req-timeout", type=int, default=5, help="Connection timeout for sockets, HTTP and DNS requests, in seconds (default 5)")
    args = parser.parse_args()

    hostmapper = HostMapper(
        targets_file=args.targets_file,
        recursion_depth=args.recursion_depth,
        max_concurrency=args.max_concurrency,
        verbose=args.verbose,
        debug=args.debug,
        output_dir=args.output,
        http_port_list=args.ports,
        extra_http_ports=args.extra_ports,
        use_ext_apis=args.apis,
        connection_timeout=args.req_timeout)
    await hostmapper.run()
    hostmapper.save_results()


if __name__ == "__main__":
    try:
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except Exception as exc:
        import traceback
        traceback.print_exc()
