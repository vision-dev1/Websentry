import http.server
import socketserver
import webbrowser
import json
import threading
import os
import ssl
import datetime
import socket
from urllib.parse import urlparse

dependencies_available = True
try:
    import requests
except ImportError:
    dependencies_available = False
    print("WARNING: Required dependency 'requests' not found.")
    print("Please install it using: pip install requests")
    print("Or on Kali Linux: sudo apt install python3-requests")
    print("")
    class MockRequestsResponse:
        def __init__(self, status_code=200, text="", headers=None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.cookies = []
            self.url = "https://example.com"
    
    class MockRequests:
        def get(self, url, **kwargs):
            return MockRequestsResponse()
    
    requests = MockRequests()

class VulnerabilityScanner:
    def __init__(self):
        self.results = {}
        self.scan_log = []
    
    def check_http_to_https(self, url):
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                return {"status": "secure", "message": "Already using HTTPS"}
            
            http_url = f"http://{parsed.netloc}{parsed.path}"
            response = requests.get(http_url, timeout=10, allow_redirects=True)
            
            if response.url.startswith('https'):
                return {"status": "redirects", "message": "HTTP properly redirects to HTTPS"}
            else:
                return {"status": "insecure", "message": "HTTP does not redirect to HTTPS"}
        except Exception as e:
            return {"status": "error", "message": f"Error checking HTTP to HTTPS: {str(e)}"}
    
    def check_ssl_certificate(self, url):
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return {"status": "not_applicable", "message": "Not using HTTPS"}
            
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert and 'notAfter' in cert:
                        not_after_str = cert['notAfter']
                        if isinstance(not_after_str, str):
                            not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (not_after - datetime.datetime.utcnow()).days
                            
                            if days_until_expiry < 0:
                                return {"status": "expired", "message": f"Certificate expired {abs(days_until_expiry)} days ago"}
                            elif days_until_expiry < 30:
                                return {"status": "expiring_soon", "message": f"Certificate expires in {days_until_expiry} days"}
                            else:
                                return {"status": "valid", "message": f"Certificate valid for {days_until_expiry} more days"}
                        else:
                            return {"status": "info", "message": "Certificate information unavailable"}
                    else:
                        return {"status": "info", "message": "Certificate information unavailable"}
        except Exception as e:
            return {"status": "error", "message": f"Error checking SSL certificate: {str(e)}"}
    
    def check_security_headers(self, url):
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-XSS-Protection': headers.get('X-XSS-Protection')
            }
            
            missing_headers = [header for header, value in security_headers.items() if not value]
            present_headers = {header: value for header, value in security_headers.items() if value}
            
            if not missing_headers:
                return {"status": "good", "message": "All key security headers present", "details": present_headers}
            else:
                return {"status": "warning", "message": f"Missing headers: {', '.join(missing_headers)}", "details": present_headers}
        except Exception as e:
            return {"status": "error", "message": f"Error checking security headers: {str(e)}"}
    
    def check_cookie_flags(self, url):
        try:
            response = requests.get(url, timeout=10)
            cookies = response.cookies
            
            if not cookies:
                return {"status": "info", "message": "No cookies found"}
            
            cookie_issues = []
            for cookie in cookies:
                issues = []
                if not getattr(cookie, 'secure', False):
                    issues.append("Missing Secure flag")
                
                if not getattr(cookie, 'httponly', False):
                    issues.append("Missing HttpOnly flag")
                
                if not getattr(cookie, 'samesite', None):
                    issues.append("Missing SameSite attribute")
                
                if issues:
                    cookie_issues.append(f"{cookie.name}: {', '.join(issues)}")
            
            if not cookie_issues:
                return {"status": "good", "message": "All cookies have proper security flags"}
            else:
                return {"status": "warning", "message": "Cookie security issues found", "details": cookie_issues}
        except Exception as e:
            return {"status": "error", "message": f"Error checking cookie flags: {str(e)}"}
    
    def check_robots_txt(self, url):
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            robots_url = f"{base_url}/robots.txt"
            robots_response = requests.get(robots_url, timeout=10)
            robots_exists = robots_response.status_code == 200
            
            sitemap_found = False
            if robots_exists:
                if 'sitemap:' in robots_response.text.lower():
                    sitemap_found = True
            
            sitemap_paths = ['/sitemap.xml', '/sitemap_index.xml']
            sitemap_exists = False
            for path in sitemap_paths:
                sitemap_url = f"{base_url}{path}"
                sitemap_response = requests.get(sitemap_url, timeout=10)
                if sitemap_response.status_code == 200:
                    sitemap_exists = True
                    break
            
            result = {
                "robots_txt": "Found" if robots_exists else "Not found",
                "sitemap_in_robots": sitemap_found,
                "sitemap_xml": "Found" if sitemap_exists else "Not found"
            }
            
            return {"status": "info", "message": "Robots.txt and sitemap check complete", "details": result}
        except Exception as e:
            return {"status": "error", "message": f"Error checking robots.txt: {str(e)}"}
    
    def check_directory_listing(self, url):
        try:
            parsed = urlparse(url)
            test_paths = ['/images/', '/css/', '/js/', '/assets/']
            vulnerable_paths = []
            
            for path in test_paths:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                try:
                    response = requests.get(test_url, timeout=5)
                    indicators = ['Index of', 'Directory Listing', '<title>Index of', 'Parent Directory']
                    if any(indicator in response.text for indicator in indicators):
                        vulnerable_paths.append(path)
                except:
                    continue
            
            if vulnerable_paths:
                return {"status": "vulnerable", "message": "Directory listing enabled", "details": vulnerable_paths}
            else:
                return {"status": "safe", "message": "No directory listing vulnerabilities found"}
        except Exception as e:
            return {"status": "error", "message": f"Error checking directory listing: {str(e)}"}
    
    def check_server_banner(self, url):
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                if parsed.scheme == 'https':
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        ssock.send(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                        response = ssock.recv(4096).decode('utf-8', errors='ignore')
                else:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            server = None
            for line in response.split('\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
            
            if server:
                return {"status": "info", "message": f"Server identified: {server}"}
            else:
                return {"status": "info", "message": "No server banner found"}
        except Exception as e:
            return {"status": "error", "message": f"Error checking server banner: {str(e)}"}
    
    def scan_website(self, url, advanced_modules=False):
        self.results = {
            "url": url,
            "timestamp": datetime.datetime.now().isoformat(),
            "checks": {}
        }
        
        checks = [
            ("HTTP to HTTPS", self.check_http_to_https),
            ("SSL Certificate", self.check_ssl_certificate),
            ("Security Headers", self.check_security_headers),
            ("Cookie Flags", self.check_cookie_flags),
            ("Robots.txt", self.check_robots_txt),
            ("Directory Listing", self.check_directory_listing),
            ("Server Banner", self.check_server_banner)
        ]
        
        for check_name, check_function in checks:
            try:
                self.results["checks"][check_name] = check_function(url)
            except Exception as e:
                self.results["checks"][check_name] = {"status": "error", "message": f"Failed to run check: {str(e)}"}
        
        self.scan_log.append(self.results)
        
        try:
            if not os.path.exists('scan_logs'):
                os.makedirs('scan_logs')
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_logs/scan_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
        except Exception as e:
            print(f"Error saving scan log: {e}")
        
        return self.results

class WebRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        if self.path == '/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            url = data.get('url')
            advanced = data.get('advanced', False)
            
            if not url:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "URL is required"}).encode())
                return
            
            if not url.startswith('http'):
                url = 'https://' + url
            
            scanner = VulnerabilityScanner()
            results = scanner.scan_website(url, advanced)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(results).encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    PORT = 8081
    Handler = WebRequestHandler
    
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Server running at http://localhost:{PORT}/")
        webbrowser.open(f"http://localhost:{PORT}/")
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()