import argparse
import logging
import requests
import os
import sys
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detects common authentication bypass vulnerabilities.")
    parser.add_argument("url", help="The target URL to scan (e.g., http://example.com)")
    parser.add_argument("--username_list", help="Path to a file containing a list of usernames to test (one per line).  If not provided, uses a default list.", default=None)
    parser.add_argument("--password_list", help="Path to a file containing a list of passwords to test (one per line).  If not provided, uses a default list.", default=None)
    parser.add_argument("--path_traversal_payloads", help="Path to a file containing path traversal payloads to test (one per line). If not provided, uses a default list.", default=None)
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for HTTP requests in seconds.")
    parser.add_argument("--user_agent", default="VulnAuthBypassDetector/1.0", help="User-Agent string to use for requests.")
    parser.add_argument("--output", help="Path to save the report to.")
    parser.add_argument("--login_path", default="login", help="Login path relative to the target URL path. Default: login")
    parser.add_argument("--username_field", default="username", help="Form field name for the username. Default: username")
    parser.add_argument("--password_field", default="password", help="Form field name for the password. Default: password")
    parser.add_argument("--file_path", default="file", help="File endpoint path relative to the target URL path, used for path traversal probes. Default: file")
    parser.add_argument("--file_param", default="name", help="Query parameter name for path traversal probes. Default: name")

    return parser.parse_args()


def _join_under_base(url, relative_path):
    """Join a relative path under the target URL path, preserving any prefix."""
    base = url if url.endswith('/') else url + '/'
    return urljoin(base, relative_path.lstrip('/'))


def test_default_credentials(url, username_list, password_list, timeout, user_agent, login_path="login", username_field="username", password_field="password"):
    """
    Tests for default credentials on the target URL.

    Args:
        url (str): The target URL.
        username_list (list): A list of usernames to try.
        password_list (list): A list of passwords to try.
        timeout (int): The request timeout in seconds.
        user_agent (str): The User-Agent string to use.

    Returns:
        list: A list of vulnerable credentials (username, password) or an empty list if none found.
    """

    vulnerable_credentials = []
    headers = {'User-Agent': user_agent}  # set user agent header
    reached = 0

    if not username_list or not password_list:
        logging.warning("Username or password lists are empty. Skipping default credential check.")
        return vulnerable_credentials, reached

    login_url = _join_under_base(url, login_path)

    for username in username_list:
        for password_index, password in enumerate(password_list, start=1):
            try:
                data = {username_field: username, password_field: password}
                # Do not follow redirects: a 302 is itself a success signal, and
                # error status bodies are judged as returned.
                response = requests.post(login_url, data=data, timeout=timeout, headers=headers, allow_redirects=False)
                reached += 1

                if "login_successful" in response.text or response.status_code == 302:
                    logging.info(f"Default credentials found: username={username}, password=*** (password list entry {password_index})")
                    vulnerable_credentials.append((username, password_index))

            except requests.exceptions.RequestException as e:
                logging.error(f"Error during request: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")

    return vulnerable_credentials, reached


def test_path_traversal(url, path_traversal_payloads, timeout, user_agent, file_path="file", file_param="name"):
    """
    Tests for path traversal vulnerabilities in the target URL.

    Args:
        url (str): The target URL.
        path_traversal_payloads (list): A list of path traversal payloads to try.
        timeout (int): The request timeout in seconds.
        user_agent (str): The User-Agent string to use.

    Returns:
        list: A list of vulnerable URLs or an empty list if none found.
    """
    vulnerable_urls = []
    headers = {'User-Agent': user_agent}
    reached = 0

    if not path_traversal_payloads:
        logging.warning("Path traversal payload list is empty. Skipping path traversal check.")
        return vulnerable_urls, reached

    for payload in path_traversal_payloads:
        test_url = _join_under_base(url, file_path) + f"?{file_param}={payload}"

        try:
            response = requests.get(test_url, timeout=timeout, headers=headers)
            reached += 1

            # Check if the path traversal was successful.
            # This depends on the application and what files it allows access to.
            # A common test is to try to access /etc/passwd (on Linux) or boot.ini (on Windows)
            # If you see the contents of those files in the response, it's a vulnerability.
            if "root:" in response.text or "[boot loader]" in response.text:
                logging.warning(f"Path traversal vulnerability found at: {test_url}")
                vulnerable_urls.append(test_url)

        except requests.exceptions.RequestException as e:
            logging.error(f"Error during request: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

    return vulnerable_urls, reached

def load_list_from_file(file_path):
    """
    Loads a list of strings from a file, one string per line.

    Args:
        file_path (str): The path to the file.

    Returns:
        list: A list of strings.  Returns an empty list if the file does not exist or is empty.
    """
    try:
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return None

        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

def main():
    """
    Main function of the script.
    """
    args = setup_argparse()

    url = args.url.rstrip('/') #Remove trailing slash

    # Input validation: Check if the URL is valid
    if not url.startswith(('http://', 'https://')):
        logging.error("Invalid URL. URL must start with http:// or https://")
        sys.exit(1)


    # Load username and password lists
    default_usernames = ["admin", "administrator", "test", "user"]
    default_passwords = ["password", "admin", "123456", "test"]
    default_path_traversal_payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\boot.ini"]


    username_list = load_list_from_file(args.username_list) if args.username_list else default_usernames
    password_list = load_list_from_file(args.password_list) if args.password_list else default_passwords
    path_traversal_payloads = load_list_from_file(args.path_traversal_payloads) if args.path_traversal_payloads else default_path_traversal_payloads

    if username_list is None or password_list is None or path_traversal_payloads is None:
        logging.error("A supplied list file could not be read. Scan not performed.")
        sys.exit(1)
    if not username_list or not password_list or not path_traversal_payloads:
        logging.error("A supplied list file was empty. Scan not performed.")
        sys.exit(1)

    # Strip an output path that would overwrite an input list file.
    if args.output:
        out_resolved = os.path.realpath(args.output)
        for supplied in (args.username_list, args.password_list, args.path_traversal_payloads):
            if supplied and os.path.realpath(supplied) == out_resolved:
                logging.error("Output path matches an input file. Refusing to overwrite it.")
                sys.exit(1)

    # Run the vulnerability checks
    vulnerable_credentials, cred_reached = test_default_credentials(url, username_list, password_list, args.timeout, args.user_agent, args.login_path, args.username_field, args.password_field)
    vulnerable_urls, trav_reached = test_path_traversal(url, path_traversal_payloads, args.timeout, args.user_agent, args.file_path, args.file_param)

    if cred_reached + trav_reached == 0:
        logging.error("No request reached the target. Scan not performed; no verdict is available.")
        sys.exit(1)

    # Output the results
    if vulnerable_credentials:
        print("\nVulnerable Default Credentials Found:")
        for username, password_index in vulnerable_credentials:
            print(f"  Username: {username}, Password: *** (password list entry {password_index})")
    else:
        print("\nNo vulnerable default credentials found.")

    if vulnerable_urls:
        print("\nVulnerable Path Traversal URLs Found:")
        for vulnerable_url in vulnerable_urls:
            print(f"  {vulnerable_url}")
    else:
        print("\nNo vulnerable path traversal URLs found.")

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write("Vulnerability Scan Results:\n\n")

                f.write("Vulnerable Default Credentials:\n")
                if vulnerable_credentials:
                   for username, password_index in vulnerable_credentials:
                        f.write(f"  Username: {username}, Password: *** (password list entry {password_index})\n")
                else:
                    f.write("  None found.\n")

                f.write("\nVulnerable Path Traversal URLs:\n")
                if vulnerable_urls:
                    for vulnerable_url in vulnerable_urls:
                        f.write(f"  {vulnerable_url}\n")
                else:
                    f.write("  None found.\n")

            logging.info(f"Report saved to {args.output}")

        except Exception as e:
            logging.error(f"Error writing to output file: {e}")



if __name__ == "__main__":
    main()