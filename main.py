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


    return parser.parse_args()


def test_default_credentials(url, username_list, password_list, timeout, user_agent):
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


    if not username_list or not password_list:
        logging.warning("Username or password lists are empty. Skipping default credential check.")
        return vulnerable_credentials

    for username in username_list:
        for password in password_list:
            try:
                # Replace this with the actual authentication logic of the target application.
                # This is a simplified example.  In reality, you need to understand the
                # application's authentication mechanism (e.g., form-based, API endpoint, etc.)

                # Example: Assume a simple login form at /login
                login_url = urljoin(url, "/login")

                # Example: Assume the form data is username=...&password=...
                data = {'username': username, 'password': password}
                response = requests.post(login_url, data=data, timeout=timeout, headers=headers)
                response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                # Check if the login was successful.  This depends on the application.
                # For example, it might redirect to a different page, set a cookie, or return a specific message.
                if "login_successful" in response.text or response.status_code == 302:
                    logging.info(f"Default credentials found: username={username}, password={password}")
                    vulnerable_credentials.append((username, password))

            except requests.exceptions.RequestException as e:
                logging.error(f"Error during request: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")


    return vulnerable_credentials


def test_path_traversal(url, path_traversal_payloads, timeout, user_agent):
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


    if not path_traversal_payloads:
        logging.warning("Path traversal payload list is empty. Skipping path traversal check.")
        return vulnerable_urls

    for payload in path_traversal_payloads:
        # Example: Assume a file inclusion vulnerability at /file?name=...
        test_url = urljoin(url, f"/file?name={payload}")

        try:
            response = requests.get(test_url, timeout=timeout, headers=headers)
            response.raise_for_status()

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

    return vulnerable_urls

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
            logging.warning(f"File not found: {file_path}")
            return []

        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return []

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


    # Run the vulnerability checks
    vulnerable_credentials = test_default_credentials(url, username_list, password_list, args.timeout, args.user_agent)
    vulnerable_urls = test_path_traversal(url, path_traversal_payloads, args.timeout, args.user_agent)


    # Output the results
    if vulnerable_credentials:
        print("\nVulnerable Default Credentials Found:")
        for username, password in vulnerable_credentials:
            print(f"  Username: {username}, Password: {password}")
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
                   for username, password in vulnerable_credentials:
                        f.write(f"  Username: {username}, Password: {password}\n")
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