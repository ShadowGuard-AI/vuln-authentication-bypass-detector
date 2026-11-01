# vuln-Authentication-Bypass-Detector
Tests a login form for default credentials and probes a file endpoint for path traversal. It does not test authentication mechanisms in general: it posts form fields to one login path and checks the response for a success marker or a redirect, under the assumptions stated below. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Assumptions and configuration
- The login request is a POST to the `login` path under the target URL path, so scanning `http://host/app` posts to `http://host/app/login`. Change it with `--login_path`.
- The form fields are named `username` and `password` by default. Change them with `--username_field` and `--password_field`.
- A login counts as successful when the response body contains `login_successful` or the status is 302. Redirects are not followed for this test, and error status bodies are judged as returned.
- The path traversal probe is a GET to the `file` path under the target URL path with the payload in the `name` query parameter, for example `http://host/app/file?name=...`. Change them with `--file_path` and `--file_param`.
- A matched password is never printed or saved in clear. Output names the username and which entry of the password list matched, with the password masked.
- If no request reaches the target, or a supplied list file cannot be read or is empty, the run exits non-zero and prints no clean verdict.

## Install
`git clone https://github.com/ShadowGuardAI/vuln-authentication-bypass-detector`

## Usage
`./vuln-authentication-bypass-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--username_list`: Path to a file containing a list of usernames to test (one per line). If not provided, uses a default list.
- `--password_list`: Path to a file containing a list of passwords to test (one per line). If not provided, uses a default list.
- `--path_traversal_payloads`: Path to a file containing path traversal payloads to test (one per line). If not provided, uses a default list.
- `--timeout`: Timeout for HTTP requests in seconds.
- `--user_agent`: User-Agent string to use for requests.
- `--output`: Path to save the report to.
- `--login_path`: Login path relative to the target URL path. Default: login
- `--username_field`: Form field name for the username. Default: username
- `--password_field`: Form field name for the password. Default: password
- `--file_path`: File endpoint path relative to the target URL path. Default: file
- `--file_param`: Query parameter name for path traversal probes. Default: name

## License
Copyright (c) ShadowGuardAI
