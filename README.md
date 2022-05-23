# Traceroute for Public Cloud Networks

This repository includes the FAST traceroute technique, that separates sending probes and waiting for replies. I'm currently revamping how I re-create the traceroute paths.

## Installation
Clone the repository. From inside the `cloudtrace` directory, run `python setup.py sdist bdist_wheel build_ext && pip install -e .`. This will install the `fasttrace` script. `fasttrace` sends ICMP packets, so it requires superuser privileges.
