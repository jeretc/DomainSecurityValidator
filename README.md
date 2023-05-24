# Domain Security Validator

Author: [Jeret Christopher @ M0du5](https://github.com/jeretc)

This utility checks the following records for a domain:

- SPF (Sender Policy Framework)
- DMARC (Domain-based Message Authentication, Reporting, and Conformance)
- DKIM (DomainKeys Identified Mail)

## Usage
1. Install the required dependencies using the command: `pip install -r requirements.txt`.
2. Run the script using the command: `python main.py`.
3. Enter a domain name to validate its security records.
4. The script will provide information on SPF, DMARC, DKIM, and spoofability of the domain.

## Dependencies
- [dnspython](https://pypi.org/project/dnspython/)
- [pyfiglet](https://pypi.org/project/pyfiglet/)

## License
This project is licensed under the [MIT License](LICENSE).

