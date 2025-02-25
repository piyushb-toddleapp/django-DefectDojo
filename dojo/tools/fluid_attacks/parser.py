import csv
import hashlib
import io
import sys
from dojo.models import Finding
from cvss.cvss3 import CVSS3
import cvss.parser
import re

class FluidAttacksParser(object):
    """
    Parsing Fluid Attacks Reports
    """

    def get_scan_types(self):
        return ["Fluid Attacks Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Fluid Attacks Scan"
 
    def get_description_for_scan_types(self, scan_type):
        return "Fluid Attacks report file can be imported in CSV format."

    def get_findings(self, filename, test):
        if filename is None:
            return []

        # Increase CSV field size limit
        maxInt = sys.maxsize
        while True:
            try:
                csv.field_size_limit(maxInt)
                break
            except OverflowError:
                maxInt = int(maxInt/10)

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        dupes = dict()
        for row in csvarray:
            finding = Finding(test=test)

            # Handle title
            title = row.get('title', '')
            if title:
                title_parts = title.split('.')
                if len(title_parts) > 1:
                    finding.title = '.'.join(title_parts[1:]).strip()
                else:
                    finding.title = title.strip()

            # Handle CWE
            cwe_str = row.get('cwe', '')
            if cwe_str:
                cwe_match = re.search(r'CWE-(\d+)', cwe_str)
                if cwe_match:
                    finding.cwe = int(cwe_match.group(1))

            # Handle description and snippet
            description = row.get('description', '')
            snippet = row.get('snippet', '')
            if description is None:
                description = ''
            if snippet:
                description += f"\n\nCode Snippet:\n```\n{snippet}\n```"
            finding.description = description

            # Handle CVSS
            cvss_vector = row.get('cvss', '')
            if cvss_vector:
                vectors = cvss.parser.parse_cvss_from_text(cvss_vector)
                if len(vectors) > 0 and type(vectors[0]) == CVSS3:
                    finding.cvss = vectors[0].clean_vector()
                    finding.severity = vectors[0].severities()[0]
                    vectors[0].compute_base_score()
                    finding.cvssv3_score = vectors[0].scores()[0]
                else:
                    finding.severity = "Medium"
            else:
                finding.severity = "Medium"

            # Add references
            finding.references = row.get('finding', '')

            # Add file location
            finding.file_path = ""

            description_column = row.get('description', '') or ''

            # Use regex to find the file path after 'fluid-attacks-scanning-report/'
            match = re.search(r'fluid-attacks-scanning-report/(.+)', description_column)

            if match:
                finding.file_path = match.group(1)  # Get the part after 'fluid-attacks-scanning-report/'

            # Add method information
            method = row.get('method', '')
            if method:
                finding.static_finding = True
                finding.dynamic_finding = False

            # Extract component information from description (safely)
            if description and 'Use of' in description and 'at version' in description:
                try:
                    comp_parts = description.split('Use of ')[1].split(' at version ')
                    finding.component_name = comp_parts[0]
                    finding.component_version = comp_parts[1].split(' ')[0]
                except:
                    finding.component_name = ''
                    finding.component_version = ''

            # Handle unique findings
            if finding.title is None:
                finding.title = ""
            if finding.description is None:
                finding.description = ""

            key = hashlib.sha256(
                (finding.title + '|' + finding.description).encode("utf-8")
            ).hexdigest()

            if key not in dupes:
                dupes[key] = finding

        return list(dupes.values())
