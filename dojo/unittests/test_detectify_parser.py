import hashlib

from django.test import TestCase

from dojo.models import Test
from dojo.tools.detectify.parser import DetectifyJsonParser


class TestFile(object):

    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestDetectifyJsonParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = DetectifyJsonParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vulnerabilities_has_no_findings(self):
        testfile = open("dojo/unittests/scans/detectify/no_findings_report_export.json")
        parser = DetectifyJsonParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        testfile = open("dojo/unittests/scans/detectify/single_finding_report_export.json")
        parser = DetectifyJsonParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/detectify/multiple_findings_report_export.json")
        parser = DetectifyJsonParser(testfile, Test())
        self.assertEqual(2, len(parser.items))

    def test_parse_single_vulnerability_finding(self):

        testfile = open("dojo/unittests/scans/detectify/single_finding_report_export.json")
        parser = DetectifyJsonParser(testfile, Test())
        finding = parser.items[0]

        m = hashlib.sha256()
        m.update("www.example.com")
        m.update("Content-Security-Policy / Missing Header")
        m.update("Invalid Header Value")
        m.update("0")
        m.update("https://www.example.com/")
        finding_hash = m.hexdigest()

        self.assertEqual('Content-Security-Policy / Missing Header on www.example.com ({})'.format(finding_hash),
                         finding.title)
        self.assertEqual('Info', finding.severity)
        self.assertEqual('CVSS score: 0', finding.impact)
        expected_references = "* [Content Security Policy Reference (MISC)](https://content-security-policy.com/)\n" \
                              "* [Content Security Policy (OWASP)](https://www.owasp.org/index.php/Content_Security_Policy)\n" \
                              "* [Content Security Policy Cheat Sheet (OWASP)](https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet)\n" \
                              "* [Content Security Policy (GOOGLE)](https://developers.google.com/web/fundamentals/security/csp/)\n" \
                              "* [Content Security Policy (MOZILLA)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)\n" \
                              "* [Content Security Policy (WIKIPEDIA)](https://en.wikipedia.org/wiki/Content_Security_Policy)\n"
        self.assertEqual(expected_references, finding.references)

    def test_parse_multiple_vulnerability_finding(self):

        testfile = open("dojo/unittests/scans/detectify/multiple_findings_report_export.json")
        parser = DetectifyJsonParser(testfile, Test())
        finding1 = parser.items[1]
        finding2 = parser.items[0]

        m = hashlib.sha256()
        m.update("www.example.com")
        m.update("Content-Security-Policy / Missing Header")
        m.update("Invalid Header Value")
        m.update("0")
        m.update("https://www.example.com/")
        finding1_hash = m.hexdigest()

        self.assertEqual('Content-Security-Policy / Missing Header on www.example.com ({})'.format(finding1_hash),
                         finding1.title)
        self.assertEqual('Info', finding1.severity)
        self.assertEqual('CVSS score: 0', finding1.impact)
        expected_references = "* [Content Security Policy Reference (MISC)](https://content-security-policy.com/)\n" \
                              "* [Content Security Policy (OWASP)](https://www.owasp.org/index.php/Content_Security_Policy)\n" \
                              "* [Content Security Policy Cheat Sheet (OWASP)](https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet)\n" \
                              "* [Content Security Policy (GOOGLE)](https://developers.google.com/web/fundamentals/security/csp/)\n" \
                              "* [Content Security Policy (MOZILLA)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)\n" \
                              "* [Content Security Policy (WIKIPEDIA)](https://en.wikipedia.org/wiki/Content_Security_Policy)\n"
        self.assertEqual(expected_references, finding1.references)

        m = hashlib.sha256()
        m.update("www.example.com")
        m.update("External Links using target='_blank'")
        m.update("External Links using target='_blank'")
        m.update("4.9")
        m.update("https://www.example.com/path/some-path")
        finding2_hash = m.hexdigest()

        self.assertEqual("External Links using target='_blank' on www.example.com/path/some-path ({})".format(
            finding2_hash), finding2.title)
        self.assertEqual('Medium', finding2.severity)
        self.assertEqual('CVSS score: 4.9', finding2.impact)
        expected_references = "* [Target=\"_blank\"?-?the most underestimated vulnerability ever (MISC)](https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c#.oh7ggu8gn)\n" \
                              "* [Hacker News Discussion (YCOMBINATOR)](https://news.ycombinator.com/item?id=11631292)\n" \
                              "* [Target Blank Vulnerability (GITHUB)](https://github.com/chafikhnini/target-blank-vulnerability)\n" \
                              "* [When to use target=\"_blank\" (MISC)](https://css-tricks.com/use-target_blank/)\n"
        self.assertEqual(expected_references, finding2.references)
