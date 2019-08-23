from __future__ import with_statement

import cgi
import hashlib
import json
from urlparse import urlparse

from dojo.models import Finding, Endpoint

__author__ = "Mario Gastegger"


class DetectifyJsonParser(object):
    def __init__(self, json_output, test):
        if json_output:
            tree = self.parse_json(json_output)
        else:
            tree = None

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        try:
            tree = json.load(json_output)
        except ValueError as e:
            raise Exception("Invalid format ({})".format(e))

        return tree

    def get_items(self, tree, test):
        items = {}

        findings = tree['findings']
        scan_finished_datetime = tree['export']['finished']
        # This is most likely the scan profile
        scan_profile = tree['export']['target']

        for finding in findings:

            # I define it to be the point in time when the scan was finished
            finding['date'] = scan_finished_datetime
            # Scan profile is used in the title
            finding['scan_profile'] = scan_profile

            item = get_item(finding, test)
            dupe_key = str(item.url) + item.severity + item.title
            if dupe_key in items:
                items[dupe_key].unsaved_endpoints = items[dupe_key].unsaved_endpoints + item.unsaved_endpoints

                # make sure only unique endpoints are retained
                unique_objs = []
                new_list = []
                for o in items[dupe_key].unsaved_endpoints:
                    if o.__unicode__() in unique_objs:
                        continue
                    new_list.append(o)
                    unique_objs.append(o.__unicode__())

                items[dupe_key].unsaved_endpoints = new_list
            else:
                items[dupe_key] = item

        return items.values()


def do_clean(value):
    myreturn = ""
    if value is not None:
        if len(value) > 0:
            for x in value:
                myreturn += x.text
    return myreturn


def get_item(finding, test):

    url = get_url(finding)

    o = urlparse(url)

    protocol = o.scheme
    host = o.netloc
    path = o.path
    query = o.query
    fragment = o.fragment

    if o.port:
        port = o.port
    else:
        if protocol == 'https':
            port = 443
        else:
            port = 80

    endpoints = get_or_create_endpoints(fragment, host, path, port, protocol, query)

    title = get_title(finding, host, path)
    date = finding['date']
    description = get_description(finding)
    impact = get_impact(finding)
    severity = get_severity(finding)
    tags = get_tags()
    references = get_references(finding)

    # Finding and Endpoint objects returned have not been saved to the database
    dd_finding = Finding(test=test,
                         active=True,
                         verified=False,
                         false_p=False,
                         duplicate=False,
                         out_of_scope=False,
                         mitigated=None,
                         title=title,
                         date=date,
                         url=url,
                         severity=severity,
                         description=description,
                         references=references,
                         impact=impact,
                         numerical_severity=Finding.get_numerical_severity(severity))
    dd_finding.unsaved_endpoints = endpoints
    dd_finding.unsaved_tags = tags

    return dd_finding


def get_or_create_endpoints(fragment, host, path, port, protocol, query):
    try:
        dupe_endpoint = Endpoint.objects.get(protocol=protocol,
                                             host=host,
                                             query=query,
                                             prot=port,
                                             fragment=fragment,
                                             path=path)
    except:
        dupe_endpoint = None
    if not dupe_endpoint:
        endpoint = Endpoint(protocol=protocol,
                            host=host,
                            query=query,
                            port=port,
                            fragment=fragment,
                            path=path)
    else:
        endpoint = dupe_endpoint
    if not dupe_endpoint:
        endpoints = [endpoint]
    else:
        endpoints = [endpoint, dupe_endpoint]
    return endpoints


def get_url(item_node):
    if 'target' in item_node:
        url = item_node['target']
    else:
        url = item_node['scan_profile']
    return url


def get_references(item_node):
    """
    format 'References' from 'resources'(list)
    :param item_node: finding object.
    :return: Formatted references text.
    """
    # if references:
    #     references = html2text.html2text(references)

    if 'resources' in item_node:
        references = ""
        for res in item_node['resources']:
            references += "* [{} ({})]({})\n".format(res['resource'], res['source'], res['link'])
    else:
        references = None

    return references


def get_tags():
    return ', '.join(['detectify', 'import'])


def get_title(item_node, host, path):
    m = hashlib.sha256()
    m.update(item_node['scan_profile'])
    m.update(item_node['name'])
    m.update(item_node['category'])
    m.update(item_node['score'])
    m.update(item_node['target'])
    finding_hash = m.hexdigest()

    return "{} on {}{} ({})".format(item_node['name'], host, path, finding_hash)


def get_description(item_node):

    if 'details' in item_node and len(item_node['details']) > 0:
        description = 'Below you can find more detailed information about the finding. Depending on the finding ' \
                      'type, you might see a code snippet, or other information.'
        for detail in item_node['details']:
            if detail['type'] == 'Text':
                description += "\n\n" + detail['value'].replace('\\r', '').replace('\\n', '  \n')
            # elif detail['type'] == 'HTML': # Does not work properly
            #     description += "\n\n<pre><code>\n" + detail['value'].replace('\\r', '').replace('\\n', '  \n') + "\n</code></pre>"
            else:
                description += "\n\n" + detail['value'].replace('\\r', '').replace('\\n', '  \n')
    else:
        description = ""
    return description


def get_impact(item_node):
    return "CVSS score: " + item_node['score'] if 'score' in item_node else "CVSS score: N/A"


def get_severity(item_node):
    # severity is ignored: item_node['severity']
    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if 'score' in item_node:
        if float(item_node['score']) == 0:
            severity = "Info"
        elif 0.1 <= float(item_node['score']) <= 3.9:
            severity = "Low"
        elif 4.0 <= float(item_node['score']) <= 6.9:
            severity = "Medium"
        elif 7.0 <= float(item_node['score']) <= 8.9:
            severity = "High"
        else:
            severity = "Critical"
    else:
        # Don't over look in case of error
        severity = "Critical"
    return severity


def headers_exist(finding):
    """
    :param finding: the finding
    :return: True if request have been made.
    """
    return len(finding['headers']['request']) > 0 and len(finding['headers']['response']) > 0


def header_attr_to_string(fields):
    """
    Makes a list from the request or response header dictionary.
    :param fields: the respective dictionary, i.e. request or response.
    :return: A pretty formatted list.
    """
    attrs = ""
    for field in fields:
        attrs = attrs + "\t{}: {}\n".format(field['name'], field['value'])

    return attrs


def header_general_to_string(obj):
    """
    Makes a list from the general header dictionary.
    :param obj: the general header dictionary.
    :return: A pretty formatted list.

    """
    attrs = ""
    for key, value in obj.items():
        attrs = attrs + "\t{}: {}\n".format(key, value)

    return attrs


def format_description(finding):
    """
    format 'Description' from details (list)
    :param finding: finding string.
    :return: Formatted description text.
    """
    details_preamble = "Below you can find more detailed information about the finding. Depending on the finding " \
                       "type, you might see a code snippet, or other information."
    request_response_preamble = "Below you can see the request header sent by Detectify and the response header " \
                                "that Detectify received from your domain."

    description = "{}\n{}".format(details_preamble, finding['details'])
    if headers_exist(finding):
        description += "{}\nRequest:\n{}\nResponse:\n{}".format(request_response_preamble,
                                                                header_general_to_string(finding['headers']['general']),
                                                                header_attr_to_string(finding['headers']['request']),
                                                                header_attr_to_string(finding['headers']['response']))

    return description
