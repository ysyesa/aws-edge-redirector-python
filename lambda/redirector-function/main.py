import rule_engine
import json
import boto3
from datetime import datetime


class Utilities:    
    @staticmethod
    def convert_wildcard_into_regex_pattern(str_wildcard):
        regex_pattern = ''
        for char in str_wildcard:
            if char == '.':
                regex_pattern = regex_pattern + '\\'
            elif char == '*':
                regex_pattern = regex_pattern + '.'
            regex_pattern = regex_pattern + char
        return regex_pattern


class RedirectorFact:
    def __init__(self, uri, querystring):
        self.uri = uri
        self.querystring = querystring
        self.current_time = datetime.now()

    
    def to_json(self):
        return {
            'uri': self.uri,
            'querystring': self.querystring,
            'current_time': self.current_time
        }


class RedirectorRules:
    def __init__(self, ruleset):
        self.ruleset = ruleset
        self.rules = []
        self.rules_redirect_destination = {}
        self.__build_rules_ruleset()

    
    def __build_rules_ruleset(self):
        rules_ruleset = self.ruleset.get('rules', [])
        for json_rule in rules_ruleset:
            origin, redirect, status_code, start_time, end_time = self.__get_rule_detail(json_rule)
            str_rule = 'uri == "{0}" and d"{1}" <= current_time and current_time <= d"{2}"'.format(
                origin,
                start_time,
                end_time
            )
            self.rules_redirect_destination[str_rule] = {
                'origin': origin,
                'destination': redirect,
                'status_code': status_code
            }
            rule = rule_engine.Rule(str_rule)
            self.rules.append(rule)

        wildcards_ruleset = self.ruleset.get('wildcards', [])
        for json_rule in wildcards_ruleset:
            origin, redirect, status_code, start_time, end_time = self.__get_rule_detail(json_rule)
            origin_regex = Utilities.convert_wildcard_into_regex_pattern(origin)
            str_rule = 'uri =~ "{0}" and d"{1}" <= current_time and current_time <= d"{2}"'.format(
                origin_regex,
                start_time,
                end_time
            )                
            self.rules_redirect_destination[str_rule] = {
                'origin': origin,
                'destination': redirect,
                'status_code': status_code
            }
            rule = rule_engine.Rule(str_rule)
            self.rules.append(rule)

        querystrings_ruleset = self.ruleset.get('querystrings', [])
        for json_rule in querystrings_ruleset:
            origin, redirect, status_code, start_time, end_time = self.__get_rule_detail(json_rule)
            str_rule = 'querystring == "{0}" and d"{1}" <= current_time and current_time <= d"{2}"'.format(
                origin,
                start_time,
                end_time
            )
            self.rules_redirect_destination[str_rule] = {
                'origin': origin,
                'destination': redirect,
                'status_code': status_code
            }
            rule = rule_engine.Rule(str_rule)
            self.rules.append(rule)


    def __get_rule_detail(self, json_rule):
        origin = json_rule.get('original', '')
        redirect = json_rule.get('redirect', '')
        status_code = json_rule.get('statusCode', 301)
        start_time = json_rule.get('startTime', None)
        end_time = json_rule.get('endTime', None)
        
        if start_time is None:
            start_time = datetime.min
        else:
            start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M:%S.%fZ')
        
        if end_time is None:
            end_time = datetime.max
        else:
            end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M:%S.%fZ')

        return origin, redirect, status_code, start_time, end_time


    def __render_wildcard_on_redirect_destination(self, destination, origin, uri):
        origin_components = origin.split('*')
        uri_component = uri
        for origin_component in origin_components:
            uri_component = uri_component.replace(origin_component, '')
        destination = destination.replace('*', uri_component)
        return destination


    def evaluate_fact(self, json_fact):
        for rule in self.rules:
            if rule.matches(json_fact):
                result = self.rules_redirect_destination[str(rule)]
                destination = result['destination']
                if '*' in destination:
                    origin = result['origin']
                    uri = json_fact['uri']
                    result['destination'] = self.__render_wildcard_on_redirect_destination(destination, origin, uri)
                return result
        return None


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    uri = request.get('uri', '')
    querystring = request.get('querystring', '')

    if request['origin'].get('s3', None) is not None:
        custom_headers = request['origin']['s3']['customHeaders']
    else:
        custom_headers = request['origin']['custom']['customHeaders']

    bucket_rules = custom_headers['rules_bucket'][0]['value']
    key_rules = custom_headers['rules_file'][0]['value']

    json_rule = get_rule_from_s3(bucket_rules, key_rules)
    redirection_rules = RedirectorRules(json_rule)
    redirection_fact = RedirectorFact(uri, querystring)
    
    redirection = redirection_rules.evaluate_fact(redirection_fact.to_json())
    if redirection is not None:
        response = {
            'status': redirection['status_code'],
            'headers': {
                'location': [{
                    'key': 'Location',
                    'value': redirection['destination']
                }]
            }
        }
        return response
        
    return request


def get_rule_from_s3(bucket_rule, key_rule):
    s3_client = boto3.client('s3')
    response = s3_client.get_object(
        Bucket=bucket_rule,
        Key=key_rule
    )
    json_rule = json.loads(response['Body'].read().decode('utf-8'))
    return json_rule


def test_function(uri, querystring):
    SAMPLE_JSON = {
        'uri': uri,
        'querystring': querystring,
        'ruleset': {
            "rules": [
                {
                    "$$hashKey": "object:25",
                    "original": "/index.html",
                    "redirect": "/newindex.html",
                    "statusCode": 301,
                    "startTime": "2021-07-09T07:16:00.000Z",
                    "endTime": "2022-07-13T07:16:00.000Z"
                },
                {
                    "$$hashKey": "object:79",
                    "original": "/page1/page2/index.html",
                    "redirect": "/newindex.html",
                    "statusCode": 301,
                    "startTime": "2021-07-10T12:11:53.944Z",
                    "endTime": "2022-07-13T12:11:00.000Z"
                }
            ],
            "wildcards": [
                {
                    "$$hashKey": "object:351",
                    "original": "/wildcard/*",
                    "redirect": "/redirected/*",
                    "statusCode": 301,
                    "startTime": "2021-07-09T07:16:00.000Z",
                    "endTime": "2022-07-13T07:16:00.000Z"
                }
            ],
            "querystrings": [
                {
                    "$$hashKey": "object:676",
                    "original": "a=1&b=2",
                    "redirect": "/redirectindex.html",
                    "statusCode": 301,
                    "startTime": "2021-07-09T07:17:00.000Z",
                    "endTime": "2022-07-13T07:17:00.000Z"
                }
            ],
            "refreshTime": "10"
        }
    }

    redirector_rules = RedirectorRules(SAMPLE_JSON['ruleset'])
    redirector_fact = RedirectorFact(
        SAMPLE_JSON['uri'], 
        SAMPLE_JSON['querystring']
    )
    redirection = redirector_rules.evaluate_fact(redirector_fact.to_json())
    if redirection is not None:
        print(redirection['destination'])
        print(redirection['status_code'])
    return redirection


if __name__ == '__main__':
    test_function('/wildcard/path1/path2/path3', '')
