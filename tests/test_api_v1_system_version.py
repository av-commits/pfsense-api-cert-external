import unit_test_framework

class APIUnitTestSystemVersion(unit_test_framework.APIUnitTest):
    url = "/api/v1/system/version"
    get_payloads = [{}]

APIUnitTestSystemVersion()