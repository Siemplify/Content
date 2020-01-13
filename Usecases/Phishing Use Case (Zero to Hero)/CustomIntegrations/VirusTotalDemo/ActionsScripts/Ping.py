from SiemplifyUtils import output_handler
from VirusTotal import VirusTotalManager
from SiemplifyAction import SiemplifyAction

IDENTIFIER = 'VirusTotal'
SCRIPT_NAME = "VirusTotal - Ping"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    #conf = siemplify.get_configuration(IDENTIFIER)
    #api_key = conf['Api Key']
    api_key = "f6d290c8f2d0c4d887a42449efdaf9eb37b13cf8fbc041814d789647ae5cc1f3"
    use_ssl = True
    vt = VirusTotalManager(api_key, use_ssl)

    try:
        is_connected = vt.test_connectivity()
        if is_connected:
            output_message = "Connection Established"
            result_value = 'true'
        else:
            output_message = "Connection Failed"
            result_value = 'false'
    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result_value = "false"
        output_message = "Some errors occurred. Please check log"

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()