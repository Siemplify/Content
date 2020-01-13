from SiemplifyUtils import output_handler
from XForceManager import XForceManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    #conf = siemplify.get_configuration('XForce')
    #address = conf['Address']
    #api_key = conf['Api Key']
    #api_password = conf['Api Password']
    #verify_ssl = conf['Verify SSL'].lower() == 'true'
    address = "https://api.xforce.ibmcloud.com"
    api_key = "916023e4-3402-4a39-a46c-a2256240b4bd"
    api_password = "373ed111-da6e-4c13-98d5-abb0a4ed8251"
    verify_ssl = True
    xforce_manager = XForceManager(api_key, api_password, address, verify_ssl=verify_ssl)

    connectivity = xforce_manager.test_connectivity()
    output_message = "Connected Successfully"
    siemplify.end(output_message, connectivity)


if __name__ == '__main__':
    main()
