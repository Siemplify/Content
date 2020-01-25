from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from VirusTotal import VirusTotalManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import get_domain_from_entity, flat_dict_to_csv, add_prefix_to_dict, convert_dict_to_json_result_dict
import json

# Consts
DOMAIN_RESULT_URL_FORMAT = 'https://www.virustotal.com/#/domain/{0}'
VT_PREFIX = 'VT'
SCRIPT_NAME = 'VirusTotal_GetDomainReport'
IDENTIFIER = 'VirusTotal'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    #conf = siemplify.get_configuration(IDENTIFIER)
    #api_key = conf['Api Key']
    api_key = "f6d290c8f2d0c4d887a42449efdaf9eb37b13cf8fbc041814d789647ae5cc1f3"
    use_ssl = True
    vt = VirusTotalManager(api_key, use_ssl)

    entities_to_update = []
    result_value = 'false'
    error = False
    json_results = {}
    missing_entities = []
    output_massage = ""

    for entity in siemplify.target_entities:
        # Search a domains in virus total.
        if entity.entity_type == EntityTypes.HOSTNAME or entity.entity_type == EntityTypes.USER:
            try:
                domain_report = vt.get_domain_report(get_domain_from_entity(entity).lower())
                if domain_report:
                    result_value = 'true'
                    json_results[entity.identifier] = domain_report

                    enrichment_object = vt.build_domain_enrichment(domain_report)
                    # Scan flat data - update enrichment
                    entity.additional_properties.update(add_prefix_to_dict(enrichment_object, VT_PREFIX))
                    entities_to_update.append(entity)
                    entity.is_enriched = True

                    # Scan detections_information
                    siemplify.result.add_entity_table('{0} Score Report'.format(entity.identifier), flat_dict_to_csv(enrichment_object))

                    web_link = DOMAIN_RESULT_URL_FORMAT.format(get_domain_from_entity(entity))
                    siemplify.result.add_entity_link("{0} Link to web report".format(entity.identifier), web_link)
                else:
                    # If report is none, and error not raised - probably entity can't be found.
                    missing_entities.append(entity.identifier)

            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                error = True

    if entities_to_update:
        siemplify.update_entities(entities_to_update)
        entities_names = [entity.identifier for entity in entities_to_update]
        output_massage += 'The following Domains were submitted and analyzed in VirusTotal: \n' + '\n'.join(
            entities_names) + '\n \n *Check online report for full details.\n'
    if missing_entities:
        output_massage += 'The following Domains NOT found in VirusTotal: \n{0}'.format('\n'.join(missing_entities))

    if error:
        output_massage += "\n\nErrors Accrued check logs for more information"

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    siemplify.end(output_massage, result_value)


if __name__ == '__main__':
    main()