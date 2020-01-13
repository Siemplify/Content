from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import add_prefix_to_dict_keys, construct_csv, convert_dict_to_json_result_dict
from XForceManager import XForceManager, XForceNotFoundError, XForceAccessDeniedError
import json

URL = EntityTypes.URL
SCRIPT_NAME = "IBM XForce - Get Url Info"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    #conf = siemplify.get_configuration('XForce')
    #address = conf['Address']
    #api_key = conf['Api Key']
    #api_password = conf['Api Password']
    #verify_ssl = conf['Verify SSL'].lower() == 'true'
    address = "https://api.xforce.ibmcloud.com"
    api_key = "916023e4-3402-4a39-a46c-a2256240b4bd"
    api_password = "373ed111-da6e-4c13-98d5-abb0a4ed8251"
    verify_ssl = True

    xf_manager = XForceManager(api_key, api_password, address, verify_ssl=verify_ssl)
    threshold = int(siemplify.parameters.get('Threshold')) if siemplify.parameters.get('Threshold') else 1

    risk_score = 0
    enriched_entities = []
    csv_results = []
    entities_with_score = {}
    output_message = ''
    is_risk = 'false'
    json_results = {}

    not_found_entities = []
    access_denied = []
    not_enriched_entities = []

    for entity in siemplify.target_entities:
        if entity.entity_type == URL:
            try:
                report = xf_manager.get_url_info(entity.identifier)
                if report:
                    json_results[entity.identifier] = report
                    risk_score = report.get('result').get('score') or 0
                    categories_list = report.get('result', {}).get('categoryDescriptions', {}).keys() or []
                    categories = '| '.join(str(category) for category in categories_list)

                    # Attach report
                    siemplify.result.add_entity_json(entity.identifier, json.dumps(report))

                    # Build csv table (URL - Score - Categories(comma separated))
                    csv_results.append({"URL": entity.identifier, "Score": float(risk_score), "Categories": categories})

                    # Enrich - Score and Categories (comma separated)
                    flat_report = add_prefix_to_dict_keys({"Score": float(risk_score), "Categories": categories}, "IBM_XForce")
                    entity.additional_properties.update(flat_report)
                    entity.is_enriched = True

                    # Add Insight and mark as suspicious if risk score exceed threshold
                    if int(threshold) < risk_score:
                        entity.is_suspicious = True
                        is_risk = True
                        insight_msg = 'IBM XForce - {0} marked as suspicious'.format(entity.identifier)
                        siemplify.add_entity_insight(entity, insight_msg, triggered_by='XForce')

                    entities_with_score.update({entity.identifier: risk_score})
                    enriched_entities.append(entity)

            except XForceNotFoundError as e:
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                not_found_entities.append(entity.identifier)

            except XForceAccessDeniedError as e:
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                access_denied.append(entity.identifier)

            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                not_enriched_entities.append(entity.identifier)

    if csv_results:
        # Add csv table
        siemplify.result.add_data_table("Report", construct_csv(csv_results))

    if entities_with_score:
        output_message = "The following entities were enriched \n"
        for url, score in entities_with_score.items():
            output_message = '{0} {1} returned risk score: {2} \n'.format(output_message, url, score)
        siemplify.update_entities(enriched_entities)

    if not_found_entities:
        output_message += "The following entities were not found in IBM X-Force: {0} \n".format('\n'.join(not_found_entities))

    if access_denied:
        output_message += "The following entities were not enriched - Access was denied: {0} \n".format('\n'.join(access_denied))

    if not_enriched_entities:
        output_message += "The following entities were not enriched - API error: {0} \n".format('\n'.join(not_enriched_entities))

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, is_risk)


if __name__ == "__main__":
    main()
