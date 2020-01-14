from SiemplifyUtils import output_handler
# Imports
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv, add_prefix_to_dict_keys, convert_dict_to_json_result_dict
from AlienVaultTIManager import AlienVaultTIManager
import json

# Consts
ADDRESS = EntityTypes.ADDRESS
FILEHASH = EntityTypes.FILEHASH
URL = EntityTypes.URL
HOSTNAME = EntityTypes.HOSTNAME


# Enrich target entity with alienvault info and add csv table to entity
def enrich_entity(report, entity, siemplify):
    country = report.get('geo').get('country_code') if report.get('geo') else None
    flat_report = dict_to_flat(report)
    csv_output = flat_dict_to_csv(flat_report)
    flat_report = add_prefix_to_dict_keys(flat_report, "AlienVault")
    siemplify.result.add_entity_table(entity.identifier, csv_output)
    entity.additional_properties.update(flat_report)
    entity.additional_properties['Country'] = country
    entity.is_enriched = True
    return True


@output_handler
def main():
    siemplify = SiemplifyAction()
    entities_to_enrich = []
    not_found_entities = []
    json_result = {}

    # Configuration.
    #conf = siemplify.get_configuration('AlienVaultTI')
    #api_key = conf['Api Key']
    api_key = "4ec3af1186c8c80e033899a9912a36d4e9838e80dfba63c1000a70edb202ccba"
    alienvault = AlienVaultTIManager(api_key)

    for entity in siemplify.target_entities:
        if entity.entity_type == ADDRESS and not entity.is_internal:
            ip_info = alienvault.enrich_ip(entity.identifier)
            if ip_info:
                json_result[entity.identifier] = ip_info
                csv_output = enrich_entity(ip_info, entity, siemplify)
                entities_to_enrich.append(entity)
            else: 
                not_found_entities.append(entity)

        if entity.entity_type == FILEHASH:
            hash_info = alienvault.enrich_hash(entity.identifier)
            if hash_info:
                json_result[entity.identifier] = hash_info
                csv_output = enrich_entity(hash_info, entity, siemplify)
                entities_to_enrich.append(entity)
            else: 
                not_found_entities.append(entity)

        if entity.entity_type == URL:
            url_info = alienvault.enrich_url(entity.identifier)
            if url_info:
                json_result[entity.identifier] = url_info
                csv_output = enrich_entity(url_info, entity, siemplify)
                entities_to_enrich.append(entity)
            else: 
                not_found_entities.append(entity)

        if entity.entity_type == HOSTNAME and not entity.is_internal:
            host_info = alienvault.enrich_host(entity.identifier)
            if host_info:
                json_result[entity.identifier] = host_info
                csv_output = enrich_entity(host_info, entity, siemplify)
                entities_to_enrich.append(entity)
            else: 
                not_found_entities.append(entity)

    if entities_to_enrich:
        output_message = "Following entities were enriched by AlienVault. \n{0}".format(entities_to_enrich)
        if not_found_entities:
            output_message = "{0} \n\nCould not find results for the following entities \n{1}".format(output_message,
                                                                                                      not_found_entities)

        siemplify.update_entities(entities_to_enrich)
        result_value = True
    else:
        output_message = 'No entities were enriched.'
        result_value = False

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
