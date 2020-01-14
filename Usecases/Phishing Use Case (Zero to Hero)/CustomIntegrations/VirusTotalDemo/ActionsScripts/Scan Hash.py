from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from VirusTotal import VirusTotalManager, FILEHASH_TYPE, ScanStatus, ENTITY_TASK_ID_KEY, ENTITY_REPORT_KEY, ENTITY_STATUS_KEY
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from SiemplifyUtils import add_prefix_to_dict, convert_dict_to_json_result_dict
import json
import sys

"""
structure
entities_handle = {{"entitiy_id":
                 {"report": {"report/None"},
                  "task_id": "id/None",
                  "status": "missing/done/ready"}
             }, }
"""

VT_PREFIX = "VT"
ACTION_NAME = "VirusTotal_ScanHash"
PROVIDER = "VirusTotal"


def get_entity_by_identifier(entities, identifier):
    for entity in entities:
        if entity.identifier.lower() == identifier.lower():
            return entity


def add_siemplify_results(siemplify, vt_instance, entity, report, threshold):
    is_risky = False
    entity.additional_properties.update(add_prefix_to_dict(vt_instance.build_hash_enrichment(report),
                                                           VT_PREFIX))
    entity.is_enriched = True

    entity_table = vt_instance.build_engine_csv(report['scans'])
    siemplify.result.add_entity_table(entity.identifier, entity_table)

    web_link = report.get('permalink', 'No permalink found in results.')
    siemplify.result.add_entity_link(entity.identifier, web_link)

    if int(threshold) <= report.get('positives', 0):
        is_risky = True
        entity.is_suspicious = True

        insight_msg = 'VirusTotal - Hash was marked as malicious by {0} of {1} engines. Threshold set to - {2}'.format(
            report.get('positives'), report.get('total'), threshold)

        siemplify.add_entity_insight(entity, insight_msg, triggered_by='VirusTotal')

    return is_risky


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    #conf = siemplify.get_configuration(IDENTIFIER)
    #pi_key = conf['Api Key']
    api_key = "f6d290c8f2d0c4d887a42449efdaf9eb37b13cf8fbc041814d789647ae5cc1f3"
    use_ssl = True
    vt = VirusTotalManager(api_key, use_ssl)
    rescan_after_days = int(siemplify.parameters.get('Rescan after days')) if siemplify.parameters.get('Rescan after days') else None

    entities_handle = {}
    output_message = ""
    siemplify.LOGGER.info("Action START")

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.FILEHASH:
            try:
                # Search a file hash in virusTotal
                entities_handle.update(vt.define_resource_status(entity.identifier, FILEHASH_TYPE, rescan_after_days))

            except Exception as err:
                error_message = 'Error fetching report for entity {0}, Error: {1}'.format(
                    entity.identifier,
                    err.message
                )
                siemplify.LOGGER.error(error_message)
                siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("Sync Part END !!!")
    siemplify.end(output_message, json.dumps(entities_handle), EXECUTION_STATE_INPROGRESS)


def fetch_scan_report_async():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    siemplify.LOGGER.info("ASync Part START !!!")
    conf = siemplify.get_configuration(PROVIDER)
    api_key = conf.get('Api Key')
    use_ssl = conf.get('Verify SSL').lower() == 'true'
    vt = VirusTotalManager(api_key, use_ssl)

    # Extract entities_handle
    # {entity.identifier: {"Report": {}, "Task ID": None, "Status": "Missing/done"}}
    entities_handle = json.loads(siemplify.parameters["additional_data"])
    threshold = siemplify.parameters.get('Threshold', 3)
    json_results = {}
    entities_to_enrich = []
    output_message = ""
    errors_flag = False
    is_risky = False

    for entity_identifier, entity_handle in entities_handle.items():
        task_id = entity_handle.get(ENTITY_TASK_ID_KEY)

        try:
            if task_id and entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.QUEUED:
                # check if analysis completed
                entity_report = vt.is_scan_report_ready(task_id, FILEHASH_TYPE)
                if entity_report:
                    # is_ready = True, fetch the report
                    entity_handle[ENTITY_STATUS_KEY] = ScanStatus.DONE
                    entity_handle[ENTITY_REPORT_KEY] = entity_report

        except Exception as err:
            error_message = 'Error Rescan {0} with task ID {1}, Error: {2}'.format(
                entity_identifier, task_id, err.message)
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors_flag = True

    # Flag to determine the async action status - continue, end
    is_queued_items = False
    for entity_identifier, entity_handle in entities_handle.items():
        if entity_handle[ENTITY_STATUS_KEY] == ScanStatus.QUEUED:
            is_queued_items = True

    if is_queued_items:
        siemplify.LOGGER.info("Continuing...the requested items are still queued for analysis")
        siemplify.end(output_message, json.dumps(entities_handle), EXECUTION_STATE_INPROGRESS)

    # Action END
    else:
        missing_hashes = []
        report_hashes = []
        rescan_hashes = []

        for entity_identifier, entity_handle in entities_handle.items():
            if entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.DONE and entity_handle.get(ENTITY_REPORT_KEY):
                if entity_handle.get(ENTITY_TASK_ID_KEY):
                    rescan_hashes.append(entity_identifier)
                else:
                    report_hashes.append(entity_identifier)

                # Report enrichment & data table
                json_results[entity_identifier] = entity_handle.get(ENTITY_REPORT_KEY)
                entity = get_entity_by_identifier(siemplify.target_entities, entity_identifier)
                try:
                    # Fetch report
                    is_risky_entity = add_siemplify_results(siemplify, vt, entity, entity_handle.get(ENTITY_REPORT_KEY), threshold)
                    if is_risky_entity:
                        is_risky = True
                    entities_to_enrich.append(entity)
                except Exception as err:
                    error_message = 'Error on hash {0}: {1}.'.format(
                        entity_identifier,
                        err.message
                    )
                    siemplify.LOGGER.error(error_message)
                    siemplify.LOGGER.exception(err)
                    errors_flag = True

            else:
                missing_hashes.append(entity_identifier)

        if report_hashes:
            # Fetch report handle
            output_message += "Reports were fetched for the following hashes: \n{0}\n".format(",".join(report_hashes))

        if rescan_hashes:
            # Rescan handle
            output_message += "Rescan the following hashes: \n{0}\n".format(",".join(rescan_hashes))

        if missing_hashes:
            # Missing hash handle
            output_message += "The following hashes does not exist on VirustTotal (file was never scanned before): " \
                              "{0}\n".format(",".join(missing_hashes))

        if errors_flag:
            output_message += "\n\n Errors occurred, check log for more information"

        siemplify.LOGGER.info("Action END !!!")
        siemplify.update_entities(entities_to_enrich)
        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
        siemplify.end(output_message, is_risky, EXECUTION_STATE_COMPLETED)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        fetch_scan_report_async()
