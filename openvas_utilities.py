import datetime
import sys
from argparse import Namespace
from gvm.transforms import EtreeTransform
import gvm
from gvm.protocols.latest import Gmp
from gvm.xml import pretty_print
from lxml.etree import fromstring


def check_auth(id, password):
    connection = gvm.connections.UnixSocketConnection(path='/run/gvmd/gvmd.sock')

    transform = EtreeTransform()
    with Gmp(connection, transform=transform) as gmp:
        response = gmp.authenticate(id, password)
        print("auth response")
        pretty_print(response)
        status = response.get('status')
        status_text = response.get('status_text')

    return status, status_text



def create_target(gmp, ipaddress, port_list_id):
    # create a unique name by adding the current datetime
    name = f"Suspect Host {ipaddress} {str(datetime.datetime.now())}"

    response = gmp.create_target(
        name=name, hosts=[ipaddress], port_list_id=port_list_id
    )
    print("target response")
    pretty_print(response)
    return response.get("id")


def create_task_wrapper(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    name = "Scan Suspect Host {ipaddress}"
    print("target id: ", target_id)
    response = gmp.create_task(
        name=name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    return response.get("id")


def start_task(gmp, task_id):
 
    response = gmp.start_task(task_id)
    print("task id api response:", response )
    pretty_print(response)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    return response[0].text


def start_scan(ipaddress, id, password) -> None:

    connection = gvm.connections.UnixSocketConnection(path='/run/gvmd/gvmd.sock')

    transform = EtreeTransform()
    with Gmp(connection, transform=transform) as gmp:
        r = gmp.authenticate(id, password)
        print("auth response")
        pretty_print( r)
        
        # ipaddress = '127.0.0.2'
        port_list_id = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
        args = [ipaddress,port_list_id]
        target_id = create_target(gmp, ipaddress, port_list_id)

        full_and_fast_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"
        openvas_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        task_id = create_task_wrapper(
            gmp,
            ipaddress,
            target_id,
            full_and_fast_scan_config_id,
            openvas_scanner_id,
        )

        report_id = start_task(gmp, task_id)

        print(
            f"Started scan of host {ipaddress}. "
            f"Corresponding report ID is {report_id}"
            f"task id is {task_id}"
        )

        return report_id, target_id, task_id


def get_scan_status(task_id, id, password):
    connection = gvm.connections.UnixSocketConnection(path='/run/gvmd/gvmd.sock')

    transform = EtreeTransform()

    with Gmp(connection, transform=transform) as gmp:
        r = gmp.authenticate(id, password)
        print("auth response")
        pretty_print( r)

        response_xml = gmp.get_task(task_id=task_id) 
        pretty_print(response_xml)
        #response = fromstring(response_xml.encode('utf-8'))
        
        status = response_xml.xpath("/get_tasks_response/task/status").pop()
        progress = response_xml.xpath("/get_tasks_response/task/progress").pop()
        print("status " , status.text)
        print("progress " , progress.text)

        return status.text, progress.text


def generate_report(report_id, id, password):
    connection = gvm.connections.UnixSocketConnection(path='/run/gvmd/gvmd.sock')

    transform = EtreeTransform()

    with Gmp(connection, transform=transform) as gmp:
        r = gmp.authenticate(id, password)
        print("auth response")
        pretty_print( r)
 
        # report_id = "9e59435c-9667-415d-9bd3-594ee483a374"

        #pdf_filename = "/home/admin1/Desktop/test_report.pdf"
     
        # pdf_report_format_id = "c402cc3e-b531-11e1-9163-406186ea4fc5"
        #pdf_report_format_id = 'a994b278-1f62-11e1-96ac-406186ea4fc5'
        #print(report_id)
        response = gmp.get_report(
            report_id=report_id, 
            #report_format_id=pdf_report_format_id,
            details=True
        )
        pretty_print(response)
        werte = response.xpath('report/report/host')
        #print(werte)
        output_list = []
        for host in werte:
            high = host.xpath('result_count/hole/page/text()')[0]
            medium = host.xpath('result_count/warning/page/text()')[0]
            low = host.xpath('result_count/info/page/text()')[0]
            log = host.xpath('result_count/log/page/text()')[0]
            false_positive = host.xpath('result_count/false_positive/page/text()')[0]
            port_count = host.xpath('port_count/page/text()')[0]
            ip = host.xpath('ip/text()')[0]
            print("Count: ", high, medium, low, log, false_positive, port_count, ip)
            temp_dict = { "high": high, 
                    "medium": medium,
                    "low":  low, 
                    "log": log, 
                    "false_positive": false_positive, 
                    "port_count":port_count,
                    "ip": ip}
            output_list.append(temp_dict)
        return output_list
        

# start_scan("www.cloudxcess.com")
