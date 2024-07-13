import time
from flask import Flask, render_template, request, jsonify
import gvm
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
import  openvas_utilities

app = Flask(__name__)

id='admin'
password='admin'

@app.route('/test_api', methods=['POST', 'GET'])
def test_api():
    params = request.args

    # Get body data
    data = request.get_json()

    # Get headers
    #headers = request.headers

    #print('Parameters:', params)
    #print('Data:', data)
    #print('Headers:', headers)
    #data['test'] = 'OK'
    
    return jsonify({"response_message": 'Server test successfull', "status_code": 200}), 200


@app.route('/check_auth', methods=['GET', 'POST'])
def check_auth():

    status, status_text = openvas_utilities.check_auth(id, password)

    message = f"status is {status} and status_text is: {status_text}"
    print(message)
    return jsonify({"auth_status": status,
                     "auth_status_text": status_text,
                    "status_code": 200}), 200


@app.route('/start_scan', methods=['GET', 'POST'])
def start_scan():

    params  = request.args
    ipaddress = params.get("ipaddress")
    report_id, target_id, task_id = openvas_utilities.start_scan(ipaddress, id, password)
    #report_id, target_id, task_id = 'aasd', 'asdsa', "task_id"
    message = f"Your Report id is: {report_id} and Target id is: {target_id} for IP address {ipaddress}"
    print(message)
    return jsonify({"report_id": report_id,
                     "target_id": target_id,
                     "task_id": task_id,
                    "status_code": 200}), 200


@app.route('/get_scan_status', methods=['GET', 'POST'])
def get_scan_status():

    params  = request.args
    task_id = params.get("task_id")
    status, progress = openvas_utilities.get_scan_status(task_id, id, password)
    #status, progress = 'aasd', 'asdsa'
    message = f"The status for task id is : {status} and progress is {progress}"
    print(message)
    return jsonify({"status": status,
                     "progress": progress,
                    "status_code": 200}), 200


@app.route('/generate_report', methods=['GET', 'POST'])
def generate_report():

    params  = request.args
    report_id = params.get("report_id")
    #high, medium, low, log, false_positive, port_count, ip = openvas_utilities.generate_report(report_id)
    output_list = openvas_utilities.generate_report(report_id, id, password)
    #high, medium, low, log, false_positive, port_count, ip = 'high', 'medium', 'low', 'log', 'false_positive', 'port_count', 'ip'
    #message = f"The report for the report_id: {report_id} is"   "high: {high}, medium: {medium}, low : {low}, log: {log}, false_positive: {false_positive}, port_count: {port_count}, ip: {ip}"
    message = f"output result report stats: {output_list}"
    print(message)
    return output_list 
    #return jsonify({ "high": high, 
     #               "medium": medium,
      #              "low":  low, 
       #             "log": log, 
      #              "false_positive": false_positive, 
      #              "port_count":port_count,
      #              "ip": ip,
      #              "status_code": 200}), 200

 
if __name__ == '__main__':
    app.run()

