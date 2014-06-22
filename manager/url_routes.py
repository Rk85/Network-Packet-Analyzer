from flask import Module
from flask import render_template, make_response, request, jsonify
from db_access import upload_document, retrive_document_details
import settings
import json
import subprocess

RULES = [
	{'display_name': "Sorce IP",
	 'rule_name' : "src host"
	},
	{'display_name': "Source Port", 
	 'rule_name': "src port"
	}
]

CLIENT_DISPLAY_FILTERS = [
        {
            'name': "All Clients",
            'id': 'all'
        },
        {
            'name': "Configure Rules",
            'id': 'new_add'
        },
        {
            'name': "Start Capture",
            'id': 'rule_configured'
        },
        {
            'name': "Stop Capture",
            'id': 'capture_started'
        }
    ]

web_routes = Module(__name__, url_prefix="/clients", name="client_routes")

@web_routes.route('/show', methods=['GET', 'POST'])
def all_clients_details():
    """
        Handle the clients display requests
    """
    design = json.loads(settings.DESIGN_DATA)
    url = settings.BASE_URL + "/" + design['_id'] + "/_view/all_clients"
       
    if request.method == 'GET':
        result = retrive_document_details({
              'url': url
        })
        total_clients = result['document_data']['rows']
        response_data = {  'form' : render_template('configured_clients.html'),
                           'response_data': {
												'clients': total_clients,
                                                'rules': RULES,
                                                'client_filters': CLIENT_DISPLAY_FILTERS
										}
                        }
        resp = make_response(jsonify(response_data), 200)
        return resp

@web_routes.route('/add', methods=['GET', 'POST'])
def add_client():
    """
        Handles the client addition requests
    """
    if request.method == 'GET':
        response_data = {  'form' : render_template('add_client.html'),
                           'response_data': {}
                        }
        resp = make_response(jsonify(response_data), 200)
        return resp
    else:
        # Construct the client request details
        # into json document for uploading into the db
        form_data = request.json if request.json else request.form
        document_data = {
            '_id' : form_data.get('host_name'),
            'host_name': form_data.get('host_name'),
            'details': form_data.get('client_details'),
            'ip' : form_data.get('ip'),
            'status_name': "new_add"
        }
        args = json.dumps({
            'command_to_send' : 'receive_packet_sniffer_file',
            'ip': document_data['ip'],
             'port': 8081
        })
        p = subprocess.Popen(['python', 'command_sender.py', args])
        p.wait()
        if p.returncode == 0:
            document_args = {
                'url': settings.BASE_URL + "/" + form_data.get('host_name'),
                'data' : json.dumps(document_data)
            }
         
            # upload the constructed document
            result = upload_document(document_args) 
        
            # If the document upload is successful
            if result.get('status') and not result.get('already_present'):
                resp_text = result.get('resp_text').format('client')
                response_data = { 'post_response': { 'response_text' : resp_text}}
                resp = make_response(jsonify(response_data), 200)
            # document upload is not successful
            else:
                resp_text = result.get('resp_text').format('client')
                response_data = { 'post_response': { 'response_text' : resp_text}}
                resp = make_response(jsonify(response_data), 400)
        else:
            resp_text = "Unknown error while reaching client"
            response_data = { 'post_response': { 'response_text' : resp_text}}
            resp = make_response(jsonify(response_data), 400)
        return resp

@web_routes.route('/add/rule', methods=['POST'])
def add_client_rule():
    """
		Adds the packet sniffing rules of the clients
    """
    url = settings.BASE_URL + "/" 
    form_data = request.json if request.json else request.form
    if form_data.get('clients'):
        for client in form_data.get('clients'):
            doc_url = url + client.get('host_name')
            result = retrive_document_details({
              'url': doc_url
            })
            if result.get('response_code') != 200:
                resp_text = "client details not present for {0}".format(client.get('host_name', ''))
                response_data = { 'post_response': { 'response_text' : resp_text}}
                resp = make_response(jsonify(response_data), 400)
                return resp
            else:
                document = result.get('document_data')
                document['rules'] = client.get('rule')
                document['status_name'] = 'rule_configured'
                document_args = {
                    'url': settings.BASE_URL + "/" + document['_id'],
                    'data' : json.dumps(document),
                    'override_doc' : True
                }
                
                # upload the constructed document
                result = upload_document(document_args)
                # If the document upload is successful
                #if not result.get('status'):
                if not result.get('status'):
                    resp_text = "client details rule update failes for {0}".format(rule.get('host_name', ''))
                    response_data = { 'post_response': { 'response_text' : resp_text}}
                    resp = make_response(jsonify(response_data), 400)
                    return resp
    resp_text = "Successfully updated rule for all the selected clients"
    response_data = { 'post_response': { 'response_text' : resp_text}}
    resp = make_response(jsonify(response_data), 200)
    return resp

@web_routes.route('/start/capture', methods=['POST'])
def start_packet_capture():
    """
		Starts the packet sniffing program in client machines
    """
    url = settings.BASE_URL + "/" 
    form_data = request.json if request.json else request.form
    if form_data.get('clients'):
        for client_id in form_data.get('clients'):
            doc_url = url + client_id
            result = retrive_document_details({
              'url': doc_url
            })
            if result.get('response_code') != 200:
                resp_text = "client details not present for {0}".format(client_id)
                response_data = { 'post_response': { 'response_text' : resp_text}}
                resp = make_response(jsonify(response_data), 400)
                return resp
            else:
                document = result.get('document_data')
                rules = document['rules']
                document['status_name'] = 'capture_started'
                document_args = {
                    'url': doc_url,
                    'data' : json.dumps(document),
                    'override_doc' : True
                }
                capture_rules = []
                for rule in rules: 
                    if rule.get('append_type'):
                        capture_rules.extend( [ rule['rule_name'], rule['rule_value'], rule['append_type'] ])
                    else:
                        capture_rules.extend( [ rule['rule_name'], rule['rule_value'] ])
                args = json.dumps({
                        'command_to_send' : 'start_packet_sniffing',
                        'ip': document['ip'],
                        'port': 8081,
                        'capture_rules': capture_rules
                })
                p = subprocess.Popen(['python', 'command_sender.py', args])
                p.wait()
                if p.returncode == 0:
                    # upload the constructed document
                    result = upload_document(document_args)
                # If the document upload is successful
                #if not result.get('status'):
                if not result.get('status') or p.returncode !=0 :
                    resp_text = "Error Happened while starting sniffer for {0}".format(client_id)
                    response_data = { 'post_response': { 'response_text' : resp_text}}
                    resp = make_response(jsonify(response_data), 400)
                    return resp
    resp_text = "Successfully started packet sniffing for all the selected clients"
    response_data = { 'post_response': { 'response_text' : resp_text}}
    resp = make_response(jsonify(response_data), 200)
    return resp

@web_routes.route('/stop/capture', methods=['POST'])
def stop_packet_capture():
    """
		Stops the packet sniffing program in client machines
    """
    url = settings.BASE_URL + "/" 
    form_data = request.json if request.json else request.form
    if form_data.get('clients'):
        for client_id in form_data.get('clients'):
            doc_url = url + client_id
            result = retrive_document_details({
              'url': doc_url
            })
            if result.get('response_code') != 200:
                resp_text = "client details not present for {0}".format(client_id)
                response_data = { 'post_response': { 'response_text' : resp_text}}
                resp = make_response(jsonify(response_data), 400)
                return resp
            else:
                document = result.get('document_data')
                document['status_name'] = 'rule_configured'
                document_args = {
                    'url': doc_url,
                    'data' : json.dumps(document),
                    'override_doc' : True
                }
                args = json.dumps({
                        'command_to_send' : 'stop_packet_sniffing',
                        'ip': document['ip'],
                        'port': 8081,
                })
                p = subprocess.Popen(['python', 'command_sender.py', args])
                p.wait()
                # upload the constructed document
                result = upload_document(document_args)
                # If the document upload is successful
                #if not result.get('status'):
                if not result.get('status') or p.returncode !=0 :
                    resp_text = "Error Happened while stoping sniffer for {0}".format(client_id)
                    response_data = { 'post_response': { 'response_text' : resp_text}}
                    resp = make_response(jsonify(response_data), 400)
                    return resp
    resp_text = "Successfully stopped packet sniffing for all the selected clients"
    response_data = { 'post_response': { 'response_text' : resp_text}}
    resp = make_response(jsonify(response_data), 200)
    return resp


@web_routes.route('/stats', methods=['GET'])
def show_client_statistics():
    """
        Show statistics of packets for all the clients
    """
    design = json.loads(settings.DESIGN_DATA)
    url = settings.BASE_URL + "/" + design['_id'] + "/_view/all_clients"
    result = retrive_document_details({
              'url': url
    })
    clients = []
    if request.method == 'GET':
        if result.get('response_code') == 200:
            result_data = result.get('document_data', {})
            for client in result_data.get('rows'):
                client = client.get('value')
                client_url = settings.BASE_URL + "/" + client['_id']
                args = json.dumps({
                        'command_to_send' : 'send_packet_stats',
                        'ip': client['ip'],
                        'port': 8081,
                        'url': client_url
                })
                p = subprocess.Popen(['python', 'command_sender.py', args])
                p.wait()
                client_result = retrive_document_details({'url': client_url})
                if client_result.get('response_code') == 200:
                    clients.append( client_result.get('document_data') )
        response_data = {  'form' : render_template('client_stats.html'),
                           'response_data': {
                                                'clients': clients,
                                                'rules': RULES,
                                                'client_filters': CLIENT_DISPLAY_FILTERS
                                        }
                        }
        resp = make_response(jsonify(response_data), 200)
        return resp

