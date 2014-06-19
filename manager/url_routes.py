from flask import Module
from flask import render_template, make_response, request, jsonify
from db_access import upload_document, retrive_document_details
import settings
import json
import subprocess

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
                           'response_data': {'clients': total_clients}
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
            'status': "Idle",
            'action': "start"
        }
        args = json.dumps({
            'command_to_send' : 'check_alive',
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
    if form_data.get('client_rules'):
        for rule in form_data.get('client_rules'):
            doc_url = url + rule.get('host_name')
            result = retrive_document_details({
              'url': doc_url
            })
            if result.get('response_code') != 200:
                resp_text = "client details not present for {0}".format(rule.get('host_name', ''))
                response_data = { 'post_response': { 'response_text' : resp_text}}
                resp = make_response(jsonify(response_data), 400)
                return resp
            else:
                document = result.get('document_data')
                document['rule'] = rule.get('rule')
                document_args = {
                    'url': settings.BASE_URL + "/" + document['_id'],
                    'data' : json.dumps(document),
                    'override_doc' : True
                }
                
                # upload the constructed document
                result = upload_document(document_args)
                # If the document upload is successful
                if not result.get('status'):
                    resp_text = "client details rule update failes for {0}".format(rule.get('host_name', ''))
                    response_data = { 'post_response': { 'response_text' : resp_text}}
                    resp = make_response(jsonify(response_data), 400)
                    return resp
    resp_text = "Successfully updated rule for all the selected clients"
    response_data = { 'post_response': { 'response_text' : resp_text}}
    resp = make_response(jsonify(response_data), 200)
    return resp
    
