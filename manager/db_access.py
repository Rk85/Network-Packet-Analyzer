import urllib2
import settings
import json

def open_server_connection(args):
    """
        Connects with the couch db server and 
        returns the connection handler 
    """
    # create a handler.
    handler = urllib2.HTTPHandler()

    # create an openerdirector instance
    opener = urllib2.build_opener(handler)
    
    # Construct the Request object with all the available details
    request = urllib2.Request(args.get('url'), data=args.get("data", None))
    for header_name, header_value in args.get("headers", {}).iteritems():
        request.add_header(header_name, header_value)
    request.get_method = lambda: args.get("method", "GET")

    connection = ''
    try:
        connection = opener.open(request)
    except (urllib2.HTTPError, urllib2.URLError) as e:
        return e
    return connection

def configure_db():
    """
        Configures the Couch db server and creats the DB in that
    """
    url = settings.BASE_URL
    args = {
        "method" : "PUT",
        "url": url
    }
    connection = open_server_connection(args)
    try:
        return True if connection and connection.code in [201, 412] else False
    except AttributeError as e:
        return False

def retrive_document_details(args):
    """
      Retrievs the details of documents with given URL.
      URL may point to document/view/show/list
    """
    # Query the document details
    connection = open_server_connection(args)
    doc_details = { 
                'response_code' :  connection and connection.code,
                'document_data': json.loads(connection.read())
    }
    connection.close()
    return doc_details

def upload_document(args):
    """
      uploads the document in the db
    """
    connection = None
    result = {
                'status' : None,
                'resp_text' : None,
                'reason': None,
                'already_present': None
    }
    upload_data = args['data']
    # make data as empty before querying the document details
    args['data'] = None
    
    # Query the preious document details
    old_doc_details = retrive_document_details(args)
    
    # Set default headers for document uploading 
    args['method'] = "PUT"
    args['Content-Type'] = 'application/json'
    try:
        # If the document already not present in the DB
        # upload a new one there
        if ( old_doc_details.get('response_code') == 404 ):
            # Assign the data back to the uploading details
            args['data'] = upload_data
            connection = open_server_connection(args)
            # Document successfully uploaded
            if connection.code == 201:
                result.update({
                                'status': True,
                                'resp_text': "{0} details successfully added",
                                'already_present': False
                })
            # Some issue while uploading the document
            else:
                result.update({
                                'status': False,
                                'resp_text': "{0} details unable to add",
                                'reason':  connection.read(),
                                'already_present': False
                })
        # If the document already present in the DB
        elif old_doc_details.get('response_code') == 200 :
            # and over-write option is set in request args
            if args.get('override_doc'):
                # convert the string data into json data
                upload_data = json.loads(upload_data)
                # get the previous document revision number
                # and add that to new document uploading args
                upload_data['_rev'] = old_doc_details['document_data']['_rev']
                args['data'] = json.dumps(upload_data)
                # upload the new document update
                connection = open_server_connection(args)
                # document update is successful
                if connection.code == 201:
                    result.update({
                                    'status': True,
                                    'resp_text': "{0} details successfully updated",
                                    'already_present': True
                    })
                # document update is not successful
                else:
                    result.update({
                                    'status': False,
                                    'resp_text': "{0} details unable to update",
                                    'reason':  connection.read(),
                                    'already_present': True
                    })
            # Document is already present but override option not
            # set in request arguement
            else:
                result.update({
                                'status': True,
                                'resp_text': "This {0} already present in the DB",
                                'already_present': True
                })
        # Un-wanted response received from DB
        else:
            result.update({
                            'status': False,
                            'resp_text': "Unknown Response",
                            'reason':  connection.read(),
                            'already_present': False
            })
    except Exception as e:
        result.update({
                        'status': False,
                        'resp_text': "Exception Occured while uploading document",
                        'reason':  str(e) ,
                        'already_present': False
            })
        if connection:
            connection.close()
        raise
        return result
    if connection:
        connection.close()
    return result

def prepare_db():
    """
      Prepares the Couch DB for normal operations
    """
    design_doc_url = settings.BASE_URL + "/_design/network_packet_analyzer"
    if ( configure_db() ):
        design_doc_args = {
            'url': design_doc_url,
            'override_doc' : settings.REWRITE_DESIGN
        }
        design_doc_args['data'] =  settings.DESIGN_DATA
        # upload our design document
        result = upload_document(design_doc_args)
        if ( result.get('status') ):
            return True
        return False
    else:
        return False
