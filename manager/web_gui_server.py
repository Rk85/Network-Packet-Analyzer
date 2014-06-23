from flask import Flask,render_template, make_response
from jinja2 import ChoiceLoader,BaseLoader
from werkzeug.wsgi import SharedDataMiddleware
import os
import sys
from db_access import prepare_db
from url_routes import web_routes
from flask import send_from_directory
import logging
from logging import config
import settings

logging.config.dictConfig(settings.LOG_CONFIG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

app = Flask(__name__)

class MyTemplateLoader(BaseLoader):
    '''
        Description : Customized class to the templates through jinja
        
    '''

    def __init__(self, template_folder):
        '''
            Description : Init function to initialize the template loader class
            
        '''
        self.template_folder = template_folder

    def get_source(self, environment, template_name):
        '''
            Description : Returns the template details to the jinja environment
            
            input_param : environment - details of the jinja enviroment
            input_type : dict
            
            input_param : template_name - Name of the template to be rendered
            input_type : string
            
            out_param : source - template source
            out_type : string
            
            out_param : path - path of the template folder
            out_type : string
            
            out_param : lambda - function to check whether the template 
                            should be read again not. False-changed, 
                            True-not changed
            out_type : function object
            
        '''
        path = os.path.join(self.template_folder, template_name)
        if not os.path.exists(path):
            raise TemplateNotFound(template)
        fd = open(path, "r")
        source = "\r\n".join( fd.readlines() )
        return source, path, lambda : False

app.register_module(web_routes)
@app.route('/')
def load_index():
    '''
        Description : View function to load the root URL
        
    '''
    return render_template("index.html")                        

@app.route('/static_files/<path:file_name>')
def static_files(file_name):
    '''
        Description : View function to the static files
        
    '''
    return send_from_directory('static_files', file_name)

app.jinja_loader = ChoiceLoader([MyTemplateLoader("templates")])

if __name__ == '__main__':
    if prepare_db():    
        app.run(debug=True, use_reloader=False, threaded=True)
    else:
        logger.error("Unable to configure DB")
