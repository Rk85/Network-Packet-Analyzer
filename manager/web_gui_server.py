from flask import Flask,render_template, make_response
from jinja2 import ChoiceLoader,BaseLoader
from werkzeug.wsgi import SharedDataMiddleware
import os
import sys
from db_access import prepare_db
from url_routes import web_routes
from flask import send_from_directory

app = Flask(__name__)


class MyTemplateLoader(BaseLoader):

    def __init__(self, template_folder):
        self.template_folder = template_folder

    def get_source(self, environment, template_name):
        path = os.path.join(self.template_folder, template_name)
        if not os.path.exists(path):
            raise TemplateNotFound(template)
        fd = open(path, "r")
        source = "\r\n".join( fd.readlines() )
        return source, path, lambda : False

app.register_module(web_routes)
@app.route('/')
def load_index():
    return render_template("index.html")                        

@app.route('/static_files/<path:file_name>')
def static_files(file_name):
    return send_from_directory('static_files', file_name)

app.jinja_loader = ChoiceLoader([MyTemplateLoader("templates")])

if __name__ == '__main__':
    if prepare_db():    
        app.run(debug=True, use_reloader=False, threaded=True)
    else:
        print "Unable to configure DB"
