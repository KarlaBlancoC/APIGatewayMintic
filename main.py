from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve

app = Flask(__name__)
cors = CORS(app)

def load_file_config():
    with open("config.json") as f:
        return json.load(f)

@app.route("/",methods=["GET"])
def test():
    data = {"message": "Servidor del API Gateway corriendo"}
    return jsonify(data)

if __name__ == '__main__':
    data_config = load_file_config()
    print(f"Server running: http://{data_config['url-backend']}:{data_config['port']}")
    serve(app, host=data_config["url-backend"],port=data_config["port"])