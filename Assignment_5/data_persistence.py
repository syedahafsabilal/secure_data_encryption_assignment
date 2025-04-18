import json
import os 
 
def load_data():
    if os.path.exists("stored_data.json"):
        with open("stored_data.json") as f:
                return json.load(f)
    else:
        return {}
def save_data(data):
    with open("stored_data.json","w") as f:
        json.dump(data,f)