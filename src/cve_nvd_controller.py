import json

import requests
from flask import request, render_template, Response
from flask.views import MethodView

from task_functions import task_3_1, task_3_2, task_3_2_2_and_4_3, task_4_1, task_4_2


class NvdCveController(MethodView):
    def __init__(self, host_addr):
        self.get_url: str = host_addr

    def get(self, task: str):
        year = request.args.get('year') if request.args.get('year') else "2023"
        range = request.args.get('range') if request.args.get('range') else "2002-2020"
        select_id = request.args.get('ids') if request.args.get('ids') else "3,9,10"
        params = {'Year': year, 'Range': range, 'SelectID': select_id}
        if task == "3.1":
            response = requests.get(self.get_url + task, params=params, verify=False)
            data = NvdCveController.check_return_response(response=response)
            print("This is data in response", data)
            task_3_1(data, args=params)
            return render_template('plotly_graphs_'+task.replace(".", "_")+'.html')
        elif task == "3.2":
            response = requests.get(self.get_url + task, params=params, verify=False)
            data = NvdCveController.check_return_response(response=response)
            task_3_2(data)
            return render_template('plotly_graphs_'+task.replace(".", "_")+'.html')
        elif task == "3.2.cvss":
            response = requests.get(self.get_url + task, params=params, verify=False)
            data = NvdCveController.check_return_response(response=response)
            task_3_2_2_and_4_3(cvss_data=data)
            return render_template('plotly_graphs_'+task.replace(".", "_")+'.html')
        elif task == "4.1":
            response = requests.get(self.get_url + task, params=params, verify=False)
            data = NvdCveController.check_return_response(response=response)
            task_4_1(data)
            return render_template('plotly_graphs_'+task.replace(".", "_")+'.html')
        elif task == "4.2":
            response = requests.get(self.get_url + task, params=params, verify=False)
            data = NvdCveController.check_return_response(response=response)
            # Access the dictionaries in the response
            dict1 = data['dict1']
            dict2 = data['dict2']
            task_4_2(component_vuln=dict1,correlation_expression=dict2)
            return render_template('plotly_graphs_'+task.replace(".", "_")+'.html')
        elif task == "4.3":
            response = requests.get(self.get_url + task, params=params, verify=False)
            data = NvdCveController.check_return_response(response=response)
            task_3_2_2_and_4_3(cvss_data=data, is_frequency_reported=True)
            return render_template('plotly_graphs_'+task.replace(".", "_")+'.html')

    @staticmethod
    def check_return_response(response):

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Handle the response data
            # Check if the response has a 'Content-Type' header
            if 'Content-Type' in response.headers and 'application/json' in response.headers['Content-Type']:
                # Response data is JSON
                json_data = response.json()
                try:
                    # Parse the response text into a dictionary
                    if type(json_data) is dict:
                        print(json_data)
                        return json_data
                    else:
                        response_data = json.loads(json_data)
                        # Now, response_data is a Python dictionary
                        return response_data
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON: {e}")
                    return Response("Invalid Data", status=400, content_type='text/plain')
            else:
                # Response data is not JSON
                try:
                    # Parse the response text into a dictionary
                    response_data = json.loads(response.text)

                    # Now, response_data is a Python dictionary
                    return response_data
                except json.JSONDecodeError as e:
                    return Response("Invalid Data", status=400, content_type='text/plain')
        else:
            return {response.status_code}
