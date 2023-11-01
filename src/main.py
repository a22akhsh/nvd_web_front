# This is an analysis of online vulnerability analysis Python Project.
# Task 4 – Correlations
import os
import argparse

from flask import Flask

import cve_nvd_controller
from task_functions import task_3_1, task_3_2, task_3_2_2_and_4_3, task_4_1, task_4_2
from backend_filter.analyse import CveNvdAnalysis

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-r", "--Range", default="2002-2020",
                    help="Provide range of years to analyse in acceptable format for example "
                         "2001-2020")
parser.add_argument("-y", "--Year", default="",
                    help="Provide the specific year to analyse in acceptable format for example "
                         "2001-2020", required=False)
parser.add_argument("-select_id", "--SelectID", default="1,2,3", help="Provide the selection ID for CVE entries ID, "
                                                                      "problem type data and description to display on "
                                                                      "screen. Do not provide more than 3 ids to select"
                                                                      ", correct input is 1,2,3 or 49,10 like this.",
                    required=False)
parser.add_argument("-t", "--Task", default="",
                    help="Provide the task id to execute for example 3_x, 3.2.cvss or 4_x", required=False)

# Read arguments from command line
args = parser.parse_args()


if __name__ == '__main__':
    print("execution started")
    # https://localhost:8081/v1/cve/backend/ - Default
    host_address = os.getenv('host_addr', default="https://localhost:8081/v1/cve/backend/")
    app = Flask(__name__)
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.add_url_rule("/v1/cve/nvd_web_front/<task>",
                     view_func=cve_nvd_controller.NvdCveController.as_view("cve_nvd_analysis_critical_infrastructure",
                                                                           host_address))
    app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')
    # docker pull erakhi/nvd-backend-data:0.1
    # kubectl create deployment nvd-backend --image=erakhi/nvd-backend-data:0.1 -n cve-nvd


