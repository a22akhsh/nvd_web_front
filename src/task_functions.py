from backend_filter.analyse import CveNvdAnalysis
from plot_graphs.graphical_analysis import PlotCveNvdGraphs


def task_3_1(cve_year_basis_vul, args):
    """
    # task-3.1 part 1: Show graphically the scale of reported vulnerabilities from 2002 until 2020.
    # Use the provided python scripts to obtain the data that you will report graphically.
    # Write a brief comment summarizing your observation.
    """
    total_reported = 0
    print("This is cve: ", cve_year_basis_vul)
    for year in cve_year_basis_vul:
        print(cve_year_basis_vul[year])
        total_reported += int(cve_year_basis_vul[year])
    PlotCveNvdGraphs.show_cve_nvd_graphical_view(cve_year_basis_vul, args['Range'], total_vuln=total_reported,
                                                 task_name="3_1")
    # PlotCveNvdGraphs.draw_plotify_based_graph(df=cve_year_basis_vul,
    #                                          title="Total number number of vulnerabilities reported in years",
    #                                          task_name="3_1")


def task_3_2(component_vuln):
    """
    RTU, PLC, HMI, MTU
    – Report graphically the scale of vulnerability instances for each of the
    following CPS component types: RTU, PLC, HMI, MTU, across all years.
    :param component_vuln:
    :return:
    """
    extract_data_and_plot(component_vuln=component_vuln, task_name="3_2")


def task_4_1(component_vuln):
    """
    Task 4.1: Threats Instances –Use the above search description()
    function to identify the following exploiting threats: overflow,
    denial of service, sql injection, Cross-Site, memory corruption.
    Propose a brief description of each of these threat instances and
    visualize graphically in a chart the number of vulnerability report
    instances corresponding to each of these threats.
    Hint: search description for threat types. Discuss briefly the resulting graphic
    :param component_vuln:
    :return:
    """
    extract_data_and_plot(component_vuln=component_vuln, task_name="4_1")


def task_4_2(component_vuln, correlation_expression):
    """
    Task 4.2: CPS threats –Correlate the above threat instances agains CPS vulnerabilities to
    visualize threats that apply only to CPS components. Discuss the results.
    You may utilise the functions shown below, or implement your own code.
    :param correlation_expression:
    :param component_vuln:
    :return:
    """
    extract_data_and_plot(component_vuln=component_vuln,
                          extra_comparison=correlation_expression, task_name="4_2")


def task_3_2_2_and_4_3(cvss_data, is_frequency_reported=False):
    """
    Task 3.2 (Part-2)
    – Compute the average CVSS scores for each of the above CPS component types, and briefly summarize your observations

    Task 4.3: Others –Propose any other interesting data correlation and a related graphical visualization along
    with a brief explanation.
    :param cvss_data:
    :param is_frequency_reported:
    :return:
    """
    task_name = "3_2_cvss"
    if is_frequency_reported:
        task_name = "4_3"
    PlotCveNvdGraphs.draw_plotify_based_graph(cvss_data, "CVSS Score Stats", sub_expressions=None, is_cvss_score=True,
                                              is_frequency_report=is_frequency_reported, task_name=task_name)


def extract_data_and_plot(component_vuln=None, extra_comparison=None, task_name=None):
    PlotCveNvdGraphs.draw_plotify_based_graph(component_vuln, "Vulnerabilities reported",
                                              sub_expressions=extra_comparison, task_name=task_name)
