import os
from functools import reduce
from random import choice

import matplotlib
import matplotlib.pyplot as plt
import plotly.graph_objects as go


class PlotCveNvdGraphs:

    def __init__(self):
        pass

    @staticmethod
    def show_cve_nvd_graphical_view(cve_year_basis_data: dict, bin_range: str, component_type=None,
                                    total_vuln=None, task_name=None):
        """
        Plots graph using Matplot library for task 3.1
        :param task_name:
        :param cve_year_basis_data: year basis data set
        :param bin_range: range of plot
        :param component_type: name of component
        :param total_vuln: total vulnerabilities reported
        :return: NA

        matplotlib.use('agg')
        # total vulnerabilities
        total_vul = []
        # labels for bars
        tick_label = []
        for key in cve_year_basis_data.keys():
            total_vul.append(cve_year_basis_data[key])
            tick_label.append(key)
        # plotting a bar chart
        plt.bar(range(len(cve_year_basis_data)), total_vul, tick_label=tick_label,
                width=0.8)
        # x-axis label
        plt.xlabel(('' if component_type is None else component_type) + " Report vulnerabilities in years")
        # frequency label
        plt.ylabel('Scale of reported vulnerabilities ' + ("" if total_vul is None else "- Total vulnerabilities "
                                                                                        "reported " + str(total_vuln)))
        # plot title
        plt.title('Years from ' + bin_range)
        # function to show the plot
        print(os.getcwd())

        plt.savefig(os.getcwd() + '/static/images/scale_of_reported_vul.png')
        """
        # Specify the plots
        bar_plots = []
        xaxis_ticktext = []
        total_vul = []
        tick_label = []
        color = ["#" + ''.join([choice('0123456789ABCDEF') for j in range(6)])
                 for i in range(50)]
        color_index = 0
        print("Start of plotting graphs")
        xtitle = "Total vulnerabilities per year"
        title = "Total reported vulnerabilities = " + str(total_vuln)
        # PlotCveNvdGraphs.__plot_vulnerability_graph(bar_plots, color, color_index, cve_year_basis_data,
        # xaxis_ticktext)
        for key1 in cve_year_basis_data.keys():
            # total vulnerabilities
            total_vul.append(cve_year_basis_data[key1])
            # labels for bars
            tick_label.append(key1)
            xaxis_ticktext.append(int(key1))
            bar_plots.append(go.Bar(x=tick_label, y=total_vul, name=key1,
                                    marker=go.bar.Marker(color=color[color_index])))
            total_vul=[]
            tick_label=[]
            # xaxis_ticktext=[]
            color_index += 1

        # Customise some display properties
        xaxis_ticktext = list(set(xaxis_ticktext))
        layout = go.Layout(
            title=go.layout.Title(text=title, x=0.5),
            yaxis_title=xtitle,
            xaxis_tickmode="array",
            xaxis_tickvals=xaxis_ticktext,
            xaxis_ticktext=tuple(xaxis_ticktext),
        )

        # Make the multi-bar plot
        fig = go.Figure(data=bar_plots, layout=layout)
        PlotCveNvdGraphs.draw_html_plotly(fig=fig, task=task_name)

    @staticmethod
    def draw_plotify_based_graph(df: dict, title: str, number_of_colors: int = 50, sub_expressions: dict = {},
                                 is_cvss_score: bool = False, is_frequency_report: bool = False, task_name=None):
        """
        This method draws the bar graphs for the passed data set.
        :param task_name:
        :param df: Data set to draw
        :param title: title of the chart
        :param number_of_colors: total number of colors to be applied
        :param sub_expressions: sub expressions
        :param is_cvss_score: if yes then plot cvss score only
        :param is_frequency_report: if yes then report frequency of occurrence with cvss_score
        :return: NA
        """
        # Specify the plots
        bar_plots = []
        xaxis_ticktext = []
        color = ["#" + ''.join([choice('0123456789ABCDEF') for j in range(6)])
                 for i in range(number_of_colors)]
        color_index = 0
        print("Start of plotting graphs")
        if sub_expressions:
            xtitle = "threat instances against CPS vulnerabilities reported"
            title = "threat instances reported"
            PlotCveNvdGraphs.__plot_instances_relation_graph_with_cvs_component(bar_plots, color, color_index,
                                                                                sub_expressions, xaxis_ticktext)
        elif is_cvss_score:
            if is_frequency_report:
                xtitle = "cvss base score avg value per year and reported frequencies for CPS components"
                title = "cvss score and reported frequency ranges for CPS components"
            else:
                xtitle = "cvss base score avg value per year for CPS components"
                title = "cvss score reported ranges for CPS components"
            print("is cvss true", is_cvss_score)
            print("is frequency true", is_frequency_report)
            PlotCveNvdGraphs.__plot_cvss_score_graph(bar_plots, color, color_index, df, xaxis_ticktext,
                                                     is_frequency_report)

        else:
            xtitle = "total vulnerabilities"
            title = "reported vulnerabilities"
            PlotCveNvdGraphs.__plot_vulnerability_graph(bar_plots, color, color_index, df, xaxis_ticktext)

        xaxis_ticktext = list(range(2002, 2024)) if sub_expressions else list(set(xaxis_ticktext))

        # Customise some display properties
        layout = go.Layout(
            title=go.layout.Title(text=title, x=0.5),
            yaxis_title=xtitle,
            xaxis_tickmode="array",
            xaxis_tickvals=xaxis_ticktext,
            xaxis_ticktext=tuple(xaxis_ticktext),
        )

        # Make the multi-bar plot
        fig = go.Figure(data=bar_plots, layout=layout)
        PlotCveNvdGraphs.draw_html_plotly(fig=fig, task=task_name)
        # print(str(fig.show()))
        # Tell Plotly to render it
        # fig.show()
        # fig.to_image('png')

    @classmethod
    def draw_html_plotly(cls, fig, task):
        # convert it to JSON
        fig_json = fig.to_json()

        # a simple HTML template
        template = """<html>
        <head>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        </head>
        <body>
            <div id='divPlotly'></div>
            <script>
                var plotly_data = {}
                Plotly.react('divPlotly', plotly_data.data, plotly_data.layout);
            </script>
        </body>

        </html>"""

        # write the JSON to the HTML template
        with open(os.getcwd() + '/templates/plotly_graphs_' + task + '.html', 'w') as f:
            f.write(template.format(fig_json))

    @classmethod
    def __plot_instances_relation_graph_with_cvs_component(cls, bar_plots, color, color_index, sub_expressions,
                                                           xaxis_ticktext):
        """
        Plots graph which displays relationship between CPS component and threat instances
        :return:
        """
        print("Plotting sub-expression graph")
        for key3 in sub_expressions.keys():
            sub_keys = sub_expressions[key3].keys()
            print(sub_keys)
            for key4 in sub_keys:
                sorted_keys = sorted(sub_expressions[key3][key4].keys())
                # total vulnerabilities
                total_vul = []
                # labels for bars
                tick_label = []
                for key5 in sorted_keys:
                    total_vul.append(sub_expressions[key3][key4][key5])
                    tick_label.append(key5)
                    xaxis_ticktext.append(key5)
                tick_label, total_vul = PlotCveNvdGraphs.__fill_missing_values_and_years(tick_label, total_vul)
                bar_plots.append(go.Bar(x=tick_label, y=total_vul, name=key3 + "-" + key4,
                                        marker=go.bar.Marker(color=color[color_index])))
                color_index += 1

    @classmethod
    def __fill_missing_values_and_years(cls, tick_label: list, total_vul: list):
        full_year_range = list(range(2002, 2024))
        values = list(range(2002, 2024))
        index = 0
        for year1 in full_year_range:
            if str(year1) in tick_label:
                values[index] = total_vul[tick_label.index(str(year1))]
            else:
                values[index] = 0
            index += 1
        return full_year_range, values

    @classmethod
    def __plot_vulnerability_graph(cls, bar_plots, color, color_index, df, xaxis_ticktext):
        """
        Plots generic bar graph for vulnerabilities reported for given data set
        """
        print("Plotting normal graph")
        for key1 in df.keys():
            # total vulnerabilities
            total_vul = []
            # labels for bars
            tick_label = []
            print(df[key1])
            if type(df[key1]) is not dict:
                continue
            sorted_keys = sorted(df[key1].keys())
            for key2 in sorted_keys:
                total_vul.append(df[key1][key2])
                tick_label.append(key2)
                xaxis_ticktext.append(key2)
            bar_plots.append(go.Bar(x=tick_label, y=total_vul, name=key1,
                                    marker=go.bar.Marker(color=color[color_index])))
            color_index += 1

    @classmethod
    def __plot_cvss_score_graph(cls, bar_plots, color, color_index, df, xaxis_ticktext, is_frequency_report):
        """
        Plots cvss score average calculation graph and if frequency of occurrence is enabled then plots it
        as well for correlation
        """
        print("Plot cvss score graph")
        for key1 in df.keys():
            # version based score
            version_2_0 = []
            version_3_0 = []
            version_3_1 = []
            total_freq_2_0 = 0
            total_freq_3_0 = 0
            total_freq_3_1 = 0
            # labels for bars
            tick_label = []
            freq_3_1 = []
            freq_3_0 = []
            freq_2_0 = []
            for key2 in df[key1].keys():
                # labels for bars
                tick_label.append(key2)
                xaxis_ticktext.append(key2)
                # print(key2)
                PlotCveNvdGraphs.__fill_missing_values(df, key1, key2, version_2_0, version_3_0, version_3_1,
                                                       freq_2_0, freq_3_0, freq_3_1)
                total_freq_2_0, total_freq_3_0, total_freq_3_1 = \
                    PlotCveNvdGraphs.__add_version_specific_score(
                        df, freq_2_0, freq_3_0, freq_3_1, key1, key2, total_freq_2_0, total_freq_3_0, total_freq_3_1,
                        version_2_0, version_3_0, version_3_1)

            total_avg_2_0 = reduce(lambda x, y: x + y, version_2_0) / len(version_2_0)
            total_avg_3_0 = reduce(lambda x, y: x + y, version_3_0) / len(version_3_0)
            total_avg_3_1 = reduce(lambda x, y: x + y, version_3_1) / len(version_3_1)
            bar_plots.append(
                go.Bar(x=tick_label, y=version_2_0, name=key1 + "- v2.0 all year avg =" + str(total_avg_2_0),
                       marker=go.bar.Marker(color=color[color_index])))
            color_index += 1
            if is_frequency_report:
                bar_plots.append(
                    go.Bar(x=tick_label, y=freq_2_0,
                           name=key1 + "- v2.0 frequency =" + str(total_freq_2_0),
                           marker=go.bar.Marker(color=color[color_index])))
                color_index += 1
            bar_plots.append(
                go.Bar(x=tick_label, y=version_3_0, name=key1 + "- v3.0 all year avg =" + str(total_avg_3_0),
                       marker=go.bar.Marker(color=color[color_index])))
            color_index += 1
            if is_frequency_report:
                bar_plots.append(
                    go.Bar(x=tick_label, y=freq_3_0,
                           name=key1 + "- v3.0 frequency =" + str(total_freq_3_0),
                           marker=go.bar.Marker(color=color[color_index])))
                color_index += 1
            bar_plots.append(
                go.Bar(x=tick_label, y=version_3_1, name=key1 + "- v3.1 all year avg =" + str(total_avg_3_1),
                       marker=go.bar.Marker(color=color[color_index])))
            color_index += 1
            if is_frequency_report:
                bar_plots.append(
                    go.Bar(x=tick_label, y=freq_3_1,
                           name=key1 + "- v3.1 frequency=" + str(total_freq_3_1),
                           marker=go.bar.Marker(color=color[color_index])))
            color_index += 1

    @classmethod
    def __add_version_specific_score(cls, df, freq_2_0, freq_3_0, freq_3_1, key1, key2, total_freq_2_0, total_freq_3_0,
                                     total_freq_3_1, version_2_0, version_3_0, version_3_1):
        for key3 in df[key1][key2]:
            avg = reduce(lambda x, y: x + y, df[key1][key2][key3]) / len(df[key1][key2][key3]) \
                if df[key1][key2][key3] else float(0.0)
            if key3 == "2.0" or avg == 0.0:
                version_2_0.append(avg)
                freq_2_0.append(len(df[key1][key2][key3]))
                total_freq_2_0 += len(df[key1][key2][key3])
            if key3 == "3.0" or avg == 0.0:
                version_3_0.append(avg)
                freq_3_0.append(len(df[key1][key2][key3]))
                total_freq_3_0 += len(df[key1][key2][key3])
            if key3 == "3.1" or avg == 0.0:
                version_3_1.append(avg)
                freq_3_1.append(len(df[key1][key2][key3]))
                total_freq_3_1 += len(df[key1][key2][key3])
        return total_freq_2_0, total_freq_3_0, total_freq_3_1

    @classmethod
    def __fill_missing_values(cls, df, key1, key2, version_2_0, version_3_0, version_3_1, freq_2_0, freq_3_0, freq_3_1):
        if not df[key1][key2]:
            version_2_0.append(0.0)
            freq_2_0.append(0.0)
            version_3_0.append(0.0)
            freq_3_0.append(0.0)
            version_3_1.append(0.0)
            freq_3_1.append(0.0)
        elif len(df[key1][key2]) < 3:
            if "2.0" not in df[key1][key2]:
                version_2_0.append(0.0)
                freq_2_0.append(0.0)
            if "3.0" not in df[key1][key2]:
                version_3_0.append(0.0)
                freq_3_0.append(0.0)
            if "3.1" not in df[key1][key2]:
                version_3_1.append(0.0)
                freq_3_1.append(0.0)


def insert_missing_years(list_years: list):
    start = int(list_years[0])
    index = 0
    for year in list_years:
        if int(year) == start:
            index += 1
            start += 1
            pass
        else:
            list_years.insert(index, str(start))
            index += 1
            start += 1
    return list_years
