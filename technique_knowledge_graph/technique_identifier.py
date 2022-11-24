import itertools
import time
import xlsxwriter
import sys
sys.path.extend([".", "technique_knowledge_graph"])

from technique_knowledge_graph.technique_template import *


class NodeMatchInstance:
    matched_node: AttackGraphNode
    matched_score: float

    def __init__(self, node, score):
        self.matched_node = node
        self.matched_score = score


# Record TechniqueTemplate Matching Record
class TechniqueIdentifier:
    technique_template: TechniqueTemplate

    node_match_record: dict
    edge_match_record: dict
    node_count: int
    edge_count: int

    def __init__(self, technique_template: TechniqueTemplate):
        self.technique_template = technique_template
        logging.info(f"---technique identification: Init technique template {technique_template.technique_name} as identifier!---")

        self.node_match_record = {}
        self.node_count = len(self.technique_template.technique_node_list)
        self.edge_match_record = {}
        self.edge_count = len(self.technique_template.technique_edge_dict.keys())

    def node_alignment(self, attack_node: AttackGraphNode):
        index = -1
        for technique_node in self.technique_template.technique_node_list:
            index += 1

            # complete template node list
            if technique_node.instance_count == 0:
                self.node_match_record[index] = None
                continue

            # accept node as a match
            # 与之前相同的结点对比规则,对比technique_node & attack_node
            #if similarity_score > threshold && 没有被match过，则将该index加入node_match_record
            # node_match_record[index]放入（攻击结点，相似分数）
            node_similarity_score = technique_node.get_similarity(attack_node)
            if node_similarity_score >= TechniqueTemplate.NODE_SIMILAR_ACCEPT_THRESHOLD:
                if index not in self.node_match_record.keys():
                    self.node_match_record[index] = []
                self.node_match_record[index].append((attack_node, node_similarity_score))

        # 每个template和攻击子图做match，找到与某一个template最相近的子图
        # 先评估子图中每个attack_node和每个template结点的相似度
        # 将每个technique_node对应的一组attack_node做笛卡尔积，选出一组technique_like_attack_nodes(底下的item)计算其和此template的相似分值
        # 找出最大的一组，作为与该template对应的attack_node，即该攻击子图与某template的match分值
        # 这笛卡尔积的运算量，也太大了叭？？？！！！！
    def subgraph_alignment(self, subgraph: set, attack_graph: AttackGraph):
        self.node_match_record = {}
        # 对于子图里的每个结点，和template中的结点做对齐
        for node in subgraph:
            self.node_alignment(attack_graph.attackNode_dict[node])

        k_list = []
        v_list = []
        # k为template中technique的index；v为攻击点和对应分数
        for k, v in self.node_match_record.items():
            k_list.append(k)
            # v =  [(attack_node, node_similarity_score),...,(attack_node, node_similarity_score)]
            if v is None:
                v_list.append([''])
            else:
                v_list.append(v)

        self.node_match_record = {}
        best_match_score = 0
        best_match_record = {}
        # *：将列表拆成两个独立参数，然后进行组合
        for item in itertools.product(*v_list):
    # 对于每一组template_like_attack_nodes，如果第i个template结点对应的为空，则为none；不然，则为其对应的attack_nodes
            for i in range(0, len(k_list)):
                if item[i] == '':
                    self.node_match_record[k_list[i]] = None
                else:
                    self.node_match_record[k_list[i]] = item[i]
            # node_match_record:【node_index, node_node_similarity】
    # 对于technique模板中的边，分别计算在此组attack——nodes下的分值
            for template_edge, instance_count in self.technique_template.technique_edge_dict.items():
                source_index = template_edge[0]
                sink_index = template_edge[1]

                # No matched node for edge
                # 异常处理：如果起点或终点在node_match_record中不存在——没有对应的template点，其边记录为0，出现异常也记为0
                try:
                    if self.node_match_record[source_index] is None or self.node_match_record[sink_index] is None:
                        self.edge_match_record[template_edge] = 0.0
                        continue
                except:
                    self.edge_match_record[template_edge] = 0.0
                    continue

                source_node = self.node_match_record[source_index][0]
                sink_node = self.node_match_record[sink_index][0]

                if source_node == sink_node:
                    distance = 1
                else:
                    try:
                        # 找两点之间最短路径，如果有错误，就将边之间的分值记为0.
                        distance = nx.shortest_path_length(attack_graph.attackgraph_nx, source_node, sink_node)
                    except:
                        self.edge_match_record[template_edge] = 0.0
                        continue

                source_node_matching_score = self.node_match_record[source_index][1]
                sink_node_matching_score = self.node_match_record[sink_index][1]
                # 边匹配计算分数=结点分数相乘后开方，除以结点之间距离
                edge_matching_score = math.sqrt(source_node_matching_score * sink_node_matching_score) / distance
                self.edge_match_record[template_edge] = edge_matching_score

            match_score = self.get_graph_alignment_score()
            if match_score > best_match_score:
                best_match_score = match_score
                best_match_record = self.node_match_record

        self.node_match_record = best_match_record

    def get_graph_alignment_score(self):
        return self.get_node_alignment_score() + self.get_edge_alignment_score()

    def get_node_alignment_score(self):
        node_alignment_score = 0.0

        if self.node_match_record is None:
            return 0
        index = 0
        for node_index, node_node_similarity in self.node_match_record.items():
            if self.technique_template.technique_node_list[node_index].type == "actor":
                continue

            if node_node_similarity is not None:
                # ToDo: Need to select the larger similarity score
                # 攻击结点和模板节点的相似度*模板结点出现的次数
                node_alignment_score += node_node_similarity[1] * self.technique_template.technique_node_list[node_index].instance_count  # math.sqrt

            index += 1

        node_alignment_score /= (self.technique_template.node_normalization + 1)
        return node_alignment_score

    def get_edge_alignment_score(self):
        edge_alignment_score = 0.0

        for edge, edge_similarity in self.edge_match_record.items():
            edge_alignment_score += edge_similarity * (self.technique_template.technique_edge_dict[edge])

        edge_alignment_score /= (self.technique_template.edge_normalization + 1)

        return edge_alignment_score


# Matching process, involve multiple TechniqueIdentifier at one time
class AttackMatcher:
    attack_graph: AttackGraph
    attack_graph_nx: nx.DiGraph
    technique_identifier_list: list
    technique_matching_score: dict
    technique_matching_subgraph: dict
    technique_matching_record: dict

    normalized_factor: float

    def __init__(self, attack_graph: AttackGraph):
        self.attack_graph = attack_graph
        self.attack_graph_nx = attack_graph.attackgraph_nx
        self.technique_identifier_list = []
        self.technique_matching_score = {}
        self.technique_matching_subgraph = {}
        self.technique_matching_record = {}
        # 总的规范化数量=边+结点数量
        self.normalized_factor = self.attack_graph_nx.number_of_nodes() + self.attack_graph_nx.number_of_edges()

    def add_technique_identifier(self, technique_identifier: TechniqueIdentifier):
        # 加载technique_identifier
        # 判断传入需检测的template的边数是否为0，如果不为0，则将其加入technique_identifier_list
        if technique_identifier.edge_count == 0:
            return
        self.technique_identifier_list.append(technique_identifier)

    def attack_matching(self):
        # subgraph_list = nx.strongly_connected_components(self.attack_graph_nx)
        # 将attack_graph变成无向图后，找到所有连通子图
        subgraph_list = nx.connected_components(self.attack_graph_nx.to_undirected())
        for subgraph in subgraph_list:
            logging.debug("---Get subgraph: %s---" % subgraph)
            # matching_result = []

            for technique_identifier in self.technique_identifier_list:
                # technique和子图对齐
                technique_identifier.subgraph_alignment(subgraph, self.attack_graph)

            # for node in subgraph:
            #     # Try to find a match in technique_identifier_list
            #     for technique_identifier in self.technique_identifier_list:
            #         technique_identifier.node_alignment(node, nx_graph)

            # for edge in subgraph.edges():
            #     for technique_identifier in self.technique_identifier_list:
            #         technique_identifier.edge_alignment(edge, nx_graph)

            # find the most match technique
            for technique_identifier in self.technique_identifier_list:
                node_alignment_score = technique_identifier.get_graph_alignment_score() #/ self.normalized_factor

                if technique_identifier.technique_template.technique_name not in self.technique_matching_score.keys():
                    self.technique_matching_score[technique_identifier.technique_template.technique_name] = node_alignment_score
                    self.technique_matching_subgraph[technique_identifier.technique_template.technique_name] = subgraph
                    self.technique_matching_record[technique_identifier.technique_template.technique_name] = technique_identifier.node_match_record
                elif self.technique_matching_score[technique_identifier.technique_template.technique_name] < node_alignment_score:
                    self.technique_matching_score[technique_identifier.technique_template.technique_name] = node_alignment_score
                    self.technique_matching_subgraph[technique_identifier.technique_template.technique_name] = subgraph
                    self.technique_matching_record[technique_identifier.technique_template.technique_name] = technique_identifier.node_match_record

                # matching_result.append((technique_identifier.technique_template, node_alignment_score))
                logging.debug("---S3.2: matching result %s\n=====\n%s - %f!---" % (technique_identifier.technique_template.technique_name, subgraph, node_alignment_score))
# 打印最终matching结果
    def print_match_result(self) -> dict:
        logging.info(str(self.technique_matching_score))
        logging.info(str(self.technique_matching_subgraph))
        logging.info(str(self.technique_matching_record))

        return self.technique_matching_score

    def to_json(self) -> dict:
        selected_techniques_dict = {}

        for k, v in self.technique_matching_score.items():
            if v >= 0.9:
                # selected_techniques_dict[k] = tuple(self.technique_matching_subgraph[k])
                involved_node_dict = {}
                for node in self.technique_matching_subgraph[k]:
                    if self.attack_graph.attackNode_dict[node].ioc != "":
                        involved_node_dict[node] = {
                            "type": self.attack_graph.attackNode_dict[node].type,
                            "nlp": tuple(self.attack_graph.attackNode_dict[node].nlp),
                            "ioc": tuple(self.attack_graph.attackNode_dict[node].ioc)}
                selected_techniques_dict[k] = involved_node_dict

        json_string = json.dumps(selected_techniques_dict)
        return json_string

    def to_json_file(self, output_file):
        with open(output_file, "w+") as output:
            output.write(self.to_json())


class Evaluation:

    def __init__(self):
        self.book = xlsxwriter.Workbook("technique_matching_result.xlsx")
        self.sheet = self.book.add_worksheet('report_pickTechnique')
        self.column_count = 1

        self.match_format = self.book.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})

    def add_technique_list(self, technique_list: list):
        row_count = 1
        for technique in technique_list:
            self.sheet.write(0, row_count, technique)
            row_count += 1

    def add_result(self, report_name: str, detection_result: dict, ground_truth: list):
        self.sheet.write(self.column_count, 0, report_name)

        row_count = 1
        for technique, result in detection_result.items():
            self.sheet.write(self.column_count, row_count, result)
            technique_name = technique.replace("'", "").replace("_", "/")
            if technique_name in ground_truth:
                self.sheet.conditional_format(self.column_count, row_count, self.column_count, row_count, {'type': '2_color_scale'})
            row_count += 1

        self.column_count += 1
