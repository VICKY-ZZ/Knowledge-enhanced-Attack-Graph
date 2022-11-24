from __future__ import annotations

from networkx.drawing.nx_agraph import to_agraph

from technique_knowledge_graph.attack_graph import *
from mitre_ttps.mitreGraphReader import *

import simplejson as json

class TemplateNode(AttackGraphNode):
    instance_count: int
    # 将AttackGraphNode变为TemplateNode
    def __init__(self, attack_node: AttackGraphNode):
        if attack_node is None:
            self.instance_count = 0
            self.type = ""
            # nlp为entity_text
            self.nlp = []
            self.ioc = []
        else:
            self.instance_count = 1
            self.type = attack_node.type
            self.nlp = attack_node.nlp
            self.ioc = attack_node.ioc

        logging.debug("---technique template: Init TemplateNode %s!---" % (self))

    def __str__(self):
        return f"Template Node: [type: '{self.type}', nlp: '{self.nlp}', ioc: '{self.ioc}', instance count: '{self.instance_count}']"

    NODE_NLP_SIMILAR_ACCEPT_THRESHOLD = 0.8
    NODE_IOC_SIMILAR_ACCEPT_THRESHOLD = 0.8

    def update_with(self, attack_node: AttackGraphNode) -> TemplateNode:
        # instance数量加1，即该node又多融合了一个Instance
        self.instance_count += 1
        # 融合结点
        self.merge_node(attack_node)
        return self

    def dump_to_dict(self) -> dict:
        node_data = {
            "type": self.type,
            "nlp": self.nlp,
            "ioc": self.ioc,
            "count": self.instance_count}

        return node_data

    def load_from_dict(self, node_data: dict):
        self.type = node_data["type"]
        self.nlp = node_data["nlp"]
        self.ioc = node_data["ioc"]
        self.instance_count = node_data["count"]


class TechniqueTemplate:
    NODE_SIMILAR_ACCEPT_THRESHOLD = 0.5 + 0.2

    technique_name: str  # '/techniques/T1566/001'
    template_nx: nx.DiGraph
    technique_node_list: List[TemplateNode]  # [TemplateNode, ...]
    technique_edge_dict: Dict[Tuple[int, int], int]  # [(TN1, TN2): Count, ...]
    technique_instance_dict: Dict[List[Tuple[int, int]], int]  # [[(n1,n2), ...]...]

    total_instance_count: int
    node_normalization: float
    edge_normalization: float

    def __init__(self, technique_name: str):
        self.technique_name = technique_name
        self.template_nx = nx.DiGraph()
        self.technique_node_list = []
        self.technique_edge_dict = {}
        self.technique_instance_dict = {}

        self.total_instance_count = 0
        self.node_normalization = 0
        self.edge_normalization = 0

    def update_template(self, attack_graph: AttackGraph):
        logging.info("---technique template: Update template!---")
        # 总实例数+1
        self.total_instance_count += 1
        sample_node_template_node_dict = {}

        # node matching
        # 查看sample图中的node，进行匹配与更新
        for node in attack_graph.attackgraph_nx.nodes:
            max_similarity_score = 0
            most_similar_node_index = -1

            node_index = 0
            # 遍历template中的technique_node技术结点
            for template_node in self.technique_node_list:
                # 对每一个新的节点node，与原有图中节点template_node进行相似度比对,找到相似度最大的，记录索引和分之
                similarity_score = template_node.get_similarity(attack_graph.attackNode_dict[node])
                if similarity_score > max_similarity_score:
                    max_similarity_score = similarity_score
                    most_similar_node_index = node_index

                node_index += 1

            # whether node in new sample is aligned with exist template node
            # 如果新的node的相似度分数大于THRESHOLD,则将其加入sample_node_template_dict（单独针对每个新的template为update template创立）
            # 并用该节点将与其最相似的老节点更新
            # 具体similar算法，和更新方法？
            if max_similarity_score > self.NODE_SIMILAR_ACCEPT_THRESHOLD:
                sample_node_template_node_dict[node] = most_similar_node_index
                self.technique_node_list[most_similar_node_index].update_with(attack_graph.attackNode_dict[node])
            else:
                # 如果不大于，则直接加入technique_node_list，作为新的节点
                tn = TemplateNode(attack_graph.attackNode_dict[node])
                self.technique_node_list.append(tn)
                # 设置index
                sample_node_template_node_dict[node] = len(self.technique_node_list) - 1

        instance = []
        # 查看sample图中的edge，进行匹配与更新
        for edge in attack_graph.attackgraph_nx.edges:
            # 得到现在图里面的边，后面做的是结点index的转换（由原来图，换位现在结点匹配更新后新生成的图的index）
            technique_template_edge = (sample_node_template_node_dict[edge[0]], sample_node_template_node_dict[edge[1]])
            # 查看原来的template是否包含该边
            if technique_template_edge in self.technique_edge_dict.keys():
                self.technique_edge_dict[technique_template_edge] += 1
            else:
                self.technique_edge_dict[technique_template_edge] = 1
            # 将边加入到instance中,所以instance就是现有边的集合
            instance.append(technique_template_edge)
        # 统计现有边的情况，记入technique_instance_dict,初始化时和原有edge_list相同，不知后续有什么变化？
        # 感觉是用的例子的数目，通过边的数目来记录，历史上一共有多少次这样的边
        instance = tuple(instance)
        if instance in self.technique_instance_dict.keys():
            self.technique_instance_dict[instance] += 1
        else:
            self.technique_instance_dict[instance] = 1

    def pretty_print(self, image_name: str = "template.png"):
        self.template_nx = nx.DiGraph()

        for node in self.technique_node_list:
            self.template_nx.add_node(node)

        for edge in self.technique_edge_dict.keys():
            count = self.technique_edge_dict[edge]
            if count <= 2:
                continue

            source = self.technique_node_list[edge[0]]
            sink = self.technique_node_list[edge[1]]
            self.template_nx.add_edge(source, sink, count=str(count))

        A = to_agraph(self.template_nx)
        A.node_attr['shape'] = 'rectangle'
        A.layout('dot')
        A.draw(image_name)

    def statistic(self):
        variants_count = 0
        ioc_instance_count = 0

        for k, v in self.technique_instance_dict.items():
            if v >= (self.total_instance_count / 10):
                variants_count += 1

        for node in self.technique_node_list:
            ioc_instance_count += len(node.ioc)

        csv_output = ','.join([self.technique_name[14:19], str(variants_count), str(ioc_instance_count), '\n'])
        print(csv_output)

        with open('technique_variants_count.csv', 'a+') as output_file:
            output_file.write(csv_output)

    def calculate_normalization(self):
        for node in self.technique_node_list:
            self.node_normalization += node.instance_count
        for edge, instance_count in self.technique_edge_dict:
            self.edge_normalization += instance_count

    # refer to STIX
    def dump_to_dict(self) -> dict:
        data_dict = {}

        node_list = []
        for tn in self.technique_node_list:
            node_list.append(tn.dump_to_dict())
        data_dict["nodes"] = node_list
        data_dict["edges"] = self.technique_edge_dict.items()
        data_dict["instances"] = list(self.technique_instance_dict)
        data_dict["total_count"] = self.total_instance_count

        return data_dict

    def dump_to_json(self) -> str:
        data_dict = self.dump_to_dict()
        data_json = json.dumps(data_dict, iterable_as_array=True)
        return data_json

    def dump_to_file(self, file_name: str = "template"):
        data_json = self.dump_to_json()
        with open(file_name + ".json", "w+") as json_file:
            json_file.write(data_json)

    def load_from_dict(self, data_dict: dict):
        self.total_instance_count = int(data_dict["total_count"])

        node_list = data_dict["nodes"]
        for node_info in node_list:
            tn = TemplateNode(None)
            tn.load_from_dict(node_info)
            if tn.instance_count <= 2:
                tn.instance_count = 0
            self.technique_node_list.append(tn)

        edge_list = data_dict["edges"]
        for edge in edge_list:
            edge_info = edge[0]
            count = edge[1]
            if count <= 2:
                count = 0
            self.technique_edge_dict[tuple(edge_info)] = count

        self.calculate_normalization()

        instance_list = data_dict["instances"]
        for instance in instance_list:
            edge_in_instance = []
            for edge in instance:
                edge_in_instance.append(tuple(edge))
            self.technique_instance_dict[tuple(edge_in_instance)] = 1

        self.technique_edge_dict

    def load_from_json(self, data_json: str):
        data_dict = json.loads(data_json)
        self.load_from_dict(data_dict)

    def load_from_file(self, file_name: str):
        with open(file_name, 'r') as data_file:
            data_json = data_file.read()
            self.load_from_json(data_json)
