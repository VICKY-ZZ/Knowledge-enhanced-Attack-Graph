import argparse
import logging
import sys
sys.path.extend([".", "technique_knowledge_graph"])

import os
import networkx as nx

from typing import Tuple
from typing import List
from spacy.tokens import Doc

from mitre_ttps.mitreGraphReader import MitreGraphReader, picked_techniques
from preprocess.report_preprocess import preprocess_file, clear_text
from report_parser.ioc_protection import IoCIdentifier
from report_parser.report_parser import parsingModel_training, IoCNer
from technique_knowledge_graph.attack_graph import AttackGraph
from technique_knowledge_graph.technique_identifier import TechniqueIdentifier, AttackMatcher
from technique_knowledge_graph.technique_template import TechniqueTemplate

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


def ioc_protection(text: str) -> IoCIdentifier:
    iid = IoCIdentifier(text)
    iid.ioc_protect()
    # iid.check_replace_result()
    return iid


def report_parsing(text: str) -> Tuple[IoCIdentifier, Doc]:
    iid = ioc_protection(text)
    text_without_ioc = iid.replaced_text

    ner_model = IoCNer("./new_cti.model")
    # 为什么要parse没有ioc的report呢？应该是被替换好的？？？
    # doc为标记好的文本；iid为换好词的文本
    doc = ner_model.parse(text_without_ioc)

    return iid, doc

# 输入：文本
# 输出：文本分析好的图
def attackGraph_generating(text: str, output: str = None) -> AttackGraph:
    text = text.lower()
    iid, doc = report_parsing(text)

    ag = AttackGraph(doc, ioc_identifier=iid)
    print(ag.to_json())
    if output is not None:
        ag.draw(output)
        ag.to_json_file(output + "_artifacts.json")

    return ag


def techniqueTemplate_generating(output_path: str = None, technique_list: List[str] = None) -> List[TechniqueTemplate]:
    template_list = []
    # 读取mitre文件,并作一定处理
    mgr = MitreGraphReader()
    # 2种:单一的technique；；；；自身为super,邻居为sub,放邻居编号
    super_sub_dict = mgr.get_super_sub_technique_dict()
    # 相当于自己是super,邻居是sub
    for super_technique, sub_technique_list in super_sub_dict.items():
        # 为什么是12-18呢，好像是名字欸,但是为什么呢？看不懂get_super_sub_technique_dict()里面的[n]
        if technique_list is not None and super_technique[12:18] not in technique_list:
            continue

        sample_list = []
        for sub_technique in sub_technique_list:
            # 把找到的example放入sample_list
            # 但是如何找example的呢？需要跳进函数看一看
            # 在原图中，example就在neighbor上，直接找对应例行，此处找的是sub_technique的example
            sample_list += mgr.find_examples_for_technique(sub_technique)
        techniqueTemplate_generating_perTech(super_technique[12:18], sample_list, output_path)
    # 好像一直没有往template里面加呀？？？
    return template_list


def techniqueTemplate_generating_perTech(technique_name: str, techniqueSample_list: List[str], output_path: str = None) -> TechniqueTemplate:
    technique_template = TechniqueTemplate(technique_name)
# 用每个sample更新模板
    for sample in techniqueSample_list:
        sample_graph = attackGraph_generating(sample)
        technique_template.update_template(sample_graph)
# 在template文件夹下可以看到example
    if output_path is not None:
        logging.warning(f"---technique template: Saving to {output_path}/{technique_name}!---")
        technique_template.pretty_print(f"{output_path}/{technique_name}.png")
        technique_template.dump_to_file(f"{output_path}/{technique_name}")

    return technique_template


def load_techniqueTemplate_fromFils(templatePath: str) -> List[TechniqueTemplate]:
    template_file_list = os.listdir(templatePath)
    template_list = []

    for template_file in template_file_list:
        technique_name, ext = os.path.splitext(template_file)
        if ext != ".json":
            continue

        template = TechniqueTemplate(technique_name)
        template.load_from_file(os.path.join(templatePath, template_file))
        template_list.append(template)

    return template_list


def technique_identifying(text: str, technique_list: List[str], template_path: str, output_file: str = "output") -> AttackMatcher:
    # 先对文本进行分析
    ag = attackGraph_generating(text)
    # 如果没有模板的话，就根据technique_list生成模板;如果有的话，就直接load
    if template_path == "":
        tt_list = techniqueTemplate_generating(technique_list=technique_list)
    else:
        tt_list = load_techniqueTemplate_fromFils(template_path)
    #
    attackMatcher = technique_identifying_forAttackGraph(ag, tt_list, output_file)
    return attackMatcher

# 对于每一个technique，找到一个最匹配的子图+matching_score
def technique_identifying_forAttackGraph(graph: AttackGraph, template_list: List[TechniqueTemplate], output_file: str) -> AttackMatcher:
    # 对整个有关report_text的图进行AttackMatcher实例化，用该对象的方法，对report进行match
    attackMatcher = AttackMatcher(graph)
    for template in template_list:
        # 遍历templist，对每个template进行TechniqueIdentifier实例化，该对象可记录matching record。
        #之后，将该technique_identifier加入到attackMatcher
        attackMatcher.add_technique_identifier(TechniqueIdentifier(template))
    attackMatcher.attack_matching()
    attackMatcher.print_match_result()
    # 感觉没有生成
    attackMatcher.to_json_file(output_file + "_techniques.json")

    return attackMatcher


attack_graph = None
attack_matcher = None

if __name__ == '__main__':
    # logging.basicConfig(stream=sys.stdout, level=logging.WARNING)

    parser = argparse.ArgumentParser()

    # Examples:
    # python main.py -M iocProtection -R ./data/cti/html/003495c4cb6041c52db4b9f7ead95f05.html
    # python main.py -M reportParsing -C "Cardinal RAT establishes Persistence by setting the  HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable."
    # python main.py -M attackGraphGeneration -C "Cardinal RAT establishes Persistence by setting the  HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable."
    # python main.py -M techniqueTemplateGeneration
    # python main.py -M attackGraphGeneration -R ./reports_sample/Log4Shell.html -O ./output
    # python main.py -M techniqueTemplateGeneration -O ./templates
    # python main.py -M techniqueIdentification -T ./templates -R ./reports_sample/Log4Shell.html -O ./output
    parser.add_argument('-M', '--mode', required=True, type=str, default="", help="The running mode options: 'iocProtection', 'nlpModelTraining', 'reportParsing', 'attackGraphGeneration', 'techniqueTemplateGeneration', 'techniqueIdentification")
    parser.add_argument('-L', '--logPath', required=False, type=str, default="", help="Log file's path.")
    parser.add_argument('-C', '--ctiText', required=False, type=str, default="", help="Target CTI text.")
    parser.add_argument('-R', '--reportPath', required=False, type=str, default="../AttacKG/data/cti/html/003495c4cb6041c52db4b9f7ead95f05.html", help="Target report's path.")
    parser.add_argument('-T', '--templatePath', required=False, type=str, default="", help="Technique template's path.")
    parser.add_argument('-O', '--outputPath', required=False, type=str, default="", help="Output file's path.")
    parser.add_argument('--trainingSetPath', required=False, type=str, default="../AttacKG/NLP/Doccano/20210813.jsonl", help="NLP model training dataset's path.")
    parser.add_argument('--nlpModelPath', required=False, type=str, default="../AttacKG/new_cti.model", help="NLP model's path.")
#为什么从第2个开始呢？
    # 下面在获取参数
    arguments = parser.parse_args(sys.argv[1:])

    log_path = arguments.logPath
    log_level = logging.DEBUG
    if log_path == "":
        logging.basicConfig(stream=sys.stdout, level=log_level)
    else:
        logging.basicConfig(filename=log_path, filemode='a', level=log_level)

    logging.info(f"---Running arguments: {arguments}!---")

    cti_text = arguments.ctiText
    report_path = arguments.reportPath
    report_text = clear_text(cti_text) if len(cti_text) != 0 else preprocess_file(report_path)

    running_mode = arguments.mode
    print(f"Running mode: {running_mode}")
    if running_mode == "iocProtection":
        # 什么是ioc_protection?
        #输入：报告；
        #功能：先使用"./ioc_regexPattern.json" 找到ioc，再用 "./ioc_replaceWord.json"将其换成对应类型（例如"DocumentFile": "document",），
        #不太明白换了有什么用
        #输出：replaced_text
        ioc_identifier = ioc_protection(report_text)
    elif running_mode == "nlpModelTraining":
        # NLP model training dataset's path， default 路径在../ AttacKG / NLP / Doccano / 20210813.json。好像找不到？
        # 输入:训练集路径，找不到数据hh，default="../AttacKG/data/cti/html/003495c4cb6041c52db4b9f7ead95f05.html
        #输出：训练好的模型./new_cti.model
        # 功能:指定训练数据集，进行训练，生成模型
        trainingSet_path = arguments.trainingSetPath
        parsingModel_training(trainingSet_path)
    elif running_mode == "reportParsing":
        # 输入:report_text
        # 输出:(iid, ioc)----doc为标记好的文本；iid为换好词的文本
        # 功能:分析report
        cti_doc = report_parsing(report_text)
    elif running_mode == "attackGraphGeneration":
        # 输入:报告文本，输出地址
        # 输出: 返回ag, ag = AttackGraph(doc, ioc_identifier=iid)，
        # draw pdf-----ag.draw(output)
        # 生成json文件，大概是画的内容叭~ag.to_json_file(output + "_artifacts.json")
        # 功能：分析文本+画图啦
        attack_graph = attackGraph_generating(report_text, arguments.outputPath)
    elif running_mode == "techniqueTemplateGeneration":
        # 输入:输出路径，Tactic_Technique_Reference_Example.gml
        #输出:生成json文件；；；template_list【没看到这个list更新】
        # 完成template的初始化，还没看到更新，可能这个函数不包含？？？
        # 需要仔细再看看
        techniqueTemplate_generating(output_path=arguments.outputPath)
    elif running_mode == "techniqueIdentification":
        # 输入:报告、挑选的techniques、模板地址、输出地址
        #输出:technique+对应子图+对应分数
        #功能:发现文本里的technique
        # 这个之后怎么处理呢？
        attack_matcher = technique_identifying(report_text, picked_techniques, arguments.templatePath, arguments.outputPath)
    else:
        print("Unknown running mode!")

    logging.info(f"---Done!---")
