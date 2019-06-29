#!/usr/bin/python2.7

import argparse
import os
import networkx
from networkx.drawing.nx_pydot import write_dot
import itertools


def jaccard(set1, set2):
    """
    Compute the Jaccard distance between two sets by taking
    their intersection, union and then dividing the number
    of elements in the intersection by the number of elements
    in their union
    """
    intersection = set1.intersection(set2)
    intersection_length = float(len(intersection))
    union = set1.union(set2)
    union_length = float(len(union))
    return intersection_length / union_length


def getstrings(full_path):
    """
    Extract strings from the binary indicated by fullpath
    and return the set of unique strings in the binary
    """
    strings = os.popen("strings '{0}'".format(full_path)).read()
    strings = set(strings.split("\n"))
    return strings


def pecheck(full_path):
    """
    Do a cursory sanitary check to make sure fullpath is a
    Windows PE executable (PE executables start with the
    two bytes 'MZ')
    """
    return open(full_path).read(2) == "MZ"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Identify similarities between malware samples and build "
                    "similarity graph"
    )

    parser.add_argument(
        "target_directory",
        help="Directory containing malware"
    )

    parser.add_argument(
        "output_dot_file",
        help="Where to save the output graph DOT file"
    )

    parser.add_argument(
        "output_graph_file",
        help="Where to save the output graph image"
    )

    parser.add_argument(
        "--jaccard_index_threshold", "-j", dest="threshold", type=float,
        default=0.8, help="Threshold above which to create an 'edge' between samples (0.8 default)"
    )

    parser.add_argument(
        "--graph_tool", "-g", dest="graph_tool",
        default="fdp", help="Tool to generate graph, default is fdp"
    )

    args = parser.parse_args()

    malware_paths = []          # storage for malware file paths
    malware_features = dict()   # storage for malware strings
    graph = networkx.Graph()    # similarity graph

    for root, dirs, paths in os.walk(args.target_directory):
        for path in paths:
            fullpath = os.path.join(root, path)
            malware_paths.append(fullpath)

    malware_paths = filter(pecheck, malware_paths)

    for path in malware_paths:
        features = getstrings(path)
        print "Extracted {0} features from {1}".format(len(features), path)
        malware_features[path] = features
        graph.add_node(path, label=os.path.split(path)[-1][:30])

    for malware1, malware2 in itertools.combinations(malware_paths, 2):
        jaccard_index = jaccard(malware_features[malware1], malware_features[malware2])
        if jaccard_index > args.threshold:
            print os.path.split(malware1)[-1], os.path.split(malware2)[-1], jaccard_index
            graph.add_edge(malware1, malware2, penwidth=1+(jaccard_index-args.threshold)*10)

    write_dot(graph, args.output_dot_file)
    toolname = args.graph_tool
    os.popen("'{0}' '{1}' -Goverlap=false -Gsplines=false -T png -o '{1}'.png".format(
        toolname, args.output_dot_file
    ))

