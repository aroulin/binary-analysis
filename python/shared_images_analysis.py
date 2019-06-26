#!/usr/bin/python2.7

import argparse
import logging
import tempfile
from os import popen

import networkx
import os
import pefile
import pprint

from networkx.algorithms import bipartite
from networkx.drawing.nx_agraph import write_dot

args = argparse.ArgumentParser(description="Visualize shared image relationships"
                                           " between a directory of malware samples")
args.add_argument("target_path", help="directory with malware samples")
args.add_argument("output_file", help="file to write DOT file to")
args.add_argument("malware_projection", help="file to write DOT file to")
args.add_argument("resource_projection", help="file to write DOT file to")
args.add_argument("graph_tool", help="tool to draw graphs to png", default="fdp", nargs='?')
args = args.parse_args()

network = networkx.Graph()


class ExtractImages():
    def __init__(self, target_binary):
        self.target_binary = target_binary
        self.image_basedir = None
        self.images = []

    def work(self):
        self.image_basedir = tempfile.mkdtemp()
        icondir = os.path.join(self.image_basedir, "icons")
        bitmapdir = os.path.join(self.image_basedir, "bitmaps")
        raw_resources = os.path.join(self.image_basedir, "raw")
        for directory in [icondir, bitmapdir, raw_resources]:
            os.mkdir(directory)
        rawcmd = "wrestool -x {0} -o {1} 2> " \
                 "/dev/null".format(self.target_binary, raw_resources)
        bmpcmd = "mv {0}/*.bmp {1} 2> /dev/null".format(raw_resources, bitmapdir)
        icocmd = "icotool -x {0}/*.ico -o {1}" \
                 "2> /dev/null".format(raw_resources, icondir)

        for cmd in [rawcmd, bmpcmd, icocmd]:
            try:
                os.system(cmd)
            except Exception,msg:
                pass
        for dirname in [icondir, bitmapdir]:
            for path in os.listdir(dirname):
                logging.info(path)
                path = os.path.join(dirname, path)
                imagehash = hash(open(path).read())
                if path.endswith(".png"):
                    self.images.append(path, imagehash)
                if path.endswith(".bmp"):
                    self.images.append(path, imagehash)

    def cleanup(self):
        os.system("rm -rf {0}".format(self.image_basedir))


image_objects = []
for root, dirs, files in os.walk(args.target_path):
    for path in files:
        try:
            pe = pefile.PE(os.path.join(root, path))
        except pefile.PEFormatError:
            continue
        fullpath = os.path.join(root, path)
        images = ExtractImages(fullpath)
        images.work()
        image_objects.append(images)

        for path, image_hash in images.images:
            if image_hash not in network:
                network.add_node(image_hash, image=path, label='', type='image')
            node_name = path.split("/")[-1]
            network.add_node(node_name, type="malware")
            network.add_edge(node_name, image_hash)

write_dot(network, args.output_file)
malware = set(n for n,d in network.nodes(data=True) if d['bipartite'] == 0)
hostname = set(network) - malware

malware_network = bipartite.projected_graph(network, malware)
hostname_network = bipartite.projected_graph(network, hostname)

write_dot(malware_network, args.malware_projection)
write_dot(hostname_network, args.resource_projection)

toolname = args.graph_tool

popen("'{0}' '{1}' -Goverlap=false -Gsplines=true -T png -o '{1}'.png".format(
    toolname, args.output_file
))

popen("'{0}' '{1}' -Goverlap=false -Gsplines=true -T png -o '{1}'.png".format(
    toolname, args.malware_projection
))

popen("'{0}' '{1}' -Goverlap=false -Gsplines=true -T png -o '{1}'.png".format(
    toolname, args.resource_projection
))
