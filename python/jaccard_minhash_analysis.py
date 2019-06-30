#!/usr/bin/python2.7

import shelve
import murmur
import numpy

from jaccard_simple_analysis import *

NUM_MINHASHES = 256
SKETCH_RATIO = 8

"""
Builds a database db such as
db[malware] = {'minhashes': minhash[malware], 'comments': []}
db[sketch] = {malware1, ..., malware2]

NUM_MINHASHES minhashes per malware
minhash K computed as min(hash(feature) for all features of malware), seed=K)

SKETCH_RATIO sketches per malware
sketch S computed as hash of minhash[S*SKETCH_RATION:(S+1)*SKETCH_RATIO]

Only considers malwares that match at least one same sketch
Then compute similarity as number of matching minhashes divided by NUM_MINHASHES 
"""


def wipe_database():
    """
    The python standard library 'shelve' stores the database in a file 'samples.db'
    in the same directory as this script. 'wipe_database' deletes the file, thus
    resetting the system
    """
    dbpath = "/".join(__file__.split("/")[:-1] + ['sample.db'])
    os.system("rm -f {0}".format(dbpath))


def get_database():
    dbpath = "/".join(__file__.split("/")[:-1] + ['sample.db'])
    return shelve.open(dbpath, protocol=2, writeback=True)


def minhash(features):
    minhashes = []
    sketches = []
    for i in range(NUM_MINHASHES):
        minhashes.append(
            min([murmur.string_hash(`feature`, i) for feature in features])
        )

    for i in xrange(0, NUM_MINHASHES, SKETCH_RATIO):
        sketch = murmur.string_hash(`minhashes[i:i+SKETCH_RATIO]`)
        sketches.append(sketch)

    return numpy.array(minhashes), sketches


def store_sample(path):
    """
    Stores a sample and compute its minhashes and sketches in the
    'shelve' database
    """
    db = get_database()
    features = getstrings(path)
    minhashes, sketches = minhash(features)

    for sketch in sketches:
        sketch = str(sketch)
        if sketch not in db:
            db[sketch] = set([path])
        else:
            obj = db[sketch]
            obj.add(path)
            db[sketch] = obj
        db[path] = {'minhashes': minhashes, 'comments': []}
        db.sync()

    print "Extracted {0} features from {1}".format(len(features), path)


def comment_sample(path):
    db = get_database()
    comment = raw_input("Enter your comment:")
    if not path in db:
        store_sample(path)
    comments = db[path]['comments']
    comments.append(comment)
    db[path]['comments'] = comments
    db.sync()
    print "Stored comment: ", comment


def search_sample(path):
    db = get_database()
    feats = getstrings(path)
    minhashes, sketches = minhash(feats)
    neighbors = []

    for sketch in sketches:
        sketch = str(sketch)
        if sketch not in db:
            continue
        for neighbor_path in db[sketch]:
            neighbor_minhashes = db[neighbor_path]['minhashes']
            similarity = (neighbor_minhashes == minhashes).sum() / float(NUM_MINHASHES)
            neighbors.append((neighbor_path, similarity))

    neighbors = list(set(neighbors))
    neighbors.sort(key=lambda entry: entry[1], reverse=True)
    print ""
    print "Sample name".ljust(64), "similarity"
    for neighbor, similarity in neighbors:
        short_neighbor = neighbor.split("/")[-1]
        comments = db[neighbor]['comments']
        print str("[*] " + short_neighbor).ljust(64), similarity
        for comment in comments:
            print "\t[comment]", comment


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple search system which allows you to build up a "
                    "database of malware samples (indexed by file paths "
                    "and then search for similar samples given a new sample"
    )

    parser.add_argument(
        "-l", "--load", dest="load", default=None,
        help="Path to malware directory or file to store in database"
    )

    parser.add_argument(
        "-s", "--search", dest="search", default=None,
        help="Individual malware file to perform similarity search on"
    )

    parser.add_argument(
        "-c", "--comment", dest="comment", default=None,
        help="Comment on a malware sample path"
    )

    parser.add_argument(
        "-w", "--wipe", action="store_true", default=False,
        help="Wipe sample database"
    )

    args = parser.parse_args()
    if args.load:
        malware_paths = []
        malware_features = dict()
        for root, dirs, paths in os.walk(args.load):
            for path in paths:
                full_path = os.path.join(root, path)
                malware_paths.append(full_path)

        malware_paths = filter(pecheck, malware_paths)

        for path in malware_paths:
            store_sample(path)

    if args.search:
        search_sample(args.search)

    if args.comment:
        comment_sample(args.comment)

    if args.wipe:
        wipe_database()
