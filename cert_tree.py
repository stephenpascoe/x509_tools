#!/usr/bin/env python
"""
Deduce the dependency tree from a directory of certificates.

usage: cert_tree.py <cert-dir>

  :requires: PyOpenSSL

"""

import sys, os, glob, shutil
import datetime

try:
    from OpenSSL import crypto as C
except ImportError:
    print '''PyOpenSSL is required.  
Please install with "pip install PyOpenSSL" or equivilent.'''
    sys.exit(1)


import logging
log = logging.getLogger('cert_tree')

def main():
    import optparse

    usage ='''
  %prog ca-dir

Print openssl certificate directories as a issuer tree'''

    parser = optparse.OptionParser(usage=usage)
    options, args = parser.parse_args()

    try:
        ca_dir = args[0]
    except IndexError:
        parser.error("ca-dir not specified")

    tree = build_tree(iter_certs(ca_dir))

    print '== Certificate tree'
    pp_tree(tree)
    print


def iter_certs(cert_directory):
    """
    Iterate over a certificate directory in openssl format
    yielding certificate objects.
    
    """
    done = {}
    for certfile in glob.glob(cert_directory+'/*.0'):
        cert = C.load_certificate(C.FILETYPE_PEM, open(certfile).read())
        subject = cert.get_subject()

        if subject.hash() in done:
            log.warn('Duplicate hash %s at %s' % (make_hexhash(subject), certfile))
        else:
            done[subject.hash()] = cert

        yield cert

def make_cert_str(dn):
    """
    Convenience function  to create a human-readable summary of a certificate.
    Prints the certificate hash and the most-specific component of the DN.

    """
    k, v = dn.get_components()[-1]
    hexhash = make_hexhash(dn)
    return '%s: %s=%s' % (hexhash, k, v)

    return '/'+'/'.join('%s=%s' % (k, v) for (k, v) in dn.get_components())

class TreeNode(object):
    def __init__(self, dn, not_before=None, not_after=None, children=None):
        self.dn = dn
        self.not_before = not_before
        self.not_after = not_after
        if children is None:
            self.children = set()
        else:
            self.children = set(children)

    def __hash__(self):
        return hash((TreeNode, self.dn.hash()))

def build_tree(certs):
    """
    Build a tree of certificates.

    The tree is of the form:
      tree[root_hash] = TreeNode(root_cert, not_before, not_after, [child, child, ...])
      child = (cert, [child, child, ...])
    """
    tree = {}
    for cert in certs:
        subject = cert.get_subject()
        issuer = cert.get_issuer()


        def asn1_dt(asn1_time):
            if asn1_time:
                return datetime.datetime.strptime(asn1_time, '%Y%m%d%H%M%SZ')
            else:
                return None

        not_before = asn1_dt(cert.get_notBefore())
        not_after = asn1_dt(cert.get_notAfter())


        # Hide self-signed certificates from the tree
        if subject == issuer:
            subject_e = tree.setdefault(subject.hash(), TreeNode(subject))
        else:
            issuer_e = tree.setdefault(issuer.hash(), TreeNode(issuer))
            subject_e = tree.setdefault(subject.hash(), TreeNode(subject))

            issuer_e.children.add(subject_e)

        subject_e.not_before = not_before
        subject_e.not_after = not_after
        
    # Trim all branches from the base
    for node1 in tree.values():
        for node2 in node1.children:
            try:
                del tree[node2.dn.hash()]
            except KeyError:
                pass

    return tree

def pp_tree(tree):
    """
    Pretty-print a certificate tree.
    """
    for hash in sorted(tree.keys()):
        _pp_branches(tree[hash], '')


def _pp_branches(node, prefix, tail=False):
    #!TODO: I don't think this is completely right.  Won't print "|" in all subtrees

    root = node.dn
    branches = list(node.children)

    sys.stdout.write(prefix)

    now = datetime.datetime.now()
    if ((node.not_before and now < node.not_before) or 
        (node.not_after and now > node.not_after)):
        flag = 'FAIL'
    else:
        flag = ' OK '

    date_str = '%s - %s' % ((node.not_before if node.not_before else '?'), 
                            (node.not_after if node.not_after else '?'),
                            )
    

    if tail:
        new_prefix = prefix+'    '
        print '`-- [%s] %s (%s)' % (flag, make_cert_str(root), date_str)
    else:
        new_prefix = prefix+'|   '
        print '|-- [%s] %s (%s)' % (flag, make_cert_str(root), date_str)

    if branches == []:
        return
    

    for node in branches[:-1]:
        _pp_branches(node, new_prefix)
    _pp_branches(branches[-1], new_prefix, True)


def make_hexhash(cert):
    """
    Generate the string representation of a certificate hash.

    """
    hexhash = hex(cert.hash())[2:]
    if hexhash[-1] == 'L':
        hexhash = hexhash[:-1]
    hexhash = '0'*(8-len(hexhash)) + hexhash

    return hexhash


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)

    main()
