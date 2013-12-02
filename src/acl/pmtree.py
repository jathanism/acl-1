'''
This module includes classes related to prefix match tree.

Created on Aug 16, 2013

@author: zhil2
'''

import math
from acl.parse import int2BinStr

class PMNode:
    '''
    PMNode (prefix match tree node) is the node for PMTree. It has a label 
    and an optional left/right node pair.

    Examples of PMNode:
    >>> n=PMNode('test')
    >>> print n
    test
    >>> n.leafPush()
    >>> print n.isExpanded()
    True
    >>> n.left.leafPush()
    >>> print n
    (L:(L:test)(R:test))(R:test)
    >>> print n.isConsistent()
    (True, 'test')
    >>> print n.isConsistentAndTrim()
    (True, 'test')
    >>> print n
    test
    >>> m=PMNode('hello')
    >>> l=PMNode('hello')
    >>> m.isEqualTo(l)
    True
    >>> l.leafPush()
    >>> l.left.leafPush()
    >>> m.isEqualTo(l)
    False
    >>> m.leafPush()
    >>> m.left.leafPush()
    >>> m.isEqualTo(l)
    True
    >>> m==l
    True
    >>> m!=l
    False
    >>> m.left.right.leafPush()
    >>> m.isEqualTo(l)
    False
    >>> l.fix('abc')
    >>> m.fix('abc')
    >>> m.isEqualTo(l)
    True
    '''
    def __init__(self,label):

        '''
        Constructor
        '''
        self.label=label

    def __repr__(self):
        return str(id(self))

    def __str__(self):
        '''
        Print subtree starting from this node recursively. Example:
        {(L:permit)(R:(L:(L:deny)(R:permit))(R:deny))}
        '''
        #way 1: don't display n/a or unreachable braches
        if self.label!='n/a':
            return self.label
        elif self.isExpanded():
            return '(L:'+self.left.__str__()+')(R:'+self.right.__str__()+')'
        else:
            return ''
        # #way 2: display everything
        # if self.isExpanded():
        #     return self.label+'(L:'+self.left.__str__()+ \
        #                            ')(R:'+self.right.__str__()+')'
        # else:
        #     return self.label

    def __eq__(self,other):
        return self.isEqualTo(other)
    def __ne__(self,other):
        return not self.isEqualTo(other)
    def isSameAs(self,other):
        return id(self)==id(other)
    
    def leafPush(self):
        '''
        Expands a node by adding two children nodes with the same label as its, 
        followed by overwriting its label by 'n/a'
        '''
        self.left=PMNode(self.label)
        self.right=PMNode(self.label)
        self.label='n/a'

    def isExpanded(self):
        '''
        Checks whether the node has been expanded
        '''        
        tfLeft=hasattr(self,'left')
        tfRight=hasattr(self,'right')
        assert(tfLeft==tfRight)        
        return tfLeft

    def removeChildren(self):
        '''
        Removes children of a node, also returns true if node had children,
        otherwise do nothing and return false.
        '''
        if self.isExpanded():
            delattr(self,'left')
            delattr(self,'right')
            return True
        else:
            return False

    def fix(self,label):
        '''
        Fix the label of the node, and if it has children, trim them
        '''
        self.label=label
        self.removeChildren()

    def isConsistent(self):
        '''
        Checks if the children branches have the same decisions.
        If the node has label 'n/a' and has no children, also return false.
        '''
        if not self.isExpanded():
            if self.label=='n/a':
                return (False,'n/a')
            else: 
                return (True,self.label)
        else:
            tfLeft,labelLeft=self.left.isConsistent()
            tfRight,labelRight=self.right.isConsistent()
            if tfLeft==True and tfRight==True and labelLeft==labelRight:
                return (True,labelLeft)
            else:
                return (False,'n/a')

    def isConsistentAndTrim(self):
        '''
        Checks if the children branches have the same decisions. 
        If the node has label 'n/a' and has no children, also return false.
        At the same time, it tries to trim the tree without affecting the
        Semantics.
        '''
        if not self.isExpanded():
            if self.label=='n/a':
                return (False,'n/a')
            else: 
                return (True,self.label)
        else:
            tfLeft,labelLeft=self.left.isConsistentAndTrim()
            tfRight,labelRight=self.right.isConsistentAndTrim()
            if tfLeft==True and tfRight==True and labelLeft==labelRight:
                self.fix(labelLeft)#the only difference from isConsistent()
                return (True,labelLeft)
            else:
                return (False,'n/a')

    def fetch(self,label):
        '''
        Fetch the label in the subtree. Returns a list of prefixes corresponding
        to the terminal nodes with the label        
        '''
        ps=[]
        if self.label==label:
            ps.append('')
        if self.isExpanded():
            psl=self.left.fetch(label)
            for p in psl:
                ps.append('0'+p)
            psr=self.right.fetch(label)
            for p in psr:
                ps.append('1'+p)
        return ps
        
    def isEqualTo(self,other):
        '''
        Compare the subtree starting from this node with another. Returns True
        iff structure is equal and all corresponding labels are equal.
        '''
        if self.label!=other.label:
            return False
        else:
            if (not self.isExpanded()) and (not other.isExpanded()):
                return True
            elif ((    self.isExpanded()) and (not other.isExpanded())) or \
                 ((not self.isExpanded()) and (    other.isExpanded())):
                return False
            else:
                return self.left.isEqualTo(other.left) and \
                       self.right.isEqualTo(other.right)

    def getDotCode(self):
        '''
        Generate dot code for visualize subtree from this node recursively.
        '''
        code=''
        if self.isExpanded():
            if self.label!='n/a':
                code+=repr(self)+' [label="'+self.label+'",shape=oval];\n'
            else:
                code+=repr(self)+' [label="",shape=circle];\n'
            code+=repr(self.left)+' [label="'+self.left.label+'"];\n'
            code+=repr(self)+' -> '+repr(self.left)+' [label="0"];\n'
            code+=self.left.getDotCode()
            code+=repr(self.right)+' [label="'+self.right.label+'"];\n'
            code+=repr(self)+' -> '+repr(self.right)+' [label="1"];\n'
            code+=self.right.getDotCode()                        
        else:
            code+=repr(self)+' [label="'+self.label+'",shape=box];\n'                        
        return code

class PMTree:
    '''
    PMTree (prefix match tree) is a binary tree with the following properties:
    1) Each terminal node has a label, being one of the decisions (e.g. 
    'permit' or 'deny')
    2) Each non-terminal node has a label 'n/a'
    3) Each non-terminal node n has two children node l and r. the left edge 
    (n,l) has label 
    '0' and the right edge (n,r) has label '1'
    A PMTree can be constructed via a prefix priority rule list. For example:
        r1: {101***} -> permit
        r2: {0*****} -> permit
        r3: {******} -> deny
    A PMTree can also be constructed via a range priority rule list. Example:
        r1: (0,4) -> a
        r2: (5,9) -> b
        r3: (10,12) -> a
        r4: (0,15) -> b 
                
    Examples of PMTree:
    >>> listPrefixRule=[{'prefix': '0101**', 'decision': 'deny'}, {'prefix': '0100**', 'decision': 'deny'}, {'prefix': '1**', 'decision': 'deny'}, {'prefix': '0***', 'decision': 'accept'}]
    >>> n=PMTree(listPrefixRule)
    >>> print n
    {(L:(L:accept)(R:(L:deny)(R:accept)))(R:deny)}
    >>> print n.isConsistent()
    (False, 'n/a')
    >>> print n.fetch('deny')
    ['010', '1']
    >>> print n.fetch('accept')
    ['00', '011']
    
    >>> listPrefixRule=[{'prefix': '00', 'decision': 'permit'}, {'prefix': '01', 'decision': 'deny'}, {'prefix': '10', 'decision': 'permit'}, {'prefix': '11', 'decision': 'deny'}]
    >>> n=PMTree(listPrefixRule)
    >>> print n
    {(L:(L:permit)(R:deny))(R:(L:permit)(R:deny))}
    >>> print n.isConsistent()
    (False, 'n/a')
    >>> print n.fetch('permit')
    ['00', '10']
    >>> print n.fetch('deny')
    ['01', '11']
    
    >>> listRangeRule=[{'range': (0,4), 'decision': 'a'},{'range': (5,9), 'decision': 'b'},{'range': (10,12), 'decision': 'a'},{'range': (0,15), 'decision': 'b'}]
    >>> t=PMTree(listRangeRule,listIsRange=True,fieldRange=(0,15))
    >>> print t
    {(L:(L:a)(R:(L:(L:a)(R:b))(R:b)))(R:(L:(L:b)(R:a))(R:(L:(L:a)(R:b))(R:b)))}
    '''
    def __init__(self,listRule,listIsRange=False,fieldRange=None):
        
        if listIsRange:
            listRangeRule=listRule

            #sanity check range
            assert(not not fieldRange)
            l,h=fieldRange
            assert(l==0)
            nBit=int(math.log(h+1,2))
            assert(2**nBit-1==h)    
            
            #create root node with no decision
            self._root=PMNode('n/a')
    
            'WARNING: HIGHLY INEFFICIENT!!! CHANGE!!!'
#             #go through listRangeRule
#             for rule in listRangeRule[::-1]:#in order of lowest priority to highest
#                 label=rule['decision']
#                 r=rule['range']
#                 l,h=r
#                 for n in xrange(l,h+1):
#                     prefix=int2BinStr(n,nBit)
#                     currNode=self._root#reset currNode to root
#                     for i in xrange(nBit):
#                         if prefix[i]=='*':
#                             break
#                         elif prefix[i]=='0':
#                             if not currNode.isExpanded():
#                                 currNode.leafPush()
#                             currNode=currNode.left
#                         elif prefix[i]=='1':
#                             if not currNode.isExpanded():
#                                 currNode.leafPush()
#                             currNode=currNode.right
#                         else:
#                             assert(0)
#                     currNode.fix(label)
#                 #optional - after each rule, try to trim the tree  
#                 self.trim()

            'REPLACING ABOVE'
            #go through listRangeRule
            for rule in listRangeRule[::-1]:#in order of lowest priority to highest
                label=rule['decision']
                low,high=rule['range']
                lowBS=int2BinStr(low,nBit)
                highBS=int2BinStr(high,nBit)
                
                assert(len(lowBS)==nBit)
                assert(len(highBS)==nBit)
                
                #reset currNode to root
                currLowNode=self._root
                currHighNode=self._root
                #advance pointer; if low and high diverge, fix the label
                #between them
                for i in xrange(nBit):
                    #expand 
                    if not currLowNode.isExpanded():
                        currLowNode.leafPush()
                    if (not currLowNode.isSameAs(currHighNode)) and (not currHighNode.isExpanded()):
                        currHighNode.leafPush()
                    
                    #move pointer, fix label between if diverged
                    if currLowNode.isSameAs(currHighNode) and lowBS[i]=='0' and highBS[i]=='0':
                        currLowNode=currLowNode.left
                        currHighNode=currHighNode.left
                    elif currLowNode.isSameAs(currHighNode) and lowBS[i]=='1' and highBS[i]=='1':
                        currLowNode=currLowNode.right
                        currHighNode=currHighNode.right
                    elif currLowNode.isSameAs(currHighNode) and lowBS[i]=='0' and highBS[i]=='1':
                        currLowNode=currLowNode.left
                        currHighNode=currHighNode.right                        
                    elif currLowNode.isSameAs(currHighNode) and lowBS[i]=='1' and highBS[i]=='0':
                        assert(0)
                    else:#diverge begins
                        if lowBS[i]=='0':
                            currLowNode.right.fix(label)
                            currLowNode=currLowNode.left
                        elif lowBS[i]=='1':
                            currLowNode=currLowNode.right
                        else:
                            assert(0)
                        if highBS[i]=='1':
                            currHighNode.left.fix(label)
                            currHighNode=currHighNode.right
                        elif highBS[i]=='0':
                            currHighNode=currHighNode.left
                        else:
                            assert(0)                        
                currLowNode.fix(label)
                currHighNode.fix(label)
                #optional - after each rule, try to trim the tree  
                self.trim()
                
        else:
            listPrefixRule=listRule
        
            #create root node with no decision
            self._root=PMNode('n/a')
    
            #go through listPrefixRule
            for rule in listPrefixRule[::-1]:#in order of lowest priority to highest
                label=rule['decision']
                prefix=rule['prefix']
                currNode=self._root#reset currNode to root
                for i,_ in enumerate(prefix):
                    if prefix[i]=='*':
                        break
                    elif prefix[i]=='0':
                        if not currNode.isExpanded():
                            currNode.leafPush()
                        currNode=currNode.left
                    elif prefix[i]=='1':
                        if not currNode.isExpanded():
                            currNode.leafPush()
                        currNode=currNode.right
                    else:
                        assert(0)
                currNode.fix(label)
                #optional - after each rule, try to trim the tree  
                self.trim()
    def __str__(self):
        return '{'+self._root.__str__()+'}'
    def getDotCode(self):
        code='''digraph {
rankdir="TB"
edge [fontsize=10]
node [fontsize=10,margin=0.0]
'''
        code+=self._root.getDotCode()
        code+='}\n'
        return code
    def isConsistent(self):
        return self._root.isConsistent()
    def trim(self):
        self._root.isConsistentAndTrim()
    def isConsistentIn(self,prefix):
        currNode=self._root
        for i,_ in enumerate(prefix):
            if prefix[i]=='*':
                break
            elif prefix[i]=='0':
                if currNode.isExpanded():
                    currNode=currNode.left
                else:
                    return (True,currNode.label)
            elif prefix[i]=='1':
                if currNode.isExpanded():
                    currNode=currNode.right
                else:
                    return (True,currNode.label)
            else:
                assert(0)
        return currNode.isConsistent()
    def fetch(self,label):
        return self._root.fetch(label)

if __name__ == '__main__': 
    import doctest
    print doctest.testmod()
