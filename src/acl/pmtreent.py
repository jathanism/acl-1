'''
This module includes classes related to prefix match tree with non-terminal 
label.

Created on Sep 11, 2013

@author: zhil2
'''
from acl.pmtree import PMNode

class PMNodeNT(PMNode):
    '''
    PMNodeNT (prefix match tree node with non-terminal label) is generalization 
    of PMNode with a new feature: It can have a single child (left or right), 
    whereas PMNode can have 0 or 2 children (left and right)
    
    Examples of PMNode:
    >>> n=PMNodeNT('test')
    >>> print n
    test
    >>> n.leafPush()
    >>> print n
    (L:test)(R:test)
    >>> print n.isExpanded()
    True
    >>> n.left.expandLeft()
    >>> n.left.left.label='hello'
    >>> print n
    (L:test(L:hello))(R:test)
    
    '''
    def leafPush(self):
        '''
        Expands a node by adding two children nodes with the same label as its, 
        followed by overwriting its label by 'n/a'
        '''
        self.left=PMNodeNT(self.label)
        self.right=PMNodeNT(self.label)
        self.label='n/a'
    def expandLeft(self):
        self.left=PMNodeNT('n/a')
    def expandRight(self):
        self.right=PMNodeNT('n/a')
    def isLeftExpanded(self):
        return hasattr(self,'left')
    def isRightExpanded(self):
        return hasattr(self,'right')
    def __str__(self):
        '''
        Print subtree starting from this node recursively. Example:
        {(L:permit)(R:(L:(L:deny)))}
        '''
        s=''
        if self.label!='n/a':
            s+=self.label            
        if self.isLeftExpanded():
            s+='(L:'+self.left.__str__()+')'
        if self.isRightExpanded():
            s+='(R:'+self.right.__str__()+')'
        return s
    def getDotCode(self):
        code=''
        if self.label!='n/a':
            code+=repr(self)+' [label="'+self.label+'",shape=box];\n'
        else:
            code+=repr(self)+' [label="",shape=circle];\n'
        if self.isLeftExpanded():
            code+=repr(self.left)+' [label="'+self.left.label+'"];\n'
            code+=repr(self)+' -> '+repr(self.left)+' [label="0"];\n'
            code+=self.left.getDotCode()
        if self.isRightExpanded():
            code+=repr(self.right)+' [label="'+self.right.label+'"];\n'
            code+=repr(self)+' -> '+repr(self.right)+' [label="1"];\n'
            code+=self.right.getDotCode()                                                
        return code


class PMTreeNT:
    '''
    Prefix match tree with non-terminal label. This class of trees has decisions 
    at non-terminal nodes (vs. for PMTree, decision is at terminal nodes only). 
    Further more, a node may have 0, or 1, or 2 children (for PMTree, a node
    may have 0 or 2 children).
    Typical usage: constructed with optimized rule list, and is for the purpose
    of its visualization.    
    
    Examples:
    >>> listRule=[{'prefix': '00*', 'decision': 'permit'}, {'prefix': '10*', 'decision': 'permit'}, {'prefix': '***', 'decision': 'deny'}]
    >>> t=PMTreeNT(listRule)
    >>> print t
    {deny(L:(L:permit))(R:(L:permit))}
    '''
#     >>> print t.getDotCode()
#     digraph {
#     rankdir="TB"
#     edge [fontsize=10]
#     node [fontsize=10,margin=0.0]
#     45626288 [label="deny",shape=box];
#     45626432 [label="n/a"];
#     45626288 -> 45626432 [label="0"];
#     45626432 [label="",shape=circle];
#     45626504 [label="permit"];
#     45626432 -> 45626504 [label="0"];
#     45626504 [label="permit",shape=box];
#     45626000 [label="n/a"];
#     45626288 -> 45626000 [label="1"];
#     45626000 [label="",shape=circle];
#     45626360 [label="permit"];
#     45626000 -> 45626360 [label="0"];
#     45626360 [label="permit",shape=box];
#     }
    
    
    def __init__(self,listPrefixRule):
        '''
        Construction with a prefix rule list.
        '''        
        #create root node with no decision
        self._root=PMNodeNT('n/a')

        #go through listPrefixRule
        for rule in listPrefixRule[::-1]:#in order of lowest priority to highest
            label=rule['decision']
            prefix=rule['prefix']
            currNode=self._root#reset currNode to root
            for i,_ in enumerate(prefix):
                if prefix[i]=='*':
                    break
                elif prefix[i]=='0':
                    if not currNode.isLeftExpanded():
                        currNode.expandLeft()
                    currNode=currNode.left
                elif prefix[i]=='1':
                    if not currNode.isRightExpanded():
                        currNode.expandRight()
                    currNode=currNode.right
                else:
                    assert(0)
            currNode.fix(label)
            #optional - after each rule, try to trim the tree  
            #self.trim()
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

        