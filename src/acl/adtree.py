'''
This module includes classes related to ACL decision tree (ADTree). ADTree can 
be considered as functionally similar to/different from the prefix match tree 
(PMTree, module acl.pmtree) in the following sense:
1) PMTree processes a prefix bit-by-bit, in the order from highest to lowest 
bit. ADTree processes the predicate of a ACE in the order of fields in 
adtreeFieldOrder.
2) PMTree's non-terminal node has two children -- left node and right node, and
the left edge has label 0 and the right label has label 1. ADTree's non-terminal
node has one or more children. Each associated edge is associated with a range
of values associated with the node's field. 
3) PMTree's non-terminal node always has label n/a. ADTree's non-terminal node 
can have various labels (corresponding to the fields such as src_ip, dst_ip, 
src_port, dst_port and protocol)

Created on Aug 18, 2013

@author: zhil2
'''

import math
from bisect import insort
from acl.parse import appendRuleToRangeRuleList, appendRuleToPrefixRuleList, \
                      ruleIsCovered, rulesOverlapped
from acl.pmtree import PMTree
from acl.pmtree_algo import listRange2ListPrefix, \
                        generateShortestPrefixRuleListFromTree
from misc.algorithm import excludeRange, subsetSumToX
#from acl.parse import saveSvgFile


class ADNode:
    '''
    ADNode (ACL decision node) is the node for ADTree.    
    
    Examples:
    >>> n=ADNode('ip')
    >>> print n
    (ip:)
    >>> n.hasChild()
    False
    >>> c=ADNode('port')
    >>> n.addChild((4,5),c)
    >>> n.addChild((0,1),c)
    >>> n.hasChild()
    True
    >>> print n
    (ip:|0-1||4-5|(port:))
    >>> n.addChild((2,3),ADNode('port'))
    >>> print n
    (ip:|0-1||4-5|(port:)|2-3|(port:))
    >>> d=ADNode('protocol')
    >>> c.addChild((0,10),d)
    >>> c.addChild((45,45),d)
    >>> print n
    (ip:|0-1||4-5|(port:|0-10||45-45|(protocol:))|2-3|(port:))
    >>> print c
    (port:|0-10||45-45|(protocol:))
    >>> print d
    (protocol:)
    >>> p=n.duplicate()
    >>> print p
    (ip:|0-1||4-5|(port:|0-10||45-45|(protocol:))|2-3|(port:))
    >>> p.isEqualTo(n)
    True
    >>> n.removeChildNode(c)
    >>> print n
    (ip:|2-3|(port:))
    >>> p.isEqualTo(n)
    False
    '''

    def __init__(self,label):
        self.label=label
        self.children=[]
        
    def __str__(self):
        '''
        Prints subtree starting from this node recursively.
        Implementation: use a dictionary to store children with the same node 
        as the key, and their ranges (in a list) as the value.       
        '''        
        s='('+self.label+':'
        if self.hasChild():
            
            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            
            #iterate dictionary
            for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values
                for r in rs:
                    s+='|%d-%d|' % (r[0],r[1]) 
                s+=c.__str__()
        s+=')'
        return s
    
    def __repr__(self):
        return str(id(self))
    
    def hasChild(self):
        '''
        Returns True if children is non-empty.
        '''
        return not not self.children
    
    def addChild(self,childRange,childNode):
        '''
        Expands a node by adding a children node childNode, which must be first
        created. Associated with the child node is a range (low,high).
        Note: In this way, multiple children may be associated with one child 
        node (but different ranges).
        '''
        #self.children.append((childRange,childNode))
        insort(self.children,(childRange,childNode))
        
    def removeChildNode(self,childNode):
        '''
        Removes ALL children with child node equal to childNode
        '''
        self.children=[(r,c) for r,c in self.children if c!=childNode]
        
    def removeAllChildren(self):
        '''
        Removes ALL children
        '''
        self.children=[]

    def getNodeNumber(self):
        '''
        Get the total number of (non-repeated) nodes in the subtree starting
        from this node.
        '''
        nn=1
        if self.hasChild():

            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            
            #iterate dictionary
            for c,_ in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values
                nn+=c.getNodeNumber()
        return nn

    def getNodeListInSubTree(self,ln):
        '''
        Get all the nodes in the subtree starting from this node, and
        append them to ln
        '''
        ln.append(self)
        if self.hasChild():

            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            
            #iterate dictionary
            for c,_ in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values
                c.getNodeListInSubTree(ln)
    
#     def getDotCode(self,edgeIsPrefix=False,dictFieldRange=None):
#         '''
#         Generate dot code for visualize subtree from this node recursively.
#         If flag edgeIsPrefix is true and a dictionary of field range is 
#         specified, print edge label in prefix instead of range
#         '''
#         code=''
#         if self.hasChild():
#             code+=repr(self)+' [label="'+self.label+'",shape=oval];\n'
#             
#             #add children to dictionary
#             dictNode=_generateDictNode(self.children)
#             
#             #iterate dictionary
#             for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
#                         #sorted(dictNode.items(), key=lambda x: x[1]) 
#                         #make sure sorting in order of values
#                 code+=repr(c)+' [label="'+c.label+'"];\n'
#                 code+=repr(self)+' -> '+repr(c)+' [label="'
#                 
#                 if edgeIsPrefix and dictFieldRange:
#                     rs=listRange2ListPrefix(rs,dictFieldRange[self.label])
#                 
#                 nR=0
#                 for r in rs:
#                     nR+=1
#                     if nR<=2:
#                         if edgeIsPrefix and dictFieldRange:
#                             code+='('+r+')'
#                         else:
#                             code+='(%d-%d)' % (r[0],r[1])
#                     else:
#                         code+=' ...'
#                         break  
#                 code+='"];\n'
#                 code+=c.getDotCode(edgeIsPrefix,dictFieldRange)
#         else:
#             code+=repr(self)+' [label="'+self.label+'",shape=box];\n'
#                         
#         return code

    def getCostDotCode(self,dictCost):
        '''
        Generate dot code for visualizing cost subtree from this node recursively.
        '''
        code=''
        assert(self in dictCost)
        currLabel='%d' % dictCost[self]
        if self.hasChild():
            code+=repr(self)+' [label="'+currLabel+'",shape=oval];\n'
             
            #add children to dictionary
            dictNode=_generateDictNode(self.children)
             
            #iterate dictionary
            for c,_ in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values
                code+=repr(c)+' [label="'+c.label+'"];\n'
                code+=repr(self)+' -> '+repr(c)+' [label="'
                                  
                code+='"];\n'
                code+=c.getCostDotCode(dictCost)
        else:
            currLabel='%d' % dictCost[self]
            code+=repr(self)+' [label="'+currLabel+'",shape=box];\n'
                         
        return code
    
    def generatePrefixRuleListND(self,listDecision,dictFieldRange,
                                 fmt,dictCost=None,getCode=False,
                                 listNodeOfInterest=None):
        '''
        Generate multi-dimensional prefix rule list from the subtree starting
        from this node.
        
        fmt (format): 
        prefix_overlap - predicates can overlap (calling the DP algorithm)
        prefix_nonoverlap - the predicates in the rules will be disjoint;
        range - predicate is in range format
        
        dictCost (optional):
        Dictionary to store the cost at each node.
        Key: the node (ADNode) of the tree. 
        Value: the weight of the node times number of rules associated 
        with the node.
        
        getCode (optional):
        If True, code returned is the dot code for visualizing the tree
        If False, code returned is ''
        
        listNodeOfInterest (optional):
        Only the rule list associated with the list of interested nodes
        are output to lnd.
        If None, all nodes in the subtree are of interest.
        
        Returns: 
        -- A weight
        -- A list of dictionary, with each entry including the fields and
        decision.
        -- Code for plot the resulting dot file
        '''
        '-----------code------------'
        code=''
        '-----------code------------'
        if self.hasChild():

            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            fieldRange=dictFieldRange[self.label]

            #sanity check range
            l,h=fieldRange
            assert(l==0)
            nBit=int(math.log(h+1,2))
            assert(2**nBit-1==h)
            
            #iterate dictionary
            listRangeRule=[]
            listChildren=[]
            dictWeight={}
            dictLnd={}
            dictNewCode={}
            for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values                        
                #print 'rs:'
                #print rs
                w,lnd,newCode=c.generatePrefixRuleListND(listDecision,
                                dictFieldRange,fmt,dictCost=dictCost,
                                getCode=getCode,
                                listNodeOfInterest=listNodeOfInterest)
                listChildren.append(c)
                dictWeight[c]=w
                dictLnd[c]=lnd
                dictNewCode[c]=newCode
                for r in rs:
                    appendRuleToRangeRuleList(listRangeRule,r,c)
            
            listCurrRule=[]            
            if fmt=='prefix_overlap':#rules can overlap: use DP                                        
                tree=PMTree(listRangeRule,listIsRange=True,fieldRange=fieldRange)
                #print listRangeRule
                #saveSvgFile(tree.getDotCode(),'../output/tree.svg',True)

                res=generateShortestPrefixRuleListFromTree(tree,nBit,
                                                listChildren,dictWeight)
            
                listCurrRule=res[1][0]
            elif fmt=='prefix_nonoverlap':
                for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                            #sorted(dictNode.items(), key=lambda x: x[1]) 
                            #make sure sorting in order of values                        
                    ps=listRange2ListPrefix(rs,fieldRange)
                    for p in ps:
                        appendRuleToPrefixRuleList(listCurrRule,p,c)
            elif fmt=='range':
                for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                            #sorted(dictNode.items(), key=lambda x: x[1]) 
                            #make sure sorting in order of values                        
                    for r in rs:
                        appendRuleToPrefixRuleList(listCurrRule,r,c)
                
                
            # #sort the list, such that more specific rules (less *) are in front
            #20131008 result still correct if not used
            #listCurrRule=sorted(listCurrRule,key=lambda x: x['prefix'].count('*'))

            #count num rules for each child
            dictNRule={}#dict of decision (i.e. child) -> number of rules
            for rule in listCurrRule:
                c=rule['decision']                
                dictNRule.setdefault(c,0)
                dictNRule[c]+=1
                
            #generate the new n-dim rule list via 'cross product'
            lnd=[]
            for rule in listCurrRule:
                c=rule['decision']             
                currLnd=dictLnd[c]
                for rule2 in currLnd:
                    newRule=rule2.copy()
                    ###newRule[self.label]=(prio,rule['prefix']) #20131008 remove redundant prio
                    newRule[self.label]=rule['prefix']
                    if listNodeOfInterest is None:
                        lnd.append(newRule)
                    else:
                        for n in listNodeOfInterest:
                            if c==n or c.label!=n.label:
                                lnd.append(newRule)

            
            #the weight of this node is the sum of child weight x child rules
            w=sum([dictWeight[c]*dictNRule[c] for c in listChildren])            
            #NOTE: above not particularly better than belows. do more test            
            #w=sum([dictNRule[c] for c in listChildren])
            #w=sum([dictWeight[c] for c in listChildren])
            #w=1
            
            if dictCost is not None:
                dictCost[self]=w
                #also update all the subtree nodes' cost by times the #rules
                for c in listChildren:
                    c.propagateCostGain(dictNRule[c],dictCost)
            
            '-----------code------------'
            if getCode:
                code+=repr(self)+' [label="'+self.label+'",shape=oval];\n'
                #code+=repr(self)+' [label="'+self.label+' %d' % w+'",shape=oval];\n'
            '-----------code------------'
            
               
            '-----------code------------'
            if getCode:

                #record the rules (for generate dot code only)
                ###for iRule,rule in zip(range(len(listCurrRule)),listCurrRule): #20131008 remove redundant prio
                dictPrefixs={}#dict of decision (i.e. child) -> list of (priority,prefix)
                for rule in listCurrRule:
                    c=rule['decision']                
                    ###prio=nCurrRule-iRule-1 #20131008 remove redundant prio
                    lr=dictPrefixs.setdefault(c,[])
                    ###lr.append((prio,rule['prefix'])) #20131008 remove redundant prio
                    lr.append(rule['prefix'])
                           
                for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                            #sorted(dictNode.items(), key=lambda x: x[1]) 
                            #make sure sorting in order of values
                    code+=repr(c)+' [label="'+c.label+'"];\n'
                    code+=repr(self)+' -> '+repr(c)+' [label="'
                    
                    nP=0
                    for res in dictPrefixs[c]:
                        ###prio,prefix=res #20131008 remove redundant prio
                        #prefix=res
                        nP+=1
                        if nP<=2:
                            if fmt=='range':
                                code+='(%d-%d)' % (res[0],res[1])
                            else:
                                ###code+='(%d:%s)' % (prio,prefix) #20131008 remove redundant prio
                                #code+='(%s)' % prefix
                                code+='(%s)' % res
                        else:
                            code+=' ...'
                            break
                    code+='"];\n'
                    code+=dictNewCode[c]
            '-----------code------------'
            
            #print 'weight (non-terminal): %d' % w
            return (w,lnd,code)
            
        else:#is terminal node.
            assert(self.label in listDecision)                        
            
            w=1

            if dictCost is not None:
                dictCost[self]=w
            
            #lnd=[{'decision':self.label}]#list n-dim
            lnd=[({'decision':self.label})]#list n-dim

            '-----------code------------'
            if getCode:
                code+=repr(self)+' [label="'+self.label+'",shape=box];\n'
                #code+=repr(self)+' [label="'+self.label+' %d' % w+'",shape=box];\n'
            '-----------code------------'
                        
            #print 'weight (terminal): %d' % w
            return (w,lnd,code)
            
    def isEqualTo(self,other):
        '''
        Compare the subtree starting from this node with another. Returns True
        iff structure is equal and all corresponding labels are equal.
        '''
        if self.label!=other.label:
            return False
        else:
            if (not self.hasChild()) and (not other.hasChild()):
                return True
            elif ((    self.hasChild()) and (not other.hasChild())) or \
                 ((not self.hasChild()) and (    other.hasChild())):
                return False
            else:
                # compare two nodes's children (tricky!)
                # must iterate at exactly the same order!
                # here: iterate by value, since value is non-overlapping range,
                # this is possible (in general this may not be true)

                #for both self and other, add children to dictionary  
                dictNodeSelf=_generateDictNode(self.children)
                dictNodeOther=_generateDictNode(other.children)
                                              
                #Compare list of range pairwise
                listListChildRangeSelf=[rs for c,rs in \
                            sorted(dictNodeSelf.items(),key=lambda x: x[1])]
                listListChildRangeOther=[rs for c,rs in \
                            sorted(dictNodeOther.items(),key=lambda x: x[1])]
                
                if listListChildRangeSelf!=listListChildRangeOther:
                        #The above compares all the entries in the list of list
                    return False

                #Compare children nodes pairwise
                listChildNodeSelf=[c for c,rs in \
                            sorted(dictNodeSelf.items(),key=lambda x: x[1])]
                listChildNodeOther=[c for c,rs in \
                            sorted(dictNodeOther.items(),key=lambda x: x[1])]
                
                if len(listChildNodeSelf)!=len(listChildNodeOther):
                    return False
                for i,_ in enumerate(listChildNodeSelf):
                    if not listChildNodeSelf[i].isEqualTo(listChildNodeOther[i]):
                        return False
                                                        
                return True

    def duplicate(self):
        '''
        Duplicate the subtree starting from this node. Return the duplicated
        subtree.
        Implementation: use a dictionary to store children with the same node 
        as the key, and their ranges (in a list) as the value.       
        '''
        other=ADNode(self.label)
        if self.hasChild():            

            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            
            #iterate dictionary
            for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values
                c2=c.duplicate()
                for r in rs:
                    other.addChild(r,c2)
        return other
    
    def propagateRule(self,rangeRuleND,listDecision,style='default'):
        '''
        Propagate the n-dim range rule in the subtree starting from 
        the current node. The subtree is part of the ADTree, namely, each 
        non-terminal node has a label belonging to the keys of the rule, and
        each terminal node has a label belong to listDecision. It
        propagates the rule by reading from the rule the range corresponding 
        to the current node label, splitting the subtree, and recursively
        call propagateRule in the range-overlapped children nodes, until 
        reaching the terminal node whose label is in listDecision, then it
        fixes the label with the 'decision' value in rule. 
        
        style: if 'default', overwrite decision without checking what the \
        original decision is; if 'serial', overwrite decision only if the
        original decision is 'permit' and the current rule is 'deny'; if 
        'parallel', overwrite decision only if the original decision is 'deny'
        and the current rule is 'permit'
        '''
        
        # #for ACL, limit decision to 'permit' or 'deny'
        # for d in listDecision:
        #     assert(d=='permit' or d=='deny')

        #if reached terminal decision node:
        if self.label in listDecision:
            
#             #fix the label with the rule's decision, that's it
#             self.label=rangeRuleND['decision']
            
            if style=='default':
                #fix the label with the rule's decision, that's it
                self.label=rangeRuleND['decision']
            elif style=='serial':
                if self.label=='permit' and rangeRuleND['decision']=='deny':
                    self.label=rangeRuleND['decision']
            elif style=='parallel':
                if self.label=='deny' and rangeRuleND['decision']=='permit':
                    self.label=rangeRuleND['decision']
            else:
                assert(0)
        elif self.label in rangeRuleND.keys():
            field=self.label
            r=rangeRuleND[field]
            assert(self.hasChild())            
            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            #iterate dictionary
            for c,rs in sorted(dictNode.items(), key=lambda x: x[1]):
                        #sorted(dictNode.items(), key=lambda x: x[1]) 
                        #make sure sorting in order of values
                #get list of overlapped (O) and list of nonoverlapped (NO)
                O,NO=_getRangeListOverlap(rs,r)
                #if overlapped range list is not empty, need to create a new
                #branch to duplicate the original
                if not not O:
                    if not not NO:
                        #duplicate subtree
                        c2=c.duplicate()
                        #branching tree according to new lists 
                        #self.removeAllChildren()
                        self.removeChildNode(c)
                        for r_ in O:
                            self.addChild(r_,c2)
                        for r_ in NO:
                            self.addChild(r_,c)
                        #recursively call overlapped new child
                        c2.propagateRule(rangeRuleND,listDecision,style)
                    else:#completely overlapped
                        #recursively call child
                        c.propagateRule(rangeRuleND,listDecision,style)            
                #else:#if O is empty (nothing overlapped)
                    #assert(0)#???would this ever happen??? 
                    #-> yes, this could happen           
        else:
            assert(0)#shouldn't be other cases than decision or field
    
    def trim(self):
        '''
        Trim the subtree starting from this node. Two branches of the tree can
        be merged if the ranges are adjacent (e.g. (3,5) and (6,7)) and the
        child nodes (more precisely, the subtrees from the child nodes) are 
        equal.
        '''
        #first, recursively call for all its children nodes                     
        dictNode=_generateDictNode(self.children)
        for res in sorted(dictNode.items(), key=lambda x: x[1]):
            c=res[0]
            c.trim()
        
        #1st round: merge ranges as much as possible
        if len(self.children)>1:    
            newChildren=[]        
            children=self.children #Note: must be ordered by the range!
            listMergable=[False]*(len(children)-1)
            #first iteration, get mergable or not
            for i,_ in enumerate(listMergable):
                r1,c1=children[i]
                r2,c2=children[i+1]
                if r1[1]+1==r2[0]:
                    if c1.isEqualTo(c2):
                        listMergable[i]=True
            #second iteration, merge if possible
            streak=False
            for i,_ in enumerate(listMergable):
                if listMergable[i]==True:
                    if streak==False:
                        iStart=i
                        iEnd=i+1
                        streak=True
                    else:#streak continues, don't write yet
                        iEnd+=1
                else:#if not mergable, ready to append previous nodes
                    if streak==True:
                        #add (any) node with the new range in the streak
                        r1,c1=children[iStart]
                        r2,c2=children[iEnd]
                        newChildren.append(((r1[0],r2[1]),c1))
                        streak=False
                    else:#if not mergable and no streak, safe to write i-th node
                        newChildren.append(children[i])
                    
            #last unfinished streak
            if streak==True:
                #add (any) node with the new range in the streak
                r1,c1=children[iStart]
                r2,c2=children[iEnd]
                newChildren.append(((r1[0],r2[1]),c1))
                streak=False
            else:#no streak, safe to write the last
                newChildren.append(children[-1])  
                                      
            #lastly, replace
            self.children=newChildren
        
        #second round: if child nodes are 'equal', replace with the same node
        if len(self.children)>1:
            children=self.children #Note: must be ordered by the range!
            for i,_ in enumerate(children):
                r1,c1=children[i]
                for j in range(len(children))[i+1:]:
                    r2,c2=children[j]
                    if c1.isEqualTo(c2):
                        children[j]=(r2,c1)
                        
    def propagateCostGain(self,gain,dictCost):
        '''
        Update all the subtree nodes' cost by times the gain.
        
        dictCost:
        Dictionary to store the cost at each node.
        Key: the node (ADNode) of the tree. 
        Value: the weight of the node times number of rules associated 
        with the node.
        '''
        dictCost[self]*=gain
        if self.hasChild():
            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            #iterate dictionary
            for c,_ in sorted(dictNode.items(), key=lambda x: x[1]):
                c.propagateCostGain(gain,dictCost)
    def searchCost(self,dictCost,cost):
        '''
        Search the cost in the subtree starting from this ADNode.
        If found, return a list of nodes whose sum of cost is equal to cost.
        If not found, return an empty list. 
        '''
        assert(self in dictCost)
        #first, try self
        if dictCost[self]==cost:
            return [self]
        #second, try children        
        if self.hasChild():
            #add children to dictionary
            dictNode=_generateDictNode(self.children)
            #iterate dictionary
            currDictCost={}
            for c,_ in sorted(dictNode.items(), key=lambda x: x[1]):
                currDictCost[c]=dictCost[c]
            cut=subsetSumToX(currDictCost,cost)
            if not not cut:#cut not empty: found
                return cut
            #third, still cannot make it, try children's children 
            for c,_ in sorted(dictNode.items(), key=lambda x: x[1]):
                cut=c.searchCost(dictCost,cost)
                if not not cut:
                    return cut
        return []
            
class ADTree:
    '''
    ADTree (ACL decision tree) is a tree with the following properties:
    1) Each terminal node has a label, being one of the decisions (e.g.
    'permit' or 'deny').
    2) Each non-terminal node has a label, being one of the fields (e.g.
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol')
    3) Each non-terminal node has one or more children, and each edge 
    associated with a child specifies a range within the max range of the 
    parent node's field (e.g. if label is 'src_ip', the range is within 
    [0,2^32).
    4) The field associated with the nodes of each level of the tree is
    specified in the order of adtreeFieldOrder (e.g. from highest to lowest
    level 'src_port'->'src_ip'->'dst_ip'->'dst_port'->'protocol').

    Example:
    >>> dictFieldRange=dictFieldRange={'ip':(0,15),'port':(0,7),'protocol':(0,3)}
    >>> adtreeFieldOrder=('port','ip','protocol')
    >>> defaultDecision='deny'
    >>> listDecision=('deny', 'permit')
    >>> acl=[{'port':(4,5),'ip':(0,15),'protocol':(0,3),'decision':'permit'},{'port':(0,1),'ip':(0,15),'protocol':(0,3),'decision':'permit'},]
    >>> t=ADTree(acl,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision)
    >>> print t
    {(port:|0-1||4-5|(ip:|0-15|(protocol:|0-3|(permit:)))|2-3||6-7|(ip:|0-15|(protocol:|0-3|(deny:))))}
    >>> print t.getNodeNumber()
    7
    >>> acl2=[{'port':(0,7),'ip':(0,15),'protocol':(0,1),'decision':'deny'},{'port':(0,7),'ip':(0,4),'protocol':(0,3),'decision':'permit'},{'port':(0,1),'ip':(0,15),'protocol':(0,3),'decision':'permit'},]
    >>> t2=ADTree(acl2,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision)
    >>> print t2
    {(port:|0-1|(ip:|0-15|(protocol:|0-1|(deny:)|2-3|(permit:)))|2-7|(ip:|0-4|(protocol:|0-1|(deny:)|2-3|(permit:))|5-15|(protocol:|0-3|(deny:))))}
    >>> print t2.getNodeNumber()
    11

    >>> dictFieldRange={'ip':(0,15),'port':(0,15)}
    >>> adtreeFieldOrder=('port','ip')
    >>> defaultDecision='deny'
    >>> acl=[{'port':(8,8),'ip':(8,11),'decision':'permit'},{'port':(10,11),'ip':(8,11),'decision':'permit'},]    
    >>> t=ADTree(acl,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision)
    >>> print t
    {(port:|0-7||9-9||12-15|(ip:|0-15|(deny:))|8-8||10-11|(ip:|0-7||12-15|(deny:)|8-11|(permit:)))}
    >>> res=t.generatePrefixRuleListND('prefix_overlap')
    >>> print res[0]
    [{'ip': '****', 'decision': 'deny', 'port': '1001'}, {'ip': '10**', 'decision': 'permit', 'port': '10**'}, {'ip': '****', 'decision': 'deny', 'port': '****'}]
    '''
    
    def __init__(self,rangeRuleListND,defaultDecision,adtreeFieldOrder,
                 dictFieldRange,listDecision):
        '''
        Constructor takes an range rule list, which is a list of dictionary, 
        where each dictionary correspond to an ACE, with key being the field, 
        and value being the specified range (low,high).
        Also passed in is the default decision (i.e. the rule applies to all
        possible predicate at the end of the list) and the adtreeFieldOrder,
        and a dictionary of the field range, and list of all decisions        
        '''
        
        #create root node and the node chain pointed to the defaultDecision
        self._defaultDecision=defaultDecision
        self._adtreeFieldOrder=adtreeFieldOrder
        self._dictFieldRange=dictFieldRange
        self._listDecision=listDecision
        
        #for ACL, limit decision to 'permit' or 'deny'
        for d in listDecision:
            assert(d=='permit' or d=='deny')
        
        curNode=ADNode(adtreeFieldOrder[0])
        self._root=curNode
        for field in adtreeFieldOrder[1:]:
            c=ADNode(field)
            curNode.addChild(dictFieldRange[curNode.label],c)
            curNode=c
        curNode.addChild(dictFieldRange[curNode.label],ADNode(defaultDecision))
        #print self

        #go through list
        for rule in rangeRuleListND[::-1]:#in order of lowest priority to highest

            #need to recursively call, to propagate new decision labels            
            self._root.propagateRule(rule,listDecision)
            
        #trim tree after every time adding a new ACE
            #self._root.trim()#if in for-loop, save memory            
        self._root.trim()#if out of for-loop, save time
            #print self
            
    def __str__(self):
        return '{'+self._root.__str__()+'}'
    
    def isEqualTo(self,other):
        return self._root.isEqualTo(other._root)
    def __eq__(self,other):
        return self.isEqualTo(other)
    def __ne__(self,other):
        return not self.isEqualTo(other)
    def isSameAs(self,other):
        return id(self)==id(other)

    def getNodeNumber(self):
        return self._root.getNodeNumber()
    
    def duplicate(self):
        '''
        Duplicate a ADTree.
        '''
        other=ADTree([],self._defaultDecision,self._adtreeFieldOrder,
                 self._dictFieldRange,self._listDecision)
        other._root=self._root.duplicate()
        return other        
    
    def generatePrefixRuleListND(self,fmt,getCode=False):
        '''
        fmt (format): 
        prefix_overlap - predicates can overlap (calling the DP algorithm)
        prefix_nonoverlap - the predicates in the rules will be disjoint;
        range - predicate is in range format

        '''
        _,ruleListND,newCode=self._root.generatePrefixRuleListND(
        self._listDecision,self._dictFieldRange,fmt,getCode=getCode)

        if getCode:        
            #complete dot code
            code='''digraph {
rankdir="TB"
edge [fontsize=10] 
node [fontsize=10,margin=0.0]
'''
            code+=newCode
            code+='}\n'

        else:
            code=""

        #add default rule at last if fmt is prefix_nonoverlap or range
        if fmt=='prefix_nonoverlap' or fmt=='range':
            defaultRule=_generateDefaultRule(self._adtreeFieldOrder,self._dictFieldRange,self._defaultDecision,fmt)
            ruleListND.append(defaultRule)
                
        #remove redundancy in the list 
        if fmt=='prefix_overlap' or fmt=='prefix_nonoverlap':
            ruleListND=_removeRedundancy(ruleListND,self._adtreeFieldOrder,'prefix')
        elif fmt=='range':
            ruleListND=_removeRedundancy(ruleListND,self._adtreeFieldOrder,'range')
                
        #20131008 remove redundant prio
#         #strip off prio (priority)
#         for rule in ruleListND:
#             for field in self._dictFieldRange:
#                 _,prefix=rule[field]
#                 rule[field]=prefix
                    
        return (ruleListND,code)
    
#     def getDotCode(self,edgeIsPrefix=False,dictFieldRange=None):
#         code='''digraph {
# rankdir="TB"
# edge [fontsize=10] 
# node [fontsize=10,margin=0.0]
# '''
#         code+=self._root.getDotCode(edgeIsPrefix,dictFieldRange)
#         code+='}\n'
#         return code
    def getDotCode(self,fmt):
        '''
        fmt (format): 
        prefix_overlap - predicates can overlap (calling the DP algorithm)
        prefix_nonoverlap - the predicates in the rules will be disjoint;
        range - predicate is in range format
        '''
        _,code=self.generatePrefixRuleListND(fmt,getCode=True)
        return code
    
    def generateCostDict(self,fmt):
        '''
        Generate a dictionary of cost for ADTree tree. Key: the node (ADNode) 
        of the tree. Value: the weight of the node times number of rules 
        associated with the node.
        
        fmt (format): 
        prefix_overlap - predicates can overlap (calling the DP algorithm)
        prefix_nonoverlap - the predicates in the rules will be disjoint;
        range - predicate is in range format
        '''
        dictCost={}
        _,_,_=self._root.generatePrefixRuleListND(
        self._listDecision,self._dictFieldRange,fmt,dictCost=dictCost)
        
#         #add cost of root
#         rootCost=0
#         if self._root.hasChild():
#             for _,c in self._root.children:
#                 rootCost+=dictCost[c]
#         dictCost[self._root]=rootCost

        return dictCost
    
    def getCostDotCode(self,dictCost):
        code='''digraph {
rankdir="TB"
edge [fontsize=10] 
node [fontsize=10,margin=0.0]
'''
        code+=self._root.getCostDotCode(dictCost)
        code+='}\n'
        return code
    
def _generateDictNode(children):
    '''
    Generate a dictionary from the children of a non-terminal ADNode. The 
    dictionary is in the format of key: ADNode and value: list of ranges
    associated with the same ADNode.    
    '''
    dictNode={}#key: child node, value: list of child range
    for r,c in children:
        if not (c in dictNode):
            dictNode[c]=[r]
        else:
            insort(dictNode[c],r)
                    #insort inserts value in order
    return dictNode

def _getRangeListOverlap(rs,s):
    '''
    Given a list of ranges rs and another range s, return two new list of 
    ranges rsO (rs overlapped) and rsNO (rs non-overlapped).
    
    Examples:
    >>> _getRangeListOverlap([(0,4),(6,10)],(3,7))
    ([(3, 4), (6, 7)], [(0, 2), (8, 10)])
    >>> _getRangeListOverlap([(0,4),(6,10)],(-1,7))
    ([(0, 4), (6, 7)], [(8, 10)])
    >>> _getRangeListOverlap([(0,4),(6,10)],(5,7))
    ([(6, 7)], [(0, 4), (8, 10)])
    >>> _getRangeListOverlap([(6,10)],(7,7))
    ([(7, 7)], [(6, 6), (8, 10)])
    >>> _getRangeListOverlap([(6,10)],(11,11))
    ([], [(6, 10)])
    '''
    
    rsO=[]
    rsNO=[]
    for r in rs:
        rsO_,rsNO_=_getRangeOverlap(r,s)
        rsO+=rsO_
        rsNO+=rsNO_
    return (rsO,rsNO)

def _getRangeOverlap(r,s):
    '''
    Given range r and another range s, return two new list of 
    ranges O (overlapped) and NO (non-overlapped), where O is all the 
    overlapped ranges, and NO is r excluding O
    
    Warning: very tricky!
    
    Examples:
    >>> _getRangeOverlap((3,7),(1,2))
    ([], [(3, 7)])
    >>> _getRangeOverlap((3,7),(1,3))
    ([(3, 3)], [(4, 7)])
    >>> _getRangeOverlap((3,3),(1,2))
    ([], [(3, 3)])
    >>> _getRangeOverlap((3,3),(1,3))
    ([(3, 3)], [])
    >>> _getRangeOverlap((3,7),(1,5))
    ([(3, 5)], [(6, 7)])
    >>> _getRangeOverlap((3,7),(3,5))
    ([(3, 5)], [(6, 7)])
    >>> _getRangeOverlap((7,7),(7,7))
    ([(7, 7)], [])
    >>> _getRangeOverlap((3,7),(4,6))
    ([(4, 6)], [(3, 3), (7, 7)])
    >>> _getRangeOverlap((3,7),(4,4))
    ([(4, 4)], [(3, 3), (5, 7)])
    >>> _getRangeOverlap((3,7),(4,8))
    ([(4, 7)], [(3, 3)])
    >>> _getRangeOverlap((3,7),(9,10))
    ([], [(3, 7)])
    >>> _getRangeOverlap((3,3),(9,9))
    ([], [(3, 3)])
    '''
    
    rL,rR=r
    sL,sR=s
    assert(rL<=rR)
    assert(sL<=sR)
     
    if sL<rL and sR<rL:
        O=[]
    elif sL<rL and sR<rR:
        O=[(rL,sR)]
    elif sL<rL and sR>=rR:
        O=[(rL,rR)]
    elif sL<=rR and sR<rR:
        O=[(sL,sR)]
    elif sL<=rR and sR>=rR:
        O=[(sL,rR)]
    elif sL>rR and sR>rR:
        O=[]
    else:
        assert(0)
    
    if not not O:
        NO=excludeRange(r,O[0])
    else:
        NO=[r]
    
    return (O,NO)


def _removeRedundancy(ruleListND,adtreeFieldOrder,fmt='prefix'):
    '''
    Remove redundancy (RR) in n-dim rule list.
    
    fmt:'prefix' - prefix rule or 'range' - range rule

    How: go through the rules from lowest priority to highest. For each rule,
    compare against reference rules with priority lower than it (with order
    from highest to lowest priority). When can be sure if a rule can be removed:
    if it is completely covered by a reference rule and they have the same 
    decision. When can be sure if a rule definitely cannot be removed: if it
    overwrites a reference rule (i.e., they make different decisions and they
    have some overlap in covered space). If a rule can surely be removed, 
    remove it from the list, and start the whole process all over again with
    the new list; if a rule cannot be removed surely, skip the rest of the 
    process of comparing it against its reference rules, and go on to the next
    rule.    
    '''
    continueRR=True
    while continueRR:
        continueRR=False
        outerLoopBreak=False
        for iRule,rule in zip(range(len(ruleListND)),ruleListND)[0:-1][::-1]:
                                                #from second last to first
            for refRule in ruleListND[iRule+1:]:
                                    #from current rule's next rule onwards                    
                #print rule
                #print refRule
                ruleOverlapped=rulesOverlapped(rule,refRule,adtreeFieldOrder,fmt)
                ruleCovered=ruleIsCovered(rule,refRule,adtreeFieldOrder,fmt)
                sameDecision=(refRule['decision']==rule['decision'])            
                if sameDecision and ruleCovered:
                    #remove rule, restart the looping all over again
                    ruleListND.remove(rule)
                    #print len(ruleListND)
                    outerLoopBreak=True
                    continueRR=True
                    break
                if not sameDecision and ruleOverlapped:
                    #rule should not be removed, skip lower ref rules
                    break                        
                #else: continue searching                        
            if outerLoopBreak:
                break            
        #from acl.parse import printRuleListND
        #printRuleListND(ruleListND,adtreeFieldOrder)            
    return ruleListND

def _generateDefaultRule(adtreeFieldOrder,dictFieldRange,defaultDecision,fmt):
    defaultRule={}            
    for field in adtreeFieldOrder:
        fieldRange=dictFieldRange[field]
        if fmt=='prefix_nonoverlap':
            defaultRule[field]=listRange2ListPrefix([fieldRange],fieldRange)[0]
        elif fmt=='range':
            defaultRule[field]=fieldRange
        else:
            assert(0)
    defaultRule['decision']=defaultDecision
    return defaultRule


if __name__ == '__main__': 
    import doctest
    print doctest.testmod()

        