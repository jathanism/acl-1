'''
Algorithms related to ADTree.

Created on Oct 18, 2013

@author: zhil2
'''

import math
from acl.parse import ternaryRuleListND2RangeRuleListND
from acl.adtree import ADTree, _generateDefaultRule
from acl.parse import ruleIsCovered, rulesOverlapped
from acl.parse import saveSvgFile
from misc.algorithm import getNeighbor

def generateDependencyDict(ruleListND,adtreeFieldOrder):
    '''
    Generate a dictionary of dependency for entries in the n-dim rule list.
    This operation should (asserted) be performed after the function 
    _removeRedundancy (removal of redundant rules). 
    
    Definition of dependency:
    if there is a directed dependency edge A -> B, it means that 1) A has higher
    priority than B, AND 2) A overwrites (some) of B's decisions (in other 
    words, rule A and B must yield different decisions and there are overlaps 
    of predicates between them). Exception: e.g., A -> M -> N -> C and A is 
    fully covered by M, then there is no need to have A -> C (in other words,
    A and C becomes independent conditioned on M).
    
    NOTE: the exception is not be good enough to fully remove conditional
    independence. But this will not falsely remove legitimate dependency in
    the graph. So it will not affect the correctness of the rule list 
    decomposition following the dependency generation, but merely speed up
    the generateDependencyDict function.
    
    How: two nested loops over the rule list. 
    
    Returns:
    1) the dependency dictionary
    2) the dot code to plot the dependency graph
    '''
    
    #dictDep={}
    '-----------code------------'
    code=''
    code+='''digraph {
rankdir="TB"
edge [fontsize=10] 
node [fontsize=10,margin=0.0]
'''
    for iRule,_ in enumerate(ruleListND):
        code+='%d' % iRule+' [label="'+'%d' % iRule+'",shape=oval];\n'
    '-----------code------------'
    for iRule,rule in zip(range(len(ruleListND)),ruleListND)[0:-1][::-1]:
                                                #from second last to first
        for iRefRule,refRule in zip(range(len(ruleListND)),ruleListND)[iRule+1:]:
                                    #from current rule's next rule onwards  
            #print iRule
            #print iRefRule                  
            ruleOverlapped=rulesOverlapped(rule,refRule,adtreeFieldOrder,'prefix')
            ruleCovered=ruleIsCovered(rule,refRule,adtreeFieldOrder,'prefix')
            sameDecision=(refRule['decision']==rule['decision'])            
            if not sameDecision and ruleOverlapped:
                #============
                '-----------code------------'
                code+='%d' % iRule+' -> '+'%d' % iRefRule+';\n'
                '-----------code------------'                    
                #============
                if ruleCovered:#ruleCovered is a special case of ruleOverlapped
                    break                        
                #else: continue searching                        
    code+='}\n'  
        
    #return (dictDep,code)
    return code
    
def verifyRuleList(ruleListND,defaultDecision,adtreeFieldOrder,dictFieldRange,
                   listDecision,tree):
    '''
    Verify if generated n-dim ternary rule list is equivalent to original 
    ADTree tree.
    '''
     
    #print 'Construct range list from ruleListND...'    
    rl=ternaryRuleListND2RangeRuleListND(ruleListND,adtreeFieldOrder)    
        
    #print '''
    #Create ACL decision tree from range list...'''
    ts=ADTree(rl,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision)
    #print ts
    
    return ts==tree

def generateAdtreeFromMultipleList(listRuleList,defaultDecision,
                    adtreeFieldOrder,dictFieldRange,listDecision,arrangement):
    '''
    Generate ADTree from a list of range rule list installed on switches
    with serial or parallel arrangement.
    
    arrangement:
    'serial' - a packet gets denied if it is denied by ANY of the lists; a 
    packet gets accepted if it is accepted by ALL the lists.
    'parallel' - a packet gets denied if it is denied by ALL of the lists; a 
    packet gets accepted if it is accepted by ANY of the lists.
    
    Example:
    >>> dictFieldRange={'ip':(0,15),'port':(0,7),'protocol':(0,3)}
    >>> adtreeFieldOrder=('port','ip','protocol')
    >>> defaultDecision='deny'
    >>> listDecision=('deny', 'permit')
    >>> rl1=[{'port':(2,3),'ip':(5,7),'protocol':(1,3),'decision':'permit'},{'port':(4,4),'ip':(0,12),'protocol':(1,3),'decision':'permit'},]
    >>> rl2=[{'port':(0,7),'ip':(6,12),'protocol':(3,3),'decision':'permit'},{'port':(0,6),'ip':(0,4),'protocol':(0,3),'decision':'permit'},]
    >>> t=generateAdtreeFromMultipleList([rl1,rl2],defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision,'serial')
    >>> print t
    {(port:|0-1||5-7|(ip:|0-15|(protocol:|0-3|(deny:)))|2-3|(ip:|0-5||8-15|(protocol:|0-3|(deny:))|6-7|(protocol:|0-2|(deny:)|3-3|(permit:)))|4-4|(ip:|0-4|(protocol:|0-0|(deny:)|1-3|(permit:))|5-5||13-15|(protocol:|0-3|(deny:))|6-12|(protocol:|0-2|(deny:)|3-3|(permit:))))}
    >>> t2=generateAdtreeFromMultipleList([rl1,rl2],defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision,'parallel')
    >>> print t2
    {(port:|0-1||5-6|(ip:|0-4|(protocol:|0-3|(permit:))|5-5||13-15|(protocol:|0-3|(deny:))|6-12|(protocol:|0-2|(deny:)|3-3|(permit:)))|2-3|(ip:|0-4|(protocol:|0-3|(permit:))|5-7|(protocol:|0-0|(deny:)|1-3|(permit:))|8-12|(protocol:|0-2|(deny:)|3-3|(permit:))|13-15|(protocol:|0-3|(deny:)))|4-4|(ip:|0-4|(protocol:|0-3|(permit:))|5-12|(protocol:|0-0|(deny:)|1-3|(permit:))|13-15|(protocol:|0-3|(deny:)))|7-7|(ip:|0-5||13-15|(protocol:|0-3|(deny:))|6-12|(protocol:|0-2|(deny:)|3-3|(permit:))))}
    '''
    
    #for ACL, limit decision to 'permit' or 'deny'
    for d in listDecision:
        assert(d=='permit' or d=='deny')
    
    baseTree=ADTree(listRuleList[0],defaultDecision,
                adtreeFieldOrder,dictFieldRange,listDecision)
    
    for ruleListND in listRuleList[1:]:
        currTree=ADTree(ruleListND,defaultDecision,
                adtreeFieldOrder,dictFieldRange,listDecision)
        
        #generate prefix rule list with fmt='range' 
        #will generate 'flattened' rule list (i.e. no overlap among rules). 
        #Use this list to do rule propagation in baseTree.
        #Warning: access _root (directly use a piece of code from
        #generatePrefixRuleListND, but shouldn't be a problem)
        _,rangeRuleListND,_=currTree._root.generatePrefixRuleListND(listDecision,
                                                dictFieldRange,'range')
         
        #for rule in rangeRuleListND[::-1]:#in order of lowest priority to highest
        for rule in rangeRuleListND:#since rules are non-overlapped, order 
                                    #of visiting the rules doesn't matter

            #need to recursively call, to propagate new decision labels            
            baseTree._root.propagateRule(rule,listDecision,arrangement)
             
        #trim tree after every time adding a new ACE
            #baseTree._root.trim()#if in for-loop, save memory            
        baseTree._root.trim()#if out of for-loop, save time
    
    return baseTree

def cutEven(tree,nChunk,listDecision,dictFieldRange,adtreeFieldOrder):
    
    #for ACL, limit decision to 'permit' or 'deny'
    for d in listDecision:
        assert(d=='permit' or d=='deny')
    assert(nChunk>=1)

    #costFmt='range'
    #costFmt='prefix_nonoverlap'
    costFmt='prefix_overlap'
    
    remainChunk=nChunk
    listNewTree=[]
    while remainChunk>1:
        
        #get the tree's cost dict
        dictCost=tree.generateCostDict(costFmt)
        
        assert(tree._root in dictCost)
        remainCost=dictCost[tree._root]
                
        refCost=math.floor(remainCost/float(remainChunk))

        print 'Current reference cost: %d' %refCost
        saveSvgFile(tree.getCostDotCode(dictCost),'../output/tmp.svg',True)
                
        trial_successful=False
        for i in range(20):
            currCost=refCost+getNeighbor(i)
            #clip
            if currCost<1:
                currCost=1
            if currCost>remainCost:
                currCost=remainCost

            currCut=tree._root.searchCost(dictCost,currCost)    
            #assert(not not currCut)#temporally assume that can find the cut
            if not currCut:
                continue
            else:
                trial_successful=True
            
            #generate range rule list for the new tree
            _,lnd,_=tree._root.generatePrefixRuleListND(listDecision,
                    dictFieldRange,'range',listNodeOfInterest=currCut)
            
            #construct new tree
            newTree=ADTree(lnd,'permit',adtreeFieldOrder,dictFieldRange,
                           listDecision)
    
            listNewTree.append(newTree)
            
            #in the old tree, propagate rule (permit) to overwrite the portion curved out
            defaultRule=_generateDefaultRule(adtreeFieldOrder,
                              dictFieldRange,'permit','range')
            for node in currCut:
                node.propagateRule(defaultRule,listDecision)
            tree._root.trim()
        
            remainChunk-=1
            
            if trial_successful:
                break
        if not trial_successful:
            assert(0)
    #add remaining old tree        
    listNewTree.append(tree)
    
    return listNewTree    


if __name__ == '__main__': 
    import doctest
    print doctest.testmod()