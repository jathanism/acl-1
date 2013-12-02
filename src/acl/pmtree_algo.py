'''
Algorithms related to PMTree.

Created on Oct 18, 2013

@author: zhil2
'''

import math
from acl.parse import appendRuleToRangeRuleList, appendRuleToPrefixRuleList
from acl.pmtree import PMTree

def listRange2ListPrefix(listRange,fieldRange):
    '''
    Convert a range list to prefix list.
    
    Algorithm: generate a prefix rule list based on the range list, and convert
    it to PMTree, and fetch the entries in the range list from the
    tree.
    
    Examples:
    >>> listPrefix=listRange2ListPrefix([(0,4),(10,12)],(0,15))
    >>> print listPrefix
    ['00**', '0100', '101*', '1100']
    >>> print listRange2ListPrefix([(8,8),(10,11)],(0,15))
    ['1000', '101*']
    '''
    
    #sanity check range
    l,h=fieldRange
    assert(l==0)
    nBit=int(math.log(h+1,2))
    assert(2**nBit-1==h)    

    #generate prefix rule list
    listFat=[]
    for r in listRange:
        appendRuleToRangeRuleList(listFat,r,'y')
    appendRuleToRangeRuleList(listFat,fieldRange,'n')    
    #generate tree
    tree=PMTree(listFat,True,fieldRange)
    #saveSvgFile(tree.getDotCode(),'../output/tree.svg',True)
    
    #get node with 'y' label
    ly= tree.fetch('y')

    #fill in last bits by '*' in ly
    lz=[]
    for y in ly:
        lz.append(y+(nBit-len(y))*'*')
    
    return lz

def generateShortestPrefixRuleListFromTree(tree,lenPrefix,listDecision,
                                           dictDecisionWeight):
    '''
    Generate a list of rules from a prefix match tree.
    A rule is in the format of {'prefix':prefix, 'decision':decision}.

    Algorithm: use dynamic programming for 1-D prefix rule. This 
    implementation is based on backward recursion. To avoid redundant 
    work, use a dictionary to store already-computed costs.
    
    Examples:
    >>> from acl.pmtree import PMTree
    >>> listPrefixRule=[{'prefix': '101***', 'decision': 'permit'}, {'prefix': '0*****', 'decision': 'permit'}, {'prefix': '******', 'decision': 'deny'}]
    >>> tree=PMTree(listPrefixRule)
    >>> listDecision=('deny', 'permit')
    >>> dictDecisionWeight={'deny':1,'permit':1}
    >>> generateShortestPrefixRuleListFromTree(tree,6,listDecision,dictDecisionWeight)
    (3, [[{'prefix': '0*****', 'decision': 'permit'}, {'prefix': '101***', 'decision': 'permit'}, {'prefix': '******', 'decision': 'deny'}], [{'prefix': '101***', 'decision': 'permit'}, {'prefix': '1*****', 'decision': 'deny'}, {'prefix': '******', 'decision': 'permit'}]])
    '''
    #>>> generateShortestPrefixRuleListFromTree(tree,6,listDecision,
    #dictDecisionWeight)
    
    prefix='*'*lenPrefix
    minCost=float('inf')
    listMinListRule=[]
    for decision in listDecision:
        dictCost={}
        thisCost,thisListRule=_cost(prefix,tree,decision,listDecision,
                                    dictDecisionWeight,dictCost=dictCost)
        if minCost>thisCost:
            minCost=thisCost
            listMinListRule=[]
            listMinListRule.append(thisListRule)
        elif minCost==thisCost:
            listMinListRule.append(thisListRule)
    return (minCost,listMinListRule)

def _cost(prefix,tree,decision,listDecision,dictDecisionWeight,dictCost=None):
    '''
    Compute the cost of a prefix in the tree with decision as the in the last
    rule of the corresponding rule list. dictCost: (prefix,decision) -> 
    (minCost,minListRule) is an optional dictionary, that if used, stores 
    previously computed costs to avoid repeated computation.
    
    Returns: the minimum cost and the minimum rule list
    
    Algorithm: dynamic programming in backward recursive implementation.
    
    Examples:
    >>> from acl.pmtree import PMTree    
    >>> listPrefixRule=[{'prefix': '101***', 'decision': 'permit'}, {'prefix': '0*****', 'decision': 'permit'}, {'prefix': '******', 'decision': 'deny'}]
    >>> tree=PMTree(listPrefixRule)
    >>> listDecision=('deny', 'permit')
    >>> dictDecisionWeight={'deny':1,'permit':1}
    >>> dictCost={}
    >>> _cost('000000',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    2
    >>> _cost('100000',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    1
    >>> _cost('101000',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    2
    >>> _cost('111000',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    1
    >>> _cost('0*****',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    2
    >>> _cost('11****',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    1
    >>> _cost('10****',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    2
    >>> _cost('1*****',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    2
    >>> _cost('******',tree,'deny',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    3
    >>> _cost('******',tree,'permit',listDecision,dictDecisionWeight,dictCost=dictCost)[0]
    3
    '''    
    
    debugLevel=0
    
    #if cost result already computed and stored, use it
    if dictCost is not None:
        res=dictCost.get((prefix,decision))
        if res is not None:
            if debugLevel>0:
                print (prefix,decision)+res
            return res
        
    #otherwise, do recursive computation, and store result
    isConsistent,consistencyDecision=tree.isConsistentIn(prefix)
    if isConsistent:#baseline case
        if consistencyDecision==decision:
            minCost=dictDecisionWeight[consistencyDecision]
            minListRule=[]
            appendRuleToPrefixRuleList(minListRule,prefix,consistencyDecision)            
        else:
            minCost=dictDecisionWeight[consistencyDecision]\
                                            +dictDecisionWeight[decision]
            minListRule=[]
            appendRuleToPrefixRuleList(minListRule,prefix,consistencyDecision)                        
            appendRuleToPrefixRuleList(minListRule,prefix,decision)
        if debugLevel>1:           
            print '**********************************'
            print 'prefix= '+prefix
            print 'decision= '+decision
            print 'consistencyDecision= '+consistencyDecision
            print '**********************************'
    else:
        minCost=float('inf')
        minListRule=[]
        for thisDecision in listDecision:
            prefixUnderscore=prefix.replace('*','0',1)
            prefixOverscore=prefix.replace('*','1',1)
            costUnderscore,listRuleUnderscore=_cost(prefixUnderscore,tree,
                        thisDecision,listDecision,dictDecisionWeight,dictCost=dictCost)                                  
            costOverscore, listRuleOverscore =_cost(prefixOverscore ,tree,
                        thisDecision,listDecision,dictDecisionWeight,dictCost=dictCost)                      
            if thisDecision==decision:
                thisCost=(costUnderscore+costOverscore
                          -dictDecisionWeight[thisDecision])
                thisListRule=listRuleUnderscore[0:-1]+listRuleOverscore[0:-1]
                appendRuleToPrefixRuleList(thisListRule,prefix,thisDecision)                        
            else:
                thisCost=(costUnderscore+costOverscore
                          -dictDecisionWeight[thisDecision])\
                          +dictDecisionWeight[decision]
                thisListRule=listRuleUnderscore[0:-1]+listRuleOverscore[0:-1]
                appendRuleToPrefixRuleList(thisListRule,prefix,thisDecision)                        
                appendRuleToPrefixRuleList(thisListRule,prefix,decision)                        
            if minCost>thisCost:
                minCost=thisCost
                minListRule=thisListRule
                minListRuleUnderscore=listRuleUnderscore
                minListRuleOverscore=listRuleOverscore
        if debugLevel>1:
            print '**********************************'
            print 'prefix= '+prefix
            print 'decision= '+decision
            print minListRuleUnderscore
            print minListRuleOverscore
            print '**********************************'
    if dictCost is not None:
        dictCost[(prefix,decision)]=(minCost,minListRule)
        # print '*******curr dictCost is:********'
        # print dictCost
    if debugLevel>0:    
        print (prefix,decision)+(minCost,minListRule)        
    return (minCost,minListRule)



if __name__ == '__main__': 
    import doctest
    print doctest.testmod()