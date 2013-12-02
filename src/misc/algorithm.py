'''
This module includes some commonly used algorithms.

Created on Oct 17, 2013

@author: zhil2
'''

import math

def subsetSumToX(dictCost,targetSum):
    '''
    Return a subset in dictCost that sum to targetSum.
    
    Example:
    >>> subsetSumToX({'x':3,'y':1,'z':5,'w':8},13)
    ['w', 'z']
    >>> subsetSumToX({'x':3,'y':1,'z':5,'w':8},10)
    []
    >>> subsetSumToX({'x':3,'y':1,'z':5,'w':8},1)
    ['y']
    '''
    for v in dictCost.itervalues():
        assert(v>0)
    targetSumKey=id(dictCost)
    dictCost[targetSumKey]=-targetSum
    subset=_subset_summing_to_zero(dictCost)
    if not subset:#subset is []
        return []
    else:
        assert(targetSumKey in subset)
        subset.remove(targetSumKey)
        return subset

def _subset_summing_to_zero(activities):
    '''
    Subset sum to zero problem.
    
    Example:
    >>> _subset_summing_to_zero({'x':-3,'y':-2,'z':5,'w':8})
    ['x', 'y', 'z']
    >>> _subset_summing_to_zero({'x':-3,'y':-2,'z':6,'w':8})
    []
    '''
    subsets = {0: []}
    for (activity, cost) in activities.iteritems():
        old_subsets = subsets
        subsets = {}
        for (prev_sum, subset) in old_subsets.iteritems():
            subsets[prev_sum] = subset
            new_sum = prev_sum + cost
            new_subset = subset + [activity]
            if 0 == new_sum:
                new_subset.sort()
                return new_subset
            else:
                subsets[new_sum] = new_subset
    return []

def excludeRange(r,i):
    '''
    Return the list of range equal to range r excluding range i
    '''
    rL,rR=r
    iL,iR=i
    assert(rL<=rR)
    assert(iL<=iR)
    e=[(rL,iL-1),(iR+1,rR)]
    #remove negative intervals
    e=[(low,high) for low,high in e if low<=high]
    return e

def getNeighbor(trial):
    '''
    Return a number that is in the neighbor of 0.

    Examples:
    >>> print getNeighbor(0)
    0
    >>> print getNeighbor(1)
    1
    >>> print getNeighbor(2)
    -1
    >>> print getNeighbor(3)
    2
    >>> print getNeighbor(4)
    -2
    >>> print getNeighbor(5)
    3
    >>> print getNeighbor(6)
    -3
    '''
    return int(math.ceil(trial/2.0)*((trial%2)*2-1))

if __name__ == '__main__': 
    import doctest
    print doctest.testmod()
