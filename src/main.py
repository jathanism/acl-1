'''
Sandbox for testing

Created on Aug 16, 2013

@author: zhil2

'''

import re
from subprocess import call
import csv
from time import time

from acl.parse import generatePrefixRuleListFromAcl,saveSvgFile
from acl.parse import dictFieldRange
from acl.pmtree import PMTree
from acl.pmtreent import PMTreeNT
from acl.pmtree_algo import generateShortestPrefixRuleListFromTree
from acl.adtree import ADTree
from acl.parse import printRuleListND, acl2RangeRuleListND
from acl.adtree_algo import generateAdtreeFromMultipleList, cutEven, \
                            generateDependencyDict, verifyRuleList
'''
=================
functions 
=================
'''

'''
=================
parameters
=================
'''
aclFilePath='../acl_samples/my-test-fw.test'
listField=('name','line','type','decision','protocol','src_ip','src_port',
           'dst_ip','dst_port','time','inactive','log','remark','original')
listDecision=('deny', 'permit')#the first one being the default decision by ACL
defaultDecision='deny'#default decision implied, if not specified in ACL
dictDecisionWeight={'deny':1,'permit':1}

#from few to many
#adtreeFieldOrder=('src_port','protocol','dst_ip','dst_port','src_ip',)
#adtreeFieldOrder=('protocol','src_port','dst_ip','dst_port','src_ip',)
#adtreeFieldOrder=('src_port','protocol','dst_ip','src_ip','dst_port',)
#from many to few
#adtreeFieldOrder=('src_ip','dst_port','dst_ip','protocol','src_port',)
#adtreeFieldOrder=('dst_port','src_ip','dst_ip','protocol','src_port',)
#adtreeFieldOrder=('src_ip','dst_port','dst_ip','src_port','protocol',)
'general good rule: from few to many (to reduce the AD tree size)'
adtreeFieldOrder=('protocol','src_port','dst_port','src_ip','dst_ip',)
#test:
#adtreeFieldOrder=('src_port','src_ip','dst_ip','dst_port','protocol',)


print '''
=================
Parse ACL
=================
'''

print 'Parse ACL file to csv...'
pipe=call(['perl','acl2csv.0.05.pl',aclFilePath])

print '\nGet csv file name...'
aclFileName=re.search(r'/([\w-]+).test',aclFilePath).group(1)
csvFilePath='./'+aclFileName+'-output.csv'

print 'Store ACL in list of dict...'
with open(csvFilePath, 'rb') as f:
    reader = csv.reader(f)
    acl=[]
    for ace in reader:
        acl.append(dict(zip(listField,ace)))

#test: use the first n entries
#acl=acl[100:100+30]
acl=acl[:30]
#test
#acl=acl[:3]

#==============================================================================
#test spoofing

# acl=[{'remark': '', 'protocol': 'tcp', 'name': '110', 'decision': 'permit', 
#      'time': '', 'src_ip': '1.2.3.0 255.255.255.0', 'inactive': '', 
#      'dst_port': 'range 1 65534', 'dst_ip': 'host 192.168.0.1', 
#      'src_port': 'range 1 65534', 'line': '1', 'type': 'extended', 'original': 
#      'access-list 110 extended permit udp host 10.66.129.135 host 171.71.180.230 range 2055 2065 ', 'log': ''}]

# acl=[
#      {'remark': '', 'protocol': 'udp', 'name': '110', 'decision': 'permit', 
#      'time': '', 'src_ip': 'host 10.66.129.135', 'inactive': '', 
#      'dst_port': 'range 2055 2065', 'dst_ip': 'host 171.71.180.230', 
#      'src_port': '', 'line': '1', 'type': 'extended', 'original': 
#      'access-list 110 extended permit udp host 10.66.129.135 host 171.71.180.230 range 2055 2065 ', 'log': ''},
#      {'remark': '', 'protocol': 'udp', 'name': '110', 'decision': 'permit', 
#      'time': '', 'src_ip': 'host 10.66.129.136', 'inactive': '', 
#      'dst_port': 'range 2055 2065', 'dst_ip': 'host 171.71.180.230', 
#      'src_port': '', 'line': '1', 'type': 'extended', 'original': 
#      'access-list 110 extended permit udp host 10.66.129.135 host 171.71.180.230 range 2055 2065 ', 'log': ''},     
#      ]

#==============================================================================


for ace in acl:
    print ace

# print 'Disp result...'
# print [ace['src_ip'] for ace in acl]
# print [ace['src_port'] for ace in acl]
# print [ace['dst_ip'] for ace in acl]
# print [ace['dst_port'] for ace in acl]
# print [ace['protocol'] for ace in acl]
# print [ace['decision'] for ace in acl]

print '''
=================
One-dimensional DP
=================
'''

print 'Generate (source IP -> decision) rule list...'
listPrefixRule=generatePrefixRuleListFromAcl(acl,'src_ip','decision',
                                             defaultDecision)

#test: remove all the rules with prefix is equal to all ******
listPrefixRule=[rule for rule in listPrefixRule if \
                rule['prefix']!='********************************']

#test: append all ***** -> deny rule at last
listPrefixRule.append({'prefix': '********************************',
                       'decision': 'deny'})

#==============================================================================
#test spoofing
listPrefixRule=[{'prefix': '00*', 'decision': 'permit'}, {'prefix': '01*', 'decision': 'deny'}, {'prefix': '10*', 'decision': 'permit'}, {'prefix': '11*', 'decision': 'deny'}]
#listPrefixRule=[{'prefix': '101***', 'decision': 'permit'}, {'prefix': '0*****', 'decision': 'permit'}, {'prefix': '******', 'decision': 'deny'}]
#listPrefixRule=[{'prefix': '******', 'decision': 'deny'}, {'prefix': '101***', 'decision': 'permit'}, {'prefix': '0*****', 'decision': 'permit'}]
#listPrefixRule=[{'prefix': '101***', 'decision': 'deny'}, {'prefix': '0*****', 'decision': 'permit'}, {'prefix': '******', 'decision': 'deny'}]
#listPrefixRule=[{'prefix': '0101**', 'decision': 'deny'}, {'prefix': '1**', 'decision': 'deny'}, {'prefix': '0***', 'decision': 'deny'}]
#listPrefixRule=[{'prefix': '0101**', 'decision': 'deny'}, {'prefix': '0100**', 'decision': 'deny'}, {'prefix': '1**', 'decision': 'deny'}, {'prefix': '0***', 'decision': 'permit'}]
#listPrefixRule=[{'prefix': '00', 'decision': 'permit'}, {'prefix': '01', 'decision': 'deny'}, {'prefix': '10', 'decision': 'permit'}, {'prefix': '11', 'decision': 'permit'}]

#Not a classifier (rule set is not complete):
#listPrefixRule=[{'prefix': '101***', 'decision': 'permit'}, {'prefix': '0*****', 'decision': 'permit'}]

#dictDecisionWeight={'deny':100,'permit':1}
#==============================================================================

print 'Generate prefix match tree...'
tree=PMTree(listPrefixRule)#prefix matching tree
print tree
saveSvgFile(tree.getDotCode(),'../output/main01.svg',False)

print '\nCheck if prefix is in rule list...'
prefix='1*'
#prefix='00001010001110000100100000100011'
#prefix='110000011011110001111101010100**'
#prefix='1100000110111100011111**********'
if tree.isConsistentIn(prefix)[0]:
    print prefix+' is consistent in:'
    print listPrefixRule
else:
    print prefix+' is NOT consistent in:'
    print listPrefixRule
    
print '\nRun 1-D DP algorithm to generate shortest rule list...\n'
minCost,listMinListRule=generateShortestPrefixRuleListFromTree(tree,
                len(listPrefixRule[0]['prefix']),
                listDecision,dictDecisionWeight)

print 'Length of original rule list is '+('%d' % len(listPrefixRule))
for rule in listPrefixRule:
    print rule

print ''
print 'Length of minimum rule list is '+('%d' % minCost)
for i,_ in enumerate(listMinListRule):
    print 'Minimum rule list #%d:' % (i+1)
    for rule in listMinListRule[i]:
        print rule
        
print '''\nVisualize optimal rule list in non-leaf-pushing tree'''

tree2=PMTreeNT(listMinListRule[0])
print tree2
saveSvgFile(tree2.getDotCode(),'../output/main02.svg',False)

# tree3=PMTreeNT(listMinListRule[1])
# print tree3
# saveSvgFile(tree3.getDotCode(),'../output/main03.svg',False)


print '''
==========================
Create ACL decision tree
==========================
'''
startTime=time()
 
print '''Create shortened ACL with field in adtreeFieldOrder, and convert
each entry to range (low,high) format...'''

rl=acl2RangeRuleListND(acl,adtreeFieldOrder)

#test
#==============================================================================
##test spoofing
# dictFieldRange={'ip':(0,2**32-1)}
# adtreeFieldOrder=('ip',)
# defaultDecision='deny'
# rl=[{'ip':(172130695,172130695),'decision':'permit'}]
 
# dictFieldRange={'ip':(0,15),'port':(0,15)}
# adtreeFieldOrder=('port','ip')
# defaultDecision='deny'
# rl=[
#       {'port':(8,8),'ip':(8,11),'decision':'permit'},
#       {'port':(10,11),'ip':(8,11),'decision':'permit'},
#       ]
 
# dictFieldRange={'ip':(0,15),'port':(0,7),'protocol':(0,3)}
# #adtreeFieldOrder=('port','ip','protocol')
# adtreeFieldOrder=('protocol','port','ip')
# defaultDecision='deny'
# rl=[
#         {'port':(2,3),'ip':(5,7),'protocol':(1,3),'decision':'permit'},
#         {'port':(0,4),'ip':(0,12),'protocol':(0,1),'decision':'permit'},
#        {'port':(0,7),'ip':(10,12),'protocol':(0,3),'decision':'permit'},
#         {'port':(0,6),'ip':(0,4),'protocol':(0,3),'decision':'permit'},
#        {'port':(0,3),'ip':(0,12),'protocol':(0,3),'decision':'permit'},
#       {'port':(0,1),'ip':(0,15),'protocol':(0,3),'decision':'permit'},
#       ]
 
# dictFieldRange={'src_ip':(0,2**32-1),'dst_ip':(0,2**32-1),
#                 'src_port':(0,2**16-1),'dst_port':(0,2**16-1),
#                 'protocol':(0,2**8-1)}
# adtreeFieldOrder=('src_port','src_ip','dst_ip','dst_port','protocol')
# defaultDecision='deny'#default decision implied, if not specified in ACL
# rl=[{'src_port': (0, 65535), 'decision': 'permit', 'protocol': (1, 1), 
#        'src_ip': (172130695, 172130695), 'dst_port': (2055, 2065), 
#        'dst_ip': (2873603302, 2873603302)}]
 
# dictFieldRange={'src_ip':(0,2**32-1),'dst_ip':(0,2**32-1),
#                 'src_port':(0,2**16-1),'dst_port':(0,2**16-1),
#                 'protocol':(0,2**8-1)}
# adtreeFieldOrder=('src_port','src_ip','dst_ip','dst_port','protocol')
# defaultDecision='deny'#default decision implied, if not specified in ACL
# rl=[{'src_port': (0, 65535), 'decision': 'permit', 'protocol': (1, 1), 
#        'src_ip': (172130695, 172130695), 'dst_port': (2055, 2065), 
#        'dst_ip': (2873603302, 2873603302)}]
 
#==============================================================================
      
printRuleListND(rl,adtreeFieldOrder)
 
print '''
Create ACL decision tree...'''
 
#print rl
t=ADTree(rl,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision)
print t
 
print '''Total nodes in tree: %d.
''' % t.getNodeNumber()
 
print 'Time elapsed: %4f sec.\n' % (time()-startTime)
 
print '''Save dot file (in range) and display...'''
saveSvgFile(t.getDotCode('range'),'../output/main04.svg',False)
 
# print '''Save dot file (in prefix) and display...'''
# saveSvgFile(t.getDotCode('prefix_nonoverlap'),'../output/main05.svg',False)


print '''
==========================
Generate compressed (non-flippable) 
n-dim prefix rule list
==========================
'''
# startTime=time()
#    
# ruleListND,dotCode=t.generatePrefixRuleListND('prefix_nonoverlap',getCode=True)
#    
# print '''Save dot file (in compressed prefix) and display...'''
# printRuleListND(ruleListND,adtreeFieldOrder)
# print 'Length of generated n-dim (non-flippable) prefix rule list is '+ \
#                                                     ('%d.' % len(ruleListND))
# saveSvgFile(dotCode,'../output/main06.svg',False)
#    
# print '\nElapsed time: %.4f sec.' % (time()-startTime)
#     
# isEquivalent=verifyRuleList(ruleListND,defaultDecision,adtreeFieldOrder,dictFieldRange,
#                    listDecision,t)
#        
# if isEquivalent:
#     print '\nGenerated compressed rule list IS EQUIVALENT to the original rule list.'
# else:
#     print '\nGenerated compressed rule list IS NOT EQUIVALENT to the original rule list.'


print '''
==========================
Generate compressed n-dim 
prefix rule list
==========================
'''
startTime=time()

ruleListND,dotCode=t.generatePrefixRuleListND('prefix_overlap',getCode=True)

print '''Save dot file (in compressed prefix) and display...'''
printRuleListND(ruleListND,adtreeFieldOrder)
print 'Length of generated n-dim prefix rule list is '+('%d.' % len(ruleListND))
saveSvgFile(dotCode,'../output/main07.svg',False)

print '\nElapsed time: %.4f sec.' % (time()-startTime)

isEquivalent=verifyRuleList(ruleListND,defaultDecision,adtreeFieldOrder,dictFieldRange,
                   listDecision,t)
    
if isEquivalent:
    print '\nGenerated compressed rule list IS EQUIVALENT to the original rule list.'
else:
    print '\nGenerated compressed rule list IS NOT EQUIVALENT to the original rule list.'


print '''
==========================
Combine rule list
=========================='''
startTime=time()
       
#==============================================================================
##test spoofing
dictFieldRange={'ip':(0,15),'port':(0,7),'protocol':(0,3)}
adtreeFieldOrder=('protocol','port','ip',)
defaultDecision='deny'
rls=[]
rls.append([
        {'port':(2,3),'ip':(5,7),'protocol':(1,3),'decision':'permit'},
        {'port':(4,4),'ip':(0,12),'protocol':(1,3),'decision':'permit'},
      ])
rls.append([
       {'port':(0,7),'ip':(6,12),'protocol':(3,3),'decision':'permit'},
        {'port':(0,6),'ip':(0,4),'protocol':(0,3),'decision':'permit'},
      ])
# rls.append([
#        {'port':(0,7),'ip':(0,12),'protocol':(0,3),'decision':'permit'},
#       {'port':(0,6),'ip':(0,15),'protocol':(0,3),'decision':'permit'},
#       ])

# rl1=[
#         {'port':(0,7),'ip':(0,4),'protocol':(0,3),'decision':'permit'},
#         {'port':(0,7),'ip':(7,13),'protocol':(0,3),'decision':'permit'},
#       ]
# rl2=[
#         {'port':(0,7),'ip':(2,6),'protocol':(0,3),'decision':'permit'},
#         {'port':(0,7),'ip':(9,11),'protocol':(0,3),'decision':'permit'},
#       ]

rlsubset=[{'port':(0,7),'ip':(0,7),'protocol':(0,3),'decision':'permit'}]
#rlsubset=[{'port':(0,7),'ip':(0,15),'protocol':(0,3),'decision':'permit'}]
#rlsubset=[{'port':(0,7),'ip':(0,9),'protocol':(0,3),'decision':'permit'}]

#==============================================================================

t=[]
trl=[]
for i,rl in enumerate(rls):
    t.append(ADTree(rl,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision))
    trl.append(t[i].generatePrefixRuleListND('prefix_overlap')[0])

ts=generateAdtreeFromMultipleList(rls,defaultDecision,adtreeFieldOrder,
                                 dictFieldRange,listDecision,'serial')
trls,_=ts.generatePrefixRuleListND('prefix_overlap')

for i,rl in enumerate(rls):
    print '\nRule list #%d:' % i
    printRuleListND(trl[i],adtreeFieldOrder)

print '''
Rule list #1 and #2 combined in serial:'''
printRuleListND(trls,adtreeFieldOrder)

print '\nElapsed time: %.4f sec.' % (time()-startTime)


print '''
==========================
Filter input packets
==========================
'''
startTime=time()
       
print 'Generate dependency list...'    
dotCode=generateDependencyDict(trls,adtreeFieldOrder)
saveSvgFile(dotCode,'../output/main08.svg',False)

print '''
Big-switch rule list:'''
trls,_=ts.generatePrefixRuleListND('range')
printRuleListND(trls,adtreeFieldOrder)
saveSvgFile(ts.getDotCode('prefix_nonoverlap'),'../output/main09.svg',False)

print '''
Subset of packets:'''
printRuleListND(rlsubset,adtreeFieldOrder)

print '''
Assume that only a subset of packets are going through. Mute the rest
by the default decision (achieved by concatenating the list of subset in serial)...
'''
rls,_=ts.generatePrefixRuleListND('range')
tsSub=generateAdtreeFromMultipleList([rlsubset,rls],defaultDecision,adtreeFieldOrder,
                                 dictFieldRange,listDecision,'serial')

print '''rule list for the subset of packets:'''
trlSub,_=tsSub.generatePrefixRuleListND('range')
printRuleListND(trlSub,adtreeFieldOrder)

print '\nElapsed time: %.4f sec.' % (time()-startTime)

print '''
==========================
Decompose rule list
==========================
'''
startTime=time()

#==============================================================================
#real thing
dictFieldRange={'src_ip':(0,2**32-1),'dst_ip':(0,2**32-1),
                'src_port':(0,2**16-1),'dst_port':(0,2**16-1),
                'protocol':(0,2**8-1)}
listDecision=('deny', 'permit')#the first one being the default decision by ACL
defaultDecision='deny'#default decision implied, if not specified in ACL
adtreeFieldOrder=('protocol','src_port','dst_port','src_ip','dst_ip',)
rl=acl2RangeRuleListND(acl,adtreeFieldOrder)
t=ADTree(rl,defaultDecision,adtreeFieldOrder,dictFieldRange,listDecision)
tsSub=t
#==============================================================================
       
# print '''Compressed subset ternary rule list (non-flippable):'''
# trlSub2,_=tsSub.generatePrefixRuleListND('prefix_nonoverlap')
# printRuleListND(trlSub2,adtreeFieldOrder)

print '''Compressed subset ternary rule list (flippable):'''
trlSub3,_=tsSub.generatePrefixRuleListND('prefix_overlap')
printRuleListND(trlSub3,adtreeFieldOrder)

tsSubOriginal=tsSub.duplicate()

saveSvgFile(tsSub.getDotCode('range'),'../output/main10.svg',False)

nChunk=3
print '''
Decompose the subset rule list into %d in serial...''' % nChunk
listTree=cutEven(tsSub,nChunk,listDecision,dictFieldRange,adtreeFieldOrder)

for i,tree in enumerate(listTree):
    saveSvgFile(tree.getDotCode('range'),'../output/main11_%02d.svg' % i,False)
                        
for i,tree in enumerate(listTree):
    rl,_=tree.generatePrefixRuleListND('prefix_overlap')
    print 'decomposed rule list #%d (%d rules):' % (i,len(rl))
    printRuleListND(rl,adtreeFieldOrder)

print '''
Verify if the decomposed rule lists are correct...'''
rls=[]
for tree in listTree:
    rl,_=tree.generatePrefixRuleListND('range')
    rls.append(rl)    
ts=generateAdtreeFromMultipleList(rls,defaultDecision,adtreeFieldOrder,
                                 dictFieldRange,listDecision,'serial')
trls,_=ts.generatePrefixRuleListND('prefix_overlap')

isEquivalent=verifyRuleList(trls,defaultDecision,adtreeFieldOrder,dictFieldRange,
                   listDecision,tsSubOriginal)
if isEquivalent:
    print 'Decomposed rule list IS EQUIVALENT to the original rule list.'
else:
    print 'Decomposed rule list IS NOT EQUIVALENT to the original rule list.'

print '\nElapsed time: %.4f sec.' % (time()-startTime)

     



