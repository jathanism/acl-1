'''
This module includes constants/functions related to parsing ACL.

Created on Aug 15, 2013

@author: zhil2
'''
 
import re
from subprocess import call

allZeroIpv4String='0.0.0.0 0.0.0.0'

dictFieldRange={'src_ip':(0,2**32-1),'dst_ip':(0,2**32-1),
                'src_port':(0,2**16-1),'dst_port':(0,2**16-1),
                'protocol':(0,2**8-1)}

dictIpProtocol={'tcp':0,'udp':1,'esp':2,'gre':3}

dictTransportProtocol={'isakmp':500,'https':443,'sip':5060,'h323':1719, \
                       'www':80,'netbios-ssn':139,'bootps':67,'bootpc':68, \
                       'domain':953,'netbios-ns':137,'ntp':123,'tftp':69, \
                       'syslog':514,'snmp':161,'snmptrap':162,'ftp-data':20, \
                       'ssh':22,'ldap':389,'ldaps':636
                       }

def int2BinStr(i,nBit):
    '''
    Convert integer to a binary string of nBit
    '''
    return (bin(int(i))[2:].zfill(nBit))

def ipv4Str2Ternary(ipTxt):
    '''
    Convert an IPv4 address with mask in string format to IPv4 address in 
    32-bit ternary string format. 
       
    Examples:    
    >>> ipv4Str2Ternary('1.2.3.4 255.255.255.254')
    '0000000100000010000000110000010*'
    >>> ipv4Str2Ternary('host 1.2.3.4')
    '00000001000000100000001100000100'
    >>> ipv4Str2Ternary('any')
    '********************************'
    '''
    
    #print ipTxt
    oneTerm=re.match(r'([\w]+)',ipTxt).group(1)
    if oneTerm=='any':
        ipTxt=allZeroIpv4String        
    firstTerm,secondTerm=re.match(r'([\w.]+) ([\w.]+)',ipTxt).groups()
    if firstTerm=='host':
        firstTerm=secondTerm
        secondTerm='255.255.255.255'

    addr=re.match(r'([\d]+).([\d]+).([\d]+).([\d]+)',firstTerm).groups()

    addrString=''
    for byte in addr:
        addrString+=int2BinStr(byte,8)
    mask=re.match(r'([\d]+).([\d]+).([\d]+).([\d]+)',secondTerm).groups()

    maskString=''
    for byte in mask:
        maskString+=int2BinStr(byte,8)

    #limit: assuming prefix mask only
    prefix=re.match(r'([1]*)([0]*)',maskString).groups()[0]

    #return [addrString,maskString,addrString[:len(prefix)]+'*'*(32-len(prefix))]
    return addrString[:len(prefix)]+'*'*(32-len(prefix))

def ternary2Range(ipTxt):
    '''
    Convert an IPv4 address in 32-bit string format to range format (low,high) 
    with low and high in integers.
       
    Examples:    
    >>> ternary2Range('0000000100000010000000110000010*')
    (16909060, 16909061)
    >>> ternary2Range('00000001000000100000001100000100')
    (16909060, 16909060)
    >>> ternary2Range('********************************')
    (0, 4294967295)
    '''
    
    low=int(ipTxt.replace('*','0'),2)
    high=int(ipTxt.replace('*','1'),2)
    return (low,high)

def ipv4Str2Range(ipTxt):
    return ternary2Range(ipv4Str2Ternary(ipTxt))

def portStr2Range(portTxt):
    '''
    Convert a port text string to range format.
    
    Examples:    
    >>> portStr2Range('range 2055 2065')
    (2055, 2065)
    >>> portStr2Range('range ftp-data ssh')
    (20, 22)
    >>> portStr2Range('range snmp snmptrap')
    (161, 162)
    >>> portStr2Range('eq 10000')
    (10000, 10000)
    >>> portStr2Range('eq isakmp')
    (500, 500)
    >>> portStr2Range('eq https')
    (443, 443)
    >>> portStr2Range('gt 10000')
    (10001, 65535)
    >>> portStr2Range('lt 10000')
    (0, 9999)
    >>> portStr2Range(' ')
    (0, 65535)
    >>> portStr2Range('')
    (0, 65535)
    '''
    
    lowBound,highBound=(0,2**16-1)

    mo=re.match(r'([\w-]+)',portTxt)
    if not mo:
        return (lowBound,highBound)
    
    firstTerm,secondTerm=re.match(r'([\w]+) ([\w-]+)',portTxt).groups()
    #print secondTerm
    if firstTerm=='eq' or firstTerm=='gt' or firstTerm=='lt':
        
        if secondTerm.isdigit():
            secondTermInt=int(secondTerm)
        elif secondTerm in dictTransportProtocol:
            secondTermInt=dictTransportProtocol[secondTerm]
        else:
            assert(0)            
        if firstTerm=='eq':
            low=secondTermInt
            high=secondTermInt
        elif firstTerm=='gt':
            low=secondTermInt+1
            high=highBound
        elif firstTerm=='lt':
            low=lowBound
            high=secondTermInt-1
        else:
            assert(0)
        
        return (low,high)
    
    firstTerm,secondTerm,thirdTerm= \
        re.match(r'([\w]+) ([\w-]+) ([\w-]+)',portTxt).groups()
    #print secondTerm+' '+thirdTerm
    if firstTerm=='range':
        if secondTerm.isdigit():
            low=int(secondTerm)
        elif secondTerm in dictTransportProtocol:
            low=dictTransportProtocol[secondTerm]
        else:
            assert(0)
        if thirdTerm.isdigit():
            high=int(thirdTerm)
        elif thirdTerm in dictTransportProtocol:
            high=dictTransportProtocol[thirdTerm]
        else:
            assert(0)
            
    return (low,high)

def protStr2Range(protocolTxt):
    '''
    Convert a protocol text string to range format. Use lookup table, if 
    unknown, set range (-1,-1)
    
    Examples:    
    >>> protStr2Range('tcp')
    (0, 0)
    >>> protStr2Range('udp')
    (1, 1)
    >>> protStr2Range('xyz')
    (-1, -1)
    '''
    
    pid=dictIpProtocol.get(protocolTxt,-1)
    return (pid,pid)

def acl2RangeRuleListND(acl,adtreeFieldOrder):
    '''
    Convert ACL in its original Cisco format (read using acl2csv) to a n-dim
    range list
    '''
    acl2=[]
    for ace in acl:
        ace2={}
        for field in adtreeFieldOrder+('decision',):
            if field=='src_ip' or field=='dst_ip' or field=='ip':
                ace2[field]=ipv4Str2Range(ace[field])
            elif field=='src_port' or field=='dst_port' or field=='port':
                ace2[field]=portStr2Range(ace[field])
            elif field=='protocol':
                ace2[field]=protStr2Range(ace[field])
            else:
                ace2[field]=ace[field]
        acl2.append(ace2)
        #printRuleListND(acl2,adtreeFieldOrder)
    return acl2

def ternaryRuleListND2RangeRuleListND(ruleListND,adtreeFieldOrder):
    '''
    Convert a n-dim ternary rule list to a n-dim range rule list
    '''
    rl=[]
    for rule in ruleListND:
        rule2={}
        for field in adtreeFieldOrder+('decision',):
            if field=='src_ip' or field=='dst_ip' or \
               field=='src_port' or field=='dst_port' or \
               field=='protocol' or field=='ip' or field=='port':
                rule2[field]=ternary2Range(rule[field])
            else:
                rule2[field]=rule[field]
        rl.append(rule2) 
    #printRuleListND(rl,adtreeFieldOrder)
    return rl

def appendRuleToPrefixRuleList(listPrefixRule,prefix,decision):
    '''
    Appendix a rule to the prefix rule list. A rule is in the format of 
    {'prefix':prefix, 'decision':decision}.
    '''
    listPrefixRule.append(dict(zip(['prefix','decision'],[prefix,decision])))

def appendRuleToRangeRuleList(listRangeRule,r,decision):
    '''
    Appendix a rule to the range rule list. A rule is in the format of 
    {'range':r, 'decision':decision}.
    '''
    listRangeRule.append(dict(zip(['range','decision'],[r,decision])))
    
def rangeIsCovered(r1,r2):
    '''
    Test if a range r1 is covered by another range r2.
    
    Examples:
    >>> rangeIsCovered([0,5],[0,6])
    True
    >>> rangeIsCovered([0,5],[-2,6])
    True
    >>> rangeIsCovered([0,5],[1,6])
    False
    >>> rangeIsCovered([0,5],[5,6])
    False
    >>> rangeIsCovered([0,5],[7,9])
    False
    >>> rangeIsCovered([0,6],[0,5])
    False
    >>> rangeIsCovered([-2,6],[0,5])
    False
    '''
    assert(r1[0]<=r1[1] and r2[0]<=r2[1])
    return r1[0]>=r2[0] and r1[1]<=r2[1]

def rangesOverlapped(r1,r2):
    '''
    Test if a range r1 has overlap with another range r2.
    
    Examples:
    >>> rangesOverlapped([0,5],[0,6])
    True
    >>> rangesOverlapped([0,5],[-2,6])
    True
    >>> rangesOverlapped([0,5],[1,6])
    True
    >>> rangesOverlapped([0,5],[5,6])
    True
    >>> rangesOverlapped([0,5],[7,9])
    False
    >>> rangesOverlapped([7,9],[0,5])
    False
    >>> rangesOverlapped([0,6],[0,5])
    True
    >>> rangesOverlapped([-2,6],[0,5])
    True
    '''
    assert(r1[0]<=r1[1] and r2[0]<=r2[1])
    return not (r1[1]<r2[0] or r2[1]<r1[0])
    
def ternaryIsCovered(p1,p2):
    '''
    Test if a ternary string (with elements in {0,1,*}) p1 is covered by 
    another ternary string p2.
    
    Examples:
    >>> ternaryIsCovered('001*','0011')
    False
    >>> ternaryIsCovered('0011','001*')
    True
    >>> ternaryIsCovered('011','10*')
    False
    >>> ternaryIsCovered('011','011')
    True
    >>> ternaryIsCovered('001','0*1')
    True
    >>> ternaryIsCovered('0*1','0*1')
    True
    >>> ternaryIsCovered('0*1','001')
    False
    '''
    assert(len(p1)==len(p2))
    strlen=len(p1)
    for i in range(strlen):
        if (p1[i]=='0' and p2[i]=='1') or \
           (p1[i]=='1' and p2[i]=='0') or \
           (p1[i]=='*' and p2[i]=='0') or \
           (p1[i]=='*' and p2[i]=='1'):
            return False
    return True

def ruleIsCovered(rule,refRule,adtreeFieldOrder,fmt):
    '''
    Check if rule is covered by another rule refRule in every field.
    
    fmt:'prefix' - prefix rule or 'range' - range rule
    '''
    ruleIsCovered=True
    for field in adtreeFieldOrder:
        predicate=rule[field]
        refPredicate=refRule[field]
        if fmt=='prefix':
            if not ternaryIsCovered(predicate,refPredicate):
                ruleIsCovered=False
                break
        elif fmt=='range':
            if not rangeIsCovered(predicate,refPredicate):
                ruleIsCovered=False
                break
        else:
            assert(0)
    return ruleIsCovered

def rulesOverlapped(rule,refRule,adtreeFieldOrder,fmt):
    '''
    Check if rule and refRule are overlapped. Two rules are overlapped
    if for all dims, either A covers by or B covers A
    
    fmt:'prefix' - prefix rule or 'range' - range rule
    '''
    ruleOverlapped=True
    for field in adtreeFieldOrder:
        predicate=rule[field]
        refPredicate=refRule[field]
        if fmt=='prefix':
            if not (ternaryIsCovered(predicate,refPredicate) or 
                            ternaryIsCovered(refPredicate,predicate)):
                ruleOverlapped=False
                break
        elif fmt=='range':
            if not (rangesOverlapped(predicate,refPredicate)):
                ruleOverlapped=False
                break
        else:
            assert(0)
    return ruleOverlapped

def printRuleListND(ruleListND,adtreeFieldOrder):
    for iRule,rule in enumerate(ruleListND):
        s='Rule %3d - ' % iRule
        for field in adtreeFieldOrder:
            s+='%s: %s, ' % (field,rule[field])
        s+='-> %s' % rule['decision']
        print s

def generatePrefixRuleListFromAcl(acl,prefixField,decisionField,defaultDecision):
    '''
    Generate a list of rules based on a ACL, which is in the format of a list
    of dictionaries. A rule is in the format of {'prefix':prefix, 'decision':
    decision}. If defaultDecision is not empty (''), also add a default rule 
    {'prefix': '********************************', 'decision': defaultDecision}
    at the end of the rule list.

    Example:
    >>> acl=[{'remark': '', 'protocol': 'udp', 'name': '110', 'decision': 'permit', 'time': '', 'src_ip': 'host 10.66.129.135', 'inactive': '', 'dst_port': 'range 2055 2065', 'dst_ip': 'host 171.71.180.230', 'src_port': '', 'line': '1', 'type': 'extended', 'original': 'access-list 110 extended permit udp host 10.66.129.135 host 171.71.180.230 range 2055 2065 ', 'log': ''}, {'remark': '', 'protocol': 'udp', 'name': '110', 'decision': 'permit', 'time': '', 'src_ip': '10.61.32.0 255.255.255.224', 'inactive': '', 'dst_port': 'range 2055 2065', 'dst_ip': 'host 144.254.226.12', 'src_port': '', 'line': '2', 'type': 'extended', 'original': 'access-list 110 extended permit udp 10.61.32.0 255.255.255.224 host 144.254.226.12 range 2055 2065 ', 'log': ''}]
    >>> listPrefixRule=generatePrefixRuleListFromAcl(acl,'src_ip','decision','deny')
    >>> print listPrefixRule
    [{'prefix': '00001010010000101000000110000111', 'decision': 'permit'}, {'prefix': '000010100011110100100000000*****', 'decision': 'permit'}, {'prefix': '********************************', 'decision': 'deny'}]
    '''
    
    debugLevel=0
    
    #limit: for IPv4 format only
    listPrefixRule=[]
    for ace in acl:
        if debugLevel>0:
            print ace
        ipTxt=ace[prefixField]
        ipBit=ipv4Str2Ternary(ipTxt)
        appendRuleToPrefixRuleList(listPrefixRule,ipBit,ace[decisionField])
    #add the default rule if default rule is not empty
    if defaultDecision!='':
        appendRuleToPrefixRuleList(listPrefixRule,
                            ipv4Str2Ternary(allZeroIpv4String),defaultDecision)
    return listPrefixRule

def saveSvgFile(code,svgFile,display):
    '''
    Generate and save SVG file from dot code, and display graph
    '''
    dotFile=open('tmp.dot','w')
    dotFile.write(code)
    dotFile.close()
    call(['dot','-Tsvg','tmp.dot','-o',svgFile])
    call(['rm','tmp.dot'])
    if display:
        #call(['eog',svgFile])
        call(['eog',svgFile,' &'])
        

if __name__ == '__main__': 
    import doctest
    print doctest.testmod()
