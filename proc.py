import lxml.etree as ET
import json

def save_to_file(oval):
    with open('result.json', 'w') as json_file:
        json.dump(oval, json_file,indent=3)  

def retrieve_criteria(criteria_element,ns):
    criteria = {
        'operator': criteria_element.get('operator'),
        'criterion':[],
        'criteria':[]
    }
    for child in criteria_element:
        if child.tag == f'{ns}criteria':
            criteria['criteria'].append(retrieve_criteria(child,ns))
        else:
            criterion = {
                #'comment': child.get('comment'),
                'test': child.get('test_ref')
            }
            criteria['criterion'].append(criterion)
    return criteria

def getDefinitions(oval,root,ns):
    
    d = root.findall(f'.//{ns}definition')
    definitions = []
    
    for e in d:
        definitions.append(
            {
                'id': e.get('id'),
                'class': e.get('class'),
                'title': e.find(f'.//{ns}title').text,
                'version': e.get('version'),
                'issued': e.find(f'.//{ns}issued').get('date'),
                'updated': e.find(f'.//{ns}updated').get('date'),
                'platform': e.find(f'.//{ns}platform').text,
                'severity': e.find(f'.//{ns}severity').text,
                'description': e.find(f'.//{ns}description').text,
                'platform_family': e.find(f'.//{ns}affected').get('family'),
                'bugzilla': [{'id': bug.get('id')
                               ,'url': bug.get('href')
                               ,'description': bug.text} for bug in e.findall(f'.//{ns}bugzilla')],
                'refs': [{'id': ref.get('ref_id')
                                ,'src': ref.get('source') 
                                ,'url': ref.get('ref_url')} for ref in e.findall(f'.//{ns}reference')],
                'cves': [{'name':cve.text
                           ,'cwe': cve.get('cwe')
                           ,'cvss3': cve.get('cvss3')
                           ,'impact': cve.get('impact')
                           ,'url': cve.get('href'),
                           } for cve in e.findall(f'.//{ns}cve')],
                'affected_cpe':[cpe.text for cpe in e.findall(f'.//{ns}cpe')],
                'criteria': retrieve_criteria(e.find(f'.//{ns}criteria'),ns)
            }
        )
    
    oval['definitions'] = definitions
    
def getVariables(oval,root,ns):
    v = root.findall(f'.//{ns}local_variable')
    variables = []
    
    for e in v:
        variables.append(
            {
                'id': e.get('id'),
                'type': e.get('datatype'),
                'comment': e.get('comment'),
                'version': e.get('version'),
                'arithmetic': [
                    {
                        'obj_ref':e.find(f'.//{ns}object_component').get('object_ref'),
                        'obj_component':e.find(f'.//{ns}object_component').get('item_field'),
                        'operation':e.find(f'.//{ns}arithmetic').get('arithmetic_operation'),
                        'literal_type':e.find(f'.//{ns}literal_component').get('datatype'),
                        'literal_component':e.find(f'.//{ns}literal_component').text
                    }
                ]
            }
        )
        
    oval['variables'] = variables
    
def getStates(oval,root,ns):
    s = root.findall(f'.//{ns}rpminfo_state')
    states = []
    
    for e in s:
        states.append(
            {
                'id':e.get('id'),
                'version':e.get('version'),
                'evr': [{'type': evr.get('datatype')
                               ,'operation': evr.get('operation')
                               ,'text': evr.text} for evr in e.findall(f'.//{ns}evr')],
                'arch': [{'type': arch.get('datatype')
                               ,'operation': arch.get('operation')
                               ,'text': arch.text} for arch in e.findall(f'.//{ns}arch')]
            }
        )
    
    oval['states'] = states
    
def getObjects(oval,root,ns):
    o = root.findall(f'.//{ns}rpminfo_object')
    objects = []
    
    for e in o:
        objects.append(
            {
                'id':e.get('id'),
                'name': e.find(f'.//{ns}name').text,
                'version':e.get('version'),
            }
        )  
        
    oval['objects'] = objects 
    
def formTest(oval,t,ns,test_type):
    tests = []
    for e in t:
        state = e.find(f'.//{ns}state')
        tests.append({
            'id':e.get('id'),
            'type': test_type,
            'check':e.get('check'),
            'state': state.get('state_ref') if state is not None else None,
            'version':e.get('version'),
            'comment':e.get('comment'),
            'obj_ref': e.find(f'.//{ns}object').get('object_ref')
        })  
    
    oval['tests'] += tests
    
def getTests(oval,root,ns,nsi):
    t = root.findall(f'.//{ns}rpminfo_test')
    ti = root.findall(f'.//{nsi}textfilecontent54_test')
    
    formTest(oval,t,ns,'rpminfo_test')
    formTest(oval,ti,nsi,'textfilecontent54_test')