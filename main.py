import lxml.etree as ET
import proc 

oval = {
    'definitions': [],
    'states': [],
    'variables': [],
    'objects': [],
    'tests': []
}

def main():
    filename = 'rhel-8.oval.xml'
    ns  = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'
    nsl = '{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}'
    nsi = '{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}' 
    root = ET.parse(filename).getroot()

    proc.getDefinitions(oval,root,ns) 
    proc.getVariables(oval,root,ns)   
    proc.getStates(oval,root,nsl)
    proc.getObjects(oval,root,nsl)
    proc.getTests(oval,root,nsl,nsi)
    proc.save_to_file(oval)
        
main()
