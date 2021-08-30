import logging
import pathlib
import argparse
import os
import xml
from datetime import datetime, timedelta
from xml.etree.ElementTree import Element, ElementTree
import requests
from requests.exceptions import ConnectTimeout, ReadTimeout, ConnectionError
from retry.api import retry
from trivialsec.helpers.config import config
from trivialsec.models.cve import CVE


logger = logging.getLogger(__name__)
session = requests.Session()
OVAL_SCHEMA_VERSION = '5.11.2'
DATAFILE_DIR = '/var/cache/trivialsec'
CVE_PATTERN = r"(CVE\-\d{4}\-\d*)"
DATE_FMT = "%Y-%m-%dT%H:%M:%S"
DEFAULT_START_YEAR = 2005
PROXIES = None
if config.http_proxy or config.https_proxy:
    PROXIES = {
        'http': f'http://{config.http_proxy}',
        'https': f'https://{config.https_proxy}'
    }

"""
https://github.com/CISecurity/OVALRepo/blob/master/scripts/lib_oval.py
:Usage:

1. Create an OvalDocument:
    >>> tree = ElementTree()
    >>> tree.parse("OvalTest.xml")
    >>> document = OvalDocument(tree)

2. Find an oval element within the loaded document:
    >>> element = document.getElementByID("oval:org.mitre.oval:def:22382")
    >>> if element is not None:
    >>>    ....

3. Read an XML file with a single OVAL Definition (error checking omitted for brevity):
    >>> tree = ElementTree()    
    >>> tree.parse('test-definition.xml')
    >>> root = tree.getroot()    
    >>> definition = lib_oval.OvalDefinition(root)
    
4. Change information in the definition from #3 and write the changes
    >>> meta = definition.getMetadata()
    >>> repo = meta.getOvalRepositoryInformation()
    >>> repo.setMinimumSchemaVersion("5.9")
    >>> tree.write("outfilename.xml", UTF-8", True)        
"""

class OvalDocument(object):
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
    NS_DEFAULT  = {"def": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
    NS_OVAL     = {"oval": "http://oval.mitre.org/XMLSchema/oval-common-5"}
    NS_XSI      = {"xsi": "http://www.w3.org/2001/XMLSchema-instance"}

    @staticmethod
    def indent(elem, level=0):
        i = "\n" + level*"  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                OvalDocument.indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i    
    
    @staticmethod            
    def getOvalTimestamp(timestamp=None):
        """Renders a datetime to a string formatted according to the OVAL specification.
        if the timestamp argument is None (which it is by default) or is not of type datetime,
        this function will return a string using the current datetime.
        
        @type timestamp: datetime
        @param timestamp: A datetime to be formatted as an OVAL timestamp, or None to use the current time.
        
        @rtype: string
        @return: a string formatted as per OVAL
        """
        if timestamp is None or not isinstance(timestamp, datetime):
            now = datetime.utcnow() 
            return now.strftime(OvalDocument.TIME_FORMAT)
        else:
            return timestamp.strftime(OvalDocument.TIME_FORMAT)

    def __init__(self, tree :ElementTree = None):
        if tree is None:
            root = Element("oval_definitions")
            self.tree = ElementTree(root)
            element = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}generator")
            gen = OvalGenerator(element)
            gen.setProduct("The CIS OVAL Repository")
            gen.setTimestamp()
            gen.setSchemaVersion("5.10.1")
            root.append(gen.get_element())
            return        

        self.tree = tree
        self.id_to_definition = { el.getId(): el for el in self.getDefinitions()} if self.getDefinitions() else {}
        self.id_to_test = {el.getId(): el for el in self.getTests()} if self.getTests() else {}
        self.id_to_object = {el.getId(): el for el in self.getObjects()} if self.getObjects() else {}
        self.id_to_state = {el.getId(): el for el in self.getStates()} if self.getStates() else {}
        self.id_to_variable = {el.getId(): el for el in self.getVariables()} if self.getVariables() else {}

    def parseFromFile(self, filename):
        """
        Load an OVAL document from a filename and parse that into an ElementTree
        Returns False if the filename is empty or there is an error parsing the XML document
        @type filename: string
        @param filename: The path to the OVAL XML document to parse
        
        @rtype:    boolean
        @return:    True on success, otherwise False
        """
        try: 
            if not filename:
                self.tree = None
                return False
            else:
                self.tree = xml.etree.ElementTree.parse(filename)
                return True
        except Exception:
            return False

    def parseFromText(self, xmltext):
        """
        Initializes the ElementTree by parsing the xmltext as XML
        Returns False if the string could not be parsed as XML
        
        @rtype:    boolean
        @return:    True on success, otherwise False
        """
        try:
            if not xmltext:
                return False
            else:
                root = xml.etree.ElementTree.fromstring(xmltext)
                self.tree = ElementTree(root)
                return True
        except Exception:
            return False

    def writeToFile(self, filename):
        """
        Writes the internal representation of the XmlTree to the given file name
        Returns False on error
        
        @rtype:    boolean
        @return:    True on success, otherwise False
        """
        try:
            if not filename:
                return False
            if not self.tree:
                return False
            
            self.tree.write(filename, "UTF-8", True, OvalDocument.NS_DEFAULT, "xml")
                
        except Exception:
            return False

    def to_string(self):
        
        if not self.tree:
            return None
        
        root = self.tree.getroot()
        if root is None:
            return ""
        OvalDocument.indent(root)
        return xml.etree.ElementTree.tostring(root, "UTF-8", "xml").decode("utf-8")

    def getDocumentRoot(self):
        """
        Returns the root element of the XML tree if one has been loaded.
        Otherwise, returns None
        
        @rtype:    Element
        @return:    The root Element of the OVAL document, or None
        """
        if not self.tree:
            return None
        
        return self.tree.getroot()

    def getGenerator(self, create=False):
        """
        Gets the generator for this OVAL document as an OvalGenerator object.
        If the generator element does not exist, the default behavior is to
        return none.  However, setting the optional parameter to True will cause
        a default generate element to be created, added to the document, and that will be returned.
        A value of None may also be returned if this OvalDocument is empty
        
        @rtype:    OvalGenerator
        @return:    An OvalGenerator object, or None if it does not exist and create was not set to True
        """
        if not self.tree:
            return None
        
        root = self.getDocumentRoot()
        if not root:
            return None
        
        gen_element = root.find("def:generator", OvalDocument.NS_DEFAULT)
        
        if gen_element is not None:
            return OvalGenerator(gen_element)
        
        if not create:
            return None
        else:
            element = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}generator")
            gen = OvalGenerator(element)
            gen.setProduct("The CIS OVAL Repository")
            gen.setTimestamp(None)
            gen.setSchemaVersion("5.10.1")
            return gen

    def getDefinitions(self):
        """
        Returns a list of all definitions found in this OvalDocment where each item in the list is of type OvalDefinition
        Returns None if no definitions could be found
        
        @rtype:    List
        @return:    All definitions in the OVAL document or None if none were found
        """
        root = self.getDocumentRoot()
        if not root:
            return None
        
        defroot = root.find("def:definitions", OvalDocument.NS_DEFAULT)
        
        if defroot is None:
            return None
        
        element_list = list(defroot)
        if not element_list:
            return None
        
        return [OvalDefinition(element) for element in element_list]

    def getTests(self):
        """
        Returns a list of all tests in this OvalDocument where each list item is of type OvalTest
        Returns None if no tests could be found
        
        @rtype:    List
        @return:    All tests in the OVAL document or None if none were found
        """
        root = self.getDocumentRoot()
        if not root:
            return None
        testroot = root.find("def:tests", OvalDocument.NS_DEFAULT)
        if testroot is None:
            return None
        element_list = list(testroot)
        if not element_list:
            return None
        return [OvalTest(element) for element in element_list]

    def getObjects(self):
        """
        Returns a list of all objects in this OvalDocument where each list item is of type OvalObject
        Returns None if no objects could be found
        
        @rtype:    List
        @return:    All objects in the OVAL document or None if none were found
        """
        root = self.getDocumentRoot()
        if not root:
            return None
        objectroot = root.find("def:objects", OvalDocument.NS_DEFAULT)
        if objectroot is None:
            return None
        element_list = list(objectroot)
        if not element_list:
            return None
        return [OvalObject(element) for element in element_list]

    def getStates(self):
        """
        Returns a list of all states in this OvalDocument where each list item is of type OvalState
        Returns None if no states could be found
        
        @rtype:    List
        @return:    All states in the OVAL document or None if none were found
        """
        root = self.getDocumentRoot()
        if not root:
            return None
        stateroot = root.find("def:states", OvalDocument.NS_DEFAULT)
        if stateroot is None:
            return None
        element_list = list(stateroot)
        if not element_list:
            return None
        return [OvalState(element) for element in element_list]

    def getVariables(self):
        """
        Returns a list of all variables in this OvalDocument where each list item is of type OvalVariable
        Returns None if no variables could be found
        
        @rtype:    List
        @return:    All variables in the OVAL document or None if none were found
        """
        root = self.getDocumentRoot()
        if not root:
            return None
        varroot = root.find("def:variables", OvalDocument.NS_DEFAULT)
        if varroot is None:
            return None
        element_list = list(varroot)
        if not element_list:
            return None
        return [OvalVariable(element) for element in element_list]

    def getElementByID(self, ovalid):
        """
        Uses the ovalid argument to determine what type of element is being referenced and locate that element
        in the OVAL ElementTree.
        Returns an OvalElement of the appropriate class (OvalDefinition, OvalTest, ...) 
        or None if there is no ElementTree or if a matching item could not be found
        
        @rtype:    OvalElement
        @return:    The located element as the appropriate OvalElement subclass, or None if no matching element was found.
        """
        if not ovalid:
            return None
        root = self.getDocumentRoot()
        if not root:
            return None
        try:
            oval_type = OvalElement.getElementTypeFromOvalID(ovalid)
        except Exception:
            return None
        if oval_type == OvalDefinition.DEFINITION:
            return self.id_to_definition[ovalid]
        elif oval_type == OvalDefinition.TEST:
            return self.id_to_test[ovalid]
        elif oval_type == OvalDefinition.OBJECT:
            return self.id_to_object[ovalid]
        elif oval_type == OvalDefinition.STATE:
            return self.id_to_state[ovalid]
        elif oval_type == OvalDefinition.VARIABLE:
            return self.id_to_variable[ovalid]
        else:
            return None

    def addElement(self, element, replace=True):
        """
        Adds the element to the ElementTree for this OVAL document
        The element argument must be of type OvalElement
        This method uses the OVALID of the element to determine what type of element it is
        and if an existing element with that OVALID already exists.
        This method will also create the necessary structure (id est, adding <definitions>, <tests>, etc)
        if the ElementTree does not already contain it.
        By default this method will replace an existing item with the same OVALID, but this behavior can
        be overridden by changing the option second argument to a value of "False"
        Returns True on success, otherwise False
        
        @rtype:    boolean
        @return:    True if the element was added to the document, otherwise False
        """
        if not element or element is None:
            return False
        if not self.tree or self.tree is None:
            return False
        ovalid = element.getId()
        if not ovalid:
            return False
        root = self.tree.getroot()
        if not root:
            root = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}oval_definitions")
            self.tree._setroot(root)
        # If replace has been set to False, then we want to exit with no changes
        #  when an element with this OVALID already appears in the document            
        if not replace:
            existing = self.getElementByID(ovalid)
            if existing:
                return False
        try:
            oval_type = OvalElement.getElementTypeFromOvalID(ovalid)
        except Exception:
            return False
        # Depending on the ID type, find the parent for it or create that parent if it doesn't exist
        # Then append the current element
        if oval_type == OvalDefinition.DEFINITION:
            parent = root.find("def:definitions", OvalDocument.NS_DEFAULT)
            if parent is None:
                parent = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}definitions")
                root.append(parent)
            parent.append(element.getElement())
            self.id_to_definition[ovalid] = element
            return True
        elif oval_type == OvalDefinition.TEST:
            parent = root.find("def:tests", OvalDocument.NS_DEFAULT)
            if parent is None:
                parent = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}tests")
                root.append(parent)
            parent.append(element.getElement())
            self.id_to_test[ovalid] = element
            return True
        elif oval_type == OvalDefinition.OBJECT:
            parent = root.find("def:objects", OvalDocument.NS_DEFAULT)
            if parent is None:
                parent = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}objects")
                root.append(parent)
            parent.append(element.getElement())
            self.id_to_object[ovalid] = element
            return True
        elif oval_type == OvalDefinition.STATE:
            parent = root.find("def:states", OvalDocument.NS_DEFAULT)
            if parent is None:
                parent = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}states")
                root.append(parent)
            parent.append(element.getElement())
            self.id_to_state[ovalid] = element
            return True
        elif oval_type == OvalDefinition.VARIABLE:
            parent = root.find("def:variables", OvalDocument.NS_DEFAULT)
            if parent is None:
                parent = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}variables")
                root.append(parent)
            self.id_to_variable[ovalid] = element
            parent.append(element.getElement())
            return True
        else:
            return False

class OvalGenerator(object):
    """
    Contains information about this OvalDocument, such as the schema version, the product that produced it, and when it was produced
    """
    def __init__(self, element):
        self.element = element

    def getProduct(self):
        """
        Gets the value of the product element
        """
        if self.element is None:
            return None
#         child = self.element.find("{http://oval.mitre.org/XMLSchema/oval-common-5}product_name")
        child = self.element.find("oval:product_name", OvalDocument.NS_OVAL)
        if child is None:
            return None
        else:            
            return child.text

    def get_element(self):
        return self.element

    def setProduct(self, product):
        """
        Sets a value for the product element.  If a product element does not already exist, one will be created
        """
        if self.element is None:
            return False
        if product is None:
            return False
        child = self.element.find("oval:product_name", OvalDocument.NS_OVAL)
        if child is not None:
            child.text = product
        else:
            child = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}product_name")
            child.text = product
            self.element.append(child)

    def getSchemaVersion(self):
        """
        Gets the value of the schema_version element
        """
        if self.element is None:
            return None
        child = self.element.find("oval:schema_version", OvalDocument.NS_OVAL)
        if child is not None:
            return child.text
        else:
            return None

    def setSchemaVersion(self, version):
        """
        Sets a value for the schema_version element.  If that element does not exist, one will be created.
        """
        if self.element is None:
            return False
        if version is None:
            return False
        child = self.element.find("oval:schema_version", OvalDocument.NS_OVAL)
        if child is not None:
            child.text = version
        else:
            child = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}schema_version")
            child.text = version
            self.element.append(child)

    def getTimestamp(self):
        """
        Gets the value of the timestamp element
        """
        if self.element is None:
            return None
        
        child = self.element.find("oval:timestamp", OvalDocument.NS_OVAL)
        if child is not None:
            return child.text
        else:
            return None

    def setTimestamp(self, timestamp=None):
        """
        Sets a value for the timestamp element.  If that elememtn does not exist, one will be created.
        If the timestamp argument is set to None, the timestamp will be set to the current time.
        """
        if self.element is None:
            return False
        
        if not timestamp or timestamp is None:
            now = datetime.utcnow()
            timestamp = now.strftime(OvalDocument.TIME_FORMAT)
                    
        child = self.element.find("oval:timestamp", OvalDocument.NS_OVAL)
        if child is not None:
            child.text = timestamp
        else:
            child = Element("{" + OvalDocument.NS_OVAL.get("oval") + "}timestamp")
            child.text = timestamp
            self.element.append(child)

    def getExtra(self, name, namespace=None):
        """
        Gets the value of the first child element of the generator where the tag name matches 'name'
        If the namespace argument is not provided, it will be assumed that the child element does not have a namespace.
        """
        if self.element is None:
            return None
        if not name:
            return None
        if namespace is not None:
            child = self.element.find(name, namespace)
        else:
            child = self.element.find(name)
            
        if child is not None:
            return child.text
        else:
            return None

    def setExtra(self, name, value, namespace=None):
        """
        Sets the value if the first child element with a tag name of 'name' to 'value'.  If the namespace argument is None,
        it will be assumed that the child element does not have a namespace
        """
        if not self.element or not name or not value:
            return None
        if namespace is not None:
            child = self.element.find(name, namespace)
        else:
            child = self.element.find(name)
        if child is not None:
            child.text = value
        else:
            if namespace is not None:
                child = Element(name)
            else:
                child = Element(name, namespace)
            child.text = value
            self.element.append(child)

class OvalElement(object):
    """
    The base class for the primary OVAL XML Elements.  Contains a few basic operations common to all
    OVAL Elements.
    TODO:
    """
    DEFINITION = "definition"
    TEST = "test"
    OBJECT = "object"
    STATE = "state"
    VARIABLE = "variable"

    def __init__(self, element):
        self.element = element

    def getId(self):
        """
        Returns the OVAL ID for this element, or None if
         1. This object was instantiated without an Element
         2. The underlying element does not have an "id" attribute
        """
        if self.element is None:
            return None
        return self.element.get("id")

    def setId(self, ovalid):
        """
        Sets the OVAL ID for this element
        Returns False if there is no underlying Xml ELement for this object
        """
        if self.element is None:
            return False
        if ovalid is not None:
            self.element.set("id", ovalid)

    def getVersion(self):
        if self.element is None:
            return None
        return self.element.get("version")

    def setVersion(self, version):
        if self.element is None:
            return False
        if not version:
            return False
        if not isinstance(version, int):
            return False
        self.element.set("version", version)
        return True

    def incrementVersion(self):
        version = self.getVersion()
        if not version:
            version = 1
        else:
            if not isinstance(version, int):
                version = 1
            else:
                version = version + 1
        self.setVersion(version)

    def getIndexSequence(self):
        ovalid = self.getId()
        if not ovalid or ovalid is None:
            return 1000
        # Get the numeric index from the end of the OVAL ID
        position = ovalid.rfind(':')
        if position < 0:
            return 1000
        try:
            position = position + 1
            index = ovalid[position:]
            # Apply the modulus function to determine which bucket it belongs to
            return int(int(index)/1000 + 1) * 1000
            # Or another way to do it:
#             sequence = int(index)
#             mod = sequence % 1000
#             return sequence - mod + 1000
        except Exception:
            return 1000

    def getFileName(self):
        """
        Use my OVAL ID to create a base file name.  That really just means replacing ':' with '_'
        *NOTE* This does not include the path to the file.
        """
        ovalid = self.getId()
        if not ovalid or ovalid is None:
            return None
        return ovalid.replace(':', '_') + ".xml"

    def getPredicate(self):
        """
        The portion of the element name that precedes the "_"
        So, for "password_test", the predicate would be "password"
        """
        localname = self.getLocalName()
        if not localname or localname is None:
            return None
        return localname.rsplit('_',1)[0]

    def getElement(self):
        """
        Get the raw xml.etree.ElementTree.Element for this node.  Can be used to directly manipulate the
        XML in ways not currently supported by this library
        """
        return self.element

    def getName(self):
        """
        Get the tag name (XMl element name) of the underlying XML Element, which includes the schema URI
        """
        if not self.element or self.element is None:
            return None
        return self.element.tag

    def getLocalName(self):
        """
        Just the element name with the schema URI (if any) removed
        """
        if not self.element or self.element is None:
            return None
        #Check if this node name is prefixed by a URI, in which case return every after the URI
        if '}' in self.element.tag:
            return str(self.element.tag).rsplit('}',1)[1]
        #If no namespace prefix, just return the node name
        return self.element.tag

    def getNamespace(self):
        """
        Returns the URI of the namespace or None if this node does not have a namepsace
        """
        if not self.element or self.element is None:
            return None
        tag = self.element.tag
        if not tag or tag is None:
            return None
        # If the oval ID does not contain a namespace, then we can't determine the schema shortname
        if not '}' in tag:
            return None
        try:
            position = tag.find('}')
            if position < 0:
                return None

            namespace = tag[:position]
            return namespace[1:]
        except Exception:
            return None

    def getSchemaShortName(self):
        if not self.element or self.element is None:
            return None
        tag = self.element.tag
        if not tag or tag is None:
            return None
        # If the oval ID does not contain a namespace, then we can't determine the schema shortname
        if not '}' in tag:
            return None
        try:
            schema = tag.rsplit('}', 1)[0]
            if not '#' in schema:
                return None
            return schema.rsplit('#', 1)[1].strip()
        except Exception:
            return None

    def writeToFile(self, path, with_xml_declaration=True):
        """Writes this element as a single standalone XML file
        @type path: string
        @param path: The path to the file to write
        @type with_xml_declaration: boolean
        @param with_xml_declaration: True to include the XML declaration at the top of the file (the default), or False to exclude it
        
        @rtype: boolean
        @return: True on success, otherwise False 
        """
        if not self or self is None:
            return False;
        if not self.element or self.element is None:
            return False
        if not path or path is None:
            return False;
        try:
            namespace = self.getNamespace()
            # Register this namespace with the parser as the default namespace
            xml.etree.ElementTree.register_namespace('', namespace)
            xml.etree.ElementTree.register_namespace('def', "http://oval.mitre.org/XMLSchema/oval-definitions-5")
            xml.etree.ElementTree.register_namespace('oval', "http://oval.mitre.org/XMLSchema/oval-common-5")
            xml.etree.ElementTree.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
            e = self.getElement()
            # Fix up the element so it will print nicely
            OvalDocument.indent(e)
            # Create a new ElementTree with this element as the root
            tree = ElementTree(e)
            # And finally, write the full tree to a file
            tree.write(path, "UTF-8", with_xml_declaration)
            return True
        
        except Exception:
            return False;

    @staticmethod
    def fromStandaloneFile(path):
        """For a file that contains a single OVAL XML element as the root element, instantiate the appropriate OvalElement sublcass for that element
        @type path: string
        @param path: the path to the file
        
        @rtype OvalElement
        @return None on error, or an object of the appropriate OvalElement subclass
        """
        if not path or path is None:
            return None
        if not os.path.exists(path):
            return None
        try:
            tree = ElementTree()
            tree.parse(path)            
            root = tree.getroot()
            return OvalElement.asOvalElement(root)
        
        except Exception:
            return None

    @staticmethod
    def getElementTypeFromOvalID(ovalid):
        if not ovalid or ovalid is None:
            raise ValueError("No OVAL ID given")
        segments = ovalid.split(':')
        if len(segments) != 4:
            raise ValueError('Invalid OVAL ID: {0}.'.format(ovalid))
        code = segments[2]
        if code == 'def':
            return OvalElement.DEFINITION
        elif code == 'tst':
            return OvalElement.TEST
        elif code == 'obj':
            return OvalElement.OBJECT
        elif code == 'ste':
            return OvalElement.STATE
        elif code == 'var':
            return OvalElement.VARIABLE
        else:
            raise ValueError("Unknown OVAL object type '{0}' in {1}.".format(code, ovalid))

    @staticmethod    
    def asOvalElement(element):
        if not element or element is None:
            return None
        try:        
            ovalid = element.get("id")
            if not ovalid or ovalid is None:
                return None
            oval_type = OvalElement.getElementTypeFromOvalID(ovalid)
            return OvalElement.create(oval_type, element)
        except Exception:
            return None

    @staticmethod            
    def create(oval_type, element):
        if not oval_type:
            return None
        if oval_type == OvalDefinition.DEFINITION:
            return OvalDefinition(element)
        elif oval_type == OvalDefinition.TEST:
            return OvalTest(element)
        elif oval_type == OvalDefinition.OBJECT:
            return OvalObject(element)
        elif oval_type == OvalDefinition.STATE:
            return OvalState(element)
        elif oval_type == OvalDefinition.VARIABLE:
            return OvalVariable(element)
        else:
            return None

class OvalDefinition(OvalElement):
    def __init__(self, element):
        if element is not None:
            self.element = element
        else:
            self.element = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}definition")
            self.element.set("version", "1")
            meta = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}metadata")
            self.element.append(meta)

    def getType(self):
        return OvalElement.DEFINITION

    def getMetadata(self):
        if self.element is None:
            return None
        metadata = self.element.find("def:metadata", OvalDocument.NS_DEFAULT)
        if metadata is not None:
            return OvalMetadata(metadata)
        return None

    def getClass(self):
        if self.element is None:
            return None
        return self.element.get("class")
    
    def setClass(self, ovalclass):
        if self.element is None:
            return False
        if not ovalclass:
            return False
        self.element.set("class", ovalclass)
        return True

    def getReferencingIDs(self):
        if self.element is None:
            return None
        return self.element.findall(".//*[name()='definition_ref']")

    def getTestIDs(self):
        if self.element is None:
            return None
        return self.element.findall(".//*[name()='test_ref']")

    def get_last_status_change(self):
        last_status_change = {}
        version = self.getVersion()
        last_status_change["Version"] = version
        meta = self.getMetadata()
        repo = meta.getOvalRepositoryInformation()
        if repo:
            status = repo.getStatus()
            last_status_change["Status"] = status
            last_status_change["Submitted"] = repo.getSubmitted()
            last_status_change["Modified"]  = repo.getModified()
            last_status_change["StatusChange"] = repo.getStatusChange()
        else:
            last_status_change["Status"] = None
            last_status_change["Submitted"] = None
            last_status_change["Modified"]  = None
            last_status_change["StatusChange"] = None

        return last_status_change

    def set_minimum_schema_version(self, min_schema_version):
        meta = self.getMetadata()
        repo = meta.getOvalRepositoryInformation()
        if repo:
            repo.setMinimumSchemaVersion(min_schema_version)

class OvalMetadata(object):
    def __init__(self, element):
        if element is not None:
            self.element = element
        else:
            self.element = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}metadata")

    def getTitle(self):
        if self.element is None:
            return None
        title_element = self.element.find("def:title", OvalDocument.NS_DEFAULT)
        if title_element is not None:
            return title_element.text
        return None

    def getDescription(self):
        if self.element is None:
            return None
        desc_element = self.element.find("def:description", OvalDocument.NS_DEFAULT)
        if desc_element is not None:
            return desc_element.text;
        return None

    def getAffected(self):
        if self.element is None:
            return None
        aff_element = self.element.find("def:affected", OvalDocument.NS_DEFAULT)
        if aff_element is not None:
            return OvalAffected(aff_element)
        return None

    def getOvalRepositoryInformation(self):
        if self.element is None:
            return None
        repo_element = self.element.find("def:oval_repository", OvalDocument.NS_DEFAULT)
        if repo_element is not None:
            return OvalRepositoryInformation(repo_element)
        return None

class OvalAffected(object):
    def __init__(self, element):
        self.element = element

class OvalRepositoryInformation(object):
    def __init__(self, element):
        self.element = element

    def getStatus(self):
        if self.element is None:
            return None
        status = self.element.find("def:status", OvalDocument.NS_DEFAULT)
        if status is None:
            return None
        return status.text

    def setStatus(self, status):
        if self.element is None:
            return
        if not status or status is None:
            return
        element = self.element.find("def:status", OvalDocument.NS_DEFAULT)
        if element is None:
            element = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}status")
            self.element.append(element)
        
        element.text = status

    def getMinimumSchemaVersion(self):
        if self.element is None:
            return None
        version = self.element.find("def:min_schema", OvalDocument.NS_DEFAULT)
        if version is None:
            return None        
        return version.text

    def setMinimumSchemaVersion(self, version):
        if self.element is None:
            return
        
        if not version or version is None:
            return
        
        child = self.element.find("def:min_schema_version", OvalDocument.NS_DEFAULT)
        
        if child is None:
            child = Element("{" + OvalDocument.NS_DEFAULT.get("def") + "}min_schema_version")
            self.element.append(child)
        
        child.text = version

    def getContributor(self, type):
        results = {}
        if self.element is not None:
            findstr = "def:dates/def:%s" % type
            subs = self.element.findall(findstr, OvalDocument.NS_DEFAULT)
            if subs is not None and len(subs) > 0:
                sub = subs[(len(subs) - 1)]
                results["Date"] = sub.get("date")

                contributors = []
                contribs = sub.findall("def:contributor", OvalDocument.NS_DEFAULT)
                for c in contribs:
                    curr = {}
                    curr["Organization"] = c.get("organization")
                    curr["Contributor"]  = c.text
                    contributors.append(curr)

                results["Contributors"] = contributors

        return results

    def getCreated(self):
        return self.getContributor("created")

    def getSubmitted(self):
        return self.getContributor("submitted")

    def getModified(self):
        return self.getContributor("modified")

    def getStatusChange(self):
        status_change = {}
        if self.element is not None:
            scs = self.element.findall("def:dates/def:status_change", OvalDocument.NS_DEFAULT)
            if scs is not None and len(scs) > 0:
                sc = scs[(len(scs) - 1)]
                status_change["Date"] = sc.get("date")
                status_change["Status"] = sc.text

        return status_change

class OvalTest(OvalElement):
    def __init__(self, element):
        self.element = element
    def getType(self):
        return OvalElement.TEST

class OvalObject(OvalElement):
    def __init__(self, element):
        self.element = element
    def getType(self):
        return OvalElement.OBJECT

class OvalState(OvalElement):    
    def __init__(self, element):
        self.element = element
    def getType(self):
        return OvalElement.STATE

class OvalVariable(OvalElement):    
    def __init__(self, element):
        self.element = element
    def getType(self):
        return OvalElement.VARIABLE

@retry((ConnectTimeout, ReadTimeout, ConnectionError), tries=10, delay=30, backoff=5)
def query_raw(url :str):
    logger.info(f'Downloading {url}')
    resp = requests.get(url, proxies=PROXIES, headers={'user-agent': config.user_agent}, timeout=300)
    if resp.status_code != 200:
        logger.error(f'{resp.status_code} {url}')
        return None
    return resp.text

def definition_to_dict(definition :OvalDefinition):
    try:
        if definition.getLocalName() != 'definition' or definition.getClass() != 'patch':
            return None
        oval_id = definition.getId()
        cpe_definitions = set()
        for c1 in definition.element:
            if not c1.tag.endswith('criteria'):
                continue
            for c2 in c1:
                if not c2.tag.endswith('criteria'):
                    continue
                for c3 in c2:
                    if not c3.tag.endswith('extend_definition'):
                        continue
                    cpe_definitions.add(c3.get('definition_ref'))

        metadata = definition.getMetadata()
        description = metadata.getDescription()
        title = metadata.getTitle()
        repository = metadata.getOvalRepositoryInformation()
        contributors = set()
        status = 'DRAFT'
        submitted_at = None
        submitted_by = None
        if repository is not None:
            status = repository.getStatus()
            submitted = repository.getSubmitted()
            submitted_at = submitted.get('Date')
            submitted_contributor = submitted.get('Contributors')[0]
            submitted_by = (submitted_contributor['Contributor'], submitted_contributor['Organization'])
            contributors.add((submitted_contributor['Contributor'], submitted_contributor['Organization']))
            for contributor in repository.getModified().get('Contributors', []):
                contributors.add((contributor['Contributor'], contributor['Organization']))

        cve_refs = set()
        vendors = []
        for reference in metadata.element:
            if not reference.tag.endswith('reference'):
                continue
            if reference.get('source') != 'CVE':
                vendors.append({
                    'ref_id': reference.get('ref_id'),
                    'ref_url': derive_ref_url(reference.get('ref_id'), reference.get('ref_url')),
                })
                continue
            cve_refs.add(reference.get('ref_id'))

        return {
            'oval_id': oval_id,
            'title': title,
            'description': description,
            'submitted_at': submitted_at,
            'submitted_by': submitted_by,
            'status': status,
            'cpe_definitions': list(cpe_definitions),
            'cve': list(cve_refs),
            'contributors': list(contributors),
            'vendors': vendors,
        }
    except Exception as ex:
        for _ in map(print, definition.element.itertext()):
            pass
        raise ex

def derive_ref_url(ref_id, ref_url = None):
    if ref_url is not None:
        return ref_url
    if ref_id.startswith('CESA-'):
        ref_url = 'https://www.google.com/search?q=site%3Ahttps%3A%2F%2Flists.centos.org+%22CESA-2012%3A1288%22'
    return ref_url

def local_oval(local_file :str):
    oval_file = pathlib.Path(local_file)
    if not oval_file.is_file():
        return None
    stored_tree = ElementTree()
    stored_tree.parse(local_file)
    return OvalDocument(stored_tree)

def remote_oval(url :str, local_file :str) -> OvalDocument:
    logger.info(url)
    raw = query_raw(url)
    oval_file = pathlib.Path(local_file)
    oval_file.write_text(raw)
    tree = ElementTree()
    tree.parse(local_file)
    return OvalDocument(tree)

def cpe_from_definitions(document :OvalDocument, definitions :list):
    cpe_refs = set()
    for cpe_ref in definitions:
        for definition_reference in document.getElementByID(cpe_ref).getMetadata().element:
            if not definition_reference.tag.endswith('reference'):
                continue
            if definition_reference.get('source') != 'CPE':
                continue
            cpe_refs.add(definition_reference.get('ref_id'))
    return list(cpe_refs)

def save_definition(definition :dict):
    for cve_id in definition.get('cve', []):
        cve = CVE()
        cve.cve_id = cve_id
        original_cve = CVE()
        save = False
        if cve.hydrate():
            original_cve = cve
        else:
            cve.assigner = 'Unknown'
            cve.description = definition.get('description')
            cve.published_at = definition.get('submitted_at')
            cve.last_modified = datetime.utcnow()
            save = True

        if cve.title is None:
            cve.title = definition.get('title')
            save = True

        cpes = set(original_cve.cpe or [])
        reference_urls = set()
        for ref in original_cve.references or []:
            reference_urls.add(ref['url'])
        cve.references = original_cve.references or []
        remediation_sources = set()
        for remediation in original_cve.remediation or []:
            remediation_sources.add(remediation['source_url'])

        for vendor in definition['vendors']:
            if vendor.get('ref_url') is None:
                continue
            if vendor.get('ref_url') not in remediation_sources:
                cve.remediation.append({
                    'type': 'patch',
                    'source': definition.get('oval_id'),
                    'source_id': vendor.get('ref_id'),
                    'source_url': vendor.get('ref_url'),
                    'affected_packages': [],
                    'contributors': definition.get('contributors', []),
                    'description': definition.get('description'),
                    'published_at': definition.get('submitted_at'),
                })
                save = True

            if 'cve.mitre.org' in vendor.get('ref_url'):
                continue
            if vendor.get('ref_url') not in reference_urls:
                cve.references.append({
                    'url': vendor.get('ref_url'),
                    'name': vendor.get('ref_id'),
                    'source': definition.get('oval_id'),
                    'tags': ['Information Sharing', 'OVAL'],
                })
                save = True

        for cpe_ref in definition['cpe_refs']:
            if cpe_ref not in cpes:
                cpes.add(cpe_ref)
                save = True

        cve.cpe = list(cpes)
        if save is True:
            extra = None
            doc = cve.get_doc()
            if doc is not None:
                extra = {'_nvd': doc.get('_source', {}).get('_nvd')}
            cve.persist(extra=extra)

def main(sources :list, not_before :datetime, process :bool = False):
    for source_file, sources_url in sources:
        filename = f"{DATAFILE_DIR}/{source_file}"
        stored_document = local_oval(filename)
        document = None
        if process is True:
            document = stored_document
        process = True if process is True else stored_document is None
        if stored_document is not None:
            stored_generator = stored_document.getGenerator()
            stored_cis_ts = datetime.fromisoformat(stored_generator.getTimestamp().replace('T', ' '))
            day_ago = datetime.utcnow() - timedelta(days=1)
            if stored_cis_ts < day_ago:
                document = remote_oval(sources_url, filename)
                generator = document.getGenerator()
                cis_data_ts = datetime.fromisoformat(generator.getTimestamp().replace('T', ' '))
                if cis_data_ts > stored_cis_ts:
                    process = True
        if process is False:
            logger.info('OVAL already processed')
            return
        if document is None:
            document = remote_oval(sources_url, filename)
        for item in document.getDefinitions():
            definition = definition_to_dict(item)
            if definition is None:
                continue
            if definition.get('submitted_at') is not None:
                published = datetime.fromisoformat(definition.get('submitted_at')).replace(tzinfo=None)
                if published < not_before:
                    logger.info(f'{published} < {not_before}')
                    continue
            definition['cpe_refs'] = cpe_from_definitions(document, definition['cpe_definitions'])
            save_definition(definition)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-y', '--since-year', help='optionally specify a year to start from', dest='year', default=DEFAULT_START_YEAR)
    parser.add_argument('--not-before', help='ISO format datetime string to skip all OVAL records published until this time', dest='not_before', default=None)
    parser.add_argument('-f', '--force-process', help='Just process the stored file, if it exists', dest='force', action="store_true")
    parser.add_argument('-s', '--only-show-errors', help='set logging level to ERROR (default CRITICAL)', dest='log_level_error', action="store_true")
    parser.add_argument('-q', '--quiet', help='set logging level to WARNING (default CRITICAL)', dest='log_level_warning', action="store_true")
    parser.add_argument('-v', '--verbose', help='set logging level to INFO (default CRITICAL)', dest='log_level_info', action="store_true")
    parser.add_argument('-vv', '--debug', help='set logging level to DEBUG (default CRITICAL)', dest='log_level_debug', action="store_true")
    args = parser.parse_args()
    log_level = logging.CRITICAL
    if args.log_level_error:
        log_level = logging.ERROR
    if args.log_level_warning:
        log_level = logging.WARNING
    if args.log_level_info:
        log_level = logging.INFO
    if args.log_level_debug:
        log_level = logging.DEBUG
    logging.basicConfig(
        format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
        level=log_level
    )
    not_before = datetime(year=int(args.year), month=1 , day=1)
    if args.not_before is not None:
        not_before = datetime.strptime(args.not_before, DATE_FMT)

    remote_sources = [
        ('cis.xml', f'https://oval.cisecurity.org/repository/download/{OVAL_SCHEMA_VERSION}/all/oval.xml'),
    ]
    year = datetime.utcnow().year
    while year >= args.year:
        remote_sources.append((f'com.redhat.rhsa-{year}.xml', f'https://www.redhat.com/security/data/oval/com.redhat.rhsa-{year}.xml'))
        year -= 1

    main(remote_sources, not_before, process=args.force)