from ghidra.program.model.data import Undefined
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.data import FloatDataType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.data import ParameterDefinitionImpl
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import EnumDataType
from ghidra.program.model.data import UnionDataType
from ghidra.program.model.data import TypedefDataType
from ghidra.program.model.data import Float16DataType
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import CharDataType
from ghidra.program.model.data import ShortDataType
from ghidra.program.model.data import LongDataType
from ghidra.program.model.data import LongLongDataType
from ghidra.program.model.data import BooleanDataType
from ghidra.program.model.data import DoubleDataType
from ghidra.program.model.data import LongDoubleDataType
from ghidra.program.model.data import SignedCharDataType
from ghidra.program.model.data import IntegerDataType
from ghidra.program.model.data import Integer16DataType
from ghidra.program.model.data import UnsignedCharDataType
from ghidra.program.model.data import UnsignedShortDataType
from ghidra.program.model.data import UnsignedIntegerDataType
from ghidra.program.model.data import UnsignedInteger16DataType
from ghidra.program.model.data import UnsignedLongDataType
from ghidra.program.model.data import UnsignedLongLongDataType
from ghidra.program.model.data import WideCharDataType
from ghidra.program.model.data import WideChar16DataType
from ghidra.program.model.data import WideChar32DataType
from ghidra.program.model.data import VoidDataType
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import FileDataTypeManager

from java.io import File
from java.lang import Exception as JavaException

import xml.etree.ElementTree as ET

import json
import glob
import os

class GdtException(Exception):
    pass

class BaseType(object):
    def __init__(self, element, manager):
        self._dataType = None
        self.element = element
        self.id = element.attrib['id']
        self.manager = manager
        self.filePath = manager.getFileFromId(element.attrib.get('file', ''))
        self.categoryPath = manager.getCategoryPathFromFile(self.filePath)
        # Check if we belong to a namespace
        nsPrefix = ''
        if 'context' in element.attrib:
            ctxElement = manager.getElementById(element.attrib['context'])
            if ctxElement.tag == "Namespace":
                nsName = ctxElement.attrib['name']
                if not nsName.endswith('::'):
                    nsPrefix = nsName + '::'
        defaultName = "anon_{0}_{1}".format(self.__class__.__name__, element.attrib['id'])
        self.name = nsPrefix + element.attrib.get('name', defaultName.lower())
        self.size = int(self.element.attrib.get('size', 0)) / 8   
        self.alignment = int(self.element.attrib.get('align', 0)) / 8            

    def align(self):
        if self.alignment:
            self.dataType.setExplicitMinimumAlignment(self.alignment)
        else:
            self.dataType.setToDefaultAligned()

    def save(self):
        self.manager.recordTypeForId(self.element.attrib['id'], self)

    def pad(self):
        if self.dataType.getLength() < self.size:
            padding = Undefined.getUndefinedDataType(self.size)
            self.dataType.add(padding, None, "Padding to match true size")

    def getElement(self):
        return self.element
        
    def setDataType(self, dataType):
        self.dataType = dataType
    
    def getDataType(self):
        return self.dataType
    
    def hasDataType(self):
        return self.dataType != None

class Array(BaseType):
    """
        Convert CastXML XML element into a Ghidra ArrayDataType.    
        Args:
            element (ElementTree): XML element
    """
    def __init__(self, element, manager):
        super(Array, self).__init__(element, manager)
        arrayTypeId = element.attrib['type']
        arrayTypeElement = manager.getElementById(arrayTypeId)
        arrayElementDataType = manager.getDataType(arrayTypeElement)
        if arrayElementDataType == None:
            raise Exception("No valid datatype for array. Specified type: " + arrayTypeId)
        maxIndex = element.attrib.get('max')
        maxIndex = int(maxIndex) if maxIndex != '' else 0
        minIndex = element.attrib.get('min')
        minIndex = int(minIndex) if minIndex != '' else 0
        elementLength = arrayElementDataType.getLength()
        numElements = (maxIndex - minIndex) + 1
        if numElements == 0:
            # FIXME: Ghidra won't accept 0 size arrays
            # Setting it to 1 would consume more bytes than it may actually exist as.
            # e.g. struct foobar baz[0] 
            return Undefined.getUndefinedDataType(1)
        self.dataType = ArrayDataType(arrayElementDataType, numElements, elementLength)
        self.save()

class Enumeration(BaseType):
    """
        Convert CastXML XML element into a Ghidra EnumDataType.    
        Args:
            element (ElementTree): XML element
    """
    def __init__(self, element, manager):
        super(Enumeration, self).__init__(element, manager)
        self.dataType = EnumDataType(self.categoryPath, self.enumName, self.size)
        for enumValue in element:
            name = enumValue.attrib['name']
            bitSize = int(element.attrib['size'])
            init = int(enumValue.attrib['init'])
            # Convert to signed integer as Java cannot coerce large unsigned numbers
            init = init & ((1 << bitSize) - 1)
            init = init | (-(init & (1 << (bitSize - 1))))
            self.dataType.add(name, init)
        self.save()

class Function(BaseType):
    """
        Convert CastXML XML element into a Ghidra FunctionDefinitionDataType.    
        Args:
            element (ElementTree): XML element
    """
    def __init__(self, element, manager):
        super(Function, self).__init__(element, manager)           
        self.dataType = FunctionDefinitionDataType(self.categoryPath, self.name)
        returnTypeElement = manager.getElementById(element.attrib['returns'])
        returnType = manager.getDataType(returnTypeElement)
        self.dataType.setReturnType(returnType)
        params = []
        argumentElements = element.getchildren()
        for i, argumentElement in enumerate(argumentElements):
            if argumentElement.tag == "Argument":
                argumentName = argumentElement.attrib.get('name', "arg_" + str(i)) 
                argumentTypeElement = manager.getElementById(argumentElement.attrib['type'])
                paramDataType = manager.getDataType(argumentTypeElement)   
                params.append(ParameterDefinitionImpl(argumentName, paramDataType, ""))
            elif argumentElement.tag == "Elipsis":
                self.dataType.setVarArgs(True)
                
        self.dataType.setArguments(params)
        self.save()

class Pointer(BaseType):
    """
        Convert CastXML XML element into a Ghidra PointerDataType.    
        Args:
            element (ElementTree): XML element
    """
    def __init__(self, element, manager):
        super(Pointer, self).__init__(element, manager)           
        pointeeElement = manager.getElementById(element.attrib['type'])
        pointeeDataType = manager.getDataType(pointeeElement)
        if pointeeDataType == None:
            pointeeDataType = Undefined.getUndefinedDataType(1)
            print("Invalid DataType returned for PointerType: tag={0} id={1}".format(
                pointeeElement.tag, pointeeElement.attrib['id'])
            )
        pointerLength = manager.getDefaultPointerSize()
        if 'size' in element.attrib:
            pointerLength = int(element.attrib['size']) / 8
        self.dataType = PointerDataType(pointeeDataType, pointerLength)
        self.save()

class Union(BaseType):
    """
        Convert CastXML XML element into a Ghidra UnionDataType.    
        Args:
            element (ElementTree): XML element
        Returns (UnionDataType): Ghidra UnionDataType
    """
    def __init__(self, element, manager):
        super(Union, self).__init__(element, manager)
        self.dataType = UnionDataType(self.categoryPath, self.name, self.manager.dtMgr)
        if 'members' in element.attrib:
            members = element.attrib['members']
            memberIds = members.split(" ")
            for memberId in memberIds:
                memberElement = manager.getElementById(memberId)
                if memberElement.tag != "Field":
                    continue
                fieldElement = manager.getElementById(memberElement.attrib['type'])
                fieldName = memberElement.attrib['name']
                fieldDataType = manager.getDataType(fieldElement)
                fieldOffset = int(memberElement.attrib['offset']) / 8
                
                self.dataType.add(fieldDataType, fieldName, hex(fieldOffset))
        self.pad()
        self.save()

class Typedef(BaseType):
    """
        Convert CastXML XML element into a Ghidra TypedefDataType.    
        Args:
            element (ElementTree): XML element
    """
    def __init__(self, element, manager):
        super(Typedef, self).__init__(element, manager)                   
        underlyingTypeElement = manager.getElementById(element.attrib['type'])
        underlyingDataType = manager.getDataType(underlyingTypeElement)
        if underlyingDataType == None:
            # Since we failed to retrieve a valid type, we will default to Undefined.
            underlyingDataType = Undefined.getUndefinedDataType(1)
            print("Invalid DataType returned for Typedef: tag={0} id={1}".format(
                underlyingTypeElement.tag, underlyingTypeElement.attrib['id'])
            )
        self.dataType = TypedefDataType(self.categoryPath, self.name, underlyingDataType)
        self.save()

class Class(BaseType):
    """
    Convert CastXML XML element into a Ghidra StructureDataType.
    Args:
        element (ElementTree): XML element
    """

    def __init__(self, element, manager):
        super(Class, self).__init__(element, manager)
        self.dataType = StructureDataType(
            self.categoryPath, self.name, self.size, manager.dtMgr
        )
        self.align()
        self.save()
        self.members = []
        self.bases = []
        self.virtualBases = []
        self.virtualMethods = collections.OrderedDict()
        self.inheritsVirtualMethods = False
        self.instance = None
        self.curOffset = 0
        self.curBitFieldOffset = -1
        self.className = element.attrib["name"]

        # Load all base classes
        if "bases" in element.attrib:
            baseElements = element.getchildren()
            for baseElement in baseElements:
                # Get base information
                baseTypeId = baseElement.attrib["type"]
                baseClass = self.manager.getTypeById(baseTypeId)
                if int(baseElement.attrib["virtual"]) == 1:
                    self.virtualBases.append(baseClass)
                else:
                    self.bases.append(baseClass)
                if baseClass.virtualMethods or baseClass.inheritsVirtualMethods:
                    self.inheritsVirtualMethods = True

        # Add each field
        if "members" in element.attrib:
            members = element.attrib["members"]
            memberIds = members.split(" ")
            for memberId in memberIds:
                fieldElement = self.manager.getElementById(memberId)
                # Skip artificial fields
                if fieldElement.attrib.get("artificial") == "1":
                    continue
                # Methods
                if fieldElement.tag in [
                    "Method",
                    "Constructor",
                    "Destructor",
                    "OperatorMethod",
                ]:
                    isVirtual = int(fieldElement.attrib["virtual"]) == 1
                    methodType = self.createMethod(fieldElement)
                    if isVirtual:
                        # Split the class out from the name
                        methodName = methodType.getName().split('::')[1]
                        self.virtualMethods[methodName] = methodType
                    continue
                if fieldElement.tag != "Field":
                    continue
                self.members.append(fieldElement)

class GDTTypeManager(object):
    def __init__(self, outputPath):
        self.dtMgr = FileDataTypeManager.createFileArchive(File(outputPath))
        self.transaction = None
        self.types = {}
        self.files = {}
        self.elements = {}
        self.fundamentalTypes = {}

    def open(self):
        self.transaction = self.dtMgr.startTransaction("")

    def close(self):
        if self.dtMgr:
            if self.transaction:
                self.dtMgr.endTransaction(self.transaction, True)
            self.dtMgr.close()     

    def save(self):
        self.dtMgr.endTransaction(self.transaction)
        self.dtMgr.save()
        self.transaction = None

    def getTypeById(self, id):
        return self.types.get(id)
    
    def recordTypeForId(self, id, newType):
        self.types[id] = newType

    def getElementById(self, id):
        return self.elements.get(id)

    def getDataTypeById(self, id):
        if id not in self.types:
            return None
        return self.types[id].dataType

    def getFileFromId(self, id):
        if id not in self.files:
            return None
        fileElement = self.files[id]
        return fileElement.attrib["name"]

    def getCategoryPathFromFile(self, filePath):
        if not filePath:
            return None
        # make sure we use the same path separators
        filePath = filePath.replace("/", "\\")
        categoryPath = "/" + filePath.split("\\")[-1]
        # print categoryPath
        return CategoryPath(categoryPath)

    def getIntType(self, isUnsigned, size):
        if isUnsigned == True:
            if size == 16:
                return UnsignedShortDataType.dataType
            elif size == 32:
                return UnsignedIntegerDataType.dataType
            elif size == 128:
                return UnsignedInteger16DataType.dataType
        else:
            if size == 16:
                return ShortDataType.dataType
            elif size == 32:
                return IntegerDataType.dataType
            elif size == 128:
                return Integer16DataType.dataType

        return None

    def getLongType(self, isUnsigned, size):
        if isUnsigned == True:
            if size == 32:
                return UnsignedLongDataType.dataType
            elif size == 64:
                return UnsignedLongLongDataType.dataType
        else:
            if size == 32:
                return LongDataType.dataType
            elif size == 64:
                return LongLongDataType.dataType
        return None

    def getFundamentalType(self, element):
        typeName = element.attrib["name"]
        typeSize = int(element.attrib["size"])
        if typeName not in self.fundamentalTypes:
            # add type to fundamentalTypes
            fundamentalType = None
            if typeName == "void":
                fundamentalType = VoidDataType.dataType
            elif typeName == "bool" or typeName == "_Bool":
                fundamentalType = BooleanDataType.dataType
            elif typeName == "char":
                fundamentalType = CharDataType.dataType
            elif typeName == "signed char":
                fundamentalType = SignedCharDataType.dataType
            elif typeName == "unsigned char":
                fundamentalType = UnsignedCharDataType.dataType
            elif typeName == "wchar_t":
                fundamentalType = WideCharDataType.dataType
            elif typeName == "char16_t":
                fundamentalType = WideChar16DataType.dataType
            elif typeName == "char32_t":
                fundamentalType = WideChar32DataType.dataType
            elif typeName in (
                "long int",
                "long long int",
            ):
                fundamentalType = self.getLongType(False, typeSize)
            elif typeName in ("long unsigned int", "long long unsigned int"):
                fundamentalType = self.getLongType(True, typeSize)
            elif typeName in ("short int", "int", "__int128"):
                fundamentalType = self.getIntType(False, typeSize)
            elif typeName in (
                "short unsigned int",
                "unsigned int",
                "unsigned __int128",
            ):
                fundamentalType = self.getIntType(True, typeSize)
            elif typeName == "float":
                fundamentalType = FloatDataType.dataType
            elif typeName == "__float128":
                fundamentalType = Float16DataType.dataType
            elif typeName == "double":
                fundamentalType = DoubleDataType.dataType
            elif typeName == "long double":
                fundamentalType = LongDoubleDataType.dataType
            elif typeName == "decltype(nullptr)":
                fundamentalType = PointerDataType.dataType
            else:
                raise Exception("Unhandled fundamental type: {}".format(typeName))
            self.fundamentalTypes[typeName] = fundamentalType
            return fundamentalType

        return self.fundamentalTypes[typeName]

    def getDataType(self, element):
        # Return existing data types
        dataType = self.getDataTypeById(element.attrib["id"])
        if dataType != None:
            return dataType

        # Create new data type
        if element.tag == "FundamentalType":
            dataType = self.getFundamentalType(element)
        elif element.tag == "CvQualifiedType":
            qtype = self.getElementById(element.attrib["type"])
            dataType = self.getDataType(qtype)
        elif element.tag in ["PointerType", "ReferenceType"]:
            dataType = Pointer(element, self).dataType
        elif element.tag == "ArrayType":
            dataType = Array(element, self).dataType
        elif element.tag == "ElaboratedType":
            elem = self.getElementById(element.attrib["type"])
            dataType = self.getDataType(elem)
        elif element.tag == "Typedef":
            dataType = Typedef(element, self).dataType
        elif element.tag in ["Class", "Struct"]:
            dataType = Class(element, self).dataType
        elif element.tag == "Union":
            dataType = Union(element, self).dataType
        elif element.tag == "Enumeration":
            dataType = Enumeration(element, self).dataType
        elif element.tag in ["FunctionType", "Function"]:
            dataType = Function(element, self).dataType
        elif element.tag == "Unimplemented":
            if "kind" in element.attrib:
                print(
                    "WARN: Encountered Unimplemented tag for kind {0}".format(
                        element.attrib["kind"]
                    )
                )
            elif "type_class" in element.attrib:
                print(
                    "WARN: Encountered Unimplemented tag for type_class {0}".format(
                        element.attrib["type_class"]
                    )
                )
            print("WARN: This is a limitation in CastXML.")
            print("WARN: Returning UndefinedDataType instead.")
            dataType = Undefined.getUndefinedDataType(1)
        else:
            print("Encountered unhandled tag: {0}".format(element.tag))
            raise Exception()

        # Since this is a new type, save it
        if dataType != None:
            self.dtMgr.resolve(dataType, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
        
        return dataType

class SourceUnit(object):
    def __init__(self, unitName, xmlFile, jsonFile, manager):
        self.manager = manager
        self.name = unitName
        self.xmlFile = xmlFile
        self.jsonFile = jsonFile
        self.xmlData = ET.parse(self.xmlFile)
        with open(self.jsonFile, 'r') as fh:
            self.classes = json.load(fh)

    def parse(self, parsedTypes, gdtManager):
        print("Processing {}".format(self.name))
        try:
            self.manager.open()
            loadableTypes = (
                # Composite
                "Class",
                "Struct", 
                "Union", 
                # Typedefs
                "Typedef", 
                # Enums
                "Enumeration",
                # Functions
                "Function"
            )
            # Add files
            for element in self.xmlData.root:
                elementId = element.attrib['id']
                if element.tag == "File":
                    self.manager.files[elementId] = element
                else:
                    self.manager.elements[elementId] = element
            
            # Now parse elements
            for element in self.xmlData.root:
                if element.tag in loadableTypes:
                    self.manager.getDataType(element)
            self.manager.save()
        except Exception as e:
            print("Exception while processing {}:\n{}".format(self.name, e))
        finally:
            self.manager.close()

def main():
    args = getScriptArgs()
    dataDir = args[0]
    print("\n**** GDT Creation Script ****")
    print("Processing files in data directory: {}".format(dataDir))
    outputPath = os.path.join(dataDir, 'output.gdt')
    # There should be one xml and json for each processed source unit
    sourceUnits = []
    for xmlFile in glob.glob(dataDir + '/*.xml'):
        # Parse the source unit e.g. my/path/target.xml becomes target
        sourceUnit = os.path.split(xmlFile)[1].rsplit('.')[0]
        jsonFile = dataDir + '/{}.classes.json'.format(sourceUnit)
        if not os.path.exists(jsonFile):
            print("ERROR: missing expected file: {}".format(jsonFile))
            raise GdtException()
        sourceUnits.append(SourceUnit(xmlFile, jsonFile))
    gdtManager = GDTTypeManager(outputPath)
    parsedTypes = {}
    for sourceUnit in sourceUnits:
        sourceUnit.parse(parsedTypes, gdtManager)
    gdtManager.close()

if __name__ == "__main__":
    main()
