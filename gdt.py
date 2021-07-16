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
import re
import traceback

from collections import defaultdict


class AnonymousCounters(object):

    types = [
        'enumeration',
        'class',
        'structure',
        'union',
        'function',
        'method',
    ]

    def __init__(self):
        self.counters = {
            x:1 for x in self.types
        }

    def get(self, counterType):
        counterType = counterType.lower()
        value = self.counters[counterType]
        self.counters[counterType] = self.counters[counterType] + 1
        return value

COUNTERS = AnonymousCounters()

# This is a cumulative map of names to types, updated during parsing.
GDT_TYPES = {}

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
        nsPrefix = manager.resolveNamespace(element)
        elementName =  element.attrib.get('name', '')
        classType = self.__class__.__name__.lower()
        self.anonymous = False
        if not elementName and classType in AnonymousCounters.types:
            # Anonymous entry, check category and add to anonymous if missing
            if not self.categoryPath:
                self.categoryPath = CategoryPath('/_anonymous_')
            anonId = COUNTERS.get(classType)
            elementName = "anon_{0}_{1}".format(classType, anonId)
            self.anonymous = True
        self.name = manager.msvc_name_fix(nsPrefix + elementName)
        self.alignment = int(self.element.attrib.get('align', 0)) / 8            

    def align(self):
        if self.alignment:
            self.dataType.setExplicitMinimumAlignment(self.alignment)
        else:
            self.dataType.setToDefaultAligned()

    def save(self):
        # print("Recording {} [{} bytes]".format(self.name, self.dataType.getLength()))
        self.manager.recordTypeForId(self.element.attrib['id'], self)

    def pad(self):
        if self.dataType.getLength() < self.size:
            padding = Undefined.getUndefinedDataType(self.size)
            self.dataType.add(padding, None, "Padding to match true size")

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
        # We will create one-length for zero-length arrays, but the structure handler
        # will set zero-length flex array based on our type
        numElements = maxIndex or 1
        elementLength = arrayElementDataType.getLength()
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
        self.size = int(element.attrib["size"]) / 8
        self.dataType = EnumDataType(self.categoryPath, self.name, self.size)
        for enumValue in element:
            name = enumValue.attrib['name']
            bitSize = int(element.attrib["size"])
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
        if self.categoryPath:    
            self.dataType = FunctionDefinitionDataType(self.categoryPath, self.name)
        else:
            self.dataType = FunctionDefinitionDataType(self.name)
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
        pointerLength = 8
        if "size" in element.attrib:
            pointerLength = int(element.attrib["size"]) / 8
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
        self.dataType = UnionDataType(self.categoryPath, self.name)
        if "incomplete" in element.attrib:
            self.size = 0
        else:
            self.size = int(element.attrib["size"]) / 8
        self.flexible = False
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
                if fieldElement.tag == "ArrayType" and 'min' in fieldElement.attrib and int(fieldElement.attrib["min"]) == 0:
                    # Set flag that specifies we contain a flexible array
                    self.flexible = True
                self.dataType.add(fieldDataType, fieldName, hex(fieldOffset))
        # print("Created Union {} [{} bytes]".format(self.name, self.dataType.getLength()))
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

class Structure(BaseType):
    """
        Convert CastXML XML element into a Ghidra StructureDataType.    
        Args:
            element (ElementTree): XML element
    """
    def __init__(self, element, manager):
        super(Structure, self).__init__(element, manager)
        # Handle forward declarations
        if "incomplete" in element.attrib:
            self.size = 0
        else:
            self.size = int(element.attrib["size"]) / 8
        
        self.dataType = StructureDataType(self.categoryPath, self.name, self.size)
        # print("Created {} [{} bytes]".format(self.name, self.size))
        self.align()
        self.save()
        self.curBitFieldOffset = -1
        self.curBitFieldStorageSize = 0
        self.anonStructId = 0
        self.anonUnionId = 0
        self.bases = {}
        self.methods = defaultdict(list)
        
        # This is our name without any namespace prepended
        self.shortName = self.name
        if ">" in self.shortName:
            self.shortName = self.shortName.rsplit(">", 1)[0]
        elif "::" in self.shortName:
            self.shortName = self.shortName.rsplit('::', 1)[1]

        print("Creating class {}".format(self.name))
        # Load all base classes
        if "bases" in element.attrib:
            baseEntries = element.getchildren()
            for baseEntry in baseEntries:
                baseTypeId = baseEntry.attrib['type']
                baseElement = manager.getElementById(baseTypeId)
                # Get base information (this creates the classes if they don't already exist)
                baseInternalType = manager.getInternalType(baseElement)
                self.bases[baseInternalType.name] = baseInternalType

        hasVirtualMethods = False
        if 'members' in element.attrib:
            members = element.attrib['members']
            memberIds = members.split(" ")
            for memberId in memberIds:
                fieldElement = manager.getElementById(memberId)
                if fieldElement.attrib.get("artificial") == "1" and "overrides" not in fieldElement.attrib:
                    continue
                # Methods
                if fieldElement.tag in [
                    "Method",
                    "Constructor",
                    "Destructor",
                    "OperatorMethod",
                ]:
                    methodDataType = self.createMethod(fieldElement)
                    if fieldElement.tag == 'Destructor':
                        methodName = '{dtor}'
                    else:
                        methodName = fieldElement.attrib['name']
                    
                    self.methods[methodName].append(methodDataType)
                    hasVirtualMethods = True
                    continue

                if fieldElement.tag != "Field":
                    continue

                # Fields representing other types (unions, arrays, etc.)
                typeElement = self.manager.getElementById(fieldElement.attrib['type'])
                fieldName = fieldElement.attrib['name']
                fieldOffset = int(fieldElement.attrib['offset']) / 8
                # Check for zero-sized flexible array at the end of the structure
                if typeElement.tag == "ArrayType" and 'min' in typeElement.attrib and int(typeElement.attrib['min']) == 0:
                    arrayElement = self.manager.getElementById(typeElement.attrib['type'])
                    arrayDataType = self.manager.getDataType(arrayElement)
                    self.dataType.setFlexibleArrayComponent(arrayDataType, fieldName, hex(fieldOffset))
                else:
                    if fieldOffset >= self.size:
                        raise Exception("Structure {}, Field {} claims to be at offset {} which is beyond the container size {}".format(
                            self.name, fieldName, hex(fieldOffset), hex(self.size)
                        ))
                    internalType = self.manager.getInternalType(typeElement)
                    fieldDataType = self.manager.getDataType(typeElement)
                    if "bits" in fieldElement.attrib:
                        # Grab the storage size (in bytes) for this bitfield:
                        fieldStorageSize = fieldDataType.getLength()
                        
                        # Figure out which byte within the structure this bitfield starts on
                        if self.curBitFieldOffset == -1 or \
                           fieldOffset >= self.curBitFieldOffset + self.curBitFieldStorageSize:
                            # First time seeing this bitfield
                            self.curBitFieldOffset = fieldOffset
                            self.curBitFieldStorageSize = fieldStorageSize

                        # The offset of the current bit (in bits) and the number of bits it consumes
                        bitOffset = (
                            int(fieldElement.attrib["offset"]) - self.curBitFieldOffset * 8
                        )
                        bitSize = int(fieldElement.attrib["bits"])
                        print(
                           "Processing bitfield member {}\n\tMember size (bits): {}\n\tMember offset in bitfield (bits): {}\n\t" \
                           "Bitfield offset in structure (bytes): {}\n\tBitfield size (bytes): {}".format(
                               fieldName, bitSize, bitOffset, self.curBitFieldOffset, self.curBitFieldStorageSize
                           )
                        )
                        self.dataType.insertBitFieldAt(
                            self.curBitFieldOffset,
                            self.curBitFieldStorageSize,
                            bitOffset,
                            fieldDataType,
                            bitSize,
                            fieldName,
                            "",
                        )
                    else:
                        # This might be an unnamed struct/union:
                        if not fieldName:
                            if typeElement.tag == "Struct":
                                fieldName = 's' + str(self.anonStructId)
                                self.anonStructId += 1
                            elif typeElement.tag == "Union":
                                fieldName = 'u' + str(self.anonUnionId)
                                self.anonUnionId += 1
                            else:
                                raise GdtException("Structure {} has an unnamed field that isn't a struct or union. Id: {}".format(
                                    self.name, memberId)
                                )
                        # print("Processing Struct:{} Field:{} Offset:{} ID: {}".format(
                        #   self.name, fieldName, fieldOffset, memberId)
                        # )
                        # Check for flexible unions (MS)
                        if isinstance(internalType, Union) and internalType.flexible:
                            # We need to add extra bytes to the end of the struct for 1 instance of the union member size
                            extraBytes = fieldDataType.getLength() - internalType.size
                            self.dataType.growStructure(extraBytes)
                        self.dataType.replaceAtOffset(fieldOffset, fieldDataType, fieldDataType.getLength(), fieldName, hex(fieldOffset))
            
        if hasVirtualMethods:
            self.manager.classes.append(self)
            
    def createMethod(self, element):
        global ANON_METHOD_COUNTER
        """
        Convert CastXML XML element into a Ghidra FunctionDefinitionDataType.

        Args:
            element (ElementTree): XML element

        Returns (FunctionDefinitionDataType): Ghidra FunctionDefinitionDataType
        """
        params = []
        argumentElements = element.getchildren()
        varArgs = False
        paramDataTypeNames = []
        methodTag = element.tag
        for i, argumentElement in enumerate(argumentElements):
            if argumentElement.tag == "Argument":
                argumentName = argumentElement.attrib.get("name", "arg_" + str(i))
                argumentTypeElement = self.manager.getElementById(
                    argumentElement.attrib["type"]
                )
                paramDataType = self.manager.getDataType(argumentTypeElement)
                paramDataTypeNames.append(paramDataType.getName())
                params.append(ParameterDefinitionImpl(argumentName, paramDataType, ""))
            elif argumentElement.tag == "Elipsis":
                varArgs = True
        paramsSignature = "<" + ",".join(paramDataTypeNames or ["void"]) + ">"
        if methodTag == 'Destructor':
            methodName = '{dtor}'
        elif methodTag == 'Constructor':
            methodName = '{ctor}'
        elif element.attrib['name'] != '':
            methodName = element.attrib['name']
        else:
            methodName = "anon_method_" + ANON_METHOD_COUNTER
            ANON_METHOD_COUNTER += 1
        functionName = (
            self.shortName
            + "::"
            + methodName
            + paramsSignature
        )
        functionType = FunctionDefinitionDataType(self.categoryPath, functionName)
        if "returns" in element.attrib:
            returnTypeElement = self.manager.getElementById(element.attrib["returns"])
            returnType = self.manager.getDataType(returnTypeElement)
        else:
            returnType = VoidDataType.dataType
        functionType.setReturnType(returnType)
        if varArgs:
            functionType.setVarArgs(True)
        functionType.setArguments(params)
        # self.manager.recordTypeForId(element.attrib['id'], functionType)
        return functionType 

    def resolveBases(self):
        # Resolve base class inheritance:
        bases = self.bases.values()[:]
        for base in bases:
            base.resolveBases()
            # Add bases of our bases to our bases!
            self.bases.update(base.bases)

    def resolveVftables(self):
        # Sort out vftables
        classData = self.manager.sourceUnit.classes.get(self.name)
        vftable = self.manager.sourceUnit.vftables.get(self.name)
        if not classData:
            #print("No class data was retrieved for {}".format(self.name))
            return
        if not vftable:
            #print("No vftable data was retrieved for {}".format(self.name))
            return
        
        classFields = classData['fields']
        # We need to keep track of our index in the function lists since the MSVC 
        # d1reportAllClassLayout option doesn't print the full signature
        methodIdxs = defaultdict(int)

        for field, offset in classFields.items():
            if 'vfptr' in field:
                vftableName = vftable['name']
                vftableDataType = StructureDataType(self.categoryPath, vftableName, vftable["size"])
                vftablePointerType = PointerDataType(vftableDataType, 8)
                for methodFullName, methodOffsets in vftable['fields'].items():
                    methodParts = methodFullName.rsplit('::', 1)
                    methodClass = methodParts[0][1:]
                    methodName = methodParts[1]
                    for methodOffset in methodOffsets:
                        methodIdx = methodIdxs[methodFullName]
                        methodIdxs[methodFullName] = methodIdxs[methodFullName] + 1
                        if methodClass == self.name:
                            if methodName not in self.methods:
                                print("Missing method {} in {}: {}".format(methodName, self.name, self.methods))
                                raise GdtException()
                            methodDataType = self.methods[methodName][methodIdx]
                        else:
                            if methodClass not in self.bases:
                                print("Missing base {} in {} bases: {}".format(methodClass, self.name, self.bases))
                                raise GdtException()
                            methodDataType = self.bases[methodClass].methods[methodName][methodIdx]
                        methodPointerType = PointerDataType(methodDataType, 8)
                        vftableDataType.replaceAtOffset(methodOffset, methodPointerType, 8, methodName, "")
                self.dataType.replaceAtOffset(offset, vftablePointerType, 8, "vftable", "")


class GDTTypeManager(object):

    LOADABLE_TYPES = [
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
    ]

    def __init__(self, outputPath):
        if os.path.exists(outputPath):
            self.dtMgr = FileDataTypeManager.openFileArchive(File(outputPath), True)
        else:
            self.dtMgr = FileDataTypeManager.createFileArchive(File(outputPath))
        self.transaction = None
        self.types = {}
        self.files = {}
        self.elements = {}
        self.classes = []
        self.fundamentalTypes = {}
        self.sourceUnit = None

    def parse(self, sourceUnit):
        self.transaction = self.dtMgr.startTransaction("")
        try:
            print("Processing {}".format(sourceUnit.name))
            self.sourceUnit = sourceUnit
            self.types = {}
            self.files = {}
            self.elements = {}
            self.classes = []
            self.fundamentalTypes = {}
            
            # Add files
            for element in sourceUnit.xmlRoot:
                elementId = element.attrib['id']
                if element.tag == "File":
                    self.files[elementId] = element
                else:
                    self.elements[elementId] = element
            
            # Now parse elements from headers within our traverse list
            for element in sourceUnit.xmlRoot:
                # Don't parse types that aren't in our traverse list.
                filePath = self.getFileFromId(element.attrib.get('file', ''))
                if not filePath:
                    continue
                
                hdrName = self.getFileNameFromPath(filePath)
                if hdrName not in self.sourceUnit.traverse:
                    continue
                # This belongs to our namespace, parse it
                if element.tag in self.LOADABLE_TYPES:
                    self.getDataType(element)
            
            # Handle base classes and vftables for classes added during parsing above
            for classType in self.classes:
                classType.resolveBases()
                classType.resolveVftables()

            # Add types we created to the manager
            for _, internalType in self.types.items():
                self.dtMgr.resolve(internalType.dataType, DataTypeConflictHandler.KEEP_HANDLER)
                # Add the type to the cumulative map (if it has a name and isn't anonymous)
                if internalType.name and not internalType.anonymous:
                    GDT_TYPES[internalType.name] = internalType.dataType.getPathName()

            self.dtMgr.endTransaction(self.transaction, True)
            self.transaction = None
            self.save()
        except Exception as e:
            print("Exception while processing {}:\n{}".format(sourceUnit.name, traceback.format_exc()))
            raise e
        except JavaException as je:
            print("JavaException while processing {}:\n{}".format(sourceUnit.name, traceback.format_exc()))
            raise je


    def close(self):
        if self.dtMgr:
            if self.transaction:
                self.dtMgr.endTransaction(self.transaction, False)
            self.dtMgr.save()
            self.dtMgr.close()     

    def save(self):
        self.dtMgr.save()
    
    def recordTypeForId(self, id, newType):
        self.types[id] = newType

    def getElementById(self, id):
        return self.elements.get(id)

    def getFileFromId(self, id):
        if id not in self.files:
            return None
        fileElement = self.files[id]
        return fileElement.attrib["name"].lower()

    def getFileNameFromPath(self, filePath):
        fileName = filePath.replace("/", "\\")
        fileName = fileName.split("\\")[-1]
        return fileName.lower()

    def getCategoryPathFromFile(self, filePath):
        if not filePath:
            return None
        # make sure we use the same path separators
        fileName = self.getFileNameFromPath(filePath)
        categoryPath = "/" + fileName
        # print categoryPath
        return CategoryPath(categoryPath.lower())

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

    def getInternalType(self, element):
        internalType = self.types.get(element.attrib["id"])
        if internalType != None:
            return internalType
        else:
            self.createDataType(element)
            return self.types.get(element.attrib["id"])

    def resolveNamespace(self, element, prefix=''):
        # Resolve namespace name by recursing upward
        if 'context' in element.attrib:
            ctxElement = self.getElementById(element.attrib['context'])
            if ctxElement.tag == "Namespace":
                nsName = ctxElement.attrib['name']
                if not nsName.endswith('::'):
                    prefix = nsName + '::' + prefix
                    # Recurse to prepend namespace parts from ancestors
                    return self.resolveNamespace(ctxElement, prefix)
        return prefix

    def msvc_name_fix(self, cname):
        cname = cname.replace('HSTRING__', 'HSTRING').replace('HSTRING,', 'HSTRING *,').replace('HSTRING>', 'HSTRING *>')
        cname = cname.replace('UINT32', 'unsigned int')
        cname = re.sub('(struct|class|enum) ', '', cname)
        cname = re.sub('(\<|(?:\, ))GUID', '\\1_GUID', cname)
        # A bunch of annoying stuff where MSVC replaces the typedef but clang doesn't
        cname = cname.replace('__FIVectorView_1_HSTRING_t', 'IVectorView<HSTRING *>')
        cname = cname.replace('__FIVectorView_1_Windows__CData__CText__CTextSegment_t', 'IVectorView<ABI::Windows::Data::Text::TextSegment>')
        cname = cname.replace('__FIMapView_2_HSTRING_IInspectable_t', 'IMapView<HSTRING *, IInspectable *>')
        return cname

    def getDataType(self, element):
        """ Returns existing types or creates new ones """
        
        # Check internal types for this parsing run
        internalType = self.types.get(element.attrib["id"])
        if internalType != None:
            if internalType.dataType == None:
                raise GdtException("Internal type for {} (id {}) is null..?".format(internalType.name, element.attrib["id"]))
            return internalType.dataType

        # Do we know about this from a previous run?
        elementName =  element.attrib.get('name', '')
        if elementName:
            nsPrefix = self.resolveNamespace(element)
            elementName = self.msvc_name_fix(nsPrefix + elementName)
            typeId = GDT_TYPES.get(elementName)
            if typeId != None:
                ghidraType = self.dtMgr.getDataType(typeId)
                if ghidraType == None:
                    raise GdtException("Ghidra type for {} (id {}) is null..?".format(elementName, typeId))
                return ghidraType

        # Must be a new type
        return self.createDataType(element)

    def createDataType(self, element):
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
            dataType = Structure(element, self).dataType
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
        
        return dataType

class SourceUnit(object):
    def __init__(self, unitName, xmlFile, classesFile, traverseFile):
        self.name = unitName
        self.xmlFile = xmlFile
        self.classesFile = classesFile
        self.traverseFile = traverseFile
        self.xmlData = ET.parse(self.xmlFile)
        self.xmlRoot = self.xmlData.getroot()
        with open(self.classesFile, 'r') as fh:
            msvcData = json.load(fh)
            self.classes = msvcData['classes']
            self.vftables = msvcData['vftables']
        with open(self.traverseFile, 'r') as fh:
            self.traverse = [x.lower() for x in json.load(fh)]

def main():
    print("\n**** GDT Creation Script ****")
    args = getScriptArgs()
    dataDir = args[0]
    print("Processing files in data directory: {}".format(dataDir))
    outputPath = dataDir + '/_WindowsSDK_.gdt'.format(dataDir)
    # Just append to the GDT if it already exists..
    #if os.path.exists(outputPath):
    #    os.unlink(outputPath)
    try:
        # There should be one xml and json for each processed source unit
        #for xmlFile in [os.path.join(dataDir, 'ProcessHacker.xml')]:
        for xmlFile in glob.glob(dataDir + '/*.xml'):
            gdtManager = GDTTypeManager(outputPath)
            # Parse the source unit e.g. my/path/target.xml becomes target
            sourceUnitName = os.path.split(xmlFile)[1].rsplit('.')[0]
            classesFile = dataDir + '/{}.classes.json'.format(sourceUnitName)
            if not os.path.exists(classesFile):
                print("ERROR: missing expected file: {}".format(classesFile))
                raise GdtException()
            traverseFile = dataDir + '/{}.traverse.json'.format(sourceUnitName)
            if not os.path.exists(traverseFile):
                print("ERROR: missing expected file: {}".format(traverseFile))
                raise GdtException()
            print("Parsing source unit: {}".format(sourceUnitName))
            sourceUnit = (SourceUnit(sourceUnitName, xmlFile, classesFile, traverseFile))
            gdtManager.parse(sourceUnit)
            gdtManager.close()
            print("Wrote data to file {}".format(outputPath))
    except Exception as e:
        print("Error parsing source units: {}".format(e))
        gdtManager.close()
    except JavaException as je:
        print("Java exception while parsing source units: {}".format(je))
        gdtManager.close()

if __name__ == "__main__":
    main()
