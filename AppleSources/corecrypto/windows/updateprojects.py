# Copyright (c) (2019-2021,2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/usr/bin/python
import os
import re
import ntpath

#these are the components from CC that windows compiles
WINCCPARTICLES = [ "cc", "ccaes", "ccansikdf", "ccasn1",  "ccblowfish",  "cccast",  "ccchacha20poly1305",  "cccmac",
    "ccder", "ccdes", "ccdh", "ccdigest", "ccdrbg", "ccec", "ccec25519", "ccecies", "cchkdf", "cchmac", "ccmd2",
    "ccmd4", "ccmd5", "ccmode", "ccn", "ccnistkdf", "ccpad", "ccpbkdf2", "ccprime", "ccrc2", "ccrc4", "ccripemd",
    "ccrng", "ccrsa", "ccsha1", "ccsha2", "ccsrp", "cctest", "ccwrap", "cczp", "corecrypto_test", "corecrypto_perf"]


#getting file names from CoreCryptoSources.cmake
file = open("../CoreCryptoSources.cmake", "r")
srcLines = file.readlines()
file.close()

cmakeFileList = []

for line in srcLines:
    line = line.strip()
    if len(line)==0 or line[0]=='#':
        continue
    #check if this is a .h ot .c
    if (".h" in line) or (".c" in line):
        for particle in WINCCPARTICLES:
            line2Check=particle+"/"
            if line2Check in line:
                cmakeFileList.append(line)
                continue
    elif re.search(r'\.s$', line):
        print ("ASM file. Skipping: "+line)
    else:
        print ("Regular line. Appending: "+line)
        cmakeFileList.append(line)

#file = open("./CoreCryptoSourcesWin.cmake", "a")
#file.write("".join(outContent))
#file.close()
def getElementIndex(sectionName, globalContent):
    retValue = 0;
    for line in globalContent:
        if line.find(sectionName)!=-1:
            return retValue
        retValue = retValue + 1
    return -1


def getVariable(sectionName, globalContent):
    retValue = []

    sectionIndex = getElementIndex(sectionName, globalContent)
    if sectionIndex == -1 :
        print (sectionName + " could not be found.")
        return ""
    else:
        print ("Found section " + sectionName +" at:"+str(sectionIndex))

    line = sectionName + "= [\n "
    #retValue+=line
    listCount = len(globalContent)-1
    for idx in range(sectionIndex+1, listCount):
        line = globalContent[idx]
        line = line.strip()
        line = line.replace('\n','')
        if line.find(")") != -1:
            #this is the last line
            line = line.replace(')', '')
            retValue+=line
            return retValue
        fileNameString = line
        retValue.append(fileNameString)
    return retValue

def copyFileContentAsString(fileName):
    file = open (fileName, "r")
    retValue = file.read()
    file.close()
    return retValue

def updateProjectTemplate(projTemplateName, sourceFiles, includePaths):
    print ("Updating project file from template: {0}".format(projTemplateName))
    projectFileContent = ""
    projFile = open (projTemplateName, "r")
    projectFileContent = projFile.read()
    projFile.close()

    projectFileContent = projectFileContent.replace("CCSourceFiles", sourceFiles)
    projectFileContent = projectFileContent.replace("CCIncludeFolders", includePaths)

    projFileName = projTemplateName.replace(".template", "")
    projFile = open(projFileName, "w")
    projFile.write(projectFileContent)
    projFile.close()

def getIncludeDirList(includePathList):
    retValue = []
    for f in includePathList:
        iPath = os.path.dirname(f)
        retValue.append("../../{0};".format(iPath))
        if f.find("corecrypto/") != -1:
            retValue.append("../../{0}/../;".format(iPath))

    return retValue

def getIncludePaths(includePathsList):
    retValue = ""
    for f in includePathsList:
        retValue+=f
    return retValue


outVariables = ["CORECRYPTO_PUBLIC_HDRS", "CORECRYPTO_PRIVATE_HDRS",
                "CORECRYPTO_PROJECT_HDRS", "CORECRYPTO_SRCS", "CORECRYPTO_TEST_HDRS",
                "CORECRYPTO_TEST_SRCS", "CORECRYPTO_PERF_SRCS"]

filesCollection = dict()

for listVariable in outVariables:
    variable = getVariable(listVariable, cmakeFileList)
    filesCollection[listVariable] = variable

fixedIncludePaths = "../../ccaes/src/vng;../../cckprng;../../corecrypto_test/include;../../corecrypto_test;../../corecrypto_test/lib;"
fixedSourceFiles = ["ccrng/crypto_test/crypto_test_rng_win.c"]
#prepare include folders
includeFilesList = filesCollection["CORECRYPTO_PROJECT_HDRS"]
includeFilesList.extend(filesCollection["CORECRYPTO_PUBLIC_HDRS"])
includeFilesList.extend(filesCollection["CORECRYPTO_PRIVATE_HDRS"])
includeFilesList.extend(filesCollection["CORECRYPTO_TEST_HDRS"])
includeFilesList = list(dict.fromkeys(includeFilesList))

#adding fips headers fPath
includeFilesList.append("./cc_fips/corecrypto/fipsport.h")

includeList = getIncludeDirList(includeFilesList)

#updateing cc source files
fileList = filesCollection["CORECRYPTO_SRCS"]
fileList = list(dict.fromkeys(fileList))
fileList.extend(fixedSourceFiles)

#remove OSX dependent files
filesToRemove = ["cc_fips/src/fipspost_get_hmac.c"]

srcFiles = ""
for f in fileList:
    if f in filesToRemove:
        continue
    srcFiles +="<ClCompile Include=\"..\\..\\{0}\"/>\n".format(f)

includeList.extend(getIncludeDirList(fileList))
includeList = list(dict.fromkeys(includeList))

includePaths = getIncludePaths(includeList)

#adding fixed includes
includePaths += fixedIncludePaths

updateProjectTemplate("./corecrypto/corecrypto.vcxproj.template", srcFiles, includePaths)

#creating copyheader.bat file
print ("\nCreating test project")

copyHeaders = copyFileContentAsString("copyHeaders.bat.template")

publicHeadersList = filesCollection["CORECRYPTO_PUBLIC_HDRS"]
publicHeadersList = list(dict.fromkeys(publicHeadersList))
copyCommand=""
for f in publicHeadersList:
    fnt = ntpath.normpath(f)
    copyCommand+="copy /Y \"..\\..\\{0}\" \"%DSTFLDR%\" \n".format(fnt)

copyHeaders = copyHeaders.replace("CopyPublicHeaders", copyCommand)

copyCommand = ""
privateHeadersList=filesCollection["CORECRYPTO_PRIVATE_HDRS"]
privateHeadersList = list(dict.fromkeys(privateHeadersList))
for f in privateHeadersList:
    fnt = ntpath.normpath(f)
    copyCommand+="copy /Y \"..\\..\\{0}\" \"%DSTFLDR%\\private\" \n".format(fnt)

copyHeaders = copyHeaders.replace("CopyPrivateHeaders", copyCommand)

copyHeadersBat = open("./copyheaders.bat", "w")
copyHeadersBat.write(copyHeaders)
copyHeadersBat.close()

#getting source files for test
testSourceExcludeList = ["ccshadow.c"]
testSourceFilesList = filesCollection["CORECRYPTO_TEST_SRCS"]
testSourceFilesList = list(dict.fromkeys(testSourceFilesList))
srcFiles = ""
for f in testSourceFilesList:
    stripLine = f.strip()
    shouldExclude = False
    for excludedPattern in testSourceExcludeList:
        if stripLine.find(excludedPattern) != -1:
            shouldExclude = True
            print ("Excluding from test: "+ stripLine)
    if shouldExclude == True:
        continue
    if re.search(r'\.c$', stripLine):#we need only c files
        srcFiles += "<ClCompile Include=\"..\\..\\{0}\"/>\n".format(stripLine)

#test scripts
CC_CONVERT_TEST_VECTORS =  "../scripts/convert_testvectors.sh"
CC_TEST_VECTORS = "../corecrypto_test/test_vectors/wycheproof/chacha20_poly1305_test.json"
GENERATED_TEST_VECTORS_DIR = "../corecrypto_test/include"
GENERATED_TEST_VECTORS = GENERATED_TEST_VECTORS_DIR+"/cc_generated_test_vectors.h"
bashCommand = "./"+CC_CONVERT_TEST_VECTORS+" "+GENERATED_TEST_VECTORS+" ../corecrypto_test/test_vectors/"

print ("Generating test vectors: {0}".format(bashCommand))
os.system(bashCommand)
#srcFiles += "<ClCompile Include=\"..\{0}\"/>\n".format(GENERATED_TEST_VECTORS)


testFixedIncludePathList = ["..\\..\\ccsha2\\src;", "..\\..\\ccrng\\src;",
                            "..\\..\\ccec25519\\src;", "..\\..\\corecrypto_test\\include;",
                            "..\\..\\corecrypto_test\\;" "../../corecrypto_test/include/yajl;"]
testIncludePaths = includePaths
testIncludePaths+=getIncludePaths(testFixedIncludePathList)

testIncludePaths+=getIncludePaths(getIncludeDirList(testSourceFilesList))


updateProjectTemplate("./corecrypto_test/corecrypto_test.vcxproj.template", srcFiles, testIncludePaths)


#updateing perf project
print ("\nCreating performace project")
perfExcludeFilePatterns = ["ccperf_ccsae", "ccperf_ccspake","ccperf_ccscrypt", "ccperf_vrf", "ccperf_kprng"]
perfFixedIncludePath = ["../../corecrypto_perf/corecrypto;","../../cczp/crypto_test;"]

perfSourceFileList = filesCollection["CORECRYPTO_PERF_SRCS"]
perfSourceFileList = list(dict.fromkeys(perfSourceFileList))

srcFiles = ""
for f in perfSourceFileList:
    stripLine = f.strip()

    shouldExclude = False
    for excludedSubs in perfExcludeFilePatterns:
        if stripLine.find(excludedSubs) != -1:
            print ("Excluding from perf: "+stripLine)
            shouldExclude = True
    if shouldExclude == True:
        continue

    if re.search(r'\.c$', stripLine):#we need only c files
        srcFiles += "<ClCompile Include=\"..\\..\\{0}\"/>\n".format(stripLine)

perfIncludePaths = includePaths
perfIncludePaths += getIncludePaths(perfFixedIncludePath)
includeFoldersFromSource = list(dict.fromkeys(getIncludeDirList(perfSourceFileList)))
perfIncludePaths +=getIncludePaths(includeFoldersFromSource)

updateProjectTemplate("./corecrypto_perf/corecrypto_perf.vcxproj.template", srcFiles, perfIncludePaths)
