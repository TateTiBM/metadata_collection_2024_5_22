#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

Collect all the necessary metadata needed for ingest

"""

from datetime import datetime
import hashlib
import subprocess
import tempfile
import xml.dom.minidom as minidom
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
import bagit

LOCATIONID = str(13068)
ARTWORK_SRC_DIR = ""
TMS_XML_DIR = ""
COMPONENTID = ""


def read_xml(tms_filepath):
    global COMPONENTID

    metadata = []

    tree = ET.parse(tms_filepath)
    root = tree.getroot()

    accessionNumber = root.find("AccessionNumber").text
    componentNumber = root.find("ComponentNumber").text
    componentName = root.find("ComponentName").text
    objectID = root.find("ObjectID").text
    COMPONENTID = root.find("ComponentID").text

    kvp = {
        "accessionNumber": accessionNumber,
        "componentNumber": componentNumber,
        "componentName": componentName,
        "objectID": objectID,
        "componentID": COMPONENTID,
    }

    metadata.append(kvp)

    return metadata


def prompt_metadata():
    global ARTWORK_SRC_DIR, TMS_XML_DIR
    metadata = []
    print("Starting user input metadata collection...")

    audioChannels = input("Component audio channels: ")
    mediaDescription = input("Component Media Description: ")
    suppliedBy = input("Supplied By: ")
    whereMade = input("Where Made: ")
    mediaLabel = input("Time-based Media Label: ")

    # Colour
    print("Colour/B&W: ")
    options = ["Colour", "Black & White", "N/A"]
    for i, option in enumerate(options):
        print(f"{i + 1} {option}")

    while True:
        try:
            selection = int(input("Please choose an option: "))
            if 1 <= selection <= len(options):
                break
            else:
                print("Invalid selection, please try again.")
        except ValueError:
            print("Invalid input, please enter a number.")
    colour = options[selection - 1]

    # User Id
    pattern = r"^[A-Za-z]{2}-\d{2,4}$"

    while True:
        userId = input("User ID [XY-##]: ")
        if re.match(pattern, userId):
            break
        else:
            print("Invalid input, please try again.")

    # Artwork Source Directory
    while True:
        artwork_src_dir = os.path.expanduser(
            input("Artwork source directory/file path: ")
        )
        if artwork_src_dir == "":
            if ARTWORK_SRC_DIR != "":
                print(
                    "Using parameter artwork source directory/file: " + ARTWORK_SRC_DIR
                )
                artwork_src_dir = ""
                break
            else:
                print("Error, no artwork source directory provided.")
        elif os.path.isdir(artwork_src_dir) or os.path.isfile(artwork_src_dir):
            print("Artwork source directory/file: " + artwork_src_dir)
            break
        else:
            print("Invalid path/file, please try again.")

    # TMS XML Directory
    while True:
        tms_xml_dir = os.path.expanduser(input("TMS XML directory path: "))
        if tms_xml_dir == "":
            if TMS_XML_DIR != "":
                print("Using parameter TMS XML directory: " + TMS_XML_DIR)
                tms_xml_dir = ""
                break
            else:
                print("Error, no TMS XML directory provided.")
        elif os.path.isdir(tms_xml_dir):
            if not tms_xml_dir.endswith("/"):
                tms_xml_dir += "/"
            print("TMS XML directory: " + tms_xml_dir)
            break
        else:
            print("Invalid path, please try again.")

    # Allow user to verify input
    validated = input(
        "Please verify that the information inputted are correct (Y/y for yes or N/n for no): "
    )

    if validated == "n" or validated == "N":
        return prompt_metadata()
    elif validated == "y" or validated == "Y":
        kvp = {
            "audioChannels": audioChannels,
            "mediaDescription": mediaDescription,
            "suppliedBy": suppliedBy,
            "whereMade": whereMade,
            "mediaLabel": mediaLabel,
            "colour": colour,
            "userId": userId,
            "artworkSrc": artwork_src_dir,
            "tmsXml": tms_xml_dir,
            "locationId": LOCATIONID,
        }

        metadata.append(kvp)
        return metadata


def create_xml_output(tms_metadata, input_metadata, comp_type, filename, directory):
    root = ET.Element("PreIngestMetadata")
    component = ET.Element("Component")

    accessionNumber = ET.Element("AccessionNumber")
    accessionNumber.text = tms_metadata[0]["accessionNumber"]
    component.append(accessionNumber)

    componentNumber = ET.Element("ComponentNumber")
    componentNumber.text = tms_metadata[0]["componentNumber"]
    component.append(componentNumber)

    componentName = ET.Element("ComponentName")
    componentName.text = tms_metadata[0]["componentName"]
    component.append(componentName)

    objectID = ET.Element("ObjectID")
    objectID.text = tms_metadata[0]["objectID"]
    component.append(objectID)

    componentID = ET.Element("ComponentID")
    componentID.text = tms_metadata[0]["componentID"]
    component.append(componentID)

    if comp_type == "ASP":
        locationId = ET.Element("LocationID")
        locationId.text = input_metadata[0]["locationId"]
        component.append(locationId)

        userId = ET.Element("PRE_INGEST_USER_ID")
        userId.text = input_metadata[0]["userId"]
        component.append(userId)

        dateStored = ET.Element("Bagging-Date")
        today = datetime.today()
        dateStored.text = today.strftime("%Y/%m/%d %H:%M:%S")
        component.append(dateStored)

        mediaDescription = ET.Element("DESCRIPTION")
        mediaDescription.text = input_metadata[0]["mediaDescription"]
        component.append(mediaDescription)

        suppliedBy = ET.Element("SUPPLIED_BY")
        suppliedBy.text = input_metadata[0]["suppliedBy"]
        component.append(suppliedBy)

        mediaLabel = ET.Element("MEDIA_LABEL")
        mediaLabel.text = input_metadata[0]["mediaLabel"]
        component.append(mediaLabel)

        root.append(component)

        # tree ouput
        treeOutput = ET.Element("TreeOutput")
        treeOutput.text = "\n" + get_tree_output()
        root.append(treeOutput)

        # # disk util
        # diskUtil = ET.Element("DiskUtility")
        # diskUtil.text = "\n" + get_disk_util()
        # root.append(diskUtil)
    elif comp_type == "SC":
        locationId = ET.Element("LocationID")
        locationId.text = input_metadata[0]["locationId"]
        component.append(locationId)

        userId = ET.Element("PRE_INGEST_USER_ID")
        userId.text = input_metadata[0]["userId"]
        component.append(userId)

        dateStored = ET.Element("Bagging-Date")
        today = datetime.today()
        dateStored.text = today.strftime("%Y/%m/%d %H:%M:%S")
        component.append(dateStored)

        mediaDescription = ET.Element("DESCRIPTION")
        mediaDescription.text = input_metadata[0]["mediaDescription"]
        component.append(mediaDescription)

        suppliedBy = ET.Element("SUPPLIED_BY")
        suppliedBy.text = input_metadata[0]["suppliedBy"]
        component.append(suppliedBy)

        root.append(component)

        # tree output
        treeOutput = ET.Element("TreeOutput")
        treeOutput.text = "\n" + get_tree_output()
        root.append(treeOutput)
    else:
        userId = ET.Element("PRE_INGEST_USER_ID")
        userId.text = input_metadata[0]["userId"]
        component.append(userId)

        locationId = ET.Element("LocationID")
        locationId.text = input_metadata[0]["locationId"]
        component.append(locationId)

        dateStored = ET.Element("Bagging-Date")
        today = datetime.today()
        dateStored.text = today.strftime("%Y-%m-%d %H:%M:%S")
        component.append(dateStored)

        root.append(component)

    dir = os.path.dirname(filename)
    os.makedirs(dir, exist_ok=True)

    output = ET.ElementTree(root)
    output.write(filename, "UTF-8", xml_declaration=True)

    with open(filename, "r") as f:
        xml_string = f.read()

    dom = minidom.parseString(xml_string)
    pretty_dom = dom.toprettyxml(indent="\t")

    with open(filename, "w") as f:
        f.write(pretty_dom)


def set_filepath(tms_metadata, dest_dir):
    # set file name: X85048_002_EF_PIR
    fn = (tms_metadata[0]["componentNumber"]).replace(".", "_")
    filename = fn + "_" + tms_metadata[0]["componentName"] + "_PIR.xml"

    # set file path
    parent_dir = os.path.dirname(os.path.dirname(dest_dir))
    filepath = os.path.join(parent_dir + "/PIR XML Output/", filename)

    return filepath


# def get_disk_util(indent=4):
#     output = subprocess.check_output(["df", "-hT", ARTWORK_SRC_DIR]).decode("utf-8")
#     lines = output.split("\n")

#     indent = "    "
#     indented_lines = [indent + line for line in lines]

#     indented_output = "\n".join(indented_lines)

#     return indented_output


def get_tree_output():
    # change directory to ARTWORK_SRC_DIR to generate tree output
    if os.path.isdir(ARTWORK_SRC_DIR):
        os.chdir(ARTWORK_SRC_DIR)
    else:
        os.chdir(os.path.dirname(ARTWORK_SRC_DIR))

    output = (subprocess.check_output(["tree", "-a"])).decode("utf-8")
    lines = output.split("\n")

    indent = "    "
    indented_lines = [indent + line for line in lines]

    indented_output = "\n".join(indented_lines)

    # change directory back to home to generate PIR XML in the right directory
    os.chdir(HOME_DIR)

    return indented_output


def generate_file_checksum(filepath):
    with open(filepath, "rb") as f:
        checksum = hashlib.md5()
        for chunk in iter(lambda: f.read(4096), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def generate_dir_checksum(directory):
    checksum = hashlib.md5()
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            checksum.update(generate_file_checksum(filepath).encode("utf-8"))
    return checksum.hexdigest()


def get_directory_size(dir):
    total_size = 0

    for dirpath, dirnames, filenames in os.walk(dir):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size


def convert_bytes(size):
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    size = round(size, 2)
    return f"{size} {units[unit_index]}"


"""

MAIN FUNCTION

"""


def main():
    global ARTWORK_SRC_DIR, TMS_XML_DIR, HOME_DIR

    HOME_DIR = os.getcwd()

    # determines if args are being passed and stored
    if len(sys.argv) == 3:
        ARTWORK_SRC_DIR = sys.argv[1]
        TMS_XML_DIR = sys.argv[2]

        if not TMS_XML_DIR.endswith("/"):
            TMS_XML_DIR += "/"

        # prompt and save cli responses
        input_metadata = prompt_metadata()
    else:
        # prompt and save cli responses
        input_metadata = prompt_metadata()

        ARTWORK_SRC_DIR = input_metadata[0]["artworkSrc"]
        TMS_XML_DIR = input_metadata[0]["tmsXml"]

    # extract information from current directory for filename
    # ex. HVDAProcessing/Pre-ingest/X99950_002_SC/
    #     tms_filepath: X99950_002_SC.xml
    #     dest_dir: X99950_002_SC
    xdir = TMS_XML_DIR.split("/")
    tms_filepath = TMS_XML_DIR + xdir[len(xdir) - 2] + ".xml"
    dest_dir = TMS_XML_DIR + xdir[len(xdir) - 2]

    # read and extract artwork metadata
    tms_metadata = read_xml(tms_filepath)

    # determine component type
    comp_type = tms_metadata[0]["componentName"]

    # start bagging
    print("-------------")

    # used to avoid generating PIR xml if source and destination directory
    # checksums do not match
    cs_error = False

    if comp_type != "ASP":
        print("Bagging artwork from " + ARTWORK_SRC_DIR)

        # generate checksum for source directory at ARTWORK_SRC_DIR
        cs_src = generate_dir_checksum(ARTWORK_SRC_DIR)

        # creates dest directory and copies contents from src to dest directory
        # used for bagging (bagit bags directory directly)
        if os.path.isdir(ARTWORK_SRC_DIR):
            artworkdir = ARTWORK_SRC_DIR.split("/")
            if artworkdir[len(artworkdir) - 1] == "":
                bag_copy_dir = os.path.join(dest_dir, artworkdir[len(artworkdir) - 2])
            else:
                bag_copy_dir = os.path.join(dest_dir, artworkdir[len(artworkdir) - 1])

            shutil.copytree(ARTWORK_SRC_DIR, bag_copy_dir)

            # generate checksum for destination directory
            cs_dest = generate_dir_checksum(dest_dir)
        elif os.path.isfile(ARTWORK_SRC_DIR):
            os.makedirs(dest_dir)
            shutil.copy(ARTWORK_SRC_DIR, dest_dir)

            # generate checksum for destination file
            cs_dest = generate_dir_checksum(dest_dir + ARTWORK_SRC_DIR)

        # compare checksums and bag if matches
        if cs_src == cs_dest:
            try:
                # bag items in dest directory
                bag = bagit.make_bag(dest_dir, checksums=["md5"])

                # get bag size
                bag_size_bytes = get_directory_size(dest_dir)

                # convert bag size to most appropriate unit
                bag_size = convert_bytes(bag_size_bytes)

                bag.info["Bag-Size"] = str(bag_size)

                # add required metadata to bag
                bag.info["Pre-Ingest-User-Id"] = str(input_metadata[0]["userId"])
                bag.info["Description"] = str(input_metadata[0]["mediaDescription"])
                bag.info["Supplied-By"] = str(input_metadata[0]["suppliedBy"])
                bag.info["Component-Audio-Channels-As-Exhibited"] = str(
                    input_metadata[0]["audioChannels"]
                )
                bag.info["Colour-Or-Black-And-White-As-Exhibited"] = str(
                    input_metadata[0]["colour"]
                )
                bag.info["Where-Made"] = str(input_metadata[0]["whereMade"])
                bag.info["Media-Label"] = str(input_metadata[0]["mediaLabel"])
                bag.info["ComponentID"] = str(COMPONENTID)

                bag.save()
            except Exception as e:
                print("error: ", str(e))

            # validates newly created bag at dest directory
            if bag.validate():
                print("Bag validated at " + dest_dir)
            else:
                print("Error validating bag at " + dest_dir)
                sys.exit()

        else:
            print("Error - source and destination directory checksums do not match")
            cs_error = True

    # generate xml for ASP and if there's no checksum error
    if not cs_error:
        # set filepath
        filepath = set_filepath(tms_metadata, dest_dir)

        # enter metadata to new xml
        create_xml_output(tms_metadata, input_metadata, comp_type, filepath, dest_dir)

        print("Output XML file: " + filepath)


if __name__ == "__main__":
    main()
