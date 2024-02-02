from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import logging
import os
import shutil
import subprocess

import jinja2
import pefile
import requests

from retrieve_pdb import download_pdb
from retrieve_pdb import get_pe_debug_infos

BASE_URL = "https://api.ntdelta.dev/api/"
WINBINDEX_BASE = "https://raw.githubusercontent.com/m417z/winbindex/gh-pages/data/by_filename_compressed/{}.json.gz"
WINBINDEX_INSIDER_BASE = (
    "https://m417z.com/winbindex-data-insider/by_filename_compressed/{}.json.gz"
)
WORKING_DIR_PATH = "C:\\Development\\ntdelta-worker\\working_dir\\"
SYMPATH = "C:\\Symbols\\"
GHIDRA_HEADLESS = "C:\\Development\\ghidra_11.0.1_PUBLIC\\support\\analyzeHeadless.bat"
ADDITIONAL_DLLS = []
INSIDER_DLLS = ["iumdll.dll"]
EXPORT_ONLY_DLLS = []

parser = argparse.ArgumentParser()
parser.add_argument("--username", required=True, help="Backend username")
parser.add_argument("--password", required=True, help="Backend password")

# Parse the command line arguments
args = parser.parse_args()

# Set the variables
BACKEND_USERNAME = args.username
BACKEND_PASSWORD = args.password


def get_dll_exports(input_dll_path):
    def decode_if_not_none(x):
        return "???" if x is None else x.decode()

    try:
        pe = pefile.PE(input_dll_path)
        data_directories = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        pe.parse_data_directories(directories=data_directories)
        exports = [
            decode_if_not_none(e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
        ]
        return exports
    except Exception as e:
        print(f"Error: {e}")

    return []


def get_all_files(directory, file_set=None):
    file_set = {}

    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)

        if os.path.isfile(path):
            if filename[72:][:-4] == "" or not filename[:6] == "ghidra":
                print("invalid function")
            elif filename[:70] not in file_set.keys():
                file_set[filename[:70]] = [filename[72:][:-4]]

            else:
                blob_funcs = file_set[filename[:70]]
                blob_funcs.append(filename[72:][:-4])
                file_set[filename[:70]] = blob_funcs

        elif os.path.isdir(path):
            file_set.update(get_all_files(path, file_set))

    return file_set


def make_symbol_server_url(pe_name, time_stamp, image_size):
    # "%s/%s/%08X%x/%s" % (server_name, pe_name, time_stamp, image_size, pe_name)
    # https://randomascii.wordpress.com/2013/03/09/symbols-the-microsoft-way/

    formatted_timestamp = ("%08X" % time_stamp)[:8]
    file_id = (f"{formatted_timestamp}{image_size:X}").lower()
    return f"https://msdl.microsoft.com/download/symbols/{pe_name}/{file_id}/{pe_name}"


def open_json_file(file_path):
    with open(file_path) as file:
        data = json.load(file)
        return data


# clean up downloaded files we no longer need
def remove_file_if_exists(file_path):
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            print(f"File '{file_path}' removed successfully.")
        except:
            print("File may be in use.")
    else:
        print(f"File '{file_path}' does not exist.")


def copy_file(template_file, out_file, blob):
    """Copy a file using a Jinja template."""
    template = jinja2.Template(open(template_file).read())
    with open(out_file, "w") as f:
        f.write(template.render(blob=blob))


def get_winbindex_json(tracked_dll_name, insider=False):
    tracked_dll_winbindex_compressed_url = WINBINDEX_BASE.format(tracked_dll_name)

    if insider:
        tracked_dll_winbindex_compressed_url = WINBINDEX_INSIDER_BASE.format(
            tracked_dll_name,
        )

    tracked_dll_winbindex_compressed_path = (
        WORKING_DIR_PATH + f"{tracked_dll_name}.json.gz"
    )
    tracked_dll_winbindex_path = WORKING_DIR_PATH + f"{tracked_dll_name}.txt"

    # Get compressed winbindex info
    tracked_dll_winbindex_compressed_response = requests.get(
        tracked_dll_winbindex_compressed_url,
        stream=True,
    )

    if tracked_dll_winbindex_compressed_response.status_code == 200:
        # Save the downloaded .gz file
        with open(tracked_dll_winbindex_compressed_path, "wb") as file:
            file.write(tracked_dll_winbindex_compressed_response.content)

        with gzip.open(tracked_dll_winbindex_compressed_path, "rb") as gz_file:
            with open(tracked_dll_winbindex_path, "wb") as output_file:
                shutil.copyfileobj(gz_file, output_file)

        return open_json_file(tracked_dll_winbindex_path)

    return None


def zip_files(directory_path, output_path, unique_id):
    # Ensure the directory path exists
    if not os.path.exists(directory_path):
        print(f"Directory '{directory_path}' does not exist.")
        return

    # Ensure the output directory exists
    full_path = os.path.abspath(output_path) + os.sep

    if not os.path.exists(full_path):
        os.makedirs(full_path)

    # Use shutil.make_archive to create a zip archive
    shutil.make_archive(full_path + os.sep + unique_id, "zip", directory_path)

    print(f"Files in '{directory_path}' have been zipped to '{output_path}'.")


logging.basicConfig(level=logging.INFO)

logging.info("Starting Update Worker")
logging.info("Getting tracking DLLs from server")
tracked_dlls_response = requests.get(BASE_URL + "dlls")

if tracked_dlls_response.status_code == 200:
    tracked_dlls = tracked_dlls_response.json()
    for tracked_dll_name in list(set(list(tracked_dlls.keys()) + ADDITIONAL_DLLS)):
        logging.info("Checking missing versions for " + tracked_dll_name)
        tracked_dll_winbindex_json_data = get_winbindex_json(tracked_dll_name)

        if tracked_dll_name in INSIDER_DLLS:
            tracked_dll_winbindex_insider_json_data = get_winbindex_json(
                tracked_dll_name,
                True,
            )
            if tracked_dll_winbindex_insider_json_data:
                tracked_dll_winbindex_json_data = (
                    tracked_dll_winbindex_json_data
                    | tracked_dll_winbindex_insider_json_data
                )

        if tracked_dll_winbindex_json_data:
            new_dll_flag = tracked_dll_name not in tracked_dlls.keys()

            # Get a list of function hashes that the server knows about for this DLL
            tracked_dll_versions_response = requests.get(
                BASE_URL + "dlls/" + tracked_dll_name,
            )
            if new_dll_flag or tracked_dll_versions_response.status_code == 200:
                tracked_dll_versions = set()
                if not new_dll_flag:
                    tracked_dll_versions = {
                        i["sha256"]
                        for i in tracked_dll_versions_response.json()["instances"]
                    }
                tracked_dll_winbindex_versions = set(
                    tracked_dll_winbindex_json_data.keys(),
                )
                missing_versions = tracked_dll_winbindex_versions - tracked_dll_versions
                for missing_version_hash in missing_versions:
                    missing_version = tracked_dll_winbindex_json_data[
                        missing_version_hash
                    ]

                    # Check DLL architecture. We only care about x64
                    if "wow64" in str(missing_version):
                        continue

                    if (
                        "fileInfo" in missing_version.keys()
                        and "version" in missing_version["fileInfo"].keys()
                    ):
                        # We don't care about forwarder shims... (OneCore)
                        if (
                            "forwarder shim"
                            in missing_version["fileInfo"]["description"]
                        ):
                            continue

                        logging.info("Missing DLL found")

                        tracked_dll_version_file_path = (
                            WORKING_DIR_PATH
                            + tracked_dll_name
                            + os.sep
                            + missing_version_hash
                            + ".blob"
                        )

                        tracked_dll_version_ts = missing_version["fileInfo"][
                            "timestamp"
                        ]
                        tracked_dll_version_size = missing_version["fileInfo"][
                            "virtualSize"
                        ]

                        tracked_dll_version_download_pe_url = make_symbol_server_url(
                            tracked_dll_name,
                            tracked_dll_version_ts,
                            tracked_dll_version_size,
                        )

                        logging.info(
                            "Downloading from: " + tracked_dll_version_download_pe_url,
                        )

                        tracked_dll_version_pe_download = requests.get(
                            tracked_dll_version_download_pe_url,
                            stream=True,
                        )
                        if tracked_dll_version_pe_download.status_code == 200:
                            if not os.path.exists(WORKING_DIR_PATH + tracked_dll_name):
                                os.makedirs(WORKING_DIR_PATH + tracked_dll_name)
                            with open(tracked_dll_version_file_path, "wb") as file:
                                file.write(tracked_dll_version_pe_download.content)

                            logging.info("Downloaded")

                            pdb_name, guid = get_pe_debug_infos(
                                tracked_dll_version_file_path,
                            )
                            if not os.path.exists(
                                SYMPATH + pdb_name + os.sep + guid + os.sep + pdb_name,
                            ):
                                download_pdb(
                                    WORKING_DIR_PATH + tracked_dll_name,
                                    pdb_name,
                                    guid,
                                )
                                tracked_dll_version_local_pdb_path = (
                                    WORKING_DIR_PATH + tracked_dll_name + os.sep + guid
                                )
                                tracked_dll_version_sympath_pdb_dir = f"{
                                    SYMPATH
                                }{pdb_name}{os.sep}{guid}"
                                if not os.path.exists(
                                    tracked_dll_version_sympath_pdb_dir,
                                ):
                                    os.makedirs(tracked_dll_version_sympath_pdb_dir)
                                shutil.copy(
                                    tracked_dll_version_local_pdb_path,
                                    f"{SYMPATH}{pdb_name}{os.sep}{
                                        guid
                                    }{os.sep}{pdb_name}",
                                )
                                remove_file_if_exists(
                                    tracked_dll_version_local_pdb_path,
                                )

                            logging.info("Symbols all set up. Time to decompile.")

                            # Ghidra time
                            tracked_dll_proj_name = "ghidra" + missing_version_hash
                            tracked_dll_proj_folder = (
                                WORKING_DIR_PATH + tracked_dll_proj_name
                            )
                            tracked_dll_proj_output_json = (
                                WORKING_DIR_PATH
                                + tracked_dll_proj_name
                                + os.sep
                                + "decompile.json"
                            )
                            tracked_dll_proj_decomp_output_path_format = (
                                WORKING_DIR_PATH
                                + tracked_dll_proj_name
                                + os.sep
                                + tracked_dll_proj_name
                                + "_"
                            )
                            tracked_dll_proj_decomp_output_path_format = (
                                tracked_dll_proj_decomp_output_path_format.replace(
                                    os.sep,
                                    os.sep + os.sep,
                                )
                            )

                            # Make sure the project folder is clear
                            if os.path.exists(tracked_dll_proj_folder):
                                shutil.rmtree(tracked_dll_proj_folder)
                                print(
                                    f"Folder '{
                                        tracked_dll_proj_folder}' deleted successfully.",
                                )

                            # # Create folder
                            if not os.path.exists(tracked_dll_proj_folder):
                                os.makedirs(tracked_dll_proj_folder)

                            copy_file(
                                "DumpFunctions.java.j2",
                                "DumpFunctions.java",
                                tracked_dll_proj_decomp_output_path_format,
                            )

                            copy_file(
                                "LoadSymbols.java.j2",
                                "LoadSymbols.java",
                                f"{SYMPATH}{pdb_name}{os.sep}{guid}{os.sep}{
                                    pdb_name
                                }".replace("\\", "\\\\"),
                            )

                            ghidra_cmd_binary_path = os.path.abspath(
                                tracked_dll_version_file_path,
                            )
                            ghidra_cmd_script_dir = os.path.abspath(os.getcwd())

                            command = "{} {} {} -import {} -scriptPath {} -preScript LoadSymbols.java -postScript DumpFunctions.java {}".format(
                                GHIDRA_HEADLESS,
                                tracked_dll_proj_folder,
                                tracked_dll_proj_name,
                                ghidra_cmd_binary_path,
                                ghidra_cmd_script_dir,
                                tracked_dll_proj_output_json,
                            )

                            # Run Ghidra Headless Script
                            p = subprocess.run(
                                command.split(" "),
                                stdout=subprocess.PIPE,
                            )

                            print(p.stdout)
                            files = get_all_files(tracked_dll_proj_folder)
                            if (len(files.keys())) > 0:
                                print(files)

                                # let's build the POST request
                                missing_version_versions_dict = {}
                                missing_version_windows_versions = missing_version[
                                    "windowsVersions"
                                ]

                                post_dict = {
                                    "name": tracked_dll_name,
                                    "description": missing_version["fileInfo"][
                                        "description"
                                    ],
                                    "virtual_size": missing_version["fileInfo"][
                                        "virtualSize"
                                    ],
                                    "size": missing_version["fileInfo"]["size"],
                                    "sha256": missing_version["fileInfo"]["sha256"],
                                    "version": missing_version["fileInfo"]["version"],
                                    "signing_date": "1970-01-01 00:00:00"
                                    if (
                                        missing_version["fileInfo"][
                                            "signingStatus"
                                        ].lower()
                                        in ["unsigned", "unknown"]
                                        or "not trusted"
                                        in missing_version["fileInfo"][
                                            "signingStatus"
                                        ].lower()
                                    )
                                    else missing_version["fileInfo"]["signingDate"][0],
                                    "functions": {},
                                    "update_info": missing_version_windows_versions,
                                }

                                # get our exports now so we dont have to do it in the loop...
                                tracked_dll_function_exports = get_dll_exports(
                                    tracked_dll_version_file_path,
                                )

                                for function_name in files[
                                    "ghidra" + missing_version_hash
                                ]:
                                    # some dlls are too big to sensibly decompile in full
                                    if tracked_dll_name in EXPORT_ONLY_DLLS:
                                        if (
                                            function_name
                                            not in tracked_dll_function_exports
                                        ):
                                            continue

                                    function_decomp_path = (
                                        tracked_dll_proj_folder
                                        + os.sep
                                        + tracked_dll_proj_name
                                        + "__"
                                        + function_name
                                        + ".txt"
                                    )
                                    with open(
                                        function_decomp_path,
                                        encoding="utf-8",
                                    ) as file:
                                        # Read the contents of the file
                                        function_c = file.read()
                                        function_c_hash = hashlib.md5(
                                            function_c.encode("utf-8"),
                                        ).hexdigest()
                                        post_dict["functions"][function_name] = {
                                            "function_c": function_c,
                                            "function_c_hash": function_c_hash,
                                        }

                                # Send the POST request
                                # Encode the username and password in base64
                                credentials = f"{BACKEND_USERNAME}:{
                                    BACKEND_PASSWORD
                                }"
                                base64_credentials = base64.b64encode(
                                    credentials.encode(),
                                ).decode()

                                # Add the Basic Auth header to the request
                                headers = {
                                    "Authorization": f"Basic {base64_credentials}",
                                }
                                response = requests.post(
                                    BASE_URL + "dlls",
                                    data=json.dumps(post_dict),
                                    headers=headers,
                                )

                                # Check the response status code
                                if response.status_code == 200:
                                    # Request was successful
                                    print("POST request successful")
                                else:
                                    # Request encountered an error
                                    print(
                                        f"POST request failed with status code: {
                                            response.status_code
                                        }",
                                    )

                                # Optionally, archive our decomp results
                                zip_files(
                                    WORKING_DIR_PATH + tracked_dll_proj_name,
                                    "archive",
                                    missing_version["fileInfo"]["sha256"],
                                )

                            # Clean up Ghidra proj mess
                            if os.path.exists(tracked_dll_proj_folder):
                                shutil.rmtree(tracked_dll_proj_folder)
                                print(
                                    f"Folder '{
                                        tracked_dll_proj_folder}' deleted successfully.",
                                )

                        else:
                            logging.info("Could not download PE from Microsoft")
                        remove_file_if_exists(tracked_dll_version_file_path)

            else:
                logging.info("Could not retrieve known versions from our server")

        else:
            logging.error("Could not get tracked DLLs from server")

        remove_file_if_exists(WORKING_DIR_PATH + f"{tracked_dll_name}.txt")
        remove_file_if_exists(WORKING_DIR_PATH + f"{tracked_dll_name}.json.gz")

else:
    logging.error("Could not get tracked DLLs from server")
