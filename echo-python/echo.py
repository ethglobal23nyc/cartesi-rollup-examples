# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from os import environ
import logging
import os
import requests
import ipfshttpclient
from web3 import Web3

# Initialize a Web3 instance with your Ethereum node URL
# Replace 'http://your_ethereum_node_url:port' with your actual node URL
w3 = Web3(Web3.HTTPProvider("http://your_ethereum_node_url:port"))

# The address of the smart contract.
contract_address = "0x..."  # Replace with your contract's address
# The private key of the smart contract-controlled wallet.
private_key = "..."  # Replace with your private key
# Ensure the private key is in bytes format
private_key = bytes.fromhex(private_key)

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")


def download_from_ipfs(cid: str, output_dir: str):
    """
    Downloads a file or directory from IPFS by its CID and saves it to the specified output directory.

    :param cid: The CID (Content Identifier) of the file or directory to download.
    :param output_dir: The local directory path where the downloaded file/directory will be saved.
    """
    try:
        # Connect to the local IPFS daemon
        client = ipfshttpclient.connect("/ip4/127.0.0.1/tcp/5001")

        # Download the file or directory by CID to the specified output directory
        client.get(cid, output_dir)

        print(f"Downloaded {cid} to {output_dir}")

    except Exception as e:
        print(f"An error occurred during download: {str(e)}")


def upload_to_ipfs(file_path: str):
    """
    Uploads a file to IPFS and returns the CID (Content Identifier) of the uploaded file.

    :param file_path: The local file path of the file to upload.
    :return: The CID of the uploaded file.
    """
    try:
        # Connect to the local IPFS daemon
        client = ipfshttpclient.connect("/ip4/127.0.0.1/tcp/5001")

        # Upload the file and get the CID
        res = client.add(file_path)

        # Extract the CID from the response
        cid = res["Hash"]

        print(f"Uploaded {file_path} to IPFS with CID: {cid}")
        return cid

    except Exception as e:
        print(f"An error occurred during upload: {str(e)}")
        return None


def model_training(model_file: str, data_dir: str):
    """
    Appends filenames from a directory to a model file and simulates training of the model.

    :param model_file: The path to the model file.
    :param data_dir: The path to the directory containing data files.
    """
    try:
        # Check if the model file exists; if not, create an empty one
        if not os.path.isfile(model_file):
            with open(model_file, "w") as _:
                pass

        # List all files in the data directory
        data_files = os.listdir(data_dir)

        # Append the filenames to the model file
        with open(model_file, "a") as model_f:
            for filename in data_files:
                model_f.write(filename + "\n")

        # Simulate training of the model
        print("Model training simulated successfully.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def broadcast_training_result(training_result: str):
    """
    Broadcasts the result of the model training to the Ethereum blockchain.

    :param training_result: The training result or data you want to store on the blockchain.
    :return: Transaction receipt or None if the transaction fails.
    """
    try:
        # Load the contract ABI and address
        # Replace with your contract's ABI and address
        contract_abi = [...]
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)

        # Prepare the transaction data to call the contract's storeTrainingResult function
        function_signature = contract.functions.storeTrainingResult(
            training_result
        ).buildTransaction(
            {
                "chainId": 1,  # Replace with the correct chain ID (e.g., 1 for Ethereum mainnet)
                "gas": 2000000,  # Adjust gas as needed
                "gasPrice": w3.toWei("10", "gwei"),  # Adjust gas price as needed
                "nonce": w3.eth.getTransactionCount(
                    w3.toChecksumAddress(sender_address)
                ),
            }
        )

        # Sign the transaction
        signed_transaction = w3.eth.account.signTransaction(
            function_signature, private_key=private_key
        )

        # Send the transaction
        tx_hash = w3.eth.sendRawTransaction(signed_transaction.rawTransaction)

        # Wait for the transaction to be mined
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        return tx_receipt

    except Exception as e:
        print(f"An error occurred while broadcasting the training result: {str(e)}")
        return None


def handle_training_work(model_file_cid: str, data_dir_cid: str):
    """
    Downloads a model file and a data directory from IPFS, simulates training,
    appends filenames to the model file, and uploads the modified model file back to IPFS.

    :param model_file_cid: The CID of the model file on IPFS.
    :param data_dir_cid: The CID of the data directory on IPFS.
    """
    try:
        # Define local directories for downloading and storing files
        download_dir = "downloads/"
        model_file_path = f"{download_dir}model_file.txt"
        data_dir_path = f"{download_dir}data_directory/"

        # Download the model file and data directory from IPFS
        download_from_ipfs(model_file_cid, download_dir)
        download_from_ipfs(data_dir_cid, download_dir)

        # Simulate training (you can replace this with your actual training code)
        print("Model training simulated successfully.")

        # Append filenames from the data directory to the model file
        with open(model_file_path, "a") as model_file:
            for root, _, files in os.walk(data_dir_path):
                for filename in files:
                    model_file.write(f"{filename}\n")

        # Upload the modified model file back to IPFS
        new_model_cid = upload_to_ipfs(model_file_path)

        print(f"Updated model file uploaded to IPFS with CID: {new_model_cid}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def verify_model_contains_filenames(model_file_path: str, data_dir_path: str) -> bool:
    """
    Verifies that the model file contains filenames from the data directory.

    :param model_file_path: The local path to the model file.
    :param data_dir_path: The local path to the data directory.
    :return: True if all filenames are found in the model file, False otherwise.
    """
    try:
        # Read filenames from the model file
        with open(model_file_path, "r") as model_file:
            model_filenames = {line.strip() for line in model_file}

        # Get a list of filenames from the data directory
        data_filenames = {filename for filename in os.listdir(data_dir_path)}

        # Check if all data filenames are present in the model file
        return data_filenames.issubset(model_filenames)

    except Exception as e:
        print(f"An error occurred during verification: {str(e)}")
        return False


def disperse_reward(receiver_address, reward_amount_wei):
    """
    Disperses a reward from a smart contract-controlled wallet to the receiver's address.

    :param receiver_address: The Ethereum address of the receiver.
    :param reward_amount_wei: The reward amount in wei (smallest unit of ether).
    :return: Transaction receipt or None if the transaction fails.
    """
    try:
        # Load the contract ABI and address
        # Replace with your contract's ABI and address
        contract_abi = [...]
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)

        # Prepare the transaction data to call the contract's disperseReward function
        function_signature = contract.functions.disperseReward(
            receiver_address, reward_amount_wei
        ).buildTransaction(
            {
                "chainId": 1,  # Replace with the correct chain ID (e.g., 1 for Ethereum mainnet)
                "gas": 2000000,  # Adjust gas as needed
                "gasPrice": w3.toWei("10", "gwei"),  # Adjust gas price as needed
                "nonce": w3.eth.getTransactionCount(
                    w3.toChecksumAddress(sender_address)
                ),
            }
        )

        # Sign the transaction
        signed_transaction = w3.eth.account.signTransaction(
            function_signature, private_key=private_key
        )

        # Send the transaction
        tx_hash = w3.eth.sendRawTransaction(signed_transaction.rawTransaction)

        # Wait for the transaction to be mined
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        return tx_receipt

    except Exception as e:
        print(f"An error occurred while dispersing the reward: {str(e)}")
        return None


def handle_verification_work(
    model_file_cid: str,
    data_dir_cid: str,
    receiver_address: str,
    reward_amount_wei: int,
):
    """
    Verifies if the model file contains the filenames from the data directory using
    their respective CIDs.

    :param model_file_cid: The CID of the model file on IPFS.
    :param data_dir_cid: The CID of the data directory on IPFS.
    """
    try:
        # Define local directories for downloading files
        download_dir = "downloads/"
        model_file_path = f"{download_dir}model_file.txt"
        data_dir_path = f"{download_dir}data_directory/"

        # Download the model file and data directory from IPFS
        download_from_ipfs(model_file_cid, download_dir)
        download_from_ipfs(data_dir_cid, download_dir)

        # Verify if the model file contains filenames from the data directory
        verification_result = verify_model_contains_filenames(
            model_file_path, data_dir_path
        )

        if verification_result:
            print("Verification successful: dispersing reward.")
            disperse_reward(
                receiver_address=receiver_address,
                reward_amount_wei=reward_amount_wei,
            )
        else:
            print(
                "Verification failed: Model does not contain all filenames from the data directory."
            )

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def handle_advance(data):
    logger.info(f"Received advance request data {data}")
    logger.info("Adding notice")
    notice = {"payload": data["payload"]}
    # Check if the request is for training or verification
    if data["payload"]["request_type"] == "training":
        # Handle training
        handle_training_work(
            data["payload"]["model_file_cid"], data["payload"]["data_dir_cid"]
        )
    elif data["payload"]["request_type"] == "verification":
        # Handle verification
        handle_verification_work(
            data["payload"]["model_file_cid"],
            data["payload"]["data_dir_cid"],
            data["payload"]["receiver_address"],
            data["payload"]["reward_amount_wei"],
        )
    else:
        print("Invalid request type.")

    response = requests.post(rollup_server + "/notice", json=notice)
    logger.info(
        f"Received notice status {response.status_code} body {response.content}"
    )
    return "accept"


def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    logger.info("Adding report")
    report = {"payload": data["payload"]}
    response = requests.post(rollup_server + "/report", json=report)
    logger.info(f"Received report status {response.status_code}")
    return "accept"


handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]

        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
