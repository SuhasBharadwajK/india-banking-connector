import base64
import json
import random
import re
import string
import hashlib
import binascii

import frappe
from cryptography.fernet import Fernet

from india_banking_connector.default import DEFAULT_CONNECTOR

HASH_KEY = "india_banking_connector"


@frappe.whitelist()
def get_default_connectors():
	return DEFAULT_CONNECTOR


def get_id(length: int = 10, text: str = "") -> str:
	"""
	Generate a random string ID of a specified length, optionally prefixed with a given text.
	If the `length` parameter is a string, it will be used as the prefix text, and the length of the generated ID will be equal to the length of this string.
	Args:
		length (int): The desired length of the generated ID. Defaults to 10.
		text (str): An optional prefix text to include in the generated ID. Defaults to an empty string.
	Returns:
		str: A randomly generated string ID of the specified length, optionally prefixed with the given text.
	"""

	if isinstance(length, str):
		text = length
		length = len(length)
		return text + "".join(
			random.choices(string.ascii_lowercase + string.digits, k=length)
		)
	elif isinstance(length, int):
		text = "".join(re.findall(r"[0-9a-zA-Z]", text))
		text_length = len(text)
		if text_length >= length:
			return text[:length]
		else:
			length = length - text_length
			return text + "".join(
				random.choices(string.ascii_lowercase + string.digits, k=length)
			)


def generate_random_key(key_length: int):
	try:
		char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
		random_key = ''.join(random.choice(char_set) for _ in range(key_length))
		return random_key

	except Exception as e:
		raise Exception(f'An exception occurred while generating random key: {e}')


def add_pkcs5_padding(message, block_size):
	"""Pads a message according to PKCS#5 padding scheme.

	Args:
			message: The message to be padded (bytes).
			block_size: The size of the block (int).

	Returns:
			The padded message (bytes).
	"""
	padding_length = block_size - (len(message) % block_size)
	padding = bytes([padding_length] * padding_length)
	return message + padding


def remove_pkcs5_padding(padded_message):
	"""Removes PKCS#5 padding from a message.

	Args:
			padded_message: The padded message (bytes).

	Returns:
			The original message (bytes).
			Raises ValueError if padding is invalid.
	"""
	if not padded_message:
			raise ValueError("Empty padded message")

	padding_length = padded_message[-1]  # Get padding length from the last byte

	if padding_length > len(padded_message) or padding_length == 0:
			raise ValueError("Invalid padding length")

	padding = padded_message[-padding_length:]

	if padding != bytes([padding_length] * padding_length): #Check if the padding bytes are correct.
			raise ValueError("Invalid padding bytes")

	return padded_message[:-padding_length]


def load_file_as_stream(file_name: str):
	try:
		# assuming filename is sent with file path
		with open(file_name, 'rb') as file_bytes:
			return file_bytes.read()
	except FileNotFoundError:
		logger.error("An error occurred while loading the config")
		raise FileNotFoundError(f"File not found: {file_name}")


def encrypt(data, key=None):
	if not key:
		key = HASH_KEY

	key = key.ljust(32)[:32].encode("utf-8")

	key = base64.urlsafe_b64encode(key)

	cipher = Fernet(key)

	json_data = json.dumps(data).encode("utf-8")
	encrypted_data = cipher.encrypt(json_data)
	return encrypted_data


def decrypt(data, key=None):
	if not key:
		key = HASH_KEY

	key = key.ljust(32)[:32].encode("utf-8")

	key = base64.urlsafe_b64encode(key)

	cipher = Fernet(key)

	decrypted_data = cipher.decrypt(data)
	return json.loads(decrypted_data.decode("utf-8"))


def generate_sha512_hash(input: str) -> str:
	try:
		digest = hashlib.sha512()  # Replace with the desired hash algorithm (e.g., sha1, md5)
		digest.update(input.encode('utf-8'))
		hashed_bytes = digest.digest()
		return bytes_to_hexlify(hashed_bytes)  # Convert bytes to hexadecimal string
	except Exception as e:
		raise Exception(f"Error hashing string: {e}")


def bytes_to_hexlify(hash_bytes):
	"""Converts bytes to a hexadecimal string (similar to Java's bytesToHex)."""
	# Method 1 (using binascii.hexlify - recommended):
	hex_string = binascii.hexlify(hash_bytes).decode('utf-8') # Decode from bytes to string
	return hex_string

