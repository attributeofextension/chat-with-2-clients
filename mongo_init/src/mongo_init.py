import os
import sys
import time
from pymongo import MongoClient
from pymongo.errors import CollectionInvalid, OperationFailure
import json

from server.src.chat_server import users_collection

MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27017"))
MONGO_ROOT_USERNAME = os.getenv("MONGO_USERNAME")
MONGO_ROOT_PASSWORD = os.getenv("MONGO_PASSWORD")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "chat_app_db")

MONGO_APP_USERNAME = os.getenv("MONGO_APP_USERNAME")
MONGO_APP_PASSWORD = os.getenv("MONGO_APP_PASSWORD")

SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), 'schemas')
SESSIONS_SCHEMA_FILE = os.path.join(SCHEMAS_DIR, 'sessions.json')
USERS_SCHEMA_FILE = os.path.join(SCHEMAS_DIR, 'users_schema.json')
MESSAGES_SCHEMA_FILE = os.path.join(SCHEMAS_DIR, 'messages_schema.json')

def load_json_schema(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Schema file not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in schema file {file_path}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error loading schema from {file_path}: {e}")
        sys.exit(1)

def apply_schema_validation(db, collection_name, validator):
    try:
        if collection_name not in db.collection_names():
            db.create_collection(collection_name, validator=validator)
            print(f"Created '{collection_name}' collection with schema validation.")
        else:
            db.command({
                'collMod': collection_name,
                'validator': validator,
                'validationLevel': 'strict',
                'validationAction': 'error'
            })
            print(f"Updated '{collection_name}' collection with schema validation.")
        return True
    except OperationFailure as e:
        print(f"WARNING: Could not apply schema validation to '{collection_name}': {e}")
        return False
    except Exception as e:
        print(f"ERROR: Failed to apply schema validation for '{collection_name}': {e}")
        return False

def create_app_user(db):
    if not MONGO_APP_USERNAME or not MONGO_APP_PASSWORD:
        print("WARNING: MONGO_APP_USERNAME or MONGO_APP_PASSWORD not set. Skipping app user creation.")
        return False
    try:
        users_in_db = db.command('usersInfo')
        user_exists = any(u['user'] == MONGO_APP_USERNAME for u in users_in_db['users'])

        if user_exists:
            print(f"User '{MONGO_APP_USERNAME}' already exists. Skipping creation.")
            return True
        else:
            db.command({
                "createUser": MONGO_APP_USERNAME,
                "pwd": MONGO_APP_PASSWORD,
                "roles": [
                    { "role": "readWrite", "db": MONGO_DB_NAME }
                ]
            })
            print(f"Successfully created restricted user '{MONGO_APP_USERNAME}' for database '{MONGO_DB_NAME}'.")
            return True
    except OperationFailure as e:
        print(f"ERROR: Failed to create app user '{MONGO_APP_USERNAME}': {e}")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error during app user creation: {e}")
        return False

def initialize_mongodb_schema():
    print("Attempting to connect to MongoDB for schema initialization...")
    client = None
    try:
        if MONGO_ROOT_USERNAME and MONGO_ROOT_PASSWORD:
            client = MongoClient(MONGO_HOST, MONGO_PORT, username=MONGO_ROOT_USERNAME, password=MONGO_ROOT_PASSWORD, authSource='admin', serverSelectionTimeoutMS=5000)
        else:
            client = MongoClient(MONGO_HOST, MONGO_PORT, serverSelectionTimeoutMS=5000)

        client.admin.command('ping')
        print("Sucessfully connected to MongoDB for schema initialization.")

        db = client[MONGO_DB_NAME] # implicitly create the db with name MONGO_DB_NAME

        if not create_app_user(db):
            print("ERROR: App User could not be created. Exiting initialization.")
            return False

        users_validator = load_json_schema(USERS_SCHEMA_FILE)
        sessions_validator = load_json_schema(SESSIONS_SCHEMA_FILE)
        messages_validator = load_json_schema(MESSAGES_SCHEMA_FILE)

        if not (users_validator and sessions_validator and messages_validator):
            print("ERROR: One or more schema validators failed to load. Exiting initialization.")
            return False

        print("\n--- Initializing 'users' collection ---")
        if not apply_schema_validation(db, "users", users_validator): return False
        try:
            users_collection = db.users
            users_collection.create_index("username", unique=True, name="unique_username")
            print("Ensured unique index on 'users.username'")
        except OperationFailure as e:
            print(f"WARNING: Could not create unique index on 'users.username': {e}")
        except Exception as e:
            print(f"ERROR: Failed to ensure indexes for 'users' collection: {e}")

        print("\n--- Initializing 'sessions' collection ---")
        if not apply_schema_validation(db, "sessions", sessions_validator): return False
        try:
            sessions_collection = db.sessions
            sessions_collection.create_index([("participants", 1)], name="session_participants_index")
            sessions_collection.create_index([("start_time", 1)], name="session_start_time_index")
            print("Ensured indexes on 'sessions' collection (participants, start_time)")
        except OperationFailure as e:
            print(f"ERROR: Failed to ensure indexes for 'sessions': {e}")
        except Exception as e:
            print(f"ERROR: Failed to ensure indexes for 'sessions' collection: {e}")

        print("\n--- Intializing 'messages' collection ---")
        if not apply_schema_validation(db, "messages", messages_validator): return False
        try:
            messages_collection = db.messages
            messages_collection.create_index([("sessionId", 1), ("timestamp", 1)], name="message_session_timestamp_index")
            messages_collection.create_index([("sender", 1)], name="message_sender_index")
            messages_collection.create_index([("receivers", 1)], name="message_receivers_index")
            print("Ensured indexes on 'messages' collection (sessionId, timestamp, sender, receivers)")
        except OperationFailure as e:
            print(f"WARNING: Could not create index on 'messages': {e}")
        except Exception as e:
            print(f"ERROR: Failed to ensure indexes for 'messages' collection: {e}")
            return False
    except Exception as e:
        print(f"ERROR: Failed to connect to MongoDB or initialize schema: {e}")
        return False
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    max_retries = 20
    retry_delay_seconds = 3
    for i in range(max_retries):
        if initialize_mongodb_schema():
            sys.exit(0)
        else:
            print(f"Attempt {i+1}/{max_retries} failed to initiaize schema. Retrying in {retry_delay_seconds} seconds...")
            time.sleep(retry_delay_seconds)
    print("Failed to initialize MongoDB schema after multiple retries. Exiting.")
    sys.exit(1)