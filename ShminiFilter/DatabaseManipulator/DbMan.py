import os
import sys
import sqlite3


# Global variables:
DATABASE_NAME = "minifilter_database.db"
entry_size = ""
calling_process = ""
execution_context = ""
file_name = ""
name_extension = ""
parent_directory = ""
share = ""
stream = ""
volume = ""
module_descriptor = ""
information_size = ""
information_type = ""
special_string = ""
security_info = ""
sharing_info = ""
timestamp = ""


def get_next_string(byte_info):
    next_string = ""
    string_size = 0
    for info_part in byte_info:
        if info_part == b'\x00':
            break  # End of string
        next_string += info_part.decode()
        string_size += 1
    return next_string, string_size


def parse_entry(update_info, entry_offset):
    global entry_size
    global calling_process
    global execution_context
    global file_name
    global name_extension
    global parent_directory
    global share
    global stream
    global volume
    global module_descriptor
    global information_size
    global information_type
    global special_string
    global security_info
    global sharing_info
    global timestamp
    entry_size = str(int.from_bytes(update_info[entry_offset: entry_offset + 4]))
    entry_offset += 4
    calling_process = hex(int.from_bytes(update_info[entry_offset: entry_offset + 8]))
    entry_offset += 8
    execution_context = update_info[entry_offset: entry_offset + 2].decode()
    entry_offset += 3
    file_name, name_length = get_next_string(update_info[entry_offset::])
    entry_offset += name_length + 1  # Length does not account for null terminator
    name_extension, extension_length = get_next_string(update_info[entry_offset::])
    entry_offset += extension_length + 1  # Length does not account for null terminator
    parent_directory, parentdir_length = get_next_string(update_info[entry_offset::])
    entry_offset += parentdir_length + 1  # Length does not account for null terminator
    share, share_length = get_next_string(update_info[entry_offset::])
    entry_offset += share_length + 1  # Length does not account for null terminator
    stream, stream_length = get_next_string(update_info[entry_offset::])
    entry_offset += stream_length + 1  # Length does not account for null terminator
    volume, volume_length = get_next_string(update_info[entry_offset::])
    entry_offset += volume_length + 1  # Length does not account for null terminator
    module_descriptor = hex(int.from_bytes(update_info[entry_offset: entry_offset + 8]))
    entry_offset += 8
    information_size = str(int.from_bytes(update_info[entry_offset: entry_offset + 4]))
    entry_offset += 4
    information_type = update_info[entry_offset: entry_offset + 4].decode()
    entry_offset += 5
    special_string, special_length = get_next_string(update_info[entry_offset::])
    entry_offset += special_length + 1  # Length does not account for null terminator
    security_info, security_info_length = get_next_string(update_info[entry_offset::])
    entry_offset += security_info_length + 1  # Length does not account for null terminator
    sharing_info, sharing_info_length = get_next_string(update_info[entry_offset::])
    entry_offset += sharing_info_length + 1  # Length does not account for null terminator
    timestamp = str(int.from_bytes(update_info[entry_offset: entry_offset + 8]))
    entry_offset += 8
    return entry_offset


def insert_into_database(sqlite_conn):
    global entry_size
    global calling_process
    global execution_context
    global file_name
    global name_extension
    global parent_directory
    global share
    global stream
    global volume
    global module_descriptor
    global information_size
    global information_type
    global special_string
    global security_info
    global sharing_info
    global timestamp
    sqlite_conn.execute(
        """
                                    INSERT INTO operations (
                                    entry_size,
                                    calling_process,
                                    execution_context,
                                    file_name,
                                    name_extension,
                                    parent_directory,    
                                    share,
                                    stream,
                                    volume,   
                                    module_descriptor,
                                    information_size,
                                    information_type,     
                                    special_string,
                                    security_info,
                                    sharing_info,                  
                                    timestamp) VALUES 
                                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                    """,
        (entry_size, calling_process, execution_context, file_name, name_extension,
         parent_directory, share, stream, volume, module_descriptor, information_size,
         information_type, special_string, security_info, sharing_info, timestamp))


def main():
    if len(sys.argv) != 2:
        print("[-] Usage: python.exe DatabaseManipulator.py name_of_relative_entry")
        return False
    if os.path.exists(sys.argv[1]):
        print("[-] Usage: python.exe DatabaseManipulator.py existing_name_of_relative_entry")
        return False
    with open(sys.argv[1], 'rb') as database_update:
        update_info = database_update.read()


    # Make sure database is up and main table is set up:
    sqlite_conn = sqlite3.connect(DATABASE_NAME)
    dbcursor = sqlite_conn.cursor()  # Used to send queries to DB
    sqlite_conn.execute("""
                            CREATE TABLE IF NOT EXISTS operations (
                            entry_size TEXT,
                            calling_process TEXT,
                            execution_context TEXT,
                            file_name TEXT,
                            name_extension TEXT,
                            parent_directory TEXT,    
                            share TEXT,
                            stream TEXT,
                            volume TEXT,   
                            module_descriptor TEXT,
                            information_size TEXT,
                            information_type TEXT,     
                            special_string TEXT,
                            security_info TEXT,
                            sharing_info TEXT,                  
                            timestamp TEXT
                            );
                            """)
    sqlite_conn.commit()


    # Go over the entries and create a list with the actual entries:
    entries_list = []
    entry_offset = 0
    while entry_offset < len(update_info):
        entry_offset = parse_entry(update_info, entry_offset)
        insert_into_database(sqlite_conn)
    dbcursor.close()
    if sqlite_conn:
        sqlite_conn.close()
        print('[+] SQLite Connection closed, finished adding current update to DB')
    return True


if __name__ == "__main__":
    main()
    