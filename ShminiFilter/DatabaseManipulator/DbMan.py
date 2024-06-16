import os
import sys
import sqlite3
import struct


# Global variables:
STARTINFO_SIZE = 280
SPECIAL_EVENT_SIZE = 56
DATABASE_NAME = "minifilter_database.db"
PARSEABLE_DATABASE_NAME = "praseable_database.txt"
basic_events_list = []
special_entry_list = []


def get_db_structure(conn, cursor):
    database_string = ""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    if tables:
        database_string += f"Database {DATABASE_NAME} contains the following tables:\n\n"
        for table_name in tables:
            table_name = table_name[0]
            database_string += f"Table: {table_name}\n"
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            database_string += f"Columns:\n"
            for col in columns:
                database_string += f"  {col[1]} ({col[2]})\n"
            cursor.execute(f"SELECT * FROM {table_name};")
            rows = cursor.fetchall()
            database_string += f" \nRows:\n"
            for row in rows:
                database_string += f"  {row}\n"
            database_string +="\n" + "-" * 40 + "\n\n"
    else:
        database_string += f"No tables found in database {DATABASE_NAME}.\n"
    return database_string


def stringify_tuple(integer_tuple):
    string_list = []
    try:
        for integer in integer_tuple:
            string_list.append(str(integer))
        return tuple(string_list)
    except:
        return ()


def get_next_string(byte_info):
    next_string = ""
    string_size = 0
    for info_part in byte_info:
        if info_part == b'\x00':
            break  # End of string
        next_string += info_part.decode()
        string_size += 1
    return next_string, string_size


def parse_entry(update_info_relative):
    global special_entry_list
    special_entry_list = []
    entry_offset = 0
    special_entry_list.append(str(int.from_bytes(update_info_relative[entry_offset: entry_offset + 4])))
    entry_offset += 4
    special_entry_list.append(hex(int.from_bytes(update_info_relative[entry_offset: entry_offset + 8])))
    entry_offset += 8
    special_entry_list.append(hex(int.from_bytes(update_info_relative[entry_offset: entry_offset + 8])))
    entry_offset += 8
    special_entry_list.append(str(int.from_bytes(update_info_relative[entry_offset: entry_offset + 4])))
    entry_offset += 4
    special_entry_list.append(str(int.from_bytes(update_info_relative[entry_offset: entry_offset + 8])))
    entry_offset += 8
    special_entry_list.append(update_info_relative[entry_offset: entry_offset + 2].decode())
    entry_offset += 3
    special_entry_list.append(update_info_relative[entry_offset: entry_offset + 4].decode())
    entry_offset += 5
    operation_descriptor, opdesc_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(operation_descriptor)
    entry_offset += opdesc_length + 1  # Length does not account for null terminator
    file_name, name_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(file_name)
    entry_offset += name_length + 1  # Length does not account for null terminator
    name_extension, extension_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(name_extension)
    entry_offset += extension_length + 1  # Length does not account for null terminator
    parent_directory, parentdir_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(parent_directory)
    entry_offset += parentdir_length + 1  # Length does not account for null terminator
    share, share_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(share)
    entry_offset += share_length + 1  # Length does not account for null terminator
    stream, stream_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(stream)
    entry_offset += stream_length + 1  # Length does not account for null terminator
    volume, volume_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(volume)
    entry_offset += volume_length + 1  # Length does not account for null terminator
    special_string, special_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(special_string)
    entry_offset += special_length + 1  # Length does not account for null terminator
    security_info, security_info_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(security_info)
    entry_offset += security_info_length + 1  # Length does not account for null terminator
    sharing_info, sharing_info_length = get_next_string(update_info_relative[entry_offset::])
    special_entry_list.append(sharing_info)
    entry_offset += sharing_info_length + 1  # Length does not account for null terminator
    special_entry_list = tuple(special_entry_list)
    return entry_offset


def insert_into_database(dbcursor, is_special):
    global basic_events_list
    global special_entry_list
    if is_special:
        dbcursor.execute(
            """
                                        INSERT INTO special_events (
                                        entry_size,
                                        calling_process,
                                        module_descriptor,
                                        information_size,
                                        timestamp,
                                        execution_context,
                                        information_type, 
                                        operation_descriptor,
                                        file_name,
                                        name_extension,
                                        parent_directory,    
                                        share,
                                        stream,
                                        volume,       
                                        special_string,
                                        security_info,
                                        sharing_info) VALUES 
                                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                        """, stringify_tuple(special_entry_list))
    else:
        dbcursor.execute(
            """
                                        INSERT INTO basic_events (
                                        EntryIdentifier,
                                        CopiedBytesCount,
                                        AccessViolationCount,
                                        CreatePreCount,
                                        ReadPreCount,
                                        WritePreCount,
                                        SetInfoPreCount,
                                        CleanupPreCount,
                                        FileSysCntlPreCount,
                                        DirControlPreCount,
                                        CreatePostCount,
                                        ReadPostCount,
                                        WritePostCount,
                                        SetInfoPostCount,
                                        CleanupPostCount,
                                        FileSysCntlPostCount,
                                        DirControlPostCount,
                                        GenericReadCount,
                                        GenericWriteCount,
                                        GenericExecuteCount,
                                        FileShareReadCount,
                                        FileShareWriteCount,
                                        FileShareDeleteCount,
                                        CRootCount,
                                        WindowsRootCount,
                                        System32RootCount,
                                        DriversRootCount,
                                        NtoskrnlCount,
                                        NtdllCount,
                                        User32dllCount,
                                        KernelModeCount,
                                        UserModeCount,
                                        TextCount,
                                        ByteCount,
                                        DetectedCount) VALUES 
                                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                        """, stringify_tuple(basic_events_list))


def main():
    global basic_events_list
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
                            CREATE TABLE IF NOT EXISTS special_events (
                            TEXT entry_size,
                            TEXT calling_process,
                            TEXT module_descriptor,
                            TEXT information_size,
                            TEXT timestamp,
                            TEXT execution_context,
                            TEXT information_type, 
                            TEXT operation_descriptor,
                            TEXT file_name,
                            TEXT name_extension,
                            TEXT parent_directory,    
                            TEXT share,
                            TEXT stream,
                            TEXT volume,       
                            TEXT special_string,
                            TEXT security_info,
                            TEXT sharing_info
                            );
                            """)
    sqlite_conn.commit()
    sqlite_conn.execute("""
                            CREATE TABLE IF NOT EXISTS basic_events (
                            EntryIdentifier TEXT,
                            CopiedBytesCount TEXT,
                            AccessViolationCount TEXT,
                            CreatePreCount TEXT,
                            ReadPreCount TEXT,
                            WritePreCount TEXT,
                            SetInfoPreCount TEXT,
                            CleanupPreCount TEXT,
                            FileSysCntlPreCount TEXT,
                            DirControlPreCount TEXT,
                            CreatePostCount TEXT,
                            ReadPostCount TEXT,
                            WritePostCount TEXT,
                            SetInfoPostCount TEXT,
                            CleanupPostCount TEXT,
                            FileSysCntlPostCount TEXT,
                            DirControlPostCount TEXT,
                            GenericReadCount TEXT,
                            GenericWriteCount TEXT,
                            GenericExecuteCount TEXT,
                            FileShareReadCount TEXT,
                            FileShareWriteCount TEXT,
                            FileShareDeleteCount TEXT,
                            CRootCount TEXT,
                            WindowsRootCount TEXT,
                            System32RootCount TEXT,
                            DriversRootCount TEXT,
                            NtoskrnlCount TEXT,
                            NtdllCount TEXT,
                            User32dllCount TEXT,
                            KernelModeCount TEXT,
                            UserModeCount TEXT,
                            TextCount TEXT,
                            ByteCount TEXT,
                            DetectedCount TEXT
                            );
                            """)
    sqlite_conn.commit()


    # Go over the entries and create a list with the actual entries:
    entries_list = []
    entry_offset = STARTINFO_SIZE
    entry_number = 0
    basic_events_list = struct.unpack("35q", update_info[0: STARTINFO_SIZE])
    insert_into_database(dbcursor, False)
    while entry_offset < len(update_info):
        entry_offset += parse_entry(update_info[entry_offset::])
        insert_into_database(dbcursor, True)
        entry_number += 1


    # Write parseable database into text file:
    with open(PARSEABLE_DATABASE_NAME, 'wt') as parse_db:
        parse_db.write(get_db_structure(sqlite_conn, dbcursor))
    dbcursor.close()
    if sqlite_conn:
        sqlite_conn.close()
        print('[+] SQLite Connection closed, finished adding current update to DB')
    return True


if __name__ == "__main__":
    main()
    