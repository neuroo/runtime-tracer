/*
    Dynamic tracing and IDA integration
    by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info

    Copyright (c) 2011 Romain Gaucher <r@rgaucher.info>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#ifndef __DATABASE_H
#define __DATABASE_H

#include <ctime>
#include "config.h"
#include "sqlite3.h"

const char db_schema[] = "CREATE TABLE IF NOT EXISTS snapshot \
(id UNSIGNED INTEGER PRIMARY KEY, trace_id UNSIGNED INTEGER, address UNSIGNED INTEGER, register UNSIGNED INTEGER, value UNSIGNED INTEGER, memory BLOB);\
CREATE TABLE IF NOT EXISTS disasm (id UNSIGNED INTEGER PRIMARY KEY, address UNSIGNED INTEGER, asm TEXT);\
CREATE TABLE IF NOT EXISTS instr (id UNSIGNED INTEGER PRIMARY KEY, trace_id UNSIGNED INTEGER, address UNSIGNED INTEGER);\
CREATE TABLE IF NOT EXISTS trace (id UNSIGNED INTEGER PRIMARY KEY, thread_id UNSIGNED INTEGER, prev_address UNSIGNED INTEGER, cur_address UNSIGNED INTEGER);\
CREATE TABLE IF NOT EXISTS register (id UNSIGNED INTEGER PRIMARY KEY, register UNSIGNED INTEGER, name TEXT);\
DELETE FROM snapshot; DELETE FROM disasm; DELETE FROM instr; DELETE FROM trace; DELETE FROM register;";

const char stmt_insert_disasm[] = "INSERT INTO disasm VALUES (NULL, ?, ?);";
const char stmt_insert_snapshot[] = "INSERT INTO snapshot VALUES (NULL, ?, ?, ?, ?, ?);";
const char stmt_insert_instr[] = "INSERT INTO instr VALUES (NULL, ?, ?);";
const char stmt_insert_trace[] = "INSERT INTO trace VALUES (NULL, ?, ?, ?);";
const char stmt_insert_register[] = "INSERT INTO register VALUES (NULL, ?, ?);";


class Database {
    string backup_path;
    sqlite3* db;

    sqlite3_stmt* insert_disasm;
    sqlite3_stmt* insert_snapshot;
    sqlite3_stmt* insert_instr;
    sqlite3_stmt* insert_trace;
    sqlite3_stmt* insert_register;

    bool usable;

    void createSchema() {
        if (db && usable) {
            sqlite3_exec(db, db_schema, 0, 0, 0);
            
            // Instanciate the prepared statements
            sqlite3_prepare(db, stmt_insert_disasm, -1, &insert_disasm, 0);
            sqlite3_prepare(db, stmt_insert_snapshot, -1, &insert_snapshot, 0);
            sqlite3_prepare(db, stmt_insert_instr, -1, &insert_instr, 0);
            sqlite3_prepare(db, stmt_insert_trace, -1, &insert_trace, 0);
            sqlite3_prepare(db, stmt_insert_register, -1, &insert_register, 0);

            populateRegisters();
        }
    }

    void populateRegister(int reg_value, const string& reg_name) {
        if (SQLITE_OK != sqlite3_bind_int(insert_register, 1, (int)reg_value)) {
#ifdef MY_DEBUG
            probelog << "populateRegister: Cannot insert INT: " << reg_value << endl << flush; 
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_text(insert_register, 2, reg_name.c_str(), reg_name.size(), SQLITE_STATIC)) {
#ifdef MY_DEBUG
            probelog << "populateRegister: Cannot insert TEXT: " << reg_name << endl << flush; 
#endif
            return;
        }
        if (SQLITE_DONE != sqlite3_step(insert_register))
            return;
        sqlite3_reset(insert_register);
    }

    void populateRegisters() {
        populateRegister(REG_EAX, "eax");
        populateRegister(REG_EBX, "ebx");
        populateRegister(REG_ECX, "ecx");
        populateRegister(REG_EDX, "edx");
        populateRegister(REG_ESI, "esi");
        populateRegister(REG_EDI, "edi");
        populateRegister(REG_ESP, "esp");
    }


    void backup(bool isSave=true) {
        int rc;                   /* Function return code */
        sqlite3 *pFile;           /* Database connection opened on zFilename */
        sqlite3_backup *pBackup;  /* Backup object used to copy data */
        sqlite3 *pTo;             /* Database to copy to (pFile or pInMemory) */
        sqlite3 *pFrom;           /* Database to copy from (pFile or pInMemory) */

        rc = sqlite3_open(backup_path.c_str(), &pFile);
        if( rc==SQLITE_OK ){
            pFrom = (isSave ? db : pFile);
            pTo   = (isSave ? pFile     : db);

            pBackup = sqlite3_backup_init(pTo, "main", pFrom, "main");
            if( pBackup ){
              (void)sqlite3_backup_step(pBackup, -1);
              (void)sqlite3_backup_finish(pBackup);
            }
            rc = sqlite3_errcode(pTo);
        }

        sqlite3_close(pFile);
    }

    string trace_time() const {
        time_t t = time(0);
        struct tm *local = localtime(&t);
        char output[30];
        strftime(output, 30, "%m-%d-%H-%M-%S", local);
        return string(output);
    }

    Database(const Database& _p) {}

  public:

    Database()
    : usable(false), db(0) {
//#ifndef MY_DEBUG
        // if (SQLITE_OK == sqlite3_open_v2("d.db", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, 0)) {
//#else
//        if (SQLITE_OK == sqlite3_open("debug-trace.db", &db)) {
//#endif
        // probelog << "DB::DB()" << endl << flush;

        if (SQLITE_OK == sqlite3_open(":memory:", &db)) {
            backup_path = "C:\\pin-trace-" + trace_time() + ".db";
            usable = true;
            createSchema();
        }
        else {
            probelog << "Error with DB: " << sqlite3_errcode(db) << endl << flush;
        }
    }

    Database& operator=(const Database& _p) {
        return *this;
    }

    void save() {
        probelog << "Backup into " << backup_path << endl << flush;
        backup();
    }

    // Can we use the database? If not, it's okay.. we'll just
    // don't persist anything!
    inline bool isReady() const {
        return usable;
    }

    void disasm(ADDRINT addr, const string& disasm) {
        if (!isReady())
            return;
        if (SQLITE_OK != sqlite3_bind_int(insert_disasm, 1, (int)addr)) {
            probelog << "Cannot bind INT: " << addr << endl << flush;
            return;
        }
        if (SQLITE_OK != sqlite3_bind_text(insert_disasm, 2, disasm.c_str(), disasm.size(), SQLITE_STATIC)) {
            probelog << "Cannot bind TEXT:" << disasm << endl << flush;
            return;
        }
        if (SQLITE_DONE != sqlite3_step(insert_disasm)) {
            probelog << "Canno execute the prepared statement" << endl << flush;
            return;
        }

        sqlite3_reset(insert_disasm);
    }


    // id INTEGER PRIMARY KEY, trace_id INTEGER, address UNSIGNED INTEGER, register UNSIGNED INTEGER, value UNSIGNED INTEGER, memory BLOB
    void snapshot(ADDRINT addr, TraceId traceid, REG reg, ADDRINT reg_value, const char* reg_str, bool skip_reg_str=false) {
        if (!isReady())
            return;

        if (SQLITE_OK != sqlite3_bind_int(insert_snapshot, 1, (int)traceid)) {
#ifdef MY_DEBUG
            probelog << "snapshot:: cannot bind int: " << traceid << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_int(insert_snapshot, 2, (int)addr)) {
#ifdef MY_DEBUG
            probelog << "snapshot:: cannot bind int: " << addr << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_int(insert_snapshot, 3, (int)reg)) {
#ifdef MY_DEBUG
            probelog << "snapshot:: cannot bind int: " << reg << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_int(insert_snapshot, 4, (int)reg_value)) {
#ifdef MY_DEBUG
            probelog << "snapshot:: cannot bind int: " << reg_value << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_blob(insert_snapshot, 5, reg_str, skip_reg_str ? 0 : size_capture, SQLITE_TRANSIENT)) {
#ifdef MY_DEBUG
            probelog << "snapshot:: cannot bind blob: " << reg_str << endl << flush;
#endif
            return;
        }
        if (SQLITE_DONE != sqlite3_step(insert_snapshot))
            return;
        sqlite3_reset(insert_snapshot);
    }



    void instr(ADDRINT addr, TraceId traceid) {
        if (!isReady())
            return;
        if (SQLITE_OK != sqlite3_bind_int(insert_instr, 1, (int)traceid)) {
#ifdef MY_DEBUG
            probelog << "instr:: Cannot bind to an INT: traceid=" << (int)traceid << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_int(insert_instr, 2, (int)addr)) {
#ifdef MY_DEBUG
            probelog << "instr:: Cannot bind to an INT: addr=" << (int)addr << endl << flush;
#endif
            return;
        }
        if (SQLITE_DONE != sqlite3_step(insert_instr))
            return;
        sqlite3_reset(insert_instr);
    }




    void trace(THREADID thread_id, ADDRINT prev_addr, ADDRINT cur_addr) {
        if (!isReady())
            return;

        if (SQLITE_OK != sqlite3_bind_int(insert_trace, 1, (int)thread_id)) {
#ifdef MY_DEBUG
            probelog << "trace:: Cannot bind to an INT: traceid=" << (int)prev_addr << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_int(insert_trace, 2, (int)prev_addr)) {
#ifdef MY_DEBUG
            probelog << "trace:: Cannot bind to an INT: traceid=" << (int)prev_addr << endl << flush;
#endif
            return;
        }
        if (SQLITE_OK != sqlite3_bind_int(insert_trace, 3, (int)cur_addr)) {
#ifdef MY_DEBUG
            probelog << "trace:: Cannot bind to an INT: addr=" << (int)cur_addr << endl << flush;
#endif
            return;
        }
        if (SQLITE_DONE != sqlite3_step(insert_trace))
            return;
        sqlite3_reset(insert_trace);
    }

    ~Database() {
        sqlite3_finalize(insert_disasm);
        sqlite3_finalize(insert_instr);
        sqlite3_finalize(insert_snapshot);
        sqlite3_finalize(insert_register);
        sqlite3_finalize(insert_trace);

        sqlite3_close(db);
    }
};

#endif
