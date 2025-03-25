#!/usr/bin/env python3
import json
import copy
import datetime
import asyncio
import sqlite3
from lib.logger import logger

import pandas as dp
from tabulate import tabulate


db_path = ('scom_database.db')

class HELPERS:
    """Helper methods methods"""
    
    async def parse_entry(_entry: dict):
        """Copy the entry dict and convert the values to strings
        
        Args: 
            _entry: msldap entry dictionary
        """
        entries = []
        try:
            async for entry, _ in _entry:
                attributes = entry['attributes']
                for k,v in attributes.items():
                    entry['attributes'][k] = str(v) # convert everything to a string 
                entries.append(entry)
            return entries
        except Exception as e:
            logger.info(f"Something went wrong during entry parsing {e}")
            
    
    def create_db():
        """Preps the database for results
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS ManagementServers (Hostname, SPN, Vulnerable, UNIQUE(Hostname))')
        cursor.execute('CREATE TABLE IF NOT EXISTS Users (Username, Description, SPN, pwdLastSet, UNIQUE(Username))')
        cursor.execute('CREATE TABLE IF NOT EXISTS Groups (Name, Description, Member,UNIQUE(Name))')
        cursor.execute('CREATE TABLE IF NOT EXISTS Credentials (Username, Password, SourceHost)')
        conn.commit()
        conn.close()
        
    def insert_to_db(table_name: str, data: dict):
        """Insert the dict into the sqlite db.
        
        Args:
            table_name (str): The table name the data is inserted into
            data (dict): The data to add to the new entry
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        spn = data['ServicePrincipalNames'].replace("['", "").replace("']", "\n").replace("', '", "\n") if 'ServicePrincipalNames' in data else ''
        
        if table_name == "ManagementServers":
            vulnerable = "False"
            if "MSOMHSvc" and "MSOMSdkSvc" in data['ServicePrincipalNames']:
                vulnerable = "True"
            cursor.execute('INSERT OR REPLACE INTO ManagementServers (Hostname, SPN, Vulnerable) VALUES (?, ?, ?)', (data['Hostname'], spn, vulnerable))
            conn.commit()
        if table_name == "Users":
            cursor.execute('INSERT OR REPLACE INTO Users (Username, Description, SPN, pwdLastSet) VALUES (?, ?, ?, ?)', (data['Username'], data['Description'], spn, data['pwdLastSet']))
            conn.commit()
        conn.close()
        
    
    def show_table(table_name:str) -> None:
        """Helper to print the table

        Args:
            table_name (str): The table name to print
        """
        conn = sqlite3.connect(db_path)
        tb = dp.read_sql(f"SELECT * FROM {table_name}", conn)
        logger.info(f"{table_name} Table:")
        logger.info(tabulate(tb, showindex=False, headers=tb.columns, tablefmt='grid'))
        conn.close()   
        

        
