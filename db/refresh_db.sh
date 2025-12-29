#!/bin/bash
rm database.db
touch database.db
sqlite3 database.db < schema.sql
