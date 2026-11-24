@echo off
REM Runs the daily feed snapshot using the project's venv. Used by Task Scheduler.
cd /d "%~dp0.."
".venv\Scripts\python.exe" scripts\snapshot_feeds.py >> data\raw\feeds_task.log 2>&1